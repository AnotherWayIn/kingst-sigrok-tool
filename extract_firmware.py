#!/usr/bin/env python3
"""
Kingst LA Series Firmware Extractor for sigrok
Extracts all firmware from the KingstVIS macOS binary so that
sigrok/sigrok-cli/PulseView can use Kingst logic analyzers.

Supports:
  Cypress FX2 (USB MCU) firmware:
    fw01A1.hex  LA1010 rev A1
    fw01A2.hex  LA1010 rev A2
    fw01A3.hex  LA1010 rev A3
    fw01A4.hex  LA1010 rev A4
    fw03A1.fw   LA1016 / LA2016 / LA5016 / LA5032 / LA1010A series
  Spartan FPGA bitstreams (required for LA2016/LA5016/LA1016/LA5032/LA1010A):
    LA1010A0.bitstream  LA1010A0.bitstream  LA1010A1.bitstream  LA1010A2.bitstream
    LA1016.bitstream    LA1016A1.bitstream  LA2016.bitstream    LA2016A1.bitstream
    LA2016A2.bitstream  LA5016.bitstream    LA5016A1.bitstream  LA5016A2.bitstream
    LA5032A0.bitstream  MS6218.bitstream

Usage:
    python3 extract_firmware.py
    python3 extract_firmware.py /path/to/KingstVIS [output_dir]
"""

import sys
import os
import struct
import zlib
from pathlib import Path


KINGSTVIS_DEFAULT_PATHS = [
    "/Applications/KingstVIS.app/Contents/MacOS/KingstVIS",
    str(Path.home() / "Downloads" / "KingstVIS.app" / "Contents" / "MacOS" / "KingstVIS"),
]

DEFAULT_OUTPUT_DIR = Path.home() / ".local" / "share" / "sigrok-firmware" / "kingst"

# Qt resource tree node is 14 bytes:
#   [0:4]  name_off  (BE u32) - byte offset into names section, pointing at hash field
#   [4:6]  flags     (BE u16) - 0=file, 2=directory
#   [6:10] v1        (BE u32) - dir: child_count; file: (country<<16)|lang
#   [10:14] v2       (BE u32) - dir: first_child_index; file: data_offset
_TREE_ENTRY_SIZE = 14
_FLAG_DIR = 2


def find_macho_const_section(data):
    """Find __TEXT __const section in a Mach-O binary. Returns (file_offset, size)."""
    if len(data) < 32:
        return None, None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:  # 64-bit little-endian Mach-O (arm64 / x86_64)
        ncmds = struct.unpack_from("<I", data, 16)[0]
        cmd_offset = 32
    else:
        return None, None

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", data, cmd_offset)
        if cmd == 0x19:  # LC_SEGMENT_64
            segname = data[cmd_offset + 8: cmd_offset + 24].rstrip(b"\x00").decode("ascii", errors="ignore")
            if segname == "__TEXT":
                nsects = struct.unpack_from("<I", data, cmd_offset + 64)[0]
                sect_off = cmd_offset + 72
                for _ in range(nsects):
                    sectname = data[sect_off: sect_off + 16].rstrip(b"\x00").decode("ascii", errors="ignore")
                    if sectname == "__const":
                        file_off = struct.unpack_from("<I", data, sect_off + 48)[0]
                        size = struct.unpack_from("<Q", data, sect_off + 40)[0]
                        return file_off, size
                    sect_off += 80
        cmd_offset += cmdsize
    return None, None


def _find_qt_anchors(const_data):
    """
    Locate the three Qt rcc sections (tree, names, data) inside __TEXT __const.

    Returns (tree_base, names_base, data_base) as byte offsets within const_data,
    or raises RuntimeError if the binary layout is not recognised.

    Strategy:
      1. Find the names section by searching for the 'fwusb' name entry
         (length=5, hash, UTF-16BE chars).  This is a stable anchor.
      2. Walk backwards from 'fwusb' to the first entry of the names section.
      3. Scan forward through all name entries; record chars_off -> name.
      4. Locate the root tree directory: a 14-byte entry with flags=2, count=3..5,
         first_child=1 that lives just before the names section.
      5. Data section starts after the names section (skip zero padding).
    """
    # ---- 1. Find 'fwusb' entry ----
    fwusb_chars = "fwusb".encode("utf-16-be")
    fwusb_needle = struct.pack(">HI", 5, 0x006DEC92) + fwusb_chars  # len + known hash + chars
    pos = const_data.find(fwusb_needle)
    if pos == -1:
        # Fallback: find by chars only
        pos = const_data.find(fwusb_chars)
        if pos == -1:
            raise RuntimeError("Could not find Qt resource 'fwusb' anchor in binary.")
        pos -= 6  # back to entry start (len + hash)
    names_base = pos  # first entry of names section = 'fwusb'

    # ---- 2+3. Walk names section, build name lookup ----
    # Qt tree name_off can point to either:
    #   (a) chars_off  = entry_start + 6   (confirmed for some entries)
    #   (b) hash_off   = entry_start + 2   (confirmed for other entries)
    # We store both offsets for every name so lookup always works.
    name_by_off = {}
    off = 0
    while True:
        abs_pos = names_base + off
        if abs_pos + 6 > len(const_data):
            break
        nl = struct.unpack_from(">H", const_data, abs_pos)[0]
        if nl == 0 or nl > 64:
            break
        nb = const_data[abs_pos + 6: abs_pos + 6 + nl * 2]
        try:
            nm = nb.decode("utf-16-be")
        except UnicodeDecodeError:
            break
        name_by_off[off + 2] = nm   # hash_off  = entry_start + 2
        name_by_off[off + 6] = nm   # chars_off = entry_start + 6
        off += 6 + nl * 2
    names_end = names_base + off

    # ---- 4. Find data section (size-prefixed blob run after names section) ----
    # The Qt rcc data section lives AFTER the names section in this binary.
    # Step by 2 (not 4) to avoid missing the start due to alignment gaps.
    data_base = None
    search = names_end
    while search < len(const_data) - 8:
        size = struct.unpack_from(">I", const_data, search)[0]
        if size == 0:
            search += 2
            continue
        if 1000 <= size <= 2_000_000:
            run, run_count = search, 0
            while run_count < 5:
                s = struct.unpack_from(">I", const_data, run)[0]
                if 1000 <= s <= 2_000_000:
                    run += 4 + s
                    run_count += 1
                else:
                    break
            if run_count >= 5:
                data_base = search
                break
        search += 2
    if data_base is None:
        raise RuntimeError("Could not locate Qt resource data section.")

    # ---- 5. Find tree base (root dir entry just before names section) ----
    # Scan backwards in 2-byte steps; look for flags=2, plausible count+child
    tree_base = None
    for candidate in range(names_base - _TREE_ENTRY_SIZE, max(0, names_base - 4000), -2):
        flags = struct.unpack_from(">H", const_data, candidate + 4)[0]
        if flags != _FLAG_DIR:
            continue
        count = struct.unpack_from(">I", const_data, candidate + 6)[0]
        first_child = struct.unpack_from(">I", const_data, candidate + 10)[0]
        if 2 <= count <= 10 and first_child == 1:
            tree_base = candidate
            break
    if tree_base is None:
        raise RuntimeError("Could not locate Qt resource tree section.")

    return tree_base, names_base, data_base, name_by_off


def _read_tree_entry(const_data, tree_base, idx):
    pos = tree_base + idx * _TREE_ENTRY_SIZE
    name_off   = struct.unpack_from(">I", const_data, pos)[0]
    flags      = struct.unpack_from(">H", const_data, pos + 4)[0]
    v1         = struct.unpack_from(">I", const_data, pos + 6)[0]
    v2         = struct.unpack_from(">I", const_data, pos + 10)[0]
    return name_off, flags, v1, v2


def _collect_dir_children(const_data, tree_base, data_base, name_by_off, dir_idx):
    """
    Return a list of (name, blob, stored_size) for all direct file children
    of the directory at tree index dir_idx.  Skips sub-directories.
    """
    _, flags, count, first_child = _read_tree_entry(const_data, tree_base, dir_idx)
    if flags != _FLAG_DIR:
        return []
    results = []
    for ci in range(first_child, first_child + count):
        name_off, child_flags, cv1, cv2 = _read_tree_entry(const_data, tree_base, ci)
        if child_flags == _FLAG_DIR:
            continue  # skip sub-dirs
        name = name_by_off.get(name_off, "")
        abs_data = data_base + cv2
        if abs_data + 4 > len(const_data):
            continue
        stored_size = struct.unpack_from(">I", const_data, abs_data)[0]
        if stored_size == 0 or stored_size > 2_000_000:
            continue
        blob = const_data[abs_data + 4: abs_data + 4 + stored_size]
        results.append((name, blob, stored_size))
    return results


def _find_dir_by_content(const_data, tree_base, data_base, name_by_off, root_idx,
                         fw_names):
    """
    Find the index of a child directory whose file children include names from fw_names.
    Returns (dir_idx, children_list) or (None, []).
    """
    _, flags, count, first_child = _read_tree_entry(const_data, tree_base, root_idx)
    if flags != _FLAG_DIR:
        return None, []
    for ci in range(first_child, first_child + count):
        _, child_flags, _, _ = _read_tree_entry(const_data, tree_base, ci)
        if child_flags != _FLAG_DIR:
            continue
        children = _collect_dir_children(const_data, tree_base, data_base, name_by_off, ci)
        child_names = {nm for nm, _, _ in children}
        if child_names & fw_names:
            return ci, children
    return None, []


def _decompress_fpga(blob):
    """Return raw FPGA bitstream bytes, decompressing zlib if needed."""
    if blob[:2] == b"\xff\xff":
        return blob  # already raw Xilinx bitstream
    if len(blob) > 4 and blob[4:6] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
        return zlib.decompress(blob[4:])
    return blob


# Known Cypress FX2 firmware file stems (start with 'fw', stored in fwusb dir).
# fw01A1-fw01A4 are Intel HEX (.hex); fw03A1 is raw binary (.fw).
_CYPRESS_FW_NAMES = {"fw01A1", "fw01A2", "fw01A3", "fw01A4", "fw03A1"}

# Known FPGA model names (stored in fwfpga dir).
_FPGA_MODELS = {
    "LA1010A0", "LA1010A1", "LA1010A2",
    "LA1016",   "LA1016A1",
    "LA2016",   "LA2016A1", "LA2016A2",
    "LA5016",   "LA5016A1", "LA5016A2",
    "LA5032A0",
    "MS6218",
}


def extract_firmware(kingstvis_path, output_dir=None):
    output_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Reading: {kingstvis_path}")
    with open(kingstvis_path, "rb") as f:
        data = f.read()

    # --- Locate __TEXT __const ---
    file_off, size = find_macho_const_section(data)
    if file_off is None:
        print("  ERROR: Not a supported Mach-O binary (expected 64-bit macOS)")
        return False

    const_data = data[file_off: file_off + size]

    # --- Locate Qt rcc sections ---
    try:
        tree_base, names_base, data_base, name_by_off = _find_qt_anchors(const_data)
    except RuntimeError as e:
        print(f"  ERROR: {e}")
        print("         Make sure you are pointing to the KingstVIS binary, not an installer.")
        return False

    extracted = []

    # --- Find and extract Cypress FX2 firmware (fwusb directory) ---
    fwusb_idx, fwusb_children = _find_dir_by_content(
        const_data, tree_base, data_base, name_by_off, 0, _CYPRESS_FW_NAMES
    )
    if fwusb_idx is not None:
        for stem, blob, stored_size in sorted(fwusb_children):
            if not stem.startswith("fw"):
                continue
            if blob[:3] == b":10":
                out_name = f"{stem}.hex"
                out_path = output_dir / out_name
                out_path.write_bytes(blob)
                print(f"  ✓  {out_path}  ({stored_size:,} bytes)  [Cypress HEX]")
                extracted.append(out_name)
            elif stored_size > 100:
                out_name = f"{stem}.fw"
                out_path = output_dir / out_name
                out_path.write_bytes(blob)
                print(f"  ✓  {out_path}  ({stored_size:,} bytes)  [Cypress binary]")
                extracted.append(out_name)
    else:
        print("  WARNING: Could not locate fwusb (Cypress FX2) firmware directory.")

    # --- Find and extract FPGA bitstreams (fwfpga directory) ---
    fwfpga_idx, fwfpga_children = _find_dir_by_content(
        const_data, tree_base, data_base, name_by_off, 0, _FPGA_MODELS
    )
    if fwfpga_idx is not None:
        unresolved_fpga = []
        for model, blob, stored_size in sorted(fwfpga_children):
            raw = _decompress_fpga(blob)
            if len(raw) < 1000:
                continue
            if model not in _FPGA_MODELS:
                # Name lookup collision — save for fallback resolution below
                unresolved_fpga.append((blob, stored_size, raw))
                continue
            out_name = f"{model}.bitstream"
            out_path = output_dir / out_name
            out_path.write_bytes(raw)
            dec_note = f", {len(raw):,} dec" if len(raw) != stored_size else ""
            print(f"  ✓  {out_path}  ({stored_size:,} bytes{dec_note})  [FPGA bitstream]")
            extracted.append(out_name)

        # Resolve any unresolved FPGA blobs by finding the missing model name
        extracted_models = {n.replace(".bitstream", "") for n in extracted if n.endswith(".bitstream")}
        missing_models = sorted(_FPGA_MODELS - extracted_models)
        for i, (blob, stored_size, raw) in enumerate(unresolved_fpga):
            if i < len(missing_models):
                model = missing_models[i]
                out_name = f"{model}.bitstream"
                out_path = output_dir / out_name
                out_path.write_bytes(raw)
                dec_note = f", {len(raw):,} dec" if len(raw) != stored_size else ""
                print(f"  ✓  {out_path}  ({stored_size:,} bytes{dec_note})  [FPGA bitstream]")
                extracted.append(out_name)
    else:
        print("  WARNING: Could not locate fwfpga (FPGA bitstream) directory.")

    if not extracted:
        print("  ERROR: No firmware files found in Qt resource tree.")
        print("         The KingstVIS version may be too old or too new.")
        return False

    print(f"\n  Extracted {len(extracted)} firmware file(s) → {output_dir}")
    return True


def find_kingstvis():
    """Auto-detect KingstVIS on common paths."""
    for p in KINGSTVIS_DEFAULT_PATHS:
        if os.path.exists(p):
            return p
    return None


def print_download_instructions():
    print("""
  KingstVIS is required to extract the firmware.
  It is free to download from the Kingst website:

    1. Go to: https://www.qdkingst.com/en/vis
    2. Download KingstVIS for macOS
    3. Open the .dmg and drag KingstVIS.app to /Applications
    4. Run this script again

  KingstVIS does NOT need to be launched or registered — just installed.
""")


def main():
    print("=" * 60)
    print("  Kingst LA Series Firmware Extractor for sigrok")
    print("=" * 60)

    if len(sys.argv) >= 2:
        kingstvis_path = sys.argv[1]
    else:
        kingstvis_path = find_kingstvis()
        if kingstvis_path:
            print(f"\n  Auto-detected KingstVIS at:\n  {kingstvis_path}\n")
        else:
            print("\n  KingstVIS not found in default locations.")
            print_download_instructions()
            print("  Usage: python3 extract_firmware.py /path/to/KingstVIS [output_dir]")
            sys.exit(1)

    if not os.path.exists(kingstvis_path):
        print(f"\n  ERROR: File not found: {kingstvis_path}")
        print_download_instructions()
        sys.exit(1)

    output_dir = sys.argv[2] if len(sys.argv) >= 3 else None

    print("\n  Extracting firmware...\n")
    success = extract_firmware(kingstvis_path, output_dir)

    if success:
        print("\n  Done! sigrok can now use your Kingst logic analyzer.")
        print("  Test with:")
        print("    sigrok-cli --driver kingst-la1010 --scan\n")
    else:
        print("\n  Extraction failed. See errors above.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
