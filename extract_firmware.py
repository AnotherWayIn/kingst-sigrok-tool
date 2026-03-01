#!/usr/bin/env python3
"""
Kingst LA Series Firmware Extractor for sigrok
Extracts all firmware from the KingstVIS binary (Linux or macOS) so that
sigrok/sigrok-cli/PulseView can use Kingst logic analyzers.

Uses the official sigrok driver (kingst-la2016) which supports all Kingst
LA devices including LA1010, LA1010A, LA1016, LA2016, LA5016, LA5032, MS6218.

Output filenames match what the official kingst-la2016 driver expects:
  MCU firmware:      kingst-la-<pid>.fw    (e.g. kingst-la-01a2.fw)
  FPGA bitstreams:   kingst-<model>-fpga.bitstream

Usage:
    python3 extract_firmware.py
    python3 extract_firmware.py /path/to/KingstVIS [output_dir]

The Linux KingstVIS binary is recommended. Download from:
    https://www.qdkingst.com/download/vis_linux
"""

import sys
import os
import struct
import codecs
import zlib
from pathlib import Path


KINGSTVIS_DEFAULT_PATHS = [
    # Linux (extracted tarball)
    str(Path.home() / "KingstVIS" / "KingstVIS"),
    "/opt/KingstVIS/KingstVIS",
    "/tmp/KingstVIS/KingstVIS",
    # macOS
    "/Applications/KingstVIS.app/Contents/MacOS/KingstVIS",
    str(Path.home() / "Downloads" / "KingstVIS.app" / "Contents" / "MacOS" / "KingstVIS"),
]

DEFAULT_OUTPUT_DIR = Path.home() / ".local" / "share" / "sigrok-firmware"

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


def _intel_hex_to_blob(hexdata):
    """Convert Intel HEX bytes to a flat binary blob."""
    datas = []
    for line in hexdata.split(b"\n"):
        line = line.strip()
        if not line or line[0:1] != b":":
            continue
        try:
            record = codecs.decode(line[1:], "hex")
        except Exception:
            continue
        byte_count, address, record_type = struct.unpack(">BHB", record[:4])
        if record_type == 0 and byte_count > 0:
            datas.append((address, record[4:4 + byte_count]))
        elif record_type == 1:
            break
    if not datas:
        return hexdata  # not valid HEX, return as-is
    datas.sort()
    last = datas[-1]
    length = last[0] + len(last[1])
    img = bytearray(length)
    for off, part in datas:
        img[off:off + len(part)] = part
    return bytes(img)


def _maybe_intel_hex_to_blob(data):
    """Convert Intel HEX to binary if it looks like HEX, otherwise return raw."""
    if data and data[0] == ord(":") and max(data) < 128:
        return _intel_hex_to_blob(data)
    return data


# ---------------------------------------------------------------------------
# Linux ELF extraction (official sigrok-util method)
# ---------------------------------------------------------------------------

ELF_MAGIC = b"\x7fELF"
_ELF_SYM_STRUCT = b"_ZL18qt_resource_struct"
_ELF_SYM_NAMES  = b"_ZL16qt_resource_name"
_ELF_SYM_DATAS  = b"_ZL16qt_resource_data"


def _is_elf(data):
    return data[:4] == ELF_MAGIC


def _parse_elf_symtab(data):
    """Parse ELF64 LE symbol table. Returns dict name->{'value', 'size', 'shndx'}."""
    if data[4] != 2:  # EI_CLASS: 2 = 64-bit
        raise RuntimeError("Only ELF64 supported")
    e_shoff, = struct.unpack_from("<Q", data, 40)
    e_shentsize, e_shnum, e_shstrndx = struct.unpack_from("<HHH", data, 58)

    def shdr(i):
        off = e_shoff + i * e_shentsize
        return struct.unpack_from("<IIQQQQIIQQ", data, off)

    # Build section name lookup
    # shdr tuple: (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, ...)
    shstrtab_s = shdr(e_shstrndx)
    shstrtab = data[shstrtab_s[4]:shstrtab_s[4] + shstrtab_s[5]]

    sections = {}
    for i in range(e_shnum):
        s = shdr(i)
        name_off = s[0]
        name = shstrtab[name_off:shstrtab.index(b"\x00", name_off)]
        sections[name] = s

    # Find .symtab and .strtab
    if b".symtab" not in sections or b".strtab" not in sections:
        raise RuntimeError("No .symtab/.strtab in ELF")

    symtab_s = sections[b".symtab"]
    strtab_s = sections[b".strtab"]
    # shdr tuple: (sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, ...)
    symtab_data = data[symtab_s[4]:symtab_s[4] + symtab_s[5]]
    strtab_data = data[strtab_s[4]:strtab_s[4] + strtab_s[5]]

    # Each Elf64_Sym = 24 bytes: name(4) info(1) other(1) shndx(2) value(8) size(8)
    syms = {}
    for i in range(len(symtab_data) // 24):
        st_name, st_info, st_other, st_shndx, st_value, st_size = \
            struct.unpack_from("<IBBHQQ", symtab_data, i * 24)
        if st_name >= len(strtab_data):
            continue
        try:
            name_end = strtab_data.index(b"\x00", st_name)
        except ValueError:
            name_end = len(strtab_data)
        name = strtab_data[st_name:name_end]
        syms[name] = {"value": st_value, "size": st_size, "shndx": st_shndx}
    return syms, sections, shdr


def _elf_sym_bytes(data, syms, sections, shdr_fn, sym_name):
    """Return the raw bytes for a named ELF symbol."""
    sym = syms.get(sym_name)
    if sym is None:
        raise RuntimeError(f"Symbol {sym_name!r} not found in ELF")
    # shdr tuple from unpack_from("<IIQQQQIIQQ"): name, type, flags, addr, off, size, ...
    s = shdr_fn(sym["shndx"])
    sh_addr, sh_off = s[3], s[4]
    addr_in_section = sym["value"] - sh_addr
    return data[sh_off + addr_in_section: sh_off + addr_in_section + sym["size"]]


def _qt_resource_name(res_names, offset):
    length, = struct.unpack_from(">H", res_names, offset)
    name = res_names[offset + 6: offset + 6 + length * 2].decode("utf-16-be")
    return name


def _qt_resource_data(res_datas, offset):
    length, = struct.unpack_from(">I", res_datas, offset)
    return res_datas[offset + 4: offset + 4 + length]


def _elf_read_qt_resources(res_struct, res_names, res_datas):
    """Walk the Qt resource tree. Returns dict {full_path: (data, compressed)}."""
    FLAG_DIR = 0x02
    FLAG_COMPRESSED = 0x01
    resources = {}

    # Parse flat table first
    table = []
    offset = 0
    while offset < len(res_struct):
        if offset + 14 > len(res_struct):
            break
        name_offset, flags = struct.unpack_from(">IH", res_struct, offset)
        offset += 6
        name = _qt_resource_name(res_names, name_offset)
        if flags & FLAG_DIR:
            child_count, first_child = struct.unpack_from(">II", res_struct, offset)
            offset += 8
            table.append((name, flags, child_count, first_child))
        else:
            country, language, data_offset = struct.unpack_from(">HHI", res_struct, offset)
            offset += 8
            table.append((name, flags, country, language, data_offset))

    def collect(idx, prefix):
        entry = table[idx]
        name, flags = entry[0], entry[1]
        path = (prefix + "/" + name).lstrip("/")
        if flags & FLAG_DIR:
            child_count, first_child = entry[2], entry[3]
            for i in range(child_count):
                collect(first_child + i, path)
        else:
            data_offset = entry[4]
            raw = _qt_resource_data(res_datas, data_offset)
            resources[path] = (raw, bool(flags & FLAG_COMPRESSED))

    collect(0, "")
    return resources


def extract_from_elf(data, output_dir):
    """Extract firmware from a Linux ELF KingstVIS binary."""
    try:
        syms, sections, shdr_fn = _parse_elf_symtab(data)
    except RuntimeError as e:
        print(f"  ERROR parsing ELF: {e}")
        return False

    try:
        res_struct = _elf_sym_bytes(data, syms, sections, shdr_fn, _ELF_SYM_STRUCT)
        res_names  = _elf_sym_bytes(data, syms, sections, shdr_fn, _ELF_SYM_NAMES)
        res_datas  = _elf_sym_bytes(data, syms, sections, shdr_fn, _ELF_SYM_DATAS)
    except RuntimeError as e:
        print(f"  ERROR locating Qt resource symbols: {e}")
        return False

    try:
        resources = _elf_read_qt_resources(res_struct, res_names, res_datas)
    except Exception as e:
        print(f"  ERROR walking Qt resource tree: {e}")
        return False

    return _write_firmware_files(resources, output_dir)


def _write_firmware_files(resources, output_dir):
    """Write extracted Qt resources as firmware files in the sigrok-expected format."""
    extracted = []
    for path, (raw, compressed) in sorted(resources.items()):
        if compressed:
            raw = zlib.decompress(raw[4:])  # skip 4-byte uncompressed size prefix

        # MCU firmware: fwusb/fw01A2 -> kingst-la-01a2.fw (binary)
        # Path may have a leading directory prefix (e.g. "res/fwusb/fw01A2")
        path_tail = path[path.find("fwusb/"):] if "fwusb/" in path else path
        path_tail2 = path[path.find("fwfpga/"):] if "fwfpga/" in path else path
        if path_tail.startswith("fwusb/fw"):
            stem = path_tail[len("fwusb/fw"):].lower()  # e.g. "01a2"
            blob = _maybe_intel_hex_to_blob(raw)
            out_name = f"kingst-la-{stem}.fw"
            out_path = output_dir / out_name
            out_path.write_bytes(blob)
            print(f"  ✓  {out_path}  ({len(blob):,} bytes)  [MCU firmware]")
            extracted.append(out_name)

        # FPGA bitstream: fwfpga/LA1010A2 -> kingst-la1010a2-fpga.bitstream
        elif path_tail2.startswith("fwfpga/"):
            model = path_tail2[len("fwfpga/"):].lower()  # e.g. "la1010a2"
            # Decompress zlib if present (some bitstreams are zlib-compressed)
            if len(raw) > 4 and raw[4:6] in (b"\x78\x9c", b"\x78\xda", b"\x78\x01"):
                try:
                    raw = zlib.decompress(raw[4:])
                except Exception:
                    pass
            if len(raw) < 1000:
                continue
            out_name = f"kingst-{model}-fpga.bitstream"
            out_path = output_dir / out_name
            out_path.write_bytes(raw)
            print(f"  ✓  {out_path}  ({len(raw):,} bytes)  [FPGA bitstream]")
            extracted.append(out_name)

    return extracted


def extract_firmware(kingstvis_path, output_dir=None):
    output_dir = Path(output_dir) if output_dir else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    print(f"  Reading: {kingstvis_path}")
    with open(kingstvis_path, "rb") as f:
        data = f.read()

    # --- Dispatch by binary format ---
    if _is_elf(data):
        print("  Detected: Linux ELF binary")
        extracted = extract_from_elf(data, output_dir)
    else:
        # Try macOS Mach-O
        file_off, size = find_macho_const_section(data)
        if file_off is None:
            print("  ERROR: Not a supported binary (expected Linux ELF or macOS Mach-O)")
            return False
        print("  Detected: macOS Mach-O binary")
        print("  NOTE: The Linux KingstVIS binary is recommended for best results.")
        print("        Download from: https://www.qdkingst.com/download/vis_linux")
        const_data = data[file_off: file_off + size]
        try:
            tree_base, names_base, data_base, name_by_off = _find_qt_anchors(const_data)
        except RuntimeError as e:
            print(f"  ERROR: {e}")
            print("         Make sure you are pointing to the KingstVIS binary, not an installer.")
            return False
        extracted = _extract_macho_firmware(const_data, tree_base, data_base, name_by_off, output_dir)

    if not extracted:
        print("  ERROR: No firmware files found in Qt resource tree.")
        print("         The KingstVIS version may be too old or too new.")
        return False

    print(f"\n  Extracted {len(extracted)} firmware file(s) → {output_dir}")
    return True


def _extract_macho_firmware(const_data, tree_base, data_base, name_by_off, output_dir):
    """Extract firmware from macOS Mach-O Qt resources. Outputs official driver filenames."""
    extracted = []

    # Build a resources dict matching the ELF path format
    resources = {}

    fwusb_idx, fwusb_children = _find_dir_by_content(
        const_data, tree_base, data_base, name_by_off, 0, _CYPRESS_FW_NAMES
    )
    if fwusb_idx is not None:
        for stem, blob, _ in sorted(fwusb_children):
            if stem.startswith("fw"):
                resources[f"fwusb/{stem}"] = (blob, False)
    else:
        print("  WARNING: Could not locate fwusb (Cypress FX2) firmware directory.")

    fwfpga_idx, fwfpga_children = _find_dir_by_content(
        const_data, tree_base, data_base, name_by_off, 0, _FPGA_MODELS
    )
    if fwfpga_idx is not None:
        unresolved = []
        for model, blob, stored_size in sorted(fwfpga_children):
            if model in _FPGA_MODELS:
                resources[f"fwfpga/{model}"] = (blob, False)
            else:
                unresolved.append((model, blob))
        # Assign unresolved blobs to missing model names
        extracted_models = {p[len("fwfpga/"):] for p in resources if p.startswith("fwfpga/")}
        missing = sorted(_FPGA_MODELS - extracted_models)
        for i, (_, blob) in enumerate(unresolved):
            if i < len(missing):
                resources[f"fwfpga/{missing[i]}"] = (blob, False)
    else:
        print("  WARNING: Could not locate fwfpga (FPGA bitstream) directory.")

    return _write_firmware_files(resources, output_dir)


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

  On Linux (recommended):
    1. Download: https://www.qdkingst.com/download/vis_linux
    2. Extract: tar -xzf KingstVIS_linux.tar.gz
    3. Run: python3 extract_firmware.py ./KingstVIS/KingstVIS

  On macOS:
    1. Go to: https://www.qdkingst.com/en/vis
    2. Download KingstVIS for macOS
    3. Open the .dmg and drag KingstVIS.app to /Applications
    4. Run: python3 extract_firmware.py

  KingstVIS does NOT need to be launched or registered.
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
        print("    sigrok-cli --driver kingst-la2016 --scan\n")
    else:
        print("\n  Extraction failed. See errors above.\n")
        sys.exit(1)


if __name__ == "__main__":
    main()
