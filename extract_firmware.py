#!/usr/bin/env python3
"""
Kingst LA Series Firmware Extractor for sigrok
Extracts Intel HEX firmware files from the KingstVIS macOS binary
so that sigrok/sigrok-cli/PulseView can use Kingst logic analyzers.

Supports: LA1010, LA1010A1/A2/A3/A4 variants

Usage:
    python3 extract_firmware.py
    python3 extract_firmware.py /path/to/KingstVIS [output_dir]
"""

import sys
import os
import struct
from pathlib import Path


KINGSTVIS_DEFAULT_PATHS = [
    "/Applications/KingstVIS.app/Contents/MacOS/KingstVIS",
    str(Path.home() / "Downloads" / "KingstVIS.app" / "Contents" / "MacOS" / "KingstVIS"),
]

DEFAULT_OUTPUT_DIR = Path.home() / ".local" / "share" / "sigrok-firmware" / "kingst"

FW_NAMES = ["fw01A1", "fw01A2", "fw01A3", "fw01A4"]


def find_macho_const_section(data):
    """Find __TEXT __const section in a Mach-O binary. Returns (file_offset, size)."""
    if len(data) < 32:
        return None, None
    magic = struct.unpack_from("<I", data, 0)[0]
    if magic == 0xFEEDFACF:  # arm64 / x86_64 little-endian 64-bit
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


def find_qt_names_section(const_data):
    """Find Qt resource names section start offset within const_data."""
    # 'fwusb' name entry: length=5 (2 BE) + hash=0x006dec92 (4 BE) + UTF-16BE 'fwusb'
    needle = struct.pack(">HI", 5, 0x006DEC92) + "fwusb".encode("utf-16-be")
    pos = const_data.find(needle)
    if pos != -1:
        return pos
    # Fallback: find by UTF-16BE string only
    pos = const_data.find("fwusb".encode("utf-16-be"))
    return pos - 6 if pos != -1 else -1


def scan_names_section(const_data, names_start):
    """Walk the Qt names section entries; return end offset."""
    pos = names_start
    while pos < names_start + 20000:
        name_len = struct.unpack_from(">H", const_data, pos)[0]
        if name_len == 0 or name_len > 64:
            break
        pos += 6 + name_len * 2
    return pos


def find_qt_data_section(const_data, search_from):
    """
    Find the Qt resource data section: first offset with 5+ consecutive
    big-endian size-prefixed blobs (each 100..1,000,000 bytes).
    """
    offset = search_from
    while offset < len(const_data) - 8:
        size = struct.unpack_from(">I", const_data, offset)[0]
        if size == 0:
            offset += 4
            continue
        if 100 <= size <= 1_000_000:
            run_off, count = offset, 0
            while count < 5:
                s = struct.unpack_from(">I", const_data, run_off)[0]
                if 100 <= s <= 1_000_000:
                    run_off += 4 + s
                    count += 1
                else:
                    break
            if count >= 5:
                return offset
        offset += 4
    return -1


def extract_hex_entries(const_data, data_start):
    """Walk data section and collect all Intel HEX blobs (start with b':10')."""
    entries = []
    offset = data_start
    while offset < len(const_data) - 4:
        size = struct.unpack_from(">I", const_data, offset)[0]
        if size == 0 or size > 1_000_000:
            break
        blob = const_data[offset + 4: offset + 4 + size]
        if blob[:3] == b":10" and size > 5000:
            entries.append(blob)
        offset += 4 + size
    return entries


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

    # --- Find names section ---
    names_start = find_qt_names_section(const_data)
    if names_start == -1:
        print("  ERROR: Could not find Qt resource names section.")
        print("         Make sure you are pointing to the KingstVIS binary, not an installer.")
        return False

    names_end = scan_names_section(const_data, names_start)

    # --- Find data section ---
    data_start = find_qt_data_section(const_data, names_end)
    if data_start == -1:
        print("  ERROR: Could not find Qt resource data section.")
        return False

    # --- Extract Intel HEX firmware blobs ---
    hex_blobs = extract_hex_entries(const_data, data_start)

    if not hex_blobs:
        print("  ERROR: No Intel HEX firmware found in binary.")
        return False

    extracted = []
    for i, blob in enumerate(hex_blobs[:len(FW_NAMES)]):
        name = FW_NAMES[i]
        out_path = output_dir / f"{name}.hex"
        out_path.write_bytes(blob)
        print(f"  ✓  {out_path}  ({len(blob):,} bytes)")
        extracted.append(name)

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
    print("=" * 58)
    print("  Kingst LA Series Firmware Extractor for sigrok")
    print("=" * 58)

    # Determine KingstVIS path
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
