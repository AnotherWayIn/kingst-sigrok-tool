# Kingst LA Series — sigrok Firmware Tool

Use your **Kingst LA1010 / LA1010A** logic analyzer with **sigrok**, **sigrok-cli**, and **PulseView** on macOS.

Kingst devices require proprietary firmware to be uploaded on each connection. This tool extracts that firmware from the free KingstVIS application so sigrok can load it automatically.

---

## Quick Start

```bash
# 1. Clone this repo
git clone https://github.com/AnotherWayIn/kingst-sigrok-tool.git
cd kingst-sigrok-tool

# 2. Install the Kingst-enabled sigrok driver
bash install_sigrok_driver.sh

# 3. Extract firmware from KingstVIS  (see below if not installed)
python3 extract_firmware.py

# 4. Plug in your LA1010 and test
sigrok-cli --driver kingst-la1010 --scan
```

Expected output:
```
The following devices were found:
kingst-la1010:conn=0.3 - Kingst LA1010A with 16 channels: D0 D1 D2 ... D15
```

---

## Requirements

### System
- macOS 12+ (Apple Silicon or Intel)
- Python 3.9+
- [Homebrew](https://brew.sh)

### KingstVIS (for firmware extraction)

The firmware files inside KingstVIS are proprietary to Kingst Electronics and **cannot be redistributed**. You must download KingstVIS yourself — it is free:

1. Go to **https://www.qdkingst.com/en/vis**
2. Download **KingstVIS for macOS**
3. Open the `.dmg` and drag `KingstVIS.app` to `/Applications`
4. KingstVIS does **not** need to be launched or registered — just installed

Then run:
```bash
python3 extract_firmware.py
```

The script auto-detects KingstVIS at `/Applications/KingstVIS.app` and extracts the firmware to:
```
~/.local/share/sigrok-firmware/kingst/
```

---

## What Gets Installed

| File | Purpose |
|------|---------|
| `fw01A1.hex` | Firmware for LA1010 hardware rev A1 |
| `fw01A2.hex` | Firmware for LA1010 hardware rev A2 (most common) |
| `fw01A3.hex` | Firmware for LA1010 hardware rev A3 |
| `fw01A4.hex` | Firmware for LA1010 hardware rev A4 |

sigrok identifies your device's hardware revision from its USB descriptor and loads the correct file automatically.

---

## Detailed Steps

### Step 1 — Install the Kingst sigrok driver

The official sigrok `libsigrok` does not include Kingst LA device support. This script installs the [AlexUg/libsigrok](https://github.com/AlexUg/libsigrok) fork which adds it:

```bash
bash install_sigrok_driver.sh
```

This will:
- Install build dependencies via Homebrew
- Clone the Kingst-enabled libsigrok fork
- Build and install it to `/opt/homebrew`

### Step 2 — Extract firmware

```bash
python3 extract_firmware.py
```

Or specify a custom path:
```bash
python3 extract_firmware.py /Applications/KingstVIS.app/Contents/MacOS/KingstVIS
python3 extract_firmware.py /Applications/KingstVIS.app/Contents/MacOS/KingstVIS ~/custom/firmware/dir
```

### Step 3 — Capture signals

```bash
# Scan for device
sigrok-cli --driver kingst-la1010 --scan

# Capture 1 second at 10MHz on channels D0 and D1
sigrok-cli --driver kingst-la1010 --config samplerate=10m \
           --channels D0,D1 --time 1s -o capture.sr

# Decode UART at 115200 baud
sigrok-cli --driver kingst-la1010 --config samplerate=1m \
           --channels D0 --time 5s \
           --protocol-decoder uart:rx=D0:baudrate=115200

# Open in PulseView GUI
pulseview
```

---

## How the Firmware Extractor Works

KingstVIS stores its firmware as Intel HEX files inside a Qt resource bundle embedded directly in the macOS Mach-O binary. The extractor:

1. Parses the Mach-O `__TEXT __const` section
2. Locates the Qt resource names section (identified by the `fwusb` directory name in UTF-16BE)
3. Finds the Qt resource data section by detecting consecutive size-prefixed blobs
4. Scans each blob for Intel HEX format (`:10...` records)
5. Writes `fw01A1.hex` through `fw01A4.hex` to the sigrok firmware directory

No network access, no KingstVIS account, no launch required.

---

## Troubleshooting

**`sigrok-cli --scan` returns nothing / firmware upload failed**
- Re-run `python3 extract_firmware.py` and check for errors
- Check firmware files exist: `ls ~/.local/share/sigrok-firmware/kingst/`
- Unplug and replug the USB cable
- Try a different USB port or cable

**`Failed to open resource 'kingst/fw01A2.hex'`**
- The firmware file is missing. Run `python3 extract_firmware.py`

**`ERROR: Not a supported Mach-O binary`**
- Make sure you're pointing to the KingstVIS **binary**, not the `.app` folder:
  `/Applications/KingstVIS.app/Contents/MacOS/KingstVIS`

**`install_sigrok_driver.sh` fails**
- Make sure Homebrew is installed: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
- Try running the dependency installs manually from the script

**Device shows wrong channel count**
- The LA1010 has 16 channels (D0–D15). If fewer show, your firmware revision may differ. All 4 `.hex` files will be tried automatically.

---

## Supported Devices

| Device | USB VID:PID | Status |
|--------|------------|--------|
| Kingst LA1010 (rev A1) | 77A1:01A1 | ✅ Supported |
| Kingst LA1010 (rev A2) | 77A1:01A2 | ✅ Supported |
| Kingst LA1010 (rev A3) | 77A1:01A3 | ✅ Supported |
| Kingst LA1010 (rev A4) | 77A1:01A4 | ✅ Supported |

Other Kingst devices (LA2016, LA5016) may work with firmware from their respective KingstVIS versions but are untested.

---

## License

The extractor script (`extract_firmware.py`) and installer (`install_sigrok_driver.sh`) are MIT licensed.

The **firmware files themselves** (`fw01A*.hex`) are proprietary to Kingst Electronics Co., Ltd. and are **not included** in this repository. You extract them from KingstVIS which you download directly from Kingst.
