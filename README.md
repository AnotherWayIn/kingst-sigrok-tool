# Kingst LA Series — sigrok Firmware Tool

Use your **Kingst logic analyzer** with **sigrok**, **sigrok-cli**, and **PulseView** on macOS.

Supports the full Kingst LA lineup: LA1010, LA1010A, LA1016, LA2016, LA5016, LA5032, and MS6218.

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

# 4. Plug in your device and test
sigrok-cli --driver kingst-la1010 --scan
```

Expected output:
```
The following devices were found:
kingst-la1010:conn=0.3 - Kingst LA2016A with 16 channels: D0 D1 D2 ... D15
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

The script auto-detects KingstVIS at `/Applications/KingstVIS.app` and extracts all firmware to:
```
~/.local/share/sigrok-firmware/kingst/
```

---

## What Gets Extracted

### Cypress FX2 USB Firmware (`.hex` / `.fw`)

These are uploaded to the device's USB microcontroller on first connect to switch it from DFU mode into the Kingst LA protocol.

| File | Device |
|------|--------|
| `fw01A2.hex` | LA1010 hardware rev A2 |
| `fw01A3.hex` | LA1010 hardware rev A3 |
| `fw01A4.hex` | LA1010 hardware rev A4 |
| `fw03A1.hex` | LA1016 / LA2016 / LA5016 / LA5032 / LA1010A series |

### Spartan FPGA Bitstreams (`.bitstream`)

These configure the on-board FPGA after the Cypress firmware loads. Each model variant has its own bitstream.

| File | Device |
|------|--------|
| `LA1010A0.bitstream` | LA1010A rev 0 |
| `LA1010A1.bitstream` | LA1010A rev 1 |
| `LA1010A2.bitstream` | LA1010A rev 2 |
| `LA1016.bitstream` | LA1016 |
| `LA1016A1.bitstream` | LA1016A rev 1 |
| `LA2016.bitstream` | LA2016 |
| `LA2016A1.bitstream` | LA2016A rev 1 |
| `LA2016A2.bitstream` | LA2016A rev 2 |
| `LA5016.bitstream` | LA5016 |
| `LA5016A1.bitstream` | LA5016A rev 1 |
| `LA5016A2.bitstream` | LA5016A rev 2 |
| `LA5032A0.bitstream` | LA5032A rev 0 |
| `MS6218.bitstream` | MS6218 |

sigrok identifies your device's model and hardware revision automatically after the Cypress firmware loads.

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

Or specify a custom KingstVIS path or output directory:
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

KingstVIS embeds all firmware inside a Qt resource bundle in the macOS Mach-O binary. The extractor:

1. Parses the Mach-O `__TEXT __const` section
2. Locates the Qt resource tree, names, and data sections using the `fwusb` directory anchor
3. Walks the resource tree to find the `fwusb` directory (Cypress FX2 firmware) and `fwfpga` directory (FPGA bitstreams)
4. Decompresses any zlib-compressed FPGA bitstreams
5. Writes all firmware files to the sigrok firmware directory

No network access, no KingstVIS account, no launch required.

---

## Troubleshooting

**`sigrok-cli --scan` returns nothing / firmware upload failed**
- Re-run `python3 extract_firmware.py` and check for errors
- Check firmware files exist: `ls ~/.local/share/sigrok-firmware/kingst/`
- Unplug and replug the USB cable
- Try a different USB port or cable

**`Failed to open resource 'kingst/fw03A1.hex'`**
- The firmware file is missing. Run `python3 extract_firmware.py`

**`ERROR: Not a supported Mach-O binary`**
- Make sure you're pointing to the KingstVIS **binary**, not the `.app` folder:
  `/Applications/KingstVIS.app/Contents/MacOS/KingstVIS`

**`install_sigrok_driver.sh` fails**
- Make sure Homebrew is installed: `/bin/bash -c "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/HEAD/install.sh)"`
- Try running the dependency installs manually from the script

**FPGA bitstream not found for my model**
- Your KingstVIS version may not include your model's bitstream. Try downloading the latest KingstVIS from https://www.qdkingst.com/en/vis

---

## Supported Devices

| Device | USB VID:PID | Cypress FW | FPGA Bitstream |
|--------|------------|------------|----------------|
| Kingst LA1010 (rev A2) | 77A1:01A2 | fw01A2.hex | — |
| Kingst LA1010 (rev A3) | 77A1:01A3 | fw01A3.hex | — |
| Kingst LA1010 (rev A4) | 77A1:01A4 | fw01A4.hex | — |
| Kingst LA1010A (rev 0) | 77A1:03A1 | fw03A1.hex | LA1010A0.bitstream |
| Kingst LA1010A (rev 1) | 77A1:03A1 | fw03A1.hex | LA1010A1.bitstream |
| Kingst LA1010A (rev 2) | 77A1:03A1 | fw03A1.hex | LA1010A2.bitstream |
| Kingst LA1016 | 77A1:03A1 | fw03A1.hex | LA1016.bitstream |
| Kingst LA1016A (rev 1) | 77A1:03A1 | fw03A1.hex | LA1016A1.bitstream |
| Kingst LA2016 | 77A1:03A1 | fw03A1.hex | LA2016.bitstream |
| Kingst LA2016A (rev 1) | 77A1:03A1 | fw03A1.hex | LA2016A1.bitstream |
| Kingst LA2016A (rev 2) | 77A1:03A1 | fw03A1.hex | LA2016A2.bitstream |
| Kingst LA5016 | 77A1:03A1 | fw03A1.hex | LA5016.bitstream |
| Kingst LA5016A (rev 1) | 77A1:03A1 | fw03A1.hex | LA5016A1.bitstream |
| Kingst LA5016A (rev 2) | 77A1:03A1 | fw03A1.hex | LA5016A2.bitstream |
| Kingst LA5032A (rev 0) | 77A1:03A1 | fw03A1.hex | LA5032A0.bitstream |
| Kingst MS6218 | 77A1:03A1 | fw03A1.hex | MS6218.bitstream |

Driver support provided by [AlexUg/libsigrok](https://github.com/AlexUg/libsigrok).

---

## License

The extractor script (`extract_firmware.py`) and installer (`install_sigrok_driver.sh`) are MIT licensed.

The **firmware files themselves** are proprietary to Kingst Electronics Co., Ltd. and are **not included** in this repository. You extract them from KingstVIS which you download directly from Kingst.
