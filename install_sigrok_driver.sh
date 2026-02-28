#!/bin/bash
# Kingst LA Series sigrok Driver Installer (macOS)
# Installs the AlexUg/libsigrok fork which adds Kingst LA device support.

set -e

REPO_URL="https://github.com/AlexUg/libsigrok.git"
BUILD_DIR="/tmp/libsigrok-kingst"

echo "=================================================="
echo "  Kingst LA Series sigrok Driver Installer"
echo "=================================================="
echo ""

# --- Check Homebrew ---
if ! command -v brew &>/dev/null; then
    echo "ERROR: Homebrew is required. Install from https://brew.sh"
    exit 1
fi

# --- Install build dependencies ---
echo "[1/4] Installing build dependencies..."
brew install cmake autoconf automake libtool pkg-config \
    libusb glib glibmm libzip doxygen check \
    libserialport hidapi libftdi 2>/dev/null || true

# --- Clone repo ---
echo ""
echo "[2/4] Cloning Kingst-enabled libsigrok..."
rm -rf "$BUILD_DIR"
git clone --depth=1 "$REPO_URL" "$BUILD_DIR"

# --- Build ---
echo ""
echo "[3/4] Building libsigrok..."
cd "$BUILD_DIR"
./autogen.sh
./configure --prefix=/opt/homebrew CFLAGS="-I/opt/homebrew/include" LDFLAGS="-L/opt/homebrew/lib"
make -j"$(sysctl -n hw.ncpu)"

# --- Install ---
echo ""
echo "[4/4] Installing..."
sudo make install

echo ""
echo "=================================================="
echo "  libsigrok (Kingst fork) installed successfully."
echo ""
echo "  Next: extract firmware with:"
echo "    python3 extract_firmware.py"
echo ""
echo "  Then test:"
echo "    sigrok-cli --driver kingst-la1010 --scan"
echo "=================================================="
