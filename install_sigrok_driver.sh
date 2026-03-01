#!/bin/bash
# Kingst LA Series sigrok Driver Installer (Linux)
# Builds the official sigrok libsigrok from source.
# The official kingst-la2016 driver supports all Kingst LA devices.

set -e

REPO_URL="https://github.com/sigrokproject/libsigrok.git"
BUILD_DIR="/tmp/libsigrok-official"

echo "=================================================="
echo "  Kingst LA Series sigrok Driver Installer"
echo "=================================================="
echo ""

# --- Check OS ---
if [[ "$(uname)" == "Darwin" ]]; then
    echo "ERROR: This installer is for Linux only."
    echo "       macOS support requires additional investigation."
    exit 1
fi

# --- Install build dependencies ---
echo "[1/4] Installing build dependencies..."
if command -v apt-get &>/dev/null; then
    sudo apt-get install -y \
        git autoconf automake libtool pkg-config \
        libusb-1.0-0-dev libglib2.0-dev libzip-dev \
        libserialport-dev check doxygen 2>/dev/null || true
elif command -v dnf &>/dev/null; then
    sudo dnf install -y \
        git autoconf automake libtool pkgconfig \
        libusb1-devel glib2-devel libzip-devel \
        libserialport-devel check doxygen 2>/dev/null || true
fi

# --- Clone official libsigrok ---
echo ""
echo "[2/4] Cloning official libsigrok..."
rm -rf "$BUILD_DIR"
git clone --depth=1 "$REPO_URL" "$BUILD_DIR"

# --- Build ---
echo ""
echo "[3/4] Building libsigrok..."
cd "$BUILD_DIR"
./autogen.sh
./configure --prefix=/usr
make -j"$(nproc)"

# --- Install ---
echo ""
echo "[4/4] Installing..."
sudo make install
sudo ldconfig

# --- udev rules for USB access ---
if [ -d /etc/udev/rules.d ]; then
    echo "Installing udev rules for Kingst devices..."
    cat <<'EOF' | sudo tee /etc/udev/rules.d/60-kingst.rules > /dev/null
ATTR{idVendor}=="77a1", ATTR{idProduct}=="01a2", MODE="0666", GROUP="plugdev"
ATTR{idVendor}=="77a1", ATTR{idProduct}=="01a3", MODE="0666", GROUP="plugdev"
ATTR{idVendor}=="77a1", ATTR{idProduct}=="03a2", MODE="0666", GROUP="plugdev"
EOF
    sudo udevadm control --reload-rules 2>/dev/null || true
fi

echo ""
echo "=================================================="
echo "  libsigrok installed successfully."
echo ""
echo "  Next: extract firmware with:"
echo "    python3 extract_firmware.py"
echo ""
echo "  Then test:"
echo "    sigrok-cli --driver kingst-la2016 --scan"
echo "=================================================="
