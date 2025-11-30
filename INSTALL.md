# Installation Guide

This guide covers all methods to install OpenFing on your system.

## Table of Contents

- [Quick Install (Recommended)](#quick-install-recommended)
- [Download Pre-built Binaries](#download-pre-built-binaries)
- [Build from Source](#build-from-source)
- [Package Managers](#package-managers)
- [Verify Installation](#verify-installation)
- [Installing Dependencies](#installing-dependencies)
- [Uninstall](#uninstall)

---

## Quick Install (Recommended)

### One-liner Install Script

```bash
curl -sSL https://raw.githubusercontent.com/yourusername/OpenFing/main/install.sh | bash
```

Or with wget:

```bash
wget -qO- https://raw.githubusercontent.com/yourusername/OpenFing/main/install.sh | bash
```

---

## Download Pre-built Binaries

### macOS

**Apple Silicon (M1/M2/M3):**
```bash
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-macos-arm64 -o openfing
chmod +x openfing
sudo mv openfing /usr/local/bin/
```

**Intel:**
```bash
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-macos-x86_64 -o openfing
chmod +x openfing
sudo mv openfing /usr/local/bin/
```

### Linux

**x86_64 (64-bit):**
```bash
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-linux-x86_64 -o openfing
chmod +x openfing
sudo mv openfing /usr/local/bin/
```

**ARM64 (Raspberry Pi 4, etc.):**
```bash
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-linux-arm64 -o openfing
chmod +x openfing
sudo mv openfing /usr/local/bin/
```

### Verify Download (Optional)

Download the checksum file and verify:

```bash
# Download checksum
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-linux-x86_64.sha256 -o openfing.sha256

# Verify
sha256sum -c openfing.sha256
```

---

## Build from Source

### Prerequisites

- [Zig](https://ziglang.org/download/) 0.13.0 or later
- Git

### Install Zig

**macOS (Homebrew):**
```bash
brew install zig
```

**Linux (Ubuntu/Debian):**
```bash
# Download latest Zig
wget https://ziglang.org/download/0.14.0/zig-linux-x86_64-0.14.0.tar.xz
tar xf zig-linux-x86_64-0.14.0.tar.xz
sudo mv zig-linux-x86_64-0.14.0 /usr/local/zig
echo 'export PATH=$PATH:/usr/local/zig' >> ~/.bashrc
source ~/.bashrc
```

**Linux (Arch):**
```bash
sudo pacman -S zig
```

### Build OpenFing

```bash
# Clone the repository
git clone https://github.com/yourusername/OpenFing.git
cd OpenFing

# Build release version
zig build -Doptimize=ReleaseFast

# Install
sudo cp zig-out/bin/openfing /usr/local/bin/
```

### Build Options

```bash
# Debug build (for development)
zig build

# Release build (optimized)
zig build -Doptimize=ReleaseFast

# Release with debug info
zig build -Doptimize=ReleaseSafe

# Small binary size
zig build -Doptimize=ReleaseSmall

# Cross-compile for different targets
zig build -Doptimize=ReleaseFast -Dtarget=aarch64-linux
zig build -Doptimize=ReleaseFast -Dtarget=x86_64-macos
```

---

## Package Managers

### Homebrew (macOS/Linux) - Coming Soon

```bash
brew tap yourusername/openfing
brew install openfing
```

### AUR (Arch Linux) - Coming Soon

```bash
yay -S openfing
```

---

## Verify Installation

After installation, verify OpenFing is working:

```bash
# Check version
openfing --help

# Run a quick scan (without sudo - limited mode)
openfing

# Run full scan (with sudo)
sudo openfing
```

---

## Installing Dependencies

OpenFing works best with `arp-scan` for full network scanning. When you run OpenFing with sudo for the first time, it will offer to install arp-scan automatically.

### Manual Installation

**macOS (Homebrew):**
```bash
brew install arp-scan
```

**Ubuntu/Debian:**
```bash
sudo apt update
sudo apt install -y arp-scan
```

**Fedora:**
```bash
sudo dnf install -y arp-scan
```

**CentOS/RHEL:**
```bash
sudo yum install -y epel-release
sudo yum install -y arp-scan
```

**Arch Linux:**
```bash
sudo pacman -S arp-scan
```

**Alpine Linux:**
```bash
sudo apk add arp-scan
```

**openSUSE:**
```bash
sudo zypper install arp-scan
```

---

## Uninstall

### If installed to /usr/local/bin:

```bash
sudo rm /usr/local/bin/openfing
```

### If built from source:

```bash
cd OpenFing
rm -rf zig-out zig-cache .zig-cache
cd ..
rm -rf OpenFing
```

---

## Troubleshooting

### "Permission denied" when running

Make sure the binary is executable:
```bash
chmod +x /usr/local/bin/openfing
```

### "Command not found"

Ensure `/usr/local/bin` is in your PATH:
```bash
echo $PATH | grep -q '/usr/local/bin' || echo 'export PATH=$PATH:/usr/local/bin' >> ~/.bashrc
source ~/.bashrc
```

### "arp-scan not found" warning

Install arp-scan using the instructions above, or run with sudo and OpenFing will offer to install it automatically.

### Limited results without sudo

This is expected behavior. Without root privileges, OpenFing can only read the ARP cache, which contains recently contacted devices. For a full network scan, run with `sudo`.

### Build fails with Zig errors

Make sure you have Zig 0.13.0 or later:
```bash
zig version
```

---

## Getting Help

- **Issues:** [GitHub Issues](https://github.com/yourusername/OpenFing/issues)
- **Discussions:** [GitHub Discussions](https://github.com/yourusername/OpenFing/discussions)

---

## Next Steps

After installation, check out:

- [README.md](README.md) - Usage examples and features
- [CONTRIBUTING.md](CONTRIBUTING.md) - How to contribute
