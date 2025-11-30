# OpenFing

<p align="center">
  <img src="https://img.shields.io/badge/language-Zig-f7a41d?style=flat-square" alt="Zig">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/yourusername/OpenFing?style=flat-square" alt="Release">
</p>

**OpenFing** is a fast, lightweight network scanner written in Zig. It discovers devices on your local network and displays detailed information including IP addresses, MAC addresses, vendor/manufacturer info, and device types — similar to the popular Fing app, but open source and runs in your terminal.

## Features

- 🚀 **Fast scanning** using ARP protocol
- 🔍 **Device discovery** on local network
- 🏭 **Vendor identification** from MAC address (OUI lookup)
- 📱 **Device categorization** (Apple, Android, IoT, Computers, etc.)
- 🔒 **Works without sudo** (limited mode using ARP cache)
- 📦 **Auto-install dependencies** (detects your package manager)
- 🖥️ **Cross-platform** (macOS and Linux)
- ⚡ **Zero dependencies** (single binary)

## Quick Start

### Download Pre-built Binary

```bash
# macOS (Apple Silicon)
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-macos-arm64 -o openfing
chmod +x openfing

# macOS (Intel)
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-macos-x86_64 -o openfing
chmod +x openfing

# Linux (x86_64)
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-linux-x86_64 -o openfing
chmod +x openfing

# Linux (ARM64)
curl -L https://github.com/yourusername/OpenFing/releases/latest/download/openfing-linux-arm64 -o openfing
chmod +x openfing
```

### Install System-wide

```bash
sudo mv openfing /usr/local/bin/
```

### Build from Source

Requires [Zig](https://ziglang.org/download/) 0.13.0 or later.

```bash
git clone https://github.com/yourusername/OpenFing.git
cd OpenFing
zig build -Doptimize=ReleaseFast
```

The binary will be at `./zig-out/bin/openfing`

## Usage

### Basic Scan (without sudo)

```bash
openfing
```

This runs in **limited mode** using only the ARP cache — showing devices you've recently communicated with.

### Full Network Scan (with sudo)

```bash
sudo openfing
```

This performs a **full ARP scan** of your network, discovering all active devices.

### Specify Network Interface

```bash
sudo openfing en0      # macOS
sudo openfing eth0     # Linux
sudo openfing wlan0    # Linux WiFi
```

## Example Output

```
+==============================================================================+
|                         NETWORK SCANNER (netscan)                            |
+==============================================================================+

Network Information:
--------------------
  Your IP       : 192.168.1.100
  Gateway       : 192.168.1.1
  Subnet        : 192.168.1.0/24
  Interface     : en0
  Running as    : root/sudo

Scanning network for devices...

+-----------------------------------------------------------------------------+
| DISCOVERED DEVICES (via arp-scan (full scan))
+-----------------------------------------------------------------------------+

IP ADDRESS        | MAC ADDRESS        | VENDOR/HOSTNAME                    | STATUS
------------------+--------------------+------------------------------------+--------
192.168.1.1       | e8:ea:4d:1d:3a:45  | HUAWEI TECHNOLOGIES (GATEWAY)      | Online
192.168.1.50      | 4c:20:b8:db:d5:e8  | Apple, Inc.                        | Online
192.168.1.100     | be:29:e5:69:04:e0  | Unknown (THIS DEVICE)              | Online
192.168.1.105     | b0:41:6f:0d:78:17  | Intel Corporate                    | Online
192.168.1.110     | 24:0d:c2:a1:b2:c3  | Espressif (IoT)                    | Online

+-----------------------------------------------------------------------------+
| SUMMARY                                                                     |
+-----------------------------------------------------------------------------+
| Total Devices   : 5                                                         |
| Online          : 5                                                         |
+-----------------------------------------------------------------------------+

Device Types (estimated):
-------------------------
  Apple Devices   : 1
  Computers       : 1
  IoT/Smart Home  : 1
  Other/Unknown   : 2
```

## Installation of Dependencies

OpenFing works best with `arp-scan` installed. When running with sudo, it will offer to install it automatically.

### Manual Installation

**macOS (Homebrew):**
```bash
brew install arp-scan
```

**Debian/Ubuntu:**
```bash
sudo apt update && sudo apt install -y arp-scan
```

**Fedora:**
```bash
sudo dnf install -y arp-scan
```

**RHEL/CentOS:**
```bash
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

## How It Works

### With sudo (Full Scan)
1. Detects your network interface and subnet
2. Uses `arp-scan` to send ARP requests to all IPs in the subnet
3. Collects responses and identifies device vendors via MAC OUI lookup
4. Displays results with categorization

### Without sudo (Limited Mode)
1. Reads the system's ARP cache (`arp -a`)
2. Shows only devices that have recently communicated with your machine
3. Still performs vendor lookup and categorization

## Comparison: With vs Without sudo

| Feature | Without sudo | With sudo |
|---------|-------------|-----------|
| Scan method | ARP cache | Full ARP scan |
| Device discovery | Recent contacts only | All active devices |
| Vendor lookup | ✅ | ✅ (more accurate) |
| Speed | Instant | 2-5 seconds |
| Requires arp-scan | ❌ | ✅ (auto-installs) |

## Supported Platforms

- ✅ macOS (Apple Silicon & Intel)
- ✅ Linux (x86_64 & ARM64)
- 🔜 Windows (planned)

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Development

```bash
# Build debug version
zig build

# Build release version
zig build -Doptimize=ReleaseFast

# Run directly
zig build run

# Run with arguments
zig build run -- en0
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- Inspired by [Fing](https://www.fing.com/)
- Built with [Zig](https://ziglang.org/)
- Uses [arp-scan](https://github.com/royhills/arp-scan) for full network scanning

## Disclaimer

This tool is intended for network administrators and security professionals to audit their own networks. Always ensure you have permission to scan a network before using this tool. Unauthorized network scanning may be illegal in your jurisdiction.

---

<p align="center">
  Made with ❤️ and Zig
</p>
# OpenFing
