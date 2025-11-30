# OpenFing

<p align="center">
  <img src="https://img.shields.io/badge/language-Zig-f7a41d?style=flat-square" alt="Zig">
  <img src="https://img.shields.io/badge/platform-macOS%20%7C%20Linux-blue?style=flat-square" alt="Platform">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/v/release/9trocode/OpenFing?style=flat-square" alt="Release">
</p>

**OpenFing** is a fast, lightweight network scanner written in Zig. It discovers devices on your local network and displays detailed information including IP addresses, MAC addresses, vendor/manufacturer info, and device types — similar to the popular Fing app, but open source and runs in your terminal.

## Why OpenFing?

Fing's original free Command Line Interface (CLI) tool has become difficult or impossible to download as the company shifted focus to paid Fing Desktop and Agent products. Their strategy now centers on subscription-based offerings (Starter and Premium tiers) for continuous monitoring and advanced features.

**Problems with the new Fing model:**

- **Monetization over simplicity** — Core functionality now locked behind subscription tiers
- **Privacy concerns** — The newer apps require user accounts and upload network data to third-party servers
- **Feature bloat** — Simple network scanning buried under GUI complexity and cloud integrations

**OpenFing offers an alternative:**

- **Free and open source** — No subscriptions, no accounts, no data collection
- **Privacy-first** — All scanning happens locally, nothing leaves your machine
- **Simple CLI** — Does one thing well: scans your network and shows you what's connected
- **Lightweight** — Single binary, no dependencies beyond optional `arp-scan`

For users who value privacy and simplicity, OpenFing brings back the straightforward network scanning experience that Fing used to provide.

## Features

- **Fast scanning** using ARP protocol
- **Device discovery** on local network
- **Vendor identification** from MAC address (OUI lookup)
- **Deep scan mode** for hostname resolution and port detection
- **Works without sudo** (multi-method discovery: ping, mDNS, SSDP, TCP probes)
- **Auto-update notifications** (gh-style update prompts)
- **Auto-install dependencies** (detects your package manager)
- **Cross-platform** (macOS and Linux)
- **Zero dependencies** (single binary)

## Quick Start

### One-Line Install (Recommended)

**macOS (Apple Silicon):**

```bash
curl -L https://github.com/9trocode/OpenFing/releases/latest/download/openfing-macos-arm64 -o openfing && chmod +x openfing && sudo mv openfing /usr/local/bin/
```

**macOS (Intel):**

```bash
curl -L https://github.com/9trocode/OpenFing/releases/latest/download/openfing-macos-x86_64 -o openfing && chmod +x openfing && sudo mv openfing /usr/local/bin/
```

**Linux (x86_64):**

```bash
curl -L https://github.com/9trocode/OpenFing/releases/latest/download/openfing-linux-x86_64 -o openfing && chmod +x openfing && sudo mv openfing /usr/local/bin/
```

**Linux (ARM64/Raspberry Pi):**

```bash
curl -L https://github.com/9trocode/OpenFing/releases/latest/download/openfing-linux-arm64 -o openfing && chmod +x openfing && sudo mv openfing /usr/local/bin/
```

### Install Script

```bash
curl -sSL https://raw.githubusercontent.com/9trocode/OpenFing/main/install.sh | bash
```

### Build from Source

Requires [Zig](https://ziglang.org/download/) 0.14.0 or later.

```bash
git clone https://github.com/9trocode/OpenFing.git
cd OpenFing
zig build -Doptimize=ReleaseFast
sudo mv zig-out/bin/openfing /usr/local/bin/
```

## Usage

```bash
openfing                      # Quick scan (no sudo needed)
sudo openfing                 # Full network scan (fast)
sudo openfing --deep          # Full scan + hostnames + ports (~4 seconds)
sudo openfing en0             # Scan specific interface
sudo openfing --install-deps  # Install arp-scan for best results
openfing --update             # Check for and install updates
openfing --help               # Show all options
```

## Example Output

```
+==============================================================================+
|                              OpenFing v1.5.1                                 |
|                         Fast Network Device Scanner                          |
+==============================================================================+

Network Information:
--------------------
  Your IP       : 192.168.1.100
  Gateway       : 192.168.1.1
  Subnet        : 192.168.1.0/24
  Interface     : en0
  Running as    : root/sudo
  Scan mode     : deep (ports + hostnames)

Scanning done

Deep scanning (hostnames + ports)... done

+-----------------------------------------------------------------------------+
| DEVICES FOUND: 5 (via arp-scan)
+-----------------------------------------------------------------------------+

IP ADDRESS        | MAC ADDRESS        | VENDOR/HOST                  | PORTS
------------------+--------------------+------------------------------+----------
192.168.1.1       | e8:ea:4d:1d:3a:45  | HUAWEI TECHNOLOGIES CO.,LTD  | HTTP
192.168.1.50      | 4c:20:b8:db:d5:e8  | Apple, Inc.                  | SSH
192.168.1.100     | be:29:e5:69:04:e0  | Unknown (THIS)               | -
192.168.1.105     | b0:41:6f:0d:78:17  | Shenzhen Maxtang             | SSH,HTTP,RDP
192.168.1.110     | 24:0d:c2:a1:b2:c3  | Espressif (IoT)              | HTTP

Total: 5 devices

Devices with open ports:
  192.168.1.1     : HTTP
  192.168.1.50    : SSH
  192.168.1.105   : SSH,HTTP,RDP
  192.168.1.110   : HTTP
```

## Auto-Update

OpenFing checks for updates once per day and shows a notification at the end of your scan:

```
A new release of openfing is available: 1.5.0 → 1.5.1
To upgrade, run: openfing --update
https://github.com/9trocode/OpenFing/releases/tag/v1.5.1
```

Use `--no-update` to disable update checking.

## Installation of Dependencies

OpenFing works best with `arp-scan` installed for full network scanning. You can install it with:

```bash
sudo openfing --install-deps
```

Or manually:

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

**Arch Linux:**

```bash
sudo pacman -S arp-scan
```

## How It Works

### With sudo (Full Scan)

1. Detects your network interface and subnet
2. Uses `arp-scan` to send ARP requests to all IPs in the subnet
3. Collects responses and identifies device vendors via MAC OUI lookup
4. Optionally resolves hostnames and scans ports (with `--deep`)

### Without sudo (Multi-Method Discovery)

1. Ping sweep to populate ARP cache
2. mDNS/Bonjour discovery (finds Apple devices, printers, Chromecasts)
3. SSDP/UPnP discovery (finds routers, smart TVs, gaming consoles)
4. TCP port probing (triggers ARP entries for servers)
5. NetBIOS discovery (finds Windows/Samba devices)
6. Reads the combined ARP cache

This multi-method approach often finds **more devices** than traditional sudo-only scanners!

## Comparison: With vs Without sudo

| Feature           | Without sudo                | With sudo           |
| ----------------- | --------------------------- | ------------------- |
| Scan method       | Multi-method discovery      | Full ARP scan       |
| Device discovery  | Excellent (multiple probes) | All active devices  |
| Vendor lookup     | Yes                         | Yes (more accurate) |
| Speed             | ~5 seconds                  | ~2 seconds          |
| Requires arp-scan | No                          | Yes (auto-installs) |

## Supported Platforms

- macOS (Apple Silicon & Intel)
- Linux (x86_64 & ARM64)
- Windows (planned)

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
zig build run -- --deep
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
