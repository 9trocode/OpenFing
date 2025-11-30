# I Built an Open Source Alternative to Fing Because Privacy Matters

**TL;DR:** Fing's CLI tool is gone, their new products require subscriptions and upload your network data to their servers. I built [OpenFing](https://github.com/9trocode/OpenFing) — a fast, privacy-first network scanner that runs entirely on your machine. No accounts, no subscriptions, no data collection.

---

## The Problem with Fing

If you've ever needed to see what devices are on your network, you've probably used Fing. It was the go-to tool — simple, fast, and it just worked.

**Was.**

Fing has pivoted hard toward monetization:

- The original free CLI tool? **Gone.** Try finding a download link. I'll wait.
- The new Fing Desktop app? Requires an account and uploads your network topology to their servers.
- Want continuous monitoring? That'll be **$4.99/month** for Starter or **$9.99/month** for Premium.

For a tool that scans *your* network and shows *you* what's connected, this feels... wrong.

Your network topology is sensitive data. It reveals:
- How many devices you own
- What brands you prefer (Apple household? IoT-heavy smart home?)
- When devices come online (your daily patterns)
- Potential security vulnerabilities

This data shouldn't leave your machine. Period.

## Enter OpenFing

I built **OpenFing** over a weekend using Zig. It's everything the old Fing CLI was, minus the corporate baggage:

```
$ openfing

+==============================================================================+
|                              OpenFing v1.4.0                                 |
|                         Fast Network Device Scanner                          |
+==============================================================================+

Network Information:
--------------------
  Your IP       : 192.168.1.100
  Gateway       : 192.168.1.1
  Subnet        : 192.168.1.0/24
  Interface     : en0

Scanning....... done

+-----------------------------------------------------------------------------+
| DEVICES FOUND: 8 (via multi-method discovery)
+-----------------------------------------------------------------------------+

IP ADDRESS        | MAC ADDRESS        | VENDOR
------------------+--------------------+-------------------------------------
192.168.1.1       | E8:EA:4D:1D:3A:45  | Huawei (GW)
192.168.1.50      | 4C:20:B8:DB:D5:E8  | Apple
192.168.1.100     | BE:29:E5:69:04:E0  | Intel (THIS)
192.168.1.105     | B0:41:6F:0D:78:17  | Shenzhen Maxtang
192.168.1.110     | 24:0D:C2:A1:B2:C3  | Espressif (IoT)
...

Total: 8 devices
```

### What Makes It Different

**1. Zero Data Collection**

Everything runs locally. There's no account creation, no telemetry, no "anonymous usage data." Your network scan results never leave your machine.

**2. Works Without Root**

Most network scanners need `sudo` because they send raw ARP packets. OpenFing uses a multi-method discovery approach that finds devices even without elevated privileges:

- Ping sweep + ARP cache
- mDNS/Bonjour discovery (finds Apple devices, printers, Chromecasts)
- SSDP/UPnP discovery (finds smart TVs, gaming consoles, routers)
- TCP port probing (triggers ARP entries for web servers, SSH hosts)
- NetBIOS discovery (finds Windows/Samba devices)

In my testing, the non-sudo scan found **more devices** than some sudo-based tools.

**3. Single Binary, No Dependencies**

It's written in Zig, which means it compiles to a single static binary. No Python runtime, no Node.js, no Docker. Just download and run.

**4. Auto-Updates (Optional)**

OpenFing checks for updates daily in the background. If a new version is available, it tells you. You can disable this with `--no-update` if you prefer.

**5. Deep Scan Mode**

Want hostnames and open ports? Use `--deep`:

```
$ sudo openfing --deep

IP ADDRESS        | MAC ADDRESS        | VENDOR/HOST                  | PORTS
------------------+--------------------+------------------------------+----------
192.168.1.1       | E8:EA:4D:1D:3A:45  | router.local                 | HTTP,HTTPS
192.168.1.50      | 4C:20:B8:DB:D5:E8  | MacBook-Pro.local            | SSH
192.168.1.110     | 24:0D:C2:A1:B2:C3  | esp-sensor.local             | HTTP
```

## Installation

### One-Liner Install

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

### Build from Source

```bash
git clone https://github.com/9trocode/OpenFing.git
cd OpenFing
zig build -Doptimize=ReleaseFast
sudo mv zig-out/bin/openfing /usr/local/bin/
```

## Usage Cheatsheet

```bash
openfing                      # Quick scan (no sudo needed)
sudo openfing                 # Full network scan
sudo openfing --deep          # Scan with hostname + port detection
sudo openfing en0             # Scan specific interface
sudo openfing --install-deps  # Install arp-scan for best results
openfing --update             # Check for updates
openfing --no-update          # Disable auto-update check
```

## Why Zig?

I chose Zig for a few reasons:

1. **No runtime dependencies** — Compiles to a static binary that works anywhere
2. **Cross-compilation is trivial** — Build for Linux ARM from my Mac with one flag
3. **C interop** — Could easily integrate libpcap later if needed
4. **Performance** — It's fast. Really fast.
5. **I wanted to learn it** — And building something useful is the best way

## The Technical Bits

For those curious about how it works:

### ARP Scanning (with sudo)

When you have root privileges and `arp-scan` installed, OpenFing uses it to send ARP "who-has" requests to every IP in your subnet. Every device must respond to ARP (it's how networking works), so this finds everything that's online.

### Multi-Method Discovery (without sudo)

Without root, we can't send raw packets. But we can be clever:

1. **Ping sweep** — Send ICMP echo requests to populate the ARP cache
2. **mDNS queries** — Apple devices and many IoT devices advertise via Bonjour
3. **SSDP multicast** — UPnP devices respond to discovery requests
4. **TCP connect** — Opening a TCP connection to common ports (22, 80, 443) triggers ARP resolution
5. **Read ARP cache** — After all that activity, the kernel's ARP cache has entries for most devices

### MAC Vendor Lookup

The first 3 bytes of a MAC address identify the manufacturer (called the OUI — Organizationally Unique Identifier). OpenFing has a built-in database covering the most common vendors: Apple, Samsung, Google, Amazon, Intel, Raspberry Pi, Espressif (ESP8266/ESP32), and more.

## Roadmap

Things I'm considering for future versions:

- [ ] Windows support
- [ ] JSON/CSV output for scripting
- [ ] Larger OUI database (or online lookup fallback)
- [ ] Device fingerprinting (OS detection)
- [ ] Historical tracking (see new devices since last scan)
- [ ] Web UI option

## Try It Out

The code is on GitHub: **[github.com/9trocode/OpenFing](https://github.com/9trocode/OpenFing)**

Star it if you find it useful. Open issues if you find bugs. PRs welcome.

And if you're still using Fing's new cloud-connected apps... maybe reconsider what you're trading for convenience.

---

*Your network. Your data. Your business.*

---

**Tags:** #networking #privacy #opensource #zig #cli #security

**Share this post:**
- [Twitter/X](https://twitter.com/intent/tweet?text=I%20found%20an%20open%20source%20alternative%20to%20Fing%20that%20doesn%27t%20upload%20your%20network%20data%20to%20the%20cloud&url=https://nitrocode.sh/openfing)
- [Hacker News](https://news.ycombinator.com/submitlink?u=https://nitrocode.sh/openfing&t=OpenFing%20-%20Open%20Source%20Network%20Scanner)
- [Reddit r/selfhosted](https://www.reddit.com/r/selfhosted/submit?url=https://nitrocode.sh/openfing&title=OpenFing%20-%20Open%20Source%20Alternative%20to%20Fing)
- [Reddit r/privacy](https://www.reddit.com/r/privacy/submit?url=https://nitrocode.sh/openfing&title=I%20built%20a%20privacy-first%20network%20scanner%20because%20Fing%20now%20uploads%20your%20data)
