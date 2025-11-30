const std = @import("std");

const Device = struct {
    ip: []const u8,
    mac: []const u8,
    hostname: []const u8,
    vendor: []const u8,
    status: []const u8,
};

const OsType = enum {
    macos,
    linux,
    unknown,
};

const PackageManager = enum {
    homebrew,
    apt,
    yum,
    dnf,
    pacman,
    apk,
    unknown,
};

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var stdout = std.io.getStdOut().writer();
    var stderr = std.io.getStdErr().writer();

    var args = std.process.args();
    _ = args.next(); // skip program name

    const interface_arg = args.next();

    // Detect OS and check privileges
    const os_type = detectOS();
    const is_root = isRunningAsRoot();

    // Header
    try stdout.print("\n", .{});
    try stdout.print("+==============================================================================+\n", .{});
    try stdout.print("|                              OpenFing v1.0.0                                 |\n", .{});
    try stdout.print("|                    Fast Network Scanner for Your Terminal                    |\n", .{});
    try stdout.print("+==============================================================================+\n\n", .{});

    // Check and install dependencies if needed
    const has_arp_scan = checkArpScan(allocator);
    if (!has_arp_scan and is_root) {
        try stdout.print("arp-scan not found. Would you like to install it? (y/n): ", .{});

        // Read user input
        var input_buf: [8]u8 = undefined;
        const stdin = std.io.getStdIn().reader();
        const input = stdin.readUntilDelimiter(&input_buf, '\n') catch "n";

        if (input.len > 0 and (input[0] == 'y' or input[0] == 'Y')) {
            try installArpScan(allocator, &stdout, os_type);
        }
    }

    // Get local network info
    const local_ip = try getLocalIP(allocator);
    defer if (local_ip) |ip| allocator.free(ip);

    const gateway_ip = try getGatewayIP(allocator);
    defer if (gateway_ip) |ip| allocator.free(ip);

    const subnet = try getSubnet(allocator, local_ip);
    defer if (subnet) |s| allocator.free(s);

    // Detect interface
    var iface_buf: [16]u8 = undefined;
    const detected_iface = if (interface_arg) |iface|
        iface
    else
        try detectInterface(allocator, &iface_buf);

    // Show network info
    try stdout.print("Network Information:\n", .{});
    try stdout.print("--------------------\n", .{});
    try stdout.print("  Your IP       : {s}\n", .{local_ip orelse "unknown"});
    try stdout.print("  Gateway       : {s}\n", .{gateway_ip orelse "unknown"});
    try stdout.print("  Subnet        : {s}\n", .{subnet orelse "unknown"});
    try stdout.print("  Interface     : {s}\n", .{detected_iface});
    try stdout.print("  Running as    : {s}\n", .{if (is_root) "root/sudo" else "user (limited mode)"});
    try stdout.print("\n", .{});

    if (!is_root) {
        try stdout.print("+-----------------------------------------------------------------------------+\n", .{});
        try stdout.print("| NOTE: Running without sudo - using ARP cache only (limited results)         |\n", .{});
        try stdout.print("| For full network scan, run: sudo openfing                                   |\n", .{});
        try stdout.print("+-----------------------------------------------------------------------------+\n\n", .{});
    }

    // Scan network
    try stdout.print("Scanning network for devices...\n\n", .{});

    var devices = std.ArrayList(Device).init(allocator);
    defer devices.deinit();

    var scan_method: []const u8 = "ARP cache";

    if (is_root) {
        // Try arp-scan first (requires root)
        const arp_scan_success = try tryArpScan(allocator, &devices, detected_iface);
        if (arp_scan_success) {
            scan_method = "arp-scan (full scan)";
        } else {
            // Fall back to ping sweep + arp
            try stdout.print("arp-scan not available, using ping sweep...\n\n", .{});
            try pingAndArpSweep(allocator, &devices, subnet, detected_iface);
            scan_method = "ping sweep + ARP";
        }
    } else {
        // Non-root: use ARP cache only
        try readArpCache(allocator, &devices);
    }

    if (devices.items.len == 0) {
        try stderr.print("No devices found.\n", .{});
        if (!is_root) {
            try stderr.print("Try running with sudo for a full scan: sudo openfing\n", .{});
        }
        return;
    }

    // Sort by IP
    sortDevicesByIP(&devices);

    // Print results
    try stdout.print("+-----------------------------------------------------------------------------+\n", .{});
    try stdout.print("| DISCOVERED DEVICES ({d} found via {s})\n", .{ devices.items.len, scan_method });
    try stdout.print("+-----------------------------------------------------------------------------+\n\n", .{});

    try stdout.print("IP ADDRESS        | MAC ADDRESS        | VENDOR/HOSTNAME                    | STATUS\n", .{});
    try stdout.print("------------------+--------------------+------------------------------------+--------\n", .{});

    var online_count: usize = 0;
    for (devices.items) |device| {
        const is_local = if (local_ip) |lip| std.mem.eql(u8, device.ip, lip) else false;
        const is_gateway = if (gateway_ip) |gip| std.mem.eql(u8, device.ip, gip) else false;

        var label_buf: [50]u8 = undefined;
        const label = if (is_local)
            std.fmt.bufPrint(&label_buf, "{s} (THIS DEVICE)", .{truncateStr(device.vendor, 20)}) catch device.vendor
        else if (is_gateway)
            std.fmt.bufPrint(&label_buf, "{s} (GATEWAY)", .{truncateStr(device.vendor, 22)}) catch device.vendor
        else if (device.hostname.len > 0 and !std.mem.eql(u8, device.hostname, "?"))
            device.hostname
        else
            device.vendor;

        try stdout.print("{s: <17} | {s: <18} | {s: <34} | {s}\n", .{
            device.ip,
            device.mac,
            truncateStr(label, 34),
            device.status,
        });

        if (std.mem.eql(u8, device.status, "Online")) {
            online_count += 1;
        }
    }

    // Summary
    try stdout.print("\n", .{});
    try stdout.print("+-----------------------------------------------------------------------------+\n", .{});
    try stdout.print("| SUMMARY                                                                     |\n", .{});
    try stdout.print("+-----------------------------------------------------------------------------+\n", .{});
    try stdout.print("| Total Devices   : {d: <58}|\n", .{devices.items.len});
    try stdout.print("| Online          : {d: <58}|\n", .{online_count});
    try stdout.print("+-----------------------------------------------------------------------------+\n\n", .{});

    // Device type breakdown
    try stdout.print("Device Types (estimated):\n", .{});
    try stdout.print("-------------------------\n", .{});

    var apple_count: usize = 0;
    var android_count: usize = 0;
    var router_count: usize = 0;
    var pc_count: usize = 0;
    var iot_count: usize = 0;
    var other_count: usize = 0;

    for (devices.items) |device| {
        const vendor = device.vendor;
        if (containsIgnoreCase(vendor, "apple") or containsIgnoreCase(vendor, "iphone") or containsIgnoreCase(vendor, "ipad")) {
            apple_count += 1;
        } else if (containsIgnoreCase(vendor, "samsung") or containsIgnoreCase(vendor, "huawei") or containsIgnoreCase(vendor, "xiaomi") or containsIgnoreCase(vendor, "oppo") or containsIgnoreCase(vendor, "oneplus")) {
            android_count += 1;
        } else if (containsIgnoreCase(vendor, "cisco") or containsIgnoreCase(vendor, "netgear") or containsIgnoreCase(vendor, "tp-link") or containsIgnoreCase(vendor, "asus") or containsIgnoreCase(vendor, "linksys") or containsIgnoreCase(vendor, "ubiquiti") or containsIgnoreCase(vendor, "mikrotik")) {
            router_count += 1;
        } else if (containsIgnoreCase(vendor, "dell") or containsIgnoreCase(vendor, "hp") or containsIgnoreCase(vendor, "lenovo") or containsIgnoreCase(vendor, "intel") or containsIgnoreCase(vendor, "realtek") or containsIgnoreCase(vendor, "microsoft")) {
            pc_count += 1;
        } else if (containsIgnoreCase(vendor, "espressif") or containsIgnoreCase(vendor, "tuya") or containsIgnoreCase(vendor, "amazon") or containsIgnoreCase(vendor, "google") or containsIgnoreCase(vendor, "nest") or containsIgnoreCase(vendor, "ring") or containsIgnoreCase(vendor, "sonos")) {
            iot_count += 1;
        } else {
            other_count += 1;
        }
    }

    if (apple_count > 0) try stdout.print("  Apple Devices   : {d}\n", .{apple_count});
    if (android_count > 0) try stdout.print("  Android/Mobile  : {d}\n", .{android_count});
    if (router_count > 0) try stdout.print("  Network Equip.  : {d}\n", .{router_count});
    if (pc_count > 0) try stdout.print("  Computers       : {d}\n", .{pc_count});
    if (iot_count > 0) try stdout.print("  IoT/Smart Home  : {d}\n", .{iot_count});
    if (other_count > 0) try stdout.print("  Other/Unknown   : {d}\n", .{other_count});

    try stdout.print("\n", .{});
}

fn detectOS() OsType {
    // Check for macOS
    const uname_result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "uname", "-s" },
    }) catch return .unknown;

    defer std.heap.page_allocator.free(uname_result.stdout);
    defer std.heap.page_allocator.free(uname_result.stderr);

    if (std.mem.startsWith(u8, uname_result.stdout, "Darwin")) {
        return .macos;
    } else if (std.mem.startsWith(u8, uname_result.stdout, "Linux")) {
        return .linux;
    }

    return .unknown;
}

fn detectPackageManager(allocator: std.mem.Allocator) PackageManager {
    // Check for various package managers
    const managers = [_]struct { cmd: []const u8, pm: PackageManager }{
        .{ .cmd = "brew --version", .pm = .homebrew },
        .{ .cmd = "apt --version", .pm = .apt },
        .{ .cmd = "dnf --version", .pm = .dnf },
        .{ .cmd = "yum --version", .pm = .yum },
        .{ .cmd = "pacman --version", .pm = .pacman },
        .{ .cmd = "apk --version", .pm = .apk },
    };

    for (managers) |m| {
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "sh", "-c", m.cmd },
        }) catch continue;

        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        if (result.term.Exited == 0) {
            return m.pm;
        }
    }

    return .unknown;
}

fn isRunningAsRoot() bool {
    // Check if running as root/sudo
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "id", "-u" },
    }) catch return false;

    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);

    // Trim and check if "0"
    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r')) {
        len -= 1;
    }

    return len == 1 and result.stdout[0] == '0';
}

fn checkArpScan(allocator: std.mem.Allocator) bool {
    const paths = [_][]const u8{
        "arp-scan --version",
        "/opt/homebrew/bin/arp-scan --version",
        "/usr/sbin/arp-scan --version",
        "/usr/local/bin/arp-scan --version",
    };

    for (paths) |cmd| {
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "sh", "-c", cmd },
        }) catch continue;

        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        if (result.stdout.len > 0 and std.mem.indexOf(u8, result.stdout, "arp-scan") != null) {
            return true;
        }
    }

    return false;
}

fn installArpScan(allocator: std.mem.Allocator, stdout: anytype, os_type: OsType) !void {
    const pm = detectPackageManager(allocator);

    const install_cmd: ?[]const u8 = switch (pm) {
        .homebrew => "brew install arp-scan",
        .apt => "apt-get update && apt-get install -y arp-scan",
        .dnf => "dnf install -y arp-scan",
        .yum => "yum install -y arp-scan",
        .pacman => "pacman -S --noconfirm arp-scan",
        .apk => "apk add arp-scan",
        .unknown => null,
    };

    if (install_cmd) |cmd| {
        try stdout.print("\nInstalling arp-scan using {s}...\n", .{@tagName(pm)});

        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "sh", "-c", cmd },
        }) catch |err| {
            try stdout.print("Failed to install: {any}\n", .{err});
            return;
        };

        defer allocator.free(result.stdout);
        defer allocator.free(result.stderr);

        if (result.term.Exited == 0) {
            try stdout.print("arp-scan installed successfully!\n\n", .{});
        } else {
            try stdout.print("Installation failed. You may need to install manually.\n", .{});
            switch (os_type) {
                .macos => try stdout.print("  brew install arp-scan\n", .{}),
                .linux => try stdout.print("  sudo apt install arp-scan  (Debian/Ubuntu)\n  sudo yum install arp-scan  (RHEL/CentOS)\n", .{}),
                .unknown => try stdout.print("  Please install arp-scan using your package manager.\n", .{}),
            }
            try stdout.print("\n", .{});
        }
    } else {
        try stdout.print("\nCouldn't detect package manager. Please install arp-scan manually:\n", .{});
        switch (os_type) {
            .macos => try stdout.print("  brew install arp-scan\n", .{}),
            .linux => try stdout.print("  sudo apt install arp-scan  (Debian/Ubuntu)\n  sudo yum install arp-scan  (RHEL/CentOS)\n", .{}),
            .unknown => try stdout.print("  Please install arp-scan using your package manager.\n", .{}),
        }
        try stdout.print("\n", .{});
    }
}

fn detectInterface(allocator: std.mem.Allocator, iface_buf: *[16]u8) ![]const u8 {
    const detect_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", "route get default 2>/dev/null | grep interface | awk '{print $2}' || ip route 2>/dev/null | grep default | awk '{print $5}' | head -1" },
    }) catch return "en0";

    defer allocator.free(detect_result.stdout);
    defer allocator.free(detect_result.stderr);

    var len = detect_result.stdout.len;
    while (len > 0 and (detect_result.stdout[len - 1] == '\n' or detect_result.stdout[len - 1] == '\r')) {
        len -= 1;
    }

    if (len > 0 and len < iface_buf.len) {
        @memcpy(iface_buf[0..len], detect_result.stdout[0..len]);
        return iface_buf[0..len];
    }
    return "en0";
}

fn truncateStr(s: []const u8, max_len: usize) []const u8 {
    if (s.len <= max_len) return s;
    return s[0..max_len];
}

fn tryArpScan(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), interface: []const u8) !bool {
    // Build command with explicit interface - try multiple paths
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "/opt/homebrew/bin/arp-scan --localnet -I {s} 2>/dev/null || /usr/sbin/arp-scan --localnet -I {s} 2>/dev/null || /usr/local/bin/arp-scan --localnet -I {s} 2>/dev/null || arp-scan --localnet -I {s} 2>/dev/null", .{ interface, interface, interface, interface }) catch return false;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return false;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) return false;

    // Parse arp-scan output (format: IP\tMAC\tVendor)
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;
        if (std.mem.startsWith(u8, line, "Interface:")) continue;
        if (std.mem.startsWith(u8, line, "Starting")) continue;
        if (std.mem.startsWith(u8, line, "Ending")) continue;
        if (std.mem.indexOf(u8, line, "packets") != null) continue;

        var parts = std.mem.splitScalar(u8, line, '\t');
        const ip = parts.next() orelse continue;
        const mac = parts.next() orelse continue;
        var vendor = parts.next() orelse "Unknown";

        if (!isValidIP(ip)) continue;

        // Skip duplicates
        var is_duplicate = false;
        for (devices.items) |existing| {
            if (std.mem.eql(u8, existing.ip, ip)) {
                is_duplicate = true;
                break;
            }
        }
        if (is_duplicate) continue;

        // Clean up vendor string
        if (std.mem.indexOf(u8, vendor, "(DUP:")) |dup_idx| {
            if (dup_idx > 0) {
                vendor = std.mem.trimRight(u8, vendor[0..dup_idx], " ");
            }
        }

        if (std.mem.eql(u8, vendor, "(Unknown)") or std.mem.startsWith(u8, vendor, "(Unknown:")) {
            vendor = "Unknown";
        }

        const ip_copy = try allocator.dupe(u8, ip);
        const mac_copy = try allocator.dupe(u8, mac);
        const vendor_copy = try allocator.dupe(u8, vendor);

        try devices.append(Device{
            .ip = ip_copy,
            .mac = mac_copy,
            .hostname = "?",
            .vendor = vendor_copy,
            .status = "Online",
        });
    }

    return devices.items.len > 0;
}

fn pingAndArpSweep(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), subnet: ?[]const u8, interface: []const u8) !void {
    _ = interface;

    // Extract base IP from subnet
    var base_ip: [16]u8 = undefined;
    var base_len: usize = 0;

    if (subnet) |s| {
        var last_dot: usize = 0;
        for (s, 0..) |c, i| {
            if (c == '.') last_dot = i;
            if (c == '/') break;
        }

        if (last_dot > 0 and last_dot < base_ip.len - 1) {
            @memcpy(base_ip[0 .. last_dot + 1], s[0 .. last_dot + 1]);
            base_len = last_dot + 1;
        }
    }

    if (base_len == 0) {
        const default = "192.168.1.";
        @memcpy(base_ip[0..default.len], default);
        base_len = default.len;
    }

    // Build subnet string
    var subnet_arg: [24]u8 = undefined;
    const subnet_str = std.fmt.bufPrint(&subnet_arg, "{s}0/24", .{base_ip[0..base_len]}) catch "192.168.1.0/24";

    // Try fping if available
    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", std.fmt.bufPrint(&base_ip, "fping -a -q -g -r 1 {s} 2>/dev/null", .{subnet_str}) catch "echo" },
    }) catch {};

    // Read ARP cache
    try readArpCache(allocator, devices);
}

fn readArpCache(allocator: std.mem.Allocator, devices: *std.ArrayList(Device)) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "arp", "-a" },
    }) catch return;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len == 0) continue;

        // Find IP in parentheses
        const ip_start = std.mem.indexOf(u8, line, "(") orelse continue;
        const ip_end = std.mem.indexOf(u8, line[ip_start..], ")") orelse continue;
        const ip = line[ip_start + 1 .. ip_start + ip_end];

        if (!isValidIP(ip)) continue;
        if (isBroadcastOrMulticast(ip)) continue;

        // Find MAC after "at "
        const at_pos = std.mem.indexOf(u8, line, " at ") orelse continue;
        const mac_start = at_pos + 4;
        var mac_end = mac_start;

        while (mac_end < line.len and line[mac_end] != ' ') {
            mac_end += 1;
        }

        const mac = line[mac_start..mac_end];

        if (std.mem.eql(u8, mac, "(incomplete)")) continue;
        if (std.mem.eql(u8, mac, "ff:ff:ff:ff:ff:ff")) continue;

        // Skip duplicates
        var is_duplicate = false;
        for (devices.items) |existing| {
            if (std.mem.eql(u8, existing.ip, ip)) {
                is_duplicate = true;
                break;
            }
        }
        if (is_duplicate) continue;

        // Get hostname
        const hostname_end = ip_start;
        var hostname = line[0..hostname_end];
        while (hostname.len > 0 and hostname[hostname.len - 1] == ' ') {
            hostname = hostname[0 .. hostname.len - 1];
        }

        // Normalize MAC
        var normalized_mac: [17]u8 = undefined;
        const norm_len = normalizeMac(mac, &normalized_mac);

        const ip_copy = try allocator.dupe(u8, ip);
        const mac_copy = try allocator.dupe(u8, normalized_mac[0..norm_len]);
        const hostname_copy = try allocator.dupe(u8, hostname);

        const vendor = lookupVendor(mac);

        try devices.append(Device{
            .ip = ip_copy,
            .mac = mac_copy,
            .hostname = hostname_copy,
            .vendor = vendor,
            .status = "Online",
        });
    }
}

fn isBroadcastOrMulticast(ip: []const u8) bool {
    if (std.mem.endsWith(u8, ip, ".255")) return true;

    // Multicast range 224.x.x.x - 239.x.x.x
    if (ip.len >= 4) {
        const first_octet = std.fmt.parseInt(u8, ip[0..@min(ip.len, 3)], 10) catch return false;
        if (first_octet >= 224 and first_octet <= 239) return true;
    }

    return false;
}

fn normalizeMac(mac: []const u8, out: *[17]u8) usize {
    var out_idx: usize = 0;
    var octet_chars: usize = 0;

    for (mac) |c| {
        if (c == ':' or c == '-') {
            if (octet_chars == 1 and out_idx > 0) {
                out[out_idx] = out[out_idx - 1];
                out[out_idx - 1] = '0';
                out_idx += 1;
            }
            if (out_idx < 17) {
                out[out_idx] = ':';
                out_idx += 1;
            }
            octet_chars = 0;
        } else if (out_idx < 17) {
            out[out_idx] = if (c >= 'a' and c <= 'f') c - 32 else c;
            out_idx += 1;
            octet_chars += 1;
        }
    }

    if (octet_chars == 1 and out_idx > 0 and out_idx < 17) {
        out[out_idx] = out[out_idx - 1];
        out[out_idx - 1] = '0';
        out_idx += 1;
    }

    return out_idx;
}

fn lookupVendor(mac: []const u8) []const u8 {
    if (mac.len < 6) return "Unknown";

    var prefix_buf: [6]u8 = undefined;
    var j: usize = 0;
    for (mac) |c| {
        if (j >= 6) break;
        if (c == ':' or c == '-') continue;
        prefix_buf[j] = if (c >= 'a' and c <= 'f') c - 32 else c;
        j += 1;
    }

    if (j < 6) return "Unknown";

    const prefix = prefix_buf[0..6];

    // Common vendor OUI prefixes
    if (std.mem.eql(u8, prefix, "00163E") or std.mem.eql(u8, prefix, "000C29") or std.mem.eql(u8, prefix, "005056")) return "VMware";

    if (std.mem.eql(u8, prefix, "0017F2") or std.mem.eql(u8, prefix, "002481") or std.mem.eql(u8, prefix, "00037A")) return "Apple";
    if (std.mem.eql(u8, prefix, "ACDE48") or std.mem.eql(u8, prefix, "D0817A") or std.mem.eql(u8, prefix, "F0D1A9")) return "Apple";
    if (std.mem.eql(u8, prefix, "5C5027") or std.mem.eql(u8, prefix, "F0B479") or std.mem.eql(u8, prefix, "ACBC32")) return "Apple";
    if (std.mem.eql(u8, prefix, "7CD1C3") or std.mem.eql(u8, prefix, "A4B197") or std.mem.eql(u8, prefix, "3C06A7")) return "Apple";
    if (std.mem.startsWith(u8, prefix, "4C20B8")) return "Apple";

    if (std.mem.eql(u8, prefix, "9C5C8E") or std.mem.eql(u8, prefix, "98D6BB") or std.mem.eql(u8, prefix, "C44202")) return "Samsung";

    if (std.mem.eql(u8, prefix, "B8D7AF") or std.mem.eql(u8, prefix, "E8BBA8") or std.mem.eql(u8, prefix, "48A472")) return "Huawei";
    if (std.mem.startsWith(u8, prefix, "E8EA4D")) return "Huawei";

    if (std.mem.eql(u8, prefix, "64B473") or std.mem.eql(u8, prefix, "8CBEBE") or std.mem.eql(u8, prefix, "F8A45F")) return "Xiaomi";

    if (std.mem.eql(u8, prefix, "00E04C") or std.mem.eql(u8, prefix, "525400") or std.mem.eql(u8, prefix, "4CED24")) return "Realtek";

    if (std.mem.eql(u8, prefix, "001E58") or std.mem.eql(u8, prefix, "8C8CAA") or std.mem.eql(u8, prefix, "A4C3F0")) return "Intel";

    if (std.mem.eql(u8, prefix, "B499BA") or std.mem.eql(u8, prefix, "F8BC12") or std.mem.eql(u8, prefix, "4C7625")) return "Dell";

    if (std.mem.eql(u8, prefix, "3C970E") or std.mem.eql(u8, prefix, "98E7F4")) return "HP";

    if (std.mem.eql(u8, prefix, "94E6F7") or std.mem.eql(u8, prefix, "C82A14") or std.mem.eql(u8, prefix, "E89216")) return "Lenovo";

    if (std.mem.eql(u8, prefix, "B0BE76") or std.mem.eql(u8, prefix, "E0E62E") or std.mem.eql(u8, prefix, "6466B3")) return "TP-Link";

    if (std.mem.eql(u8, prefix, "1062EB") or std.mem.eql(u8, prefix, "9CD36D") or std.mem.eql(u8, prefix, "C43DC7")) return "Netgear";

    if (std.mem.eql(u8, prefix, "F832E4") or std.mem.eql(u8, prefix, "001D7E")) return "Cisco";

    if (std.mem.eql(u8, prefix, "2CFDA1") or std.mem.eql(u8, prefix, "08606E") or std.mem.eql(u8, prefix, "10C37B")) return "ASUS";

    if (std.mem.eql(u8, prefix, "240DC2") or std.mem.eql(u8, prefix, "A020A6") or std.mem.eql(u8, prefix, "AC84C6")) return "Espressif (IoT)";

    if (std.mem.eql(u8, prefix, "F0272D") or std.mem.eql(u8, prefix, "74C246") or std.mem.eql(u8, prefix, "A002DC")) return "Amazon";

    if (std.mem.eql(u8, prefix, "3C5AB4") or std.mem.eql(u8, prefix, "F4F5D8") or std.mem.eql(u8, prefix, "54609A")) return "Google";

    if (std.mem.eql(u8, prefix, "18B430") or std.mem.eql(u8, prefix, "64166D")) return "Nest";

    if (std.mem.eql(u8, prefix, "B8E937") or std.mem.eql(u8, prefix, "5CA6E6") or std.mem.eql(u8, prefix, "947AF0")) return "Sonos";

    if (std.mem.eql(u8, prefix, "B827EB") or std.mem.eql(u8, prefix, "DCA632") or std.mem.eql(u8, prefix, "E45F01")) return "Raspberry Pi";

    if (std.mem.eql(u8, prefix, "001DD8") or std.mem.eql(u8, prefix, "7CB27D") or std.mem.eql(u8, prefix, "98DE00")) return "Microsoft";

    if (std.mem.eql(u8, prefix, "001FA7") or std.mem.eql(u8, prefix, "0004FF") or std.mem.eql(u8, prefix, "F8461C")) return "Sony";

    if (std.mem.eql(u8, prefix, "002709") or std.mem.eql(u8, prefix, "0022AA") or std.mem.eql(u8, prefix, "E0E751")) return "Nintendo";

    if (std.mem.eql(u8, prefix, "B8A1B8") or std.mem.eql(u8, prefix, "D02544") or std.mem.eql(u8, prefix, "84EA64")) return "Roku";

    if (std.mem.eql(u8, prefix, "802AA8") or std.mem.eql(u8, prefix, "F09FC2") or std.mem.eql(u8, prefix, "68D79A")) return "Ubiquiti";

    if (std.mem.eql(u8, prefix, "4C5E0C") or std.mem.eql(u8, prefix, "D4CA6D") or std.mem.eql(u8, prefix, "E4D332")) return "MikroTik";

    if (std.mem.eql(u8, prefix, "B0416F")) return "Shenzhen Maxtang";

    return "Unknown";
}

fn isValidIP(ip: []const u8) bool {
    var dots: usize = 0;
    for (ip) |c| {
        if (c == '.') {
            dots += 1;
        } else if (c < '0' or c > '9') {
            return false;
        }
    }
    return dots == 3;
}

fn sortDevicesByIP(devices: *std.ArrayList(Device)) void {
    const items = devices.items;
    var i: usize = 0;
    while (i < items.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < items.len) : (j += 1) {
            if (compareIPs(items[i].ip, items[j].ip) > 0) {
                const tmp = items[i];
                items[i] = items[j];
                items[j] = tmp;
            }
        }
    }
}

fn compareIPs(a: []const u8, b: []const u8) i32 {
    const a_num = ipToNum(a);
    const b_num = ipToNum(b);

    if (a_num < b_num) return -1;
    if (a_num > b_num) return 1;
    return 0;
}

fn ipToNum(ip: []const u8) u32 {
    var result: u32 = 0;
    var octet: u32 = 0;
    var shift: u5 = 24;

    for (ip) |c| {
        if (c == '.') {
            result |= octet << shift;
            octet = 0;
            if (shift >= 8) {
                shift -= 8;
            }
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    result |= octet;

    return result;
}

fn containsIgnoreCase(haystack: []const u8, needle: []const u8) bool {
    if (needle.len > haystack.len) return false;

    var i: usize = 0;
    while (i + needle.len <= haystack.len) : (i += 1) {
        var match = true;
        for (needle, 0..) |nc, j| {
            const hc = haystack[i + j];
            const nc_lower = if (nc >= 'A' and nc <= 'Z') nc + 32 else nc;
            const hc_lower = if (hc >= 'A' and hc <= 'Z') hc + 32 else hc;
            if (nc_lower != hc_lower) {
                match = false;
                break;
            }
        }
        if (match) return true;
    }
    return false;
}

fn getLocalIP(allocator: std.mem.Allocator) !?[]u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "sh",
            "-c",
            "ipconfig getifaddr en0 2>/dev/null || ip route get 1 2>/dev/null | awk '{print $7}' | head -1",
        },
    }) catch return null;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r')) {
        len -= 1;
    }

    if (len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    const ip = try allocator.alloc(u8, len);
    @memcpy(ip, result.stdout[0..len]);
    allocator.free(result.stdout);
    return ip;
}

fn getGatewayIP(allocator: std.mem.Allocator) !?[]u8 {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "sh",
            "-c",
            "netstat -nr 2>/dev/null | grep default | head -1 | awk '{print $2}'",
        },
    }) catch return null;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r')) {
        len -= 1;
    }

    if (len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    const ip = try allocator.alloc(u8, len);
    @memcpy(ip, result.stdout[0..len]);
    allocator.free(result.stdout);
    return ip;
}

fn getSubnet(allocator: std.mem.Allocator, local_ip: ?[]const u8) !?[]u8 {
    if (local_ip == null) return null;

    const ip = local_ip.?;

    var last_dot: usize = 0;
    for (ip, 0..) |c, i| {
        if (c == '.') last_dot = i;
    }

    if (last_dot == 0) return null;

    const suffix = ".0/24";
    const subnet = try allocator.alloc(u8, last_dot + suffix.len);
    @memcpy(subnet[0..last_dot], ip[0..last_dot]);
    @memcpy(subnet[last_dot..], suffix);

    return subnet;
}
