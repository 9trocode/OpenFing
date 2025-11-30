const std = @import("std");
const builtin = @import("builtin");

const VERSION = "1.4.0";
const GITHUB_REPO = "9trocode/OpenFing";
const GITHUB_API_URL = "https://api.github.com/repos/" ++ GITHUB_REPO ++ "/releases/latest";

const Device = struct {
    ip: []const u8,
    mac: []const u8,
    vendor: []const u8,
    hostname: []const u8,
    open_ports: []const u8,
};

const OsType = enum { macos, linux, unknown };

const PackageManager = enum { homebrew, apt, yum, dnf, pacman, apk, unknown };

const ArchType = enum { x86_64, arm64, unknown };

pub fn main() !void {
    const allocator = std.heap.page_allocator;
    var stdout = std.io.getStdOut().writer();
    var stderr = std.io.getStdErr().writer();

    var args = std.process.args();
    _ = args.next();

    var interface_arg: ?[]const u8 = null;
    var install_deps = false;
    var show_help = false;
    var deep_scan = false;
    var force_update = false;
    var no_update = false;
    var show_version = false;

    while (args.next()) |arg| {
        if (std.mem.eql(u8, arg, "--install-deps") or std.mem.eql(u8, arg, "-i")) {
            install_deps = true;
        } else if (std.mem.eql(u8, arg, "--help") or std.mem.eql(u8, arg, "-h")) {
            show_help = true;
        } else if (std.mem.eql(u8, arg, "--deep") or std.mem.eql(u8, arg, "-d")) {
            deep_scan = true;
        } else if (std.mem.eql(u8, arg, "--update") or std.mem.eql(u8, arg, "-u")) {
            force_update = true;
        } else if (std.mem.eql(u8, arg, "--no-update")) {
            no_update = true;
        } else if (std.mem.eql(u8, arg, "--version") or std.mem.eql(u8, arg, "-v")) {
            show_version = true;
        } else if (!std.mem.startsWith(u8, arg, "-")) {
            interface_arg = arg;
        }
    }

    const os_type = detectOS();
    const is_root = isRunningAsRoot();

    if (show_version) {
        try stdout.print("OpenFing v{s}\n", .{VERSION});
        return;
    }

    if (show_help) {
        try stdout.print(
            \\OpenFing - Fast Network Device Scanner
            \\
            \\USAGE:
            \\    openfing [OPTIONS] [INTERFACE]
            \\
            \\OPTIONS:
            \\    -h, --help          Show this help message
            \\    -v, --version       Show version information
            \\    -i, --install-deps  Install arp-scan for full network scanning
            \\    -d, --deep          Deep scan: resolve hostnames and detect open ports (slower)
            \\    -u, --update        Force check for updates and install if available
            \\    --no-update         Disable automatic update checking
            \\
            \\EXAMPLES:
            \\    openfing                    Quick scan using ARP cache
            \\    sudo openfing               Full network scan (fast)
            \\    sudo openfing --deep        Full scan with port detection (slower)
            \\    sudo openfing en0           Scan specific interface
            \\    sudo openfing --install-deps  Install arp-scan
            \\    openfing --update           Check for and install updates
            \\
            \\AUTO-UPDATE:
            \\    OpenFing checks for updates daily in the background.
            \\    Use --no-update to disable this behavior.
            \\
        , .{});
        return;
    }

    // Handle force update
    if (force_update) {
        try stdout.print("Checking for updates...\n", .{});
        const update_result = checkAndUpdate(allocator, true);
        switch (update_result) {
            .updated => |new_ver| {
                try stdout.print("Successfully updated to v{s}!\n", .{new_ver});
                try stdout.print("Please restart openfing to use the new version.\n", .{});
            },
            .up_to_date => {
                try stdout.print("You are already running the latest version (v{s}).\n", .{VERSION});
            },
            .failed => |err_msg| {
                try stdout.print("Update check failed: {s}\n", .{err_msg});
            },
            .skipped => {
                try stdout.print("Update skipped.\n", .{});
            },
        }
        return;
    }

    if (install_deps) {
        if (!is_root) {
            try stderr.print("Error: --install-deps requires sudo.\n", .{});
            return;
        }
        try installArpScan(allocator, &stdout, os_type);
        return;
    }

    // Background update check (non-blocking)
    if (!no_update) {
        spawnBackgroundUpdateCheck(allocator);
    }

    // Header
    try stdout.print("\n", .{});
    try stdout.print("+==============================================================================+\n", .{});
    try stdout.print("|                              OpenFing v{s}                                 |\n", .{VERSION});
    try stdout.print("|                         Fast Network Device Scanner                          |\n", .{});
    try stdout.print("+==============================================================================+\n\n", .{});

    const has_arp_scan = checkArpScan(allocator);
    if (!has_arp_scan and is_root) {
        try stdout.print("arp-scan not found. Install with: sudo openfing --install-deps\n\n", .{});
    }

    // Get network info
    const local_ip = try getLocalIP(allocator);
    defer if (local_ip) |ip| allocator.free(ip);

    const gateway_ip = try getGatewayIP(allocator);
    defer if (gateway_ip) |ip| allocator.free(ip);

    const subnet = try getSubnet(allocator, local_ip);
    defer if (subnet) |s| allocator.free(s);

    var iface_buf: [16]u8 = undefined;
    const iface = if (interface_arg) |i| i else try detectInterface(allocator, &iface_buf);

    try stdout.print("Network Information:\n", .{});
    try stdout.print("--------------------\n", .{});
    try stdout.print("  Your IP       : {s}\n", .{local_ip orelse "unknown"});
    try stdout.print("  Gateway       : {s}\n", .{gateway_ip orelse "unknown"});
    try stdout.print("  Subnet        : {s}\n", .{subnet orelse "unknown"});
    try stdout.print("  Interface     : {s}\n", .{iface});
    try stdout.print("  Running as    : {s}\n", .{if (is_root) "root/sudo" else "user"});
    try stdout.print("  Scan mode     : {s}\n\n", .{if (deep_scan) "deep (ports + hostnames)" else "fast"});

    if (!is_root) {
        try stdout.print("NOTE: Using multi-method discovery (ping, mDNS, SSDP, TCP probes).\n", .{});
        try stdout.print("      Run with sudo + arp-scan for potentially faster results.\n\n", .{});
    }

    try stdout.print("Scanning", .{});

    var devices = std.ArrayList(Device).init(allocator);
    defer devices.deinit();

    var scan_method: []const u8 = "ARP cache";

    if (is_root and has_arp_scan) {
        const success = try runArpScan(allocator, &devices, iface);
        if (success) {
            scan_method = "arp-scan";
        } else {
            try pingSweepAndArp(allocator, &devices, subnet, &stdout);
            scan_method = "ping sweep + ARP";
        }
    } else {
        // Non-root: use multi-method discovery for better coverage
        try multiMethodDiscovery(allocator, &devices, subnet, &stdout);
        scan_method = "multi-method discovery";
    }

    try stdout.print(" done\n\n", .{});

    if (devices.items.len == 0) {
        try stderr.print("No devices found.\n", .{});
        return;
    }

    // Deep scan: resolve hostnames and scan ports
    if (deep_scan) {
        try stdout.print("Deep scanning (hostnames + ports)...\n", .{});
        for (devices.items, 0..) |*device, idx| {
            // Hostname resolution
            const hostname = try resolveHostname(allocator, device.ip);
            if (hostname) |h| {
                device.hostname = h;
            }

            // Port scanning
            const ports = try scanCommonPorts(allocator, device.ip);
            device.open_ports = ports;

            // Progress
            if (idx % 2 == 0) {
                try stdout.print("  Scanned {d}/{d} devices\r", .{ idx + 1, devices.items.len });
            }
        }
        try stdout.print("  Scanned {d}/{d} devices\n\n", .{ devices.items.len, devices.items.len });
    }

    // Sort by IP
    sortDevicesByIP(&devices);

    // Print results
    try stdout.print("+-----------------------------------------------------------------------------+\n", .{});
    try stdout.print("| DEVICES FOUND: {d} (via {s})\n", .{ devices.items.len, scan_method });
    try stdout.print("+-----------------------------------------------------------------------------+\n\n", .{});

    if (deep_scan) {
        try stdout.print("IP ADDRESS        | MAC ADDRESS        | VENDOR/HOST                  | PORTS\n", .{});
        try stdout.print("------------------+--------------------+------------------------------+----------\n", .{});
    } else {
        try stdout.print("IP ADDRESS        | MAC ADDRESS        | VENDOR\n", .{});
        try stdout.print("------------------+--------------------+-------------------------------------\n", .{});
    }

    for (devices.items) |device| {
        const is_local = if (local_ip) |lip| std.mem.eql(u8, device.ip, lip) else false;
        const is_gateway = if (gateway_ip) |gip| std.mem.eql(u8, device.ip, gip) else false;

        var label_buf: [40]u8 = undefined;
        const display_name = if (device.hostname.len > 0 and !std.mem.eql(u8, device.hostname, "?"))
            device.hostname
        else
            device.vendor;

        const label = if (is_local)
            std.fmt.bufPrint(&label_buf, "{s} (THIS)", .{truncateStr(display_name, 28)}) catch display_name
        else if (is_gateway)
            std.fmt.bufPrint(&label_buf, "{s} (GW)", .{truncateStr(display_name, 30)}) catch display_name
        else
            display_name;

        if (deep_scan) {
            try stdout.print("{s: <17} | {s: <18} | {s: <28} | {s}\n", .{
                device.ip,
                device.mac,
                truncateStr(label, 28),
                if (device.open_ports.len > 0) device.open_ports else "-",
            });
        } else {
            try stdout.print("{s: <17} | {s: <18} | {s}\n", .{
                device.ip,
                device.mac,
                truncateStr(label, 36),
            });
        }
    }

    try stdout.print("\nTotal: {d} devices\n\n", .{devices.items.len});

    // Show port summary in deep mode
    if (deep_scan) {
        var has_ports = false;
        for (devices.items) |device| {
            if (device.open_ports.len > 0) {
                has_ports = true;
                break;
            }
        }
        if (has_ports) {
            try stdout.print("Devices with open ports:\n", .{});
            for (devices.items) |device| {
                if (device.open_ports.len > 0) {
                    try stdout.print("  {s: <15} : {s}\n", .{ device.ip, device.open_ports });
                }
            }
            try stdout.print("\n", .{});
        }
    }

    // Check if update was downloaded in background
    checkForPendingUpdate(allocator, &stdout);
}

// ============================================================================
// Auto-Update Functions
// ============================================================================

const UpdateResult = union(enum) {
    updated: []const u8,
    up_to_date: void,
    failed: []const u8,
    skipped: void,
};

fn getConfigDir(allocator: std.mem.Allocator) ![]u8 {
    const home = std.process.getEnvVarOwned(allocator, "HOME") catch {
        return error.NoHomeDir;
    };
    defer allocator.free(home);

    const config_dir = try std.fmt.allocPrint(allocator, "{s}/.openfing", .{home});
    return config_dir;
}

fn ensureConfigDir(allocator: std.mem.Allocator) !void {
    const config_dir = try getConfigDir(allocator);
    defer allocator.free(config_dir);

    std.fs.makeDirAbsolute(config_dir) catch |err| {
        if (err != error.PathAlreadyExists) {
            return err;
        }
    };
}

fn getLastCheckTime(allocator: std.mem.Allocator) !i64 {
    const config_dir = try getConfigDir(allocator);
    defer allocator.free(config_dir);

    const path = try std.fmt.allocPrint(allocator, "{s}/last_update_check", .{config_dir});
    defer allocator.free(path);

    const file = std.fs.openFileAbsolute(path, .{}) catch {
        return 0;
    };
    defer file.close();

    var buf: [32]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch return 0;
    if (bytes_read == 0) return 0;

    const timestamp_str = std.mem.trimRight(u8, buf[0..bytes_read], "\n\r ");
    return std.fmt.parseInt(i64, timestamp_str, 10) catch 0;
}

fn setLastCheckTime(allocator: std.mem.Allocator, timestamp: i64) !void {
    try ensureConfigDir(allocator);

    const config_dir = try getConfigDir(allocator);
    defer allocator.free(config_dir);

    const path = try std.fmt.allocPrint(allocator, "{s}/last_update_check", .{config_dir});
    defer allocator.free(path);

    const file = try std.fs.createFileAbsolute(path, .{});
    defer file.close();

    var buf: [32]u8 = undefined;
    const timestamp_str = std.fmt.bufPrint(&buf, "{d}", .{timestamp}) catch return;
    _ = try file.write(timestamp_str);
}

fn shouldCheckForUpdates(allocator: std.mem.Allocator) bool {
    const last_check = getLastCheckTime(allocator) catch return true;
    const now = std.time.timestamp();
    const one_day: i64 = 24 * 60 * 60;

    return (now - last_check) > one_day;
}

fn detectArch() ArchType {
    return switch (builtin.cpu.arch) {
        .x86_64 => .x86_64,
        .aarch64 => .arm64,
        else => .unknown,
    };
}

fn getDownloadUrl(allocator: std.mem.Allocator, tag: []const u8) ![]u8 {
    const os_type = detectOS();
    const arch_type = detectArch();

    const os_str = switch (os_type) {
        .macos => "macos",
        .linux => "linux",
        .unknown => return error.UnsupportedOS,
    };

    const arch_str = switch (arch_type) {
        .x86_64 => "x86_64",
        .arm64 => "arm64",
        .unknown => return error.UnsupportedArch,
    };

    return try std.fmt.allocPrint(
        allocator,
        "https://github.com/{s}/releases/download/{s}/openfing-{s}-{s}",
        .{ GITHUB_REPO, tag, os_str, arch_str },
    );
}

fn parseVersionFromJson(json: []const u8) ?[]const u8 {
    // Simple JSON parsing for "tag_name": "vX.Y.Z"
    const tag_key = "\"tag_name\":";
    const start_idx = std.mem.indexOf(u8, json, tag_key) orelse return null;
    const after_key = start_idx + tag_key.len;

    // Find the opening quote
    var i = after_key;
    while (i < json.len and (json[i] == ' ' or json[i] == '"')) : (i += 1) {}
    if (i >= json.len) return null;

    // Skip 'v' prefix if present
    if (json[i] == 'v') i += 1;

    const version_start = i;

    // Find the closing quote
    while (i < json.len and json[i] != '"') : (i += 1) {}
    if (i >= json.len) return null;

    return json[version_start..i];
}

fn parseTagFromJson(json: []const u8) ?[]const u8 {
    // Simple JSON parsing for "tag_name": "vX.Y.Z"
    const tag_key = "\"tag_name\":";
    const start_idx = std.mem.indexOf(u8, json, tag_key) orelse return null;
    const after_key = start_idx + tag_key.len;

    // Find the opening quote
    var i = after_key;
    while (i < json.len and json[i] == ' ') : (i += 1) {}
    if (i >= json.len or json[i] != '"') return null;
    i += 1; // Skip opening quote

    const tag_start = i;

    // Find the closing quote
    while (i < json.len and json[i] != '"') : (i += 1) {}
    if (i >= json.len) return null;

    return json[tag_start..i];
}

fn compareVersions(current: []const u8, latest: []const u8) i32 {
    var current_parts: [3]u32 = .{ 0, 0, 0 };
    var latest_parts: [3]u32 = .{ 0, 0, 0 };

    var current_iter = std.mem.splitScalar(u8, current, '.');
    var latest_iter = std.mem.splitScalar(u8, latest, '.');

    var i: usize = 0;
    while (current_iter.next()) |part| {
        if (i >= 3) break;
        current_parts[i] = std.fmt.parseInt(u32, part, 10) catch 0;
        i += 1;
    }

    i = 0;
    while (latest_iter.next()) |part| {
        if (i >= 3) break;
        latest_parts[i] = std.fmt.parseInt(u32, part, 10) catch 0;
        i += 1;
    }

    for (0..3) |j| {
        if (latest_parts[j] > current_parts[j]) return 1;
        if (latest_parts[j] < current_parts[j]) return -1;
    }

    return 0;
}

fn fetchLatestRelease(allocator: std.mem.Allocator) ![]u8 {
    // Use curl to fetch the GitHub API (more reliable than Zig's HTTP client for HTTPS)
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{
            "curl",
            "-s",
            "-H",
            "Accept: application/vnd.github.v3+json",
            "-H",
            "User-Agent: OpenFing-Updater",
            GITHUB_API_URL,
        },
        .max_output_bytes = 64 * 1024,
    }) catch return error.FetchFailed;

    allocator.free(result.stderr);

    if (result.term.Exited != 0 or result.stdout.len == 0) {
        allocator.free(result.stdout);
        return error.FetchFailed;
    }

    return result.stdout;
}

fn downloadBinary(allocator: std.mem.Allocator, url: []const u8, dest_path: []const u8) !void {
    var cmd_buf: [1024]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "curl -sL -o \"{s}\" \"{s}\" && chmod +x \"{s}\"", .{ dest_path, url, dest_path }) catch return error.CommandTooLong;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 4096,
    }) catch return error.DownloadFailed;

    allocator.free(result.stdout);
    allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        return error.DownloadFailed;
    }
}

fn getSelfPath(allocator: std.mem.Allocator) ![]u8 {
    // Get the path to the current executable
    var path_buf: [std.fs.max_path_bytes]u8 = undefined;
    const self_path = std.fs.selfExePath(&path_buf) catch {
        // Fallback: try to find openfing in PATH
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "which", "openfing" },
        }) catch return error.SelfPathNotFound;

        defer allocator.free(result.stderr);

        if (result.stdout.len == 0) {
            allocator.free(result.stdout);
            return error.SelfPathNotFound;
        }

        var len = result.stdout.len;
        while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r')) {
            len -= 1;
        }

        const path = try allocator.alloc(u8, len);
        @memcpy(path, result.stdout[0..len]);
        allocator.free(result.stdout);
        return path;
    };

    return try allocator.dupe(u8, self_path);
}

fn checkAndUpdate(allocator: std.mem.Allocator, force: bool) UpdateResult {
    // Check if we should run the update check
    if (!force and !shouldCheckForUpdates(allocator)) {
        return .skipped;
    }

    // Update last check time
    setLastCheckTime(allocator, std.time.timestamp()) catch {};

    // Fetch latest release info from GitHub
    const json = fetchLatestRelease(allocator) catch {
        return .{ .failed = "Failed to fetch release info from GitHub" };
    };
    defer allocator.free(json);

    // Parse version from JSON
    const latest_version = parseVersionFromJson(json) orelse {
        return .{ .failed = "Failed to parse version from GitHub response" };
    };

    const tag = parseTagFromJson(json) orelse {
        return .{ .failed = "Failed to parse tag from GitHub response" };
    };

    // Compare versions
    if (compareVersions(VERSION, latest_version) >= 0) {
        return .up_to_date;
    }

    // Get download URL
    const download_url = getDownloadUrl(allocator, tag) catch {
        return .{ .failed = "Unsupported platform for auto-update" };
    };
    defer allocator.free(download_url);

    // Get current executable path
    const self_path = getSelfPath(allocator) catch {
        return .{ .failed = "Could not determine executable path" };
    };
    defer allocator.free(self_path);

    // Download to temp location
    const config_dir = getConfigDir(allocator) catch {
        return .{ .failed = "Could not get config directory" };
    };
    defer allocator.free(config_dir);

    ensureConfigDir(allocator) catch {};

    const temp_path = std.fmt.allocPrint(allocator, "{s}/openfing_new", .{config_dir}) catch {
        return .{ .failed = "Memory allocation failed" };
    };
    defer allocator.free(temp_path);

    downloadBinary(allocator, download_url, temp_path) catch {
        return .{ .failed = "Failed to download new version" };
    };

    // Try to replace the binary
    // First, check if we have write permission
    var replace_cmd_buf: [1024]u8 = undefined;
    const replace_cmd = std.fmt.bufPrint(&replace_cmd_buf, "cp \"{s}\" \"{s}.bak\" 2>/dev/null; mv \"{s}\" \"{s}\" 2>/dev/null", .{ self_path, self_path, temp_path, self_path }) catch {
        return .{ .failed = "Command buffer overflow" };
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", replace_cmd },
    }) catch {
        // Save pending update notification
        savePendingUpdate(allocator, latest_version, temp_path) catch {};
        return .{ .failed = "Update downloaded but requires sudo to install. Run: sudo openfing --update" };
    };

    allocator.free(result.stdout);
    allocator.free(result.stderr);

    if (result.term.Exited != 0) {
        // Save pending update notification
        savePendingUpdate(allocator, latest_version, temp_path) catch {};
        return .{ .failed = "Update downloaded but requires sudo to install. Run: sudo openfing --update" };
    }

    // Copy the version to return (it will be used after this function returns)
    const version_copy = allocator.dupe(u8, latest_version) catch {
        return .{ .failed = "Memory allocation failed" };
    };

    return .{ .updated = version_copy };
}

fn savePendingUpdate(allocator: std.mem.Allocator, version: []const u8, path: []const u8) !void {
    const config_dir = try getConfigDir(allocator);
    defer allocator.free(config_dir);

    const pending_path = try std.fmt.allocPrint(allocator, "{s}/pending_update", .{config_dir});
    defer allocator.free(pending_path);

    const file = try std.fs.createFileAbsolute(pending_path, .{});
    defer file.close();

    _ = try file.write(version);
    _ = try file.write("\n");
    _ = try file.write(path);
}

fn checkForPendingUpdate(allocator: std.mem.Allocator, stdout: anytype) void {
    const config_dir = getConfigDir(allocator) catch return;
    defer allocator.free(config_dir);

    const pending_path = std.fmt.allocPrint(allocator, "{s}/pending_update", .{config_dir}) catch return;
    defer allocator.free(pending_path);

    const file = std.fs.openFileAbsolute(pending_path, .{}) catch return;
    defer file.close();

    var buf: [256]u8 = undefined;
    const bytes_read = file.readAll(&buf) catch return;
    if (bytes_read == 0) return;

    var lines = std.mem.splitScalar(u8, buf[0..bytes_read], '\n');
    const version = lines.next() orelse return;

    stdout.print("\n[Update Available] OpenFing v{s} is ready to install.\n", .{version}) catch {};
    stdout.print("Run 'sudo openfing --update' to complete the update.\n\n", .{}) catch {};
}

fn clearPendingUpdate(allocator: std.mem.Allocator) void {
    const config_dir = getConfigDir(allocator) catch return;
    defer allocator.free(config_dir);

    const pending_path = std.fmt.allocPrint(allocator, "{s}/pending_update", .{config_dir}) catch return;
    defer allocator.free(pending_path);

    std.fs.deleteFileAbsolute(pending_path) catch {};
}

fn spawnBackgroundUpdateCheck(allocator: std.mem.Allocator) void {
    // Only check if it's time (don't spawn process unnecessarily)
    if (!shouldCheckForUpdates(allocator)) {
        return;
    }

    // Get the path to self
    const self_path = getSelfPath(allocator) catch return;
    defer allocator.free(self_path);

    // Spawn a background process to check for updates
    // This runs in the background and won't block the main process
    var cmd_buf: [512]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "(\"{s}\" --update >/dev/null 2>&1 &)", .{self_path}) catch return;

    _ = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return;

    // The shell command forks to background, so run() returns quickly
}

// ============================================================================
// OS and System Detection
// ============================================================================

fn detectOS() OsType {
    return switch (builtin.os.tag) {
        .macos => .macos,
        .linux => .linux,
        else => .unknown,
    };
}

fn isRunningAsRoot() bool {
    const result = std.process.Child.run(.{
        .allocator = std.heap.page_allocator,
        .argv = &[_][]const u8{ "id", "-u" },
    }) catch return false;

    defer std.heap.page_allocator.free(result.stdout);
    defer std.heap.page_allocator.free(result.stderr);

    for (result.stdout) |c| {
        if (c == '0') return true;
        if (c >= '1' and c <= '9') return false;
    }
    return false;
}

fn checkArpScan(allocator: std.mem.Allocator) bool {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "which", "arp-scan" },
    }) catch return false;

    allocator.free(result.stdout);
    allocator.free(result.stderr);
    return result.term.Exited == 0;
}

fn detectPackageManager(allocator: std.mem.Allocator) PackageManager {
    const checks = [_]struct { cmd: []const u8, pm: PackageManager }{
        .{ .cmd = "which brew", .pm = .homebrew },
        .{ .cmd = "which apt", .pm = .apt },
        .{ .cmd = "which dnf", .pm = .dnf },
        .{ .cmd = "which yum", .pm = .yum },
        .{ .cmd = "which pacman", .pm = .pacman },
        .{ .cmd = "which apk", .pm = .apk },
    };

    for (checks) |check| {
        const result = std.process.Child.run(.{
            .allocator = allocator,
            .argv = &[_][]const u8{ "sh", "-c", check.cmd },
        }) catch continue;
        allocator.free(result.stdout);
        allocator.free(result.stderr);
        if (result.term.Exited == 0) return check.pm;
    }
    return .unknown;
}

fn installArpScan(allocator: std.mem.Allocator, stdout: anytype, os_type: OsType) !void {
    const pm = detectPackageManager(allocator);

    try stdout.print("Installing arp-scan...\n", .{});

    var cmd_buf: [256]u8 = undefined;
    const cmd = switch (pm) {
        .homebrew => std.fmt.bufPrint(&cmd_buf, "sudo -u \"$SUDO_USER\" brew install arp-scan 2>&1 || brew install arp-scan", .{}) catch return,
        .apt => "apt-get update -qq && apt-get install -y arp-scan",
        .dnf => "dnf install -y arp-scan",
        .yum => "yum install -y arp-scan",
        .pacman => "pacman -S --noconfirm arp-scan",
        .apk => "apk add arp-scan",
        .unknown => {
            try stdout.print("Unknown package manager. Install arp-scan manually.\n", .{});
            switch (os_type) {
                .macos => try stdout.print("  brew install arp-scan\n", .{}),
                .linux => try stdout.print("  sudo apt install arp-scan\n", .{}),
                .unknown => {},
            }
            return;
        },
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch |err| {
        try stdout.print("Installation failed: {}\n", .{err});
        return;
    };

    allocator.free(result.stdout);
    allocator.free(result.stderr);

    if (result.term.Exited == 0 and checkArpScan(allocator)) {
        try stdout.print("arp-scan installed successfully!\n", .{});
    } else {
        try stdout.print("Installation may have failed. Try installing manually.\n", .{});
    }
}

fn detectInterface(allocator: std.mem.Allocator, buf: []u8) ![]const u8 {
    const os_type = detectOS();

    const cmd = switch (os_type) {
        .macos => "route -n get default 2>/dev/null | grep interface | awk '{print $2}'",
        .linux => "ip route | grep default | awk '{print $5}' | head -1",
        .unknown => return "eth0",
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return if (os_type == .macos) "en0" else "eth0";

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r')) {
        len -= 1;
    }

    if (len == 0 or len > buf.len) {
        return if (os_type == .macos) "en0" else "eth0";
    }

    @memcpy(buf[0..len], result.stdout[0..len]);
    return buf[0..len];
}

fn runArpScan(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), iface: []const u8) !bool {
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "arp-scan -I {s} -l 2>/dev/null", .{iface}) catch return false;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch return false;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return false;
    }

    defer allocator.free(result.stdout);

    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (line.len < 10) continue;
        if (std.mem.startsWith(u8, line, "Interface:")) continue;
        if (std.mem.startsWith(u8, line, "Starting")) continue;
        if (std.mem.indexOf(u8, line, "packets") != null) continue;
        if (std.mem.indexOf(u8, line, "Ending") != null) continue;

        // Parse: IP\tMAC\tVendor
        var parts = std.mem.splitScalar(u8, line, '\t');
        const ip = parts.next() orelse continue;
        const mac = parts.next() orelse continue;
        const vendor_raw = parts.next() orelse "Unknown";

        if (!isValidIP(ip)) continue;

        // Clean vendor string
        var vendor = vendor_raw;
        if (std.mem.startsWith(u8, vendor, "(Unknown")) {
            vendor = "Unknown";
        } else if (std.mem.indexOf(u8, vendor, "(DUP:")) |idx| {
            vendor = std.mem.trimRight(u8, vendor[0..idx], " ");
        }

        const ip_copy = try allocator.dupe(u8, ip);
        const mac_copy = try allocator.dupe(u8, mac);
        const vendor_copy = try allocator.dupe(u8, if (vendor.len > 0 and !std.mem.eql(u8, vendor, "Unknown")) vendor else lookupVendor(mac));

        try devices.append(.{
            .ip = ip_copy,
            .mac = mac_copy,
            .vendor = vendor_copy,
            .hostname = "?",
            .open_ports = "",
        });
    }

    return devices.items.len > 0;
}

fn pingSweepAndArp(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), subnet: ?[]const u8, stdout: anytype) !void {
    if (subnet == null) {
        try readArpCache(allocator, devices);
        return;
    }

    // Extract base IP
    const sub = subnet.?;
    var last_dot: usize = 0;
    for (sub, 0..) |c, i| {
        if (c == '.') last_dot = i;
    }
    if (last_dot == 0) {
        try readArpCache(allocator, devices);
        return;
    }

    const base = sub[0..last_dot];

    // Parallel ping sweep (background) then read ARP
    var cmd_buf: [512]u8 = undefined;
    const os_type = detectOS();

    const cmd = switch (os_type) {
        .macos => std.fmt.bufPrint(&cmd_buf, "for i in $(seq 1 254); do (ping -c 1 -W 100 {s}.$i >/dev/null 2>&1 &); done; sleep 2; arp -a 2>/dev/null", .{base}) catch {
            try readArpCache(allocator, devices);
            return;
        },
        .linux => std.fmt.bufPrint(&cmd_buf, "for i in $(seq 1 254); do (ping -c 1 -W 1 {s}.$i >/dev/null 2>&1 &); done; sleep 2; arp -a 2>/dev/null", .{base}) catch {
            try readArpCache(allocator, devices);
            return;
        },
        .unknown => {
            try readArpCache(allocator, devices);
            return;
        },
    };

    try stdout.print(".", .{});

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch {
        try readArpCache(allocator, devices);
        return;
    };

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    try stdout.print(".", .{});

    try parseArpOutput(allocator, devices, result.stdout);
}

// ============================================================================
// Multi-Method Discovery (for non-root scanning)
// ============================================================================

fn multiMethodDiscovery(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), subnet: ?[]const u8, stdout: anytype) !void {
    try stdout.print(".", .{});

    // Method 1: Enhanced ping sweep with ARP cache
    try pingSweepAndArp(allocator, devices, subnet, stdout);

    try stdout.print(".", .{});

    // Method 2: mDNS/Bonjour discovery (finds Apple devices, printers, Chromecasts, etc.)
    try mdnsDiscovery(allocator, devices);

    try stdout.print(".", .{});

    // Method 3: SSDP/UPnP discovery (finds routers, smart TVs, gaming consoles, etc.)
    try ssdpDiscovery(allocator, devices, subnet);

    try stdout.print(".", .{});

    // Method 4: NetBIOS discovery (finds Windows/Samba devices)
    try netbiosDiscovery(allocator, devices, subnet);

    try stdout.print(".", .{});

    // Method 5: TCP port probe on common ports for remaining IPs
    try tcpProbeDiscovery(allocator, devices, subnet);
}

fn mdnsDiscovery(allocator: std.mem.Allocator, devices: *std.ArrayList(Device)) !void {
    const os_type = detectOS();

    // Use dns-sd on macOS, avahi-browse on Linux
    const cmd = switch (os_type) {
        .macos => "dns-sd -B _services._dns-sd._udp local. 2>/dev/null & sleep 2; kill $! 2>/dev/null; dns-sd -Z _http._tcp local. 2>/dev/null & sleep 1; kill $! 2>/dev/null; arp -a",
        .linux => "timeout 2 avahi-browse -at 2>/dev/null; arp -a",
        .unknown => return,
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch return;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Parse any new ARP entries that appeared
    try parseArpOutput(allocator, devices, result.stdout);
}

fn ssdpDiscovery(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), subnet: ?[]const u8) !void {
    _ = subnet;

    // Send SSDP M-SEARCH to multicast address 239.255.255.250:1900
    // This discovers UPnP devices (routers, smart TVs, Roku, Xbox, PlayStation, etc.)
    const ssdp_request =
        "M-SEARCH * HTTP/1.1\r\n" ++
        "HOST: 239.255.255.250:1900\r\n" ++
        "MAN: \"ssdp:discover\"\r\n" ++
        "MX: 2\r\n" ++
        "ST: ssdp:all\r\n" ++
        "\r\n";

    // Use netcat or socat to send SSDP request
    var cmd_buf: [1024]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "echo -e '{s}' | nc -u -w2 239.255.255.250 1900 2>/dev/null | grep -i 'LOCATION' | head -20; arp -a", .{ssdp_request}) catch return;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch return;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Parse SSDP responses to extract IPs and any ARP entries
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        // Look for LOCATION headers like "LOCATION: http://192.168.1.1:8080/..."
        if (std.mem.indexOf(u8, line, "LOCATION:") != null or std.mem.indexOf(u8, line, "location:") != null) {
            // Extract IP from URL
            if (extractIpFromUrl(line)) |ip| {
                // Check if already in devices
                var found = false;
                for (devices.items) |d| {
                    if (std.mem.eql(u8, d.ip, ip)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    // Try to get MAC from ARP
                    const mac = getMacForIp(allocator, ip) catch "??:??:??:??:??:??";
                    const ip_copy = try allocator.dupe(u8, ip);
                    const mac_copy = try allocator.dupe(u8, mac);

                    try devices.append(.{
                        .ip = ip_copy,
                        .mac = mac_copy,
                        .vendor = if (mac.len >= 8) lookupVendor(mac) else "UPnP Device",
                        .hostname = "?",
                        .open_ports = "",
                    });
                }
            }
        }
    }

    // Also parse any ARP output at the end
    try parseArpOutput(allocator, devices, result.stdout);
}

fn extractIpFromUrl(line: []const u8) ?[]const u8 {
    // Find "http://" or "https://"
    const http_start = std.mem.indexOf(u8, line, "http://") orelse std.mem.indexOf(u8, line, "https://") orelse return null;
    const proto_end = if (std.mem.indexOf(u8, line, "https://") != null) http_start + 8 else http_start + 7;

    if (proto_end >= line.len) return null;

    // Find the end of the IP (: or / or end of string)
    var ip_end = proto_end;
    while (ip_end < line.len) : (ip_end += 1) {
        const c = line[ip_end];
        if (c == ':' or c == '/' or c == ' ' or c == '\r' or c == '\n') break;
    }

    const potential_ip = line[proto_end..ip_end];
    if (isValidIP(potential_ip)) {
        return potential_ip;
    }
    return null;
}

fn getMacForIp(allocator: std.mem.Allocator, ip: []const u8) ![]const u8 {
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "arp -a {s} 2>/dev/null", .{ip}) catch return "??:??:??:??:??:??";

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return "??:??:??:??:??:??";

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Look for MAC address in output - try standard 17-char format first
    var i: usize = 0;
    while (i + 17 <= result.stdout.len) : (i += 1) {
        if (isMacAddress(result.stdout[i .. i + 17])) {
            return try allocator.dupe(u8, result.stdout[i .. i + 17]);
        }
    }

    // Try to find and normalize non-padded MAC (e.g., "b0:41:6f:d:78:17")
    var norm_buf: [17]u8 = undefined;
    if (findAndNormalizeMac(result.stdout, &norm_buf)) |mac| {
        return try allocator.dupe(u8, mac);
    }

    return "??:??:??:??:??:??";
}

fn netbiosDiscovery(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), subnet: ?[]const u8) !void {
    if (subnet == null) return;

    // Check if nmblookup is available
    const check_result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "which", "nmblookup" },
    }) catch return;

    allocator.free(check_result.stderr);

    if (check_result.term.Exited != 0) {
        allocator.free(check_result.stdout);
        return;
    }
    allocator.free(check_result.stdout);

    // Get broadcast address from subnet
    const sub = subnet.?;
    var last_dot: usize = 0;
    for (sub, 0..) |c, i| {
        if (c == '.') last_dot = i;
    }
    if (last_dot == 0) return;

    const base = sub[0..last_dot];

    // Query NetBIOS names on broadcast
    var cmd_buf: [256]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "nmblookup -B {s}.255 '*' 2>/dev/null | grep '<00>' | awk '{{print $1}}'; arp -a", .{base}) catch return;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch return;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Parse output for IPs
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        if (isValidIP(std.mem.trim(u8, line, " \t\r\n"))) {
            const ip = std.mem.trim(u8, line, " \t\r\n");
            var found = false;
            for (devices.items) |d| {
                if (std.mem.eql(u8, d.ip, ip)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                const mac = getMacForIp(allocator, ip) catch "??:??:??:??:??:??";
                const ip_copy = try allocator.dupe(u8, ip);
                const mac_copy = try allocator.dupe(u8, mac);

                try devices.append(.{
                    .ip = ip_copy,
                    .mac = mac_copy,
                    .vendor = if (mac.len >= 8 and !std.mem.eql(u8, mac, "??:??:??:??:??:??")) lookupVendor(mac) else "Windows/Samba",
                    .hostname = "?",
                    .open_ports = "",
                });
            }
        }
    }

    try parseArpOutput(allocator, devices, result.stdout);
}

fn tcpProbeDiscovery(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), subnet: ?[]const u8) !void {
    if (subnet == null) return;

    const sub = subnet.?;
    var last_dot: usize = 0;
    for (sub, 0..) |c, i| {
        if (c == '.') last_dot = i;
    }
    if (last_dot == 0) return;

    const base = sub[0..last_dot];

    // Common ports that most devices have open
    const probe_ports = [_][]const u8{ "22", "80", "443", "445", "8080", "62078" };

    // Build a command that probes multiple ports in parallel
    // Using nc (netcat) with short timeout
    var cmd_buf: [2048]u8 = undefined;
    const os_type = detectOS();

    // Create a script that probes IPs we haven't found yet
    // We'll probe a subset of the range to avoid too much traffic
    const cmd = switch (os_type) {
        .macos => std.fmt.bufPrint(&cmd_buf,
            \\for i in $(seq 1 254); do
            \\  for port in {s}; do
            \\    (nc -z -w1 -G1 {s}.$i $port 2>/dev/null && echo "{s}.$i:$port" &)
            \\  done
            \\done
            \\sleep 3
            \\arp -a
        , .{ "22 80 443", base, base }) catch return,
        .linux => std.fmt.bufPrint(&cmd_buf,
            \\for i in $(seq 1 254); do
            \\  for port in 22 80 443; do
            \\    (timeout 1 nc -z {s}.$i $port 2>/dev/null && echo "{s}.$i:$port" &)
            \\  done
            \\done
            \\sleep 3
            \\arp -a
        , .{ base, base }) catch return,
        .unknown => return,
    };

    _ = probe_ports;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
        .max_output_bytes = 1024 * 1024,
    }) catch return;

    defer allocator.free(result.stdout);
    defer allocator.free(result.stderr);

    // Parse output for IPs that responded
    var lines = std.mem.splitScalar(u8, result.stdout, '\n');
    while (lines.next()) |line| {
        // Look for lines like "192.168.1.50:80"
        if (std.mem.indexOf(u8, line, ":")) |colon_idx| {
            const ip = line[0..colon_idx];
            if (isValidIP(ip)) {
                var found = false;
                for (devices.items) |d| {
                    if (std.mem.eql(u8, d.ip, ip)) {
                        found = true;
                        break;
                    }
                }
                if (!found) {
                    const mac = getMacForIp(allocator, ip) catch "??:??:??:??:??:??";
                    const ip_copy = try allocator.dupe(u8, ip);
                    const mac_copy = try allocator.dupe(u8, mac);

                    try devices.append(.{
                        .ip = ip_copy,
                        .mac = mac_copy,
                        .vendor = if (mac.len >= 8 and !std.mem.eql(u8, mac, "??:??:??:??:??:??")) lookupVendor(mac) else "Unknown",
                        .hostname = "?",
                        .open_ports = "",
                    });
                }
            }
        }
    }

    // Parse ARP output at the end
    try parseArpOutput(allocator, devices, result.stdout);
}

fn readArpCache(allocator: std.mem.Allocator, devices: *std.ArrayList(Device)) !void {
    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "arp", "-a" },
    }) catch return;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return;
    }

    defer allocator.free(result.stdout);

    try parseArpOutput(allocator, devices, result.stdout);
}

fn parseArpOutput(allocator: std.mem.Allocator, devices: *std.ArrayList(Device), output: []const u8) !void {
    var lines = std.mem.splitScalar(u8, output, '\n');
    while (lines.next()) |line| {
        if (line.len < 10) continue;

        // Find IP in parentheses
        const ip_start = std.mem.indexOf(u8, line, "(") orelse continue;
        const ip_end = std.mem.indexOfPos(u8, line, ip_start, ")") orelse continue;
        const ip = line[ip_start + 1 .. ip_end];

        if (!isValidIP(ip)) continue;

        // Find MAC - try standard 17-char format first
        var mac: []const u8 = "";
        var normalized_mac_buf: [17]u8 = undefined;
        var i: usize = 0;
        while (i + 17 <= line.len) : (i += 1) {
            if (isMacAddress(line[i .. i + 17])) {
                mac = line[i .. i + 17];
                break;
            }
        }

        // Try non-padded MAC format if standard not found
        if (mac.len == 0) {
            if (findAndNormalizeMac(line, &normalized_mac_buf)) |norm_mac| {
                mac = norm_mac;
            }
        }

        if (mac.len == 0) continue;
        if (std.mem.eql(u8, mac, "ff:ff:ff:ff:ff:ff")) continue;
        if (std.mem.startsWith(u8, mac, "01:")) continue;

        // Check for duplicates
        var is_dup = false;
        for (devices.items) |d| {
            if (std.mem.eql(u8, d.ip, ip)) {
                is_dup = true;
                break;
            }
        }
        if (is_dup) continue;

        // Normalize MAC
        var mac_buf: [17]u8 = undefined;
        const normalized = normalizeMac(mac, &mac_buf);

        const ip_copy = try allocator.dupe(u8, ip);
        const mac_copy = try allocator.dupe(u8, normalized);
        const vendor = lookupVendor(normalized);

        try devices.append(.{
            .ip = ip_copy,
            .mac = mac_copy,
            .vendor = vendor,
            .hostname = "?",
            .open_ports = "",
        });
    }
}

fn resolveHostname(allocator: std.mem.Allocator, ip: []const u8) !?[]u8 {
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "host -W 1 {s} 2>/dev/null | grep 'domain name pointer' | head -1 | awk '{{print $NF}}' | sed 's/\\.$//'", .{ip}) catch return null;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return null;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r' or result.stdout[len - 1] == ' ')) {
        len -= 1;
    }

    if (len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    const hostname = try allocator.alloc(u8, len);
    @memcpy(hostname, result.stdout[0..len]);
    allocator.free(result.stdout);
    return hostname;
}

fn scanCommonPorts(allocator: std.mem.Allocator, ip: []const u8) ![]const u8 {
    const ports = [_]struct { port: u16, name: []const u8 }{
        .{ .port = 22, .name = "SSH" },
        .{ .port = 80, .name = "HTTP" },
        .{ .port = 443, .name = "HTTPS" },
        .{ .port = 445, .name = "SMB" },
        .{ .port = 548, .name = "AFP" },
        .{ .port = 3389, .name = "RDP" },
        .{ .port = 5000, .name = "UPnP" },
        .{ .port = 8080, .name = "HTTP-Alt" },
        .{ .port = 9100, .name = "Print" },
        .{ .port = 62078, .name = "iPhone" },
    };

    var open_ports = std.ArrayList(u8).init(allocator);
    errdefer open_ports.deinit();

    for (ports) |p| {
        if (try isPortOpen(allocator, ip, p.port)) {
            if (open_ports.items.len > 0) {
                try open_ports.append(',');
            }
            try open_ports.appendSlice(p.name);
        }
    }

    if (open_ports.items.len == 0) {
        return "";
    }

    return try open_ports.toOwnedSlice();
}

fn isPortOpen(allocator: std.mem.Allocator, ip: []const u8, port: u16) !bool {
    var cmd_buf: [128]u8 = undefined;
    const cmd = std.fmt.bufPrint(&cmd_buf, "nc -z -w1 {s} {d} 2>/dev/null", .{ ip, port }) catch return false;

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return false;

    allocator.free(result.stdout);
    allocator.free(result.stderr);

    return result.term.Exited == 0;
}

fn isMacAddress(s: []const u8) bool {
    if (s.len != 17) return false;
    var i: usize = 0;
    while (i < 17) : (i += 1) {
        if (i % 3 == 2) {
            if (s[i] != ':' and s[i] != '-') return false;
        } else {
            const c = s[i];
            if (!((c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F'))) return false;
        }
    }
    return true;
}

fn isHexChar(c: u8) bool {
    return (c >= '0' and c <= '9') or (c >= 'a' and c <= 'f') or (c >= 'A' and c <= 'F');
}

fn findAndNormalizeMac(output: []const u8, buf: *[17]u8) ?[]const u8 {
    // Look for MAC patterns like "b0:41:6f:d:78:17" (non-padded) or "at b0:41:6f:0d:78:17"
    // macOS arp output: "? (192.168.1.1) at b0:41:6f:d:78:17 on en0"

    var i: usize = 0;
    while (i < output.len) : (i += 1) {
        // Look for potential start of MAC (hex char followed eventually by colon)
        if (!isHexChar(output[i])) continue;

        // Try to parse 6 hex octets separated by colons
        var octets: [6]u8 = undefined;
        var octet_count: usize = 0;
        var j = i;
        var current_octet: u16 = 0; // Use u16 to avoid overflow during parsing
        var octet_digits: usize = 0;

        while (j < output.len and octet_count < 6) : (j += 1) {
            const c = output[j];
            if (isHexChar(c)) {
                const digit: u16 = if (c >= '0' and c <= '9')
                    c - '0'
                else if (c >= 'a' and c <= 'f')
                    c - 'a' + 10
                else
                    c - 'A' + 10;
                current_octet = current_octet * 16 + digit;
                octet_digits += 1;
                if (octet_digits > 2 or current_octet > 255) break; // Too many digits or value too large
            } else if (c == ':') {
                if (octet_digits == 0) break; // Empty octet
                if (current_octet > 255) break; // Invalid value
                octets[octet_count] = @truncate(current_octet);
                octet_count += 1;
                current_octet = 0;
                octet_digits = 0;
            } else {
                // End of MAC candidate
                if (octet_digits > 0 and current_octet <= 255) {
                    octets[octet_count] = @truncate(current_octet);
                    octet_count += 1;
                }
                break;
            }
        }

        // Check if we hit end of string with pending octet
        if (j >= output.len and octet_digits > 0 and octet_count < 6 and current_octet <= 255) {
            octets[octet_count] = @truncate(current_octet);
            octet_count += 1;
        }

        // Valid MAC has 6 octets
        if (octet_count == 6) {
            // Format as normalized MAC: XX:XX:XX:XX:XX:XX
            const hex_chars = "0123456789ABCDEF";
            for (0..6) |k| {
                const pos = k * 3;
                buf[pos] = hex_chars[octets[k] >> 4];
                buf[pos + 1] = hex_chars[octets[k] & 0x0F];
                if (k < 5) buf[pos + 2] = ':';
            }
            return buf[0..17];
        }
    }

    return null;
}

fn normalizeMac(mac: []const u8, buf: []u8) []const u8 {
    if (mac.len != 17 or buf.len < 17) return mac;

    for (mac, 0..) |c, i| {
        if (i >= 17) break;
        if (c >= 'a' and c <= 'f') {
            buf[i] = c - 32;
        } else if (c == '-') {
            buf[i] = ':';
        } else {
            buf[i] = c;
        }
    }
    return buf[0..17];
}

fn isValidIP(ip: []const u8) bool {
    var dots: usize = 0;
    for (ip) |c| {
        if (c == '.') dots += 1 else if (c < '0' or c > '9') return false;
    }
    return dots == 3;
}

fn truncateStr(s: []const u8, max: usize) []const u8 {
    return if (s.len <= max) s else s[0..max];
}

fn sortDevicesByIP(devices: *std.ArrayList(Device)) void {
    const items = devices.items;
    for (0..items.len) |i| {
        for (i + 1..items.len) |j| {
            if (ipToNum(items[i].ip) > ipToNum(items[j].ip)) {
                const tmp = items[i];
                items[i] = items[j];
                items[j] = tmp;
            }
        }
    }
}

fn ipToNum(ip: []const u8) u32 {
    var result: u32 = 0;
    var octet: u32 = 0;
    var shift: u5 = 24;

    for (ip) |c| {
        if (c == '.') {
            result |= octet << shift;
            octet = 0;
            if (shift >= 8) shift -= 8;
        } else if (c >= '0' and c <= '9') {
            octet = octet * 10 + (c - '0');
        }
    }
    return result | octet;
}

fn getLocalIP(allocator: std.mem.Allocator) !?[]u8 {
    const cmd = switch (detectOS()) {
        .macos => "ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null",
        .linux, .unknown => "hostname -I 2>/dev/null | awk '{print $1}'",
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return null;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r' or result.stdout[len - 1] == ' ')) {
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
    const cmd = switch (detectOS()) {
        .macos => "netstat -rn | grep default | head -1 | awk '{print $2}'",
        .linux, .unknown => "ip route | grep default | awk '{print $3}' | head -1",
    };

    const result = std.process.Child.run(.{
        .allocator = allocator,
        .argv = &[_][]const u8{ "sh", "-c", cmd },
    }) catch return null;

    defer allocator.free(result.stderr);

    if (result.stdout.len == 0) {
        allocator.free(result.stdout);
        return null;
    }

    var len = result.stdout.len;
    while (len > 0 and (result.stdout[len - 1] == '\n' or result.stdout[len - 1] == '\r' or result.stdout[len - 1] == ' ')) {
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
    const ip = local_ip orelse return null;

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

fn lookupVendor(mac: []const u8) []const u8 {
    if (mac.len < 8) return "Unknown";

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

    // VMware
    if (std.mem.eql(u8, prefix, "00163E") or std.mem.eql(u8, prefix, "000C29") or std.mem.eql(u8, prefix, "005056")) return "VMware";

    // Apple
    if (std.mem.eql(u8, prefix, "0017F2") or std.mem.eql(u8, prefix, "002481") or std.mem.eql(u8, prefix, "00037A")) return "Apple";
    if (std.mem.eql(u8, prefix, "ACDE48") or std.mem.eql(u8, prefix, "D0817A") or std.mem.eql(u8, prefix, "F0D1A9")) return "Apple";
    if (std.mem.eql(u8, prefix, "5C5027") or std.mem.eql(u8, prefix, "F0B479") or std.mem.eql(u8, prefix, "ACBC32")) return "Apple";
    if (std.mem.eql(u8, prefix, "7CD1C3") or std.mem.eql(u8, prefix, "A4B197") or std.mem.eql(u8, prefix, "3C06A7")) return "Apple";
    if (std.mem.eql(u8, prefix, "4C20B8") or std.mem.eql(u8, prefix, "28E14C") or std.mem.eql(u8, prefix, "9027E4")) return "Apple";
    if (std.mem.eql(u8, prefix, "F0989D") or std.mem.eql(u8, prefix, "B065BD") or std.mem.eql(u8, prefix, "60FEC5")) return "Apple";
    if (std.mem.eql(u8, prefix, "B8C75D") or std.mem.eql(u8, prefix, "3C2EF9") or std.mem.eql(u8, prefix, "24A074")) return "Apple";
    if (std.mem.eql(u8, prefix, "CC785F") or std.mem.eql(u8, prefix, "E0C767") or std.mem.eql(u8, prefix, "A4D1D2")) return "Apple";

    // Samsung
    if (std.mem.eql(u8, prefix, "9C5C8E") or std.mem.eql(u8, prefix, "98D6BB") or std.mem.eql(u8, prefix, "C44202")) return "Samsung";
    if (std.mem.eql(u8, prefix, "84119E") or std.mem.eql(u8, prefix, "4844F7") or std.mem.eql(u8, prefix, "B47C9C")) return "Samsung";

    // Huawei
    if (std.mem.eql(u8, prefix, "B8D7AF") or std.mem.eql(u8, prefix, "E8BBA8") or std.mem.eql(u8, prefix, "48A472")) return "Huawei";
    if (std.mem.eql(u8, prefix, "E8EA4D") or std.mem.eql(u8, prefix, "24DF6A") or std.mem.eql(u8, prefix, "04F938")) return "Huawei";
    if (std.mem.eql(u8, prefix, "88CEFA") or std.mem.eql(u8, prefix, "A47B2C") or std.mem.eql(u8, prefix, "5C7D5E")) return "Huawei";

    // Xiaomi
    if (std.mem.eql(u8, prefix, "64B473") or std.mem.eql(u8, prefix, "8CBEBE") or std.mem.eql(u8, prefix, "F8A45F")) return "Xiaomi";
    if (std.mem.eql(u8, prefix, "28E31F") or std.mem.eql(u8, prefix, "0C1DAF") or std.mem.eql(u8, prefix, "50EC50")) return "Xiaomi";

    // Google
    if (std.mem.eql(u8, prefix, "3C5AB4") or std.mem.eql(u8, prefix, "F4F5D8") or std.mem.eql(u8, prefix, "54609A")) return "Google";
    if (std.mem.eql(u8, prefix, "1C7D22") or std.mem.eql(u8, prefix, "94EB2C") or std.mem.eql(u8, prefix, "F8FF5F")) return "Google";

    // Amazon
    if (std.mem.eql(u8, prefix, "F0272D") or std.mem.eql(u8, prefix, "74C246") or std.mem.eql(u8, prefix, "A002DC")) return "Amazon";
    if (std.mem.eql(u8, prefix, "44650D") or std.mem.eql(u8, prefix, "40B4CD") or std.mem.eql(u8, prefix, "FC65DE")) return "Amazon";

    // Microsoft
    if (std.mem.eql(u8, prefix, "001DD8") or std.mem.eql(u8, prefix, "7CB27D") or std.mem.eql(u8, prefix, "98DE00")) return "Microsoft";
    if (std.mem.eql(u8, prefix, "28187D") or std.mem.eql(u8, prefix, "60455E") or std.mem.eql(u8, prefix, "C8F750")) return "Microsoft";

    // Intel
    if (std.mem.eql(u8, prefix, "001E58") or std.mem.eql(u8, prefix, "8C8CAA") or std.mem.eql(u8, prefix, "A4C3F0")) return "Intel";
    if (std.mem.eql(u8, prefix, "3C970E") or std.mem.eql(u8, prefix, "48F17F") or std.mem.eql(u8, prefix, "5C5F67")) return "Intel";
    if (std.mem.eql(u8, prefix, "E02E0B")) return "Intel";

    // Realtek
    if (std.mem.eql(u8, prefix, "00E04C") or std.mem.eql(u8, prefix, "525400") or std.mem.eql(u8, prefix, "4CED24")) return "Realtek";

    // Dell
    if (std.mem.eql(u8, prefix, "B499BA") or std.mem.eql(u8, prefix, "F8BC12") or std.mem.eql(u8, prefix, "4C7625")) return "Dell";
    if (std.mem.eql(u8, prefix, "00188B") or std.mem.eql(u8, prefix, "782BCB") or std.mem.eql(u8, prefix, "F04DA2")) return "Dell";

    // HP
    if (std.mem.eql(u8, prefix, "98E7F4") or std.mem.eql(u8, prefix, "A036BC") or std.mem.eql(u8, prefix, "1CC1DE")) return "HP";

    // Lenovo
    if (std.mem.eql(u8, prefix, "94E6F7") or std.mem.eql(u8, prefix, "C82A14") or std.mem.eql(u8, prefix, "E89216")) return "Lenovo";

    // TP-Link
    if (std.mem.eql(u8, prefix, "B0BE76") or std.mem.eql(u8, prefix, "E0E62E") or std.mem.eql(u8, prefix, "6466B3")) return "TP-Link";
    if (std.mem.eql(u8, prefix, "3C46D8") or std.mem.eql(u8, prefix, "50C7BF") or std.mem.eql(u8, prefix, "6C5AB0")) return "TP-Link";

    // Netgear
    if (std.mem.eql(u8, prefix, "1062EB") or std.mem.eql(u8, prefix, "9CD36D") or std.mem.eql(u8, prefix, "C43DC7")) return "Netgear";

    // Cisco
    if (std.mem.eql(u8, prefix, "F832E4") or std.mem.eql(u8, prefix, "001D7E") or std.mem.eql(u8, prefix, "D0C2B7")) return "Cisco";

    // ASUS
    if (std.mem.eql(u8, prefix, "2CFDA1") or std.mem.eql(u8, prefix, "08606E") or std.mem.eql(u8, prefix, "10C37B")) return "ASUS";

    // Ubiquiti
    if (std.mem.eql(u8, prefix, "802AA8") or std.mem.eql(u8, prefix, "F09FC2") or std.mem.eql(u8, prefix, "68D79A")) return "Ubiquiti";

    // Espressif (IoT)
    if (std.mem.eql(u8, prefix, "240DC2") or std.mem.eql(u8, prefix, "A020A6") or std.mem.eql(u8, prefix, "AC84C6")) return "Espressif (IoT)";
    if (std.mem.eql(u8, prefix, "5CCF7F") or std.mem.eql(u8, prefix, "60019C") or std.mem.eql(u8, prefix, "84F3EB")) return "Espressif (IoT)";

    // Raspberry Pi
    if (std.mem.eql(u8, prefix, "B827EB") or std.mem.eql(u8, prefix, "DCA632") or std.mem.eql(u8, prefix, "E45F01")) return "Raspberry Pi";

    // Sony
    if (std.mem.eql(u8, prefix, "001FA7") or std.mem.eql(u8, prefix, "0004FF") or std.mem.eql(u8, prefix, "F8461C")) return "Sony";

    // Nintendo
    if (std.mem.eql(u8, prefix, "002709") or std.mem.eql(u8, prefix, "0022AA") or std.mem.eql(u8, prefix, "E0E751")) return "Nintendo";

    // Roku
    if (std.mem.eql(u8, prefix, "B8A1B8") or std.mem.eql(u8, prefix, "D02544") or std.mem.eql(u8, prefix, "84EA64")) return "Roku";

    // Sonos
    if (std.mem.eql(u8, prefix, "B8E937") or std.mem.eql(u8, prefix, "5CA6E6") or std.mem.eql(u8, prefix, "947AF0")) return "Sonos";

    // Nest
    if (std.mem.eql(u8, prefix, "18B430") or std.mem.eql(u8, prefix, "64166D")) return "Nest";

    // Ring
    if (std.mem.eql(u8, prefix, "749564") or std.mem.eql(u8, prefix, "503030")) return "Ring";

    // Shenzhen Maxtang
    if (std.mem.eql(u8, prefix, "B0416F")) return "Shenzhen Maxtang";

    return "Unknown";
}
