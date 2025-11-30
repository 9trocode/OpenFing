# Contributing to OpenFing

Thank you for your interest in contributing to OpenFing! This document provides guidelines and information about contributing to this project.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [How to Contribute](#how-to-contribute)
- [Pull Request Process](#pull-request-process)
- [Coding Standards](#coding-standards)
- [Testing](#testing)
- [Documentation](#documentation)

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. Please:

- Be respectful and considerate in your communications
- Welcome newcomers and help them get started
- Focus on constructive feedback
- Accept responsibility for your mistakes and learn from them

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/OpenFing.git
   cd OpenFing
   ```
3. **Add the upstream remote**:
   ```bash
   git remote add upstream https://github.com/yourusername/OpenFing.git
   ```

## Development Setup

### Prerequisites

- [Zig](https://ziglang.org/download/) 0.13.0 or later
- Git
- A Linux or macOS system (for testing)
- `arp-scan` (optional, for full testing)

### Building

```bash
# Debug build
zig build

# Release build
zig build -Doptimize=ReleaseFast

# Run directly
zig build run

# Run with arguments
zig build run -- en0
```

### Project Structure

```
OpenFing/
├── src/
│   └── main.zig        # Main application source
├── build.zig           # Zig build configuration
├── .github/
│   └── workflows/
│       └── ci.yml      # CI/CD pipeline
├── README.md           # Project overview
├── INSTALL.md          # Installation guide
├── CONTRIBUTING.md     # This file
├── LICENSE             # MIT License
└── install.sh          # Installation script
```

## How to Contribute

### Reporting Bugs

Before submitting a bug report:

1. Check existing [Issues](https://github.com/yourusername/OpenFing/issues) to avoid duplicates
2. Collect relevant information:
   - OS and version (e.g., macOS 14.0, Ubuntu 22.04)
   - Zig version (`zig version`)
   - Steps to reproduce
   - Expected vs actual behavior
   - Error messages or logs

Create a new issue with the "Bug Report" template.

### Suggesting Features

We welcome feature suggestions! Please:

1. Check existing issues for similar suggestions
2. Create a new issue with the "Feature Request" template
3. Describe the use case and expected behavior
4. Consider if you'd like to implement it yourself

### Code Contributions

Areas where contributions are especially welcome:

- **Vendor database expansion** - Add more MAC OUI prefixes for better device identification
- **Platform support** - Windows support, BSD variants
- **Output formats** - JSON, CSV, XML export
- **Network features** - Port scanning, service detection
- **Performance** - Faster scanning, concurrent operations
- **Documentation** - Examples, tutorials, translations

## Pull Request Process

1. **Create a feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make your changes** following our [coding standards](#coding-standards)

3. **Test your changes**:
   ```bash
   zig build test
   zig build run
   sudo zig build run  # Test with privileges
   ```

4. **Commit with clear messages**:
   ```bash
   git commit -m "feat: add JSON output format"
   git commit -m "fix: handle empty ARP cache gracefully"
   git commit -m "docs: add examples for Linux usage"
   ```

   Follow [Conventional Commits](https://www.conventionalcommits.org/):
   - `feat:` - New feature
   - `fix:` - Bug fix
   - `docs:` - Documentation only
   - `style:` - Formatting, no code change
   - `refactor:` - Code restructuring
   - `test:` - Adding tests
   - `chore:` - Maintenance tasks

5. **Push and create a Pull Request**:
   ```bash
   git push origin feature/your-feature-name
   ```

6. **Fill out the PR template** with:
   - Description of changes
   - Related issue (if any)
   - Testing performed
   - Screenshots (if applicable)

7. **Address review feedback** promptly

## Coding Standards

### Zig Style Guide

Follow the [Zig Style Guide](https://ziglang.org/documentation/master/#Style-Guide):

- Use 4 spaces for indentation (no tabs)
- Keep lines under 100 characters when possible
- Use descriptive variable and function names
- Add comments for complex logic

### Example Code Style

```zig
/// Scans the network for active devices using ARP.
/// Returns a list of discovered devices.
fn scanNetwork(
    allocator: std.mem.Allocator,
    interface: []const u8,
) !std.ArrayList(Device) {
    var devices = std.ArrayList(Device).init(allocator);
    errdefer devices.deinit();

    // Perform ARP scan
    const result = try executeArpScan(allocator, interface);
    defer allocator.free(result);

    // Parse results
    try parseArpOutput(result, &devices);

    return devices;
}
```

### Error Handling

- Use Zig's error handling (`try`, `catch`, `errdefer`)
- Provide meaningful error messages
- Clean up resources on error paths

### Memory Management

- Always pair allocations with deallocations
- Use `defer` and `errdefer` for cleanup
- Prefer stack allocation when possible
- Document ownership of allocated memory

## Testing

### Running Tests

```bash
# Run all tests
zig build test

# Run specific test
zig test src/main.zig
```

### Manual Testing Checklist

Before submitting a PR, test:

- [ ] Build succeeds: `zig build`
- [ ] Release build succeeds: `zig build -Doptimize=ReleaseFast`
- [ ] Runs without sudo (limited mode)
- [ ] Runs with sudo (full scan)
- [ ] Works on macOS (if possible)
- [ ] Works on Linux (if possible)
- [ ] No memory leaks (check with careful review)

### Adding Tests

When adding new features, include tests:

```zig
test "parseIPAddress valid input" {
    const result = parseIPAddress("192.168.1.1");
    try std.testing.expect(result != null);
    try std.testing.expectEqual(result.?.octets[0], 192);
}

test "parseIPAddress invalid input" {
    const result = parseIPAddress("not.an.ip");
    try std.testing.expect(result == null);
}
```

## Documentation

### Code Documentation

- Add doc comments (`///`) for public functions
- Explain complex algorithms
- Document assumptions and edge cases

### User Documentation

When adding features, update:

- `README.md` - Feature overview and examples
- `INSTALL.md` - If installation steps change
- Command help text - In the source code

## Questions?

- Open a [Discussion](https://github.com/yourusername/OpenFing/discussions) for general questions
- Join our community chat (if available)
- Tag maintainers in issues if you're stuck

## Recognition

Contributors will be recognized in:

- GitHub Contributors list
- Release notes for significant contributions
- Special thanks in documentation (for major features)

---

Thank you for contributing to OpenFing! Your efforts help make network scanning accessible to everyone.
