#!/bin/bash
#
# OpenFing Installation Script
# https://github.com/9trocode/OpenFing
#
# Usage:
#   curl -sSL https://raw.githubusercontent.com/9trocode/OpenFing/main/install.sh | bash
#

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
REPO="9trocode/OpenFing"
BINARY_NAME="openfing"
INSTALL_DIR="/usr/local/bin"

# Print banner
echo -e "${BLUE}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║                    OpenFing Installer                         ║"
echo "║           Fast Network Scanner for Your Terminal              ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

# Detect OS
detect_os() {
    case "$(uname -s)" in
        Darwin*)
            OS="macos"
            ;;
        Linux*)
            OS="linux"
            ;;
        *)
            echo -e "${RED}Error: Unsupported operating system$(uname -s)${NC}"
            exit 1
            ;;
    esac
}

# Detect Architecture
detect_arch() {
    case "$(uname -m)" in
        x86_64|amd64)
            ARCH="x86_64"
            ;;
        arm64|aarch64)
            ARCH="arm64"
            ;;
        *)
            echo -e "${RED}Error: Unsupported architecture $(uname -m)${NC}"
            exit 1
            ;;
    esac
}

# Get latest release version
get_latest_version() {
    echo -e "${BLUE}Fetching latest version...${NC}"

    if command -v curl &> /dev/null; then
        VERSION=$(curl -sI "https://github.com/${REPO}/releases/latest" | grep -i "location:" | sed 's/.*tag\///' | tr -d '\r\n')
    elif command -v wget &> /dev/null; then
        VERSION=$(wget -qO- --server-response "https://github.com/${REPO}/releases/latest" 2>&1 | grep "Location:" | sed 's/.*tag\///' | tr -d '\r\n')
    else
        echo -e "${RED}Error: curl or wget is required${NC}"
        exit 1
    fi

    if [ -z "$VERSION" ]; then
        VERSION="latest"
    fi

    echo -e "${GREEN}Latest version: ${VERSION}${NC}"
}

# Download binary
download_binary() {
    local url="https://github.com/${REPO}/releases/${VERSION}/download/${BINARY_NAME}-${OS}-${ARCH}"
    local tmp_file="/tmp/${BINARY_NAME}"

    echo -e "${BLUE}Downloading OpenFing for ${OS}-${ARCH}...${NC}"
    echo -e "${BLUE}URL: ${url}${NC}"

    if command -v curl &> /dev/null; then
        curl -fsSL "$url" -o "$tmp_file"
    elif command -v wget &> /dev/null; then
        wget -q "$url" -O "$tmp_file"
    fi

    if [ ! -f "$tmp_file" ]; then
        echo -e "${RED}Error: Failed to download binary${NC}"
        exit 1
    fi

    chmod +x "$tmp_file"
    echo -e "${GREEN}Download complete!${NC}"
}

# Install binary
install_binary() {
    local tmp_file="/tmp/${BINARY_NAME}"

    echo -e "${BLUE}Installing to ${INSTALL_DIR}...${NC}"

    # Check if we need sudo
    if [ -w "$INSTALL_DIR" ]; then
        mv "$tmp_file" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo -e "${YELLOW}Requesting sudo access to install to ${INSTALL_DIR}${NC}"
        sudo mv "$tmp_file" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    echo -e "${GREEN}OpenFing installed successfully!${NC}"
}

# Install arp-scan
install_arp_scan() {
    echo ""
    echo -e "${YELLOW}For full network scanning, arp-scan is recommended.${NC}"
    read -p "Would you like to install arp-scan? (y/n) " -n 1 -r
    echo

    if [[ $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}Installing arp-scan...${NC}"

        if [ "$OS" = "macos" ]; then
            if command -v brew &> /dev/null; then
                brew install arp-scan
            else
                echo -e "${YELLOW}Homebrew not found. Please install arp-scan manually:${NC}"
                echo "  brew install arp-scan"
            fi
        elif [ "$OS" = "linux" ]; then
            if command -v apt-get &> /dev/null; then
                sudo apt-get update && sudo apt-get install -y arp-scan
            elif command -v dnf &> /dev/null; then
                sudo dnf install -y arp-scan
            elif command -v yum &> /dev/null; then
                sudo yum install -y arp-scan
            elif command -v pacman &> /dev/null; then
                sudo pacman -S --noconfirm arp-scan
            elif command -v apk &> /dev/null; then
                sudo apk add arp-scan
            else
                echo -e "${YELLOW}Could not detect package manager. Please install arp-scan manually.${NC}"
            fi
        fi
    fi
}

# Verify installation
verify_installation() {
    echo ""
    echo -e "${BLUE}Verifying installation...${NC}"

    if command -v openfing &> /dev/null; then
        echo -e "${GREEN}✓ OpenFing installed successfully!${NC}"
        echo ""
        echo -e "${BLUE}Location:${NC} $(which openfing)"
        echo ""
    else
        echo -e "${RED}✗ Installation verification failed${NC}"
        echo -e "${YELLOW}Make sure ${INSTALL_DIR} is in your PATH${NC}"
        exit 1
    fi
}

# Print usage instructions
print_usage() {
    echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║                      Quick Start                              ║${NC}"
    echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Run without sudo (limited mode - ARP cache only):${NC}"
    echo "  openfing"
    echo ""
    echo -e "${GREEN}Run with sudo (full network scan):${NC}"
    echo "  sudo openfing"
    echo ""
    echo -e "${GREEN}Specify network interface:${NC}"
    echo "  sudo openfing en0     # macOS"
    echo "  sudo openfing eth0    # Linux"
    echo ""
    echo -e "${BLUE}Documentation:${NC} https://github.com/${REPO}"
    echo ""
}

# Cleanup on error
cleanup() {
    rm -f "/tmp/${BINARY_NAME}"
}

trap cleanup EXIT

# Main
main() {
    detect_os
    detect_arch

    echo -e "${BLUE}Detected: ${OS} ${ARCH}${NC}"
    echo ""

    get_latest_version
    download_binary
    install_binary
    verify_installation
    install_arp_scan
    print_usage

    echo -e "${GREEN}Installation complete! 🎉${NC}"
}

main "$@"
