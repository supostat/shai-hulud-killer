#!/bin/bash
# Shai-Hulud 2.0 Killer - Installation Script
# Usage: curl -fsSL https://raw.githubusercontent.com/supostat/shai-hulud-killer/main/install.sh | bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Config
REPO="supostat/shai-hulud-killer"
BINARY_NAME="shai-hulud-killer"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"

echo -e "${RED}"
cat << 'EOF'
  ███████╗██╗  ██╗ █████╗ ██╗      ██╗  ██╗██╗   ██╗██╗     ██╗   ██╗██████╗ 
  ██╔════╝██║  ██║██╔══██╗██║      ██║  ██║██║   ██║██║     ██║   ██║██╔══██╗
  ███████╗███████║███████║██║█████╗███████║██║   ██║██║     ██║   ██║██║  ██║
  ╚════██║██╔══██║██╔══██║██║╚════╝██╔══██║██║   ██║██║     ██║   ██║██║  ██║
  ███████║██║  ██║██║  ██║██║      ██║  ██║╚██████╔╝███████╗╚██████╔╝██████╔╝
  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝      ╚═╝  ╚═╝ ╚═════╝ ╚══════╝ ╚═════╝ ╚═════╝ 
EOF
echo -e "${NC}"
echo -e "${YELLOW}  2.0 KILLER${NC} - Detect npm supply chain attacks"
echo ""

# Detect OS and architecture
detect_platform() {
    local os=""
    local arch=""

    case "$(uname -s)" in
        Linux*)  os="linux" ;;
        Darwin*) os="darwin" ;;
        MINGW*|MSYS*|CYGWIN*) os="windows" ;;
        *)
            echo -e "${RED}Error: Unsupported operating system $(uname -s)${NC}"
            exit 1
            ;;
    esac

    case "$(uname -m)" in
        x86_64|amd64) arch="x86_64" ;;
        arm64|aarch64) arch="aarch64" ;;
        armv7l) arch="armv7" ;;
        *)
            echo -e "${RED}Error: Unsupported architecture $(uname -m)${NC}"
            exit 1
            ;;
    esac

    echo "${os}-${arch}"
}

# Get latest release version
get_latest_version() {
    local version
    version=$(curl -sL "https://api.github.com/repos/${REPO}/releases/latest" 2>/dev/null | \
        grep '"tag_name":' | \
        sed -E 's/.*"([^"]+)".*/\1/')
    
    if [ -z "$version" ]; then
        # Fallback: try to get from tags
        version=$(curl -sL "https://api.github.com/repos/${REPO}/tags" 2>/dev/null | \
            grep '"name":' | \
            head -1 | \
            sed -E 's/.*"([^"]+)".*/\1/')
    fi
    
    echo "$version"
}

# Download and install
install() {
    local platform=$(detect_platform)
    local version="${VERSION:-$(get_latest_version)}"
    
    if [ -z "$version" ]; then
        echo -e "${RED}Error: Could not determine latest version${NC}"
        echo -e "${YELLOW}Tip: You can specify a version with VERSION=v1.0.0${NC}"
        echo ""
        echo -e "${BLUE}Trying to build from source...${NC}"
        install_from_source
        return
    fi

    echo -e "${BLUE}Platform:${NC} ${platform}"
    echo -e "${BLUE}Version:${NC}  ${version}"
    echo -e "${BLUE}Install:${NC}  ${INSTALL_DIR}/${BINARY_NAME}"
    echo ""

    local filename="${BINARY_NAME}-${version}-${platform}"
    local download_url="https://github.com/${REPO}/releases/download/${version}/${filename}"

    echo -e "${YELLOW}Downloading from ${download_url}...${NC}"
    
    # Create temp directory
    local tmp_dir=$(mktemp -d)
    local tmp_file="${tmp_dir}/${BINARY_NAME}"
    
    # Download
    local http_code
    if command -v curl &> /dev/null; then
        http_code=$(curl -fsSL -w "%{http_code}" "$download_url" -o "$tmp_file" 2>/dev/null) || true
    elif command -v wget &> /dev/null; then
        wget -q "$download_url" -O "$tmp_file" 2>/dev/null && http_code="200" || http_code="404"
    else
        echo -e "${RED}Error: curl or wget is required${NC}"
        exit 1
    fi

    if [ "$http_code" != "200" ] || [ ! -s "$tmp_file" ]; then
        echo -e "${YELLOW}Pre-built binary not found. Building from source...${NC}"
        rm -rf "$tmp_dir"
        install_from_source
        return
    fi

    # Make executable
    chmod +x "$tmp_file"

    # Install
    echo -e "${YELLOW}Installing to ${INSTALL_DIR}...${NC}"
    
    if [ -w "$INSTALL_DIR" ]; then
        mv "$tmp_file" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo -e "${YELLOW}Sudo required for installation${NC}"
        sudo mv "$tmp_file" "${INSTALL_DIR}/${BINARY_NAME}"
    fi

    # Cleanup
    rm -rf "$tmp_dir"

    print_success
}

# Install from source using cargo
install_from_source() {
    echo ""
    
    # Check if Rust is installed
    if ! command -v cargo &> /dev/null; then
        echo -e "${YELLOW}Rust not found. Installing Rust first...${NC}"
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi

    echo -e "${BLUE}Building from source...${NC}"
    echo ""
    
    # Clone and build
    local tmp_dir=$(mktemp -d)
    cd "$tmp_dir"
    
    git clone --depth 1 "https://github.com/${REPO}.git" .
    cargo build --release
    
    # Install
    echo -e "${YELLOW}Installing to ${INSTALL_DIR}...${NC}"
    
    if [ -w "$INSTALL_DIR" ]; then
        cp "target/release/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    else
        echo -e "${YELLOW}Sudo required for installation${NC}"
        sudo cp "target/release/${BINARY_NAME}" "${INSTALL_DIR}/${BINARY_NAME}"
    fi
    
    # Cleanup
    cd - > /dev/null
    rm -rf "$tmp_dir"
    
    print_success
}

# Print success message
print_success() {
    # Verify installation
    if command -v "$BINARY_NAME" &> /dev/null; then
        echo ""
        echo -e "${GREEN}✅ Successfully installed ${BINARY_NAME}!${NC}"
        echo ""
        echo -e "${CYAN}Usage:${NC}"
        echo "  ${BINARY_NAME}              # Interactive TUI"
        echo "  ${BINARY_NAME} /path        # Scan specific path"
        echo "  ${BINARY_NAME} --json /path # JSON output for CI/CD"
        echo ""
        echo -e "${CYAN}Quick scan current directory:${NC}"
        echo "  ${BINARY_NAME} ."
        echo ""
    else
        echo ""
        echo -e "${GREEN}✅ Installed to ${INSTALL_DIR}/${BINARY_NAME}${NC}"
        echo -e "${YELLOW}Note: Make sure ${INSTALL_DIR} is in your PATH${NC}"
        echo ""
        echo "Add to PATH:"
        echo "  export PATH=\"${INSTALL_DIR}:\$PATH\""
        echo ""
    fi
}

# Uninstall function
uninstall() {
    echo -e "${YELLOW}Uninstalling ${BINARY_NAME}...${NC}"
    
    if [ -f "${INSTALL_DIR}/${BINARY_NAME}" ]; then
        if [ -w "$INSTALL_DIR" ]; then
            rm "${INSTALL_DIR}/${BINARY_NAME}"
        else
            sudo rm "${INSTALL_DIR}/${BINARY_NAME}"
        fi
        echo -e "${GREEN}✅ Uninstalled successfully${NC}"
    else
        echo -e "${RED}${BINARY_NAME} not found in ${INSTALL_DIR}${NC}"
        exit 1
    fi
}

# Main
case "${1:-install}" in
    install)
        install
        ;;
    uninstall|remove)
        uninstall
        ;;
    source)
        install_from_source
        ;;
    *)
        echo "Usage: $0 [install|uninstall|source]"
        echo ""
        echo "Commands:"
        echo "  install    Install the latest version (default)"
        echo "  uninstall  Remove the installed binary"
        echo "  source     Build and install from source"
        echo ""
        echo "Environment variables:"
        echo "  INSTALL_DIR  Installation directory (default: /usr/local/bin)"
        echo "  VERSION      Specific version to install (e.g., v1.0.0)"
        exit 1
        ;;
esac
