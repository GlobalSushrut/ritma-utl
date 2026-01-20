#!/bin/bash
# Ritma Installation Script
# Usage: curl -sSL https://get.ritma.io | bash

set -e

RITMA_VERSION="${RITMA_VERSION:-latest}"
INSTALL_DIR="${INSTALL_DIR:-/usr/local/bin}"
CONFIG_DIR="${CONFIG_DIR:-/etc/ritma}"
DATA_DIR="${DATA_DIR:-/var/lib/ritma}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Check requirements
check_requirements() {
    info "Checking requirements..."
    
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root (use sudo)"
    fi
    
    # Check kernel version for eBPF
    KERNEL_VERSION=$(uname -r | cut -d. -f1-2)
    if [[ $(echo "$KERNEL_VERSION < 5.8" | bc -l) -eq 1 ]]; then
        warn "Kernel $KERNEL_VERSION detected. eBPF features require kernel 5.8+"
    fi
    
    # Check for required tools
    for cmd in curl tar; do
        if ! command -v $cmd &> /dev/null; then
            error "$cmd is required but not installed"
        fi
    done
}

# Install from source (Rust)
install_from_source() {
    info "Installing from source..."
    
    if ! command -v cargo &> /dev/null; then
        info "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
        source "$HOME/.cargo/env"
    fi
    
    info "Building Ritma..."
    cargo build --release -p ritma_cli -p tracer_sidecar
    
    info "Installing binaries..."
    cp target/release/ritma "$INSTALL_DIR/"
    cp target/release/tracer_sidecar "$INSTALL_DIR/ritma-sidecar"
    chmod +x "$INSTALL_DIR/ritma" "$INSTALL_DIR/ritma-sidecar"
}

# Install from pre-built binary
install_from_binary() {
    info "Installing pre-built binary..."
    
    ARCH=$(uname -m)
    case $ARCH in
        x86_64) ARCH="amd64" ;;
        aarch64) ARCH="arm64" ;;
        *) error "Unsupported architecture: $ARCH" ;;
    esac
    
    DOWNLOAD_URL="https://github.com/ritma-io/ritma/releases/download/${RITMA_VERSION}/ritma-${RITMA_VERSION}-linux-${ARCH}.tar.gz"
    
    info "Downloading from $DOWNLOAD_URL..."
    curl -sSL "$DOWNLOAD_URL" | tar -xz -C "$INSTALL_DIR"
}

# Setup directories and config
setup_config() {
    info "Setting up directories..."
    
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$DATA_DIR"/{out,cas,index}
    mkdir -p /var/log/ritma
    
    # Create default config if not exists
    if [[ ! -f "$CONFIG_DIR/ritma.conf" ]]; then
        cat > "$CONFIG_DIR/ritma.conf" << 'EOF'
# Ritma Configuration
RITMA_BASE_DIR=/var/lib/ritma
RITMA_OUT_DIR=/var/lib/ritma/out
RITMA_CAS_ENABLE=1
RITMA_OUT_ENABLE=1
RITMA_PRIVACY_MODE=full
RITMA_WINDOW_SECONDS=300
RUST_LOG=ritma=info
EOF
        info "Created default config at $CONFIG_DIR/ritma.conf"
    fi
}

# Install systemd service
install_service() {
    info "Installing systemd service..."
    
    cat > /lib/systemd/system/ritma-sidecar.service << 'EOF'
[Unit]
Description=Ritma Forensic Security Sidecar
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/ritma-sidecar
Restart=on-failure
RestartSec=5
EnvironmentFile=-/etc/ritma/ritma.conf
CapabilityBoundingSet=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN
AmbientCapabilities=CAP_SYS_ADMIN CAP_BPF CAP_PERFMON CAP_NET_ADMIN

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    info "Service installed. Enable with: systemctl enable ritma-sidecar"
}

# Verify installation
verify_install() {
    info "Verifying installation..."
    
    if command -v ritma &> /dev/null; then
        INSTALLED_VERSION=$(ritma --version 2>/dev/null || echo "unknown")
        info "Ritma installed: $INSTALLED_VERSION"
    else
        error "Installation verification failed"
    fi
}

# Main
main() {
    echo "========================================"
    echo "  Ritma Installation Script"
    echo "  Court-grade Forensic Observability"
    echo "========================================"
    echo
    
    check_requirements
    
    # Check if building from source or downloading binary
    if [[ -f "Cargo.toml" ]] && [[ -d "crates" ]]; then
        install_from_source
    else
        install_from_binary
    fi
    
    setup_config
    install_service
    verify_install
    
    echo
    info "Installation complete!"
    echo
    echo "Quick Start:"
    echo "  ritma --help                    # Show CLI help"
    echo "  ritma capture --duration 60     # Capture events for 60s"
    echo "  ritma verify /path/to/proofpack # Verify a proofpack"
    echo
    echo "Start sidecar service:"
    echo "  sudo systemctl start ritma-sidecar"
    echo "  sudo systemctl enable ritma-sidecar"
    echo
}

main "$@"
