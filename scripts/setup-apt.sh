#!/bin/bash
# Ritma APT Repository Setup Script
# Usage: curl -fsSL https://raw.githubusercontent.com/GlobalSushrut/ritma-utl/main/scripts/setup-apt.sh | sudo bash

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info() { echo -e "${GREEN}[INFO]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }

# Configuration
REPO_URL="https://globalsushrut.github.io/ritma-utl/apt"
KEYRING_PATH="/usr/share/keyrings/ritma-archive-keyring.gpg"
LIST_PATH="/etc/apt/sources.list.d/ritma.list"

# Check root
if [[ $EUID -ne 0 ]]; then
    error "This script must be run as root (use sudo)"
fi

info "Setting up Ritma APT repository..."

# Install dependencies
apt-get update -qq
apt-get install -y -qq curl gnupg apt-transport-https ca-certificates

# Add repository (unsigned for now, GPG signing can be added later)
info "Adding Ritma repository..."

# Create sources list
cat > "$LIST_PATH" << EOF
# Ritma - Court-grade forensic security observability
# https://ritma.io
deb [arch=amd64,arm64] ${REPO_URL} stable main
EOF

info "Repository added to $LIST_PATH"

# Update package lists
info "Updating package lists..."
apt-get update

# Show available package
info "Ritma repository setup complete!"
echo
echo "To install Ritma:"
echo "  sudo apt install ritma"
echo
echo "To start the sidecar service:"
echo "  sudo systemctl start ritma-sidecar"
echo "  sudo systemctl enable ritma-sidecar"
echo
