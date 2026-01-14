#!/bin/bash
# PackageInferno Quick Install
# Usage: curl -fsSL https://raw.githubusercontent.com/MHaggis/Package-Inferno/main/install.sh | bash

set -e

REPO="https://github.com/MHaggis/Package-Inferno"
INSTALL_DIR="${PACKAGE_INFERNO_DIR:-$HOME/package-inferno}"

echo "🔥 PackageInferno Installer"
echo "==========================="
echo ""

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker first."
    echo "   https://docs.docker.com/get-docker/"
    exit 1
fi

# Check for Docker Compose
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose v2."
    exit 1
fi

echo "✓ Docker found"
echo "✓ Docker Compose found"
echo ""

# Clone or update
if [ -d "$INSTALL_DIR" ]; then
    echo "📁 Updating existing installation at $INSTALL_DIR"
    cd "$INSTALL_DIR"
    git pull --quiet
else
    echo "📁 Installing to $INSTALL_DIR"
    git clone --quiet "$REPO" "$INSTALL_DIR"
    cd "$INSTALL_DIR"
fi

echo ""
echo "✅ PackageInferno installed!"
echo ""
echo "Quick Start:"
echo "  cd $INSTALL_DIR"
echo "  ./scripts/test_setup.sh          # Validate installation"
echo ""
echo "Or run a scan:"
echo "  cd $INSTALL_DIR"
echo "  docker compose up -d db"
echo "  ./scripts/init_db.sh"
echo "  SEEDS=\"lodash,express\" ./scripts/run_pipeline.sh"
echo ""
echo "Using pre-built images (faster):"
echo "  docker compose -f docker-compose.ghcr.yml up -d db"
echo "  ./scripts/init_db.sh"
echo "  SEEDS=\"lodash\" docker compose -f docker-compose.ghcr.yml run --rm enumerator"
echo "  docker compose -f docker-compose.ghcr.yml run --rm fetcher"
echo "  docker compose -f docker-compose.ghcr.yml run --rm analyzer"
echo ""
echo "Dashboard: http://localhost:8501"
echo "  docker compose up -d dashboard"
