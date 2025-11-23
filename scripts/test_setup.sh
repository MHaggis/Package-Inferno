#!/usr/bin/env bash
# Test script to validate PackageInferno installation
set -euo pipefail
cd "$(dirname "$0")/.."

echo "🔥 PackageInferno Setup Validation"
echo "==================================="
echo ""

# Test 1: Docker
echo "✓ Checking Docker..."
if ! command -v docker &> /dev/null; then
    echo "❌ Docker not found. Please install Docker Desktop."
    exit 1
fi
docker --version
echo ""

# Test 2: Docker Compose
echo "✓ Checking Docker Compose..."
if ! docker compose version &> /dev/null; then
    echo "❌ Docker Compose not found. Please install Docker Compose v2."
    exit 1
fi
docker compose version
echo ""

# Test 3: Database
echo "✓ Checking Database..."
docker compose up -d db
sleep 5
if ! docker exec pi-postgres pg_isready -U piuser -d packageinferno > /dev/null 2>&1; then
    echo "❌ Database not responding"
    exit 1
fi
echo "Database is ready"
echo ""

# Test 4: Schema
echo "✓ Initializing Schema..."
./scripts/init_db.sh > /dev/null 2>&1
echo "Schema initialized"
echo ""

# Test 5: Quick scan
echo "✓ Running test scan (2 packages)..."
rm -rf downloads/* out/*
export SEEDS="is-odd,is-even"
./scripts/run_pipeline.sh > /dev/null 2>&1

# Check results
PKG_COUNT=$(docker exec pi-postgres psql -U piuser -d packageinferno -t -c "SELECT COUNT(*) FROM packages;" 2>/dev/null | xargs)
FINDINGS_COUNT=$(docker exec pi-postgres psql -U piuser -d packageinferno -t -c "SELECT COUNT(*) FROM findings;" 2>/dev/null | xargs)
FINDINGS_FILES=$(ls out/findings/*.findings.json 2>/dev/null | wc -l | xargs)

echo ""
echo "📊 Test Results:"
echo "  Packages analyzed: $PKG_COUNT"
echo "  Total findings: $FINDINGS_COUNT"
echo "  Findings files: $FINDINGS_FILES"
echo ""

if [ "$PKG_COUNT" -ge 2 ] && [ "$FINDINGS_COUNT" -gt 0 ] && [ "$FINDINGS_FILES" -ge 2 ]; then
    echo "✅ ALL TESTS PASSED"
    echo ""
    echo "Next steps:"
    echo "  1. Start dashboard: docker compose up -d dashboard"
    echo "  2. Open browser: http://localhost:8501"
    echo "  3. Run bigger scan: MAX_CHUNKS=5 CHUNK_LIMIT=10 ./scripts/run_pipeline.sh"
    echo ""
    exit 0
else
    echo "❌ TESTS FAILED"
    echo "   Check logs above for errors"
    exit 1
fi

