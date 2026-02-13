#!/bin/bash
# Test scenario for xDS client demo

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "$SCRIPT_DIR/../.." && pwd)"

echo "======================================"
echo "xDS Server Test Scenario"
echo "======================================"
echo ""

# Colors for output
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

step() {
    echo -e "${BLUE}[STEP]${NC} $1"
}

info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check if client is built
if [ ! -f "$SCRIPT_DIR/xds-client" ]; then
    step "Building xDS client..."
    cd "$SCRIPT_DIR"
    go build -o xds-client
    info "Client built successfully"
fi

step "This script will help you test the xDS server and client"
echo ""
echo "Prerequisites:"
echo "  1. Kubernetes cluster running (kind, minikube, etc.)"
echo "  2. Coraza operator manager running with xDS server"
echo ""
echo "Instructions:"
echo ""
echo "Terminal 1 - Start the operator:"
echo "  cd $PROJECT_ROOT"
echo "  ./bin/manager --xds-server-port=18000"
echo ""
echo "Terminal 2 - Run this client:"
echo "  cd $SCRIPT_DIR"
echo "  ./xds-client"
echo ""
echo "Terminal 3 - Create/update RuleSets:"
echo "  kubectl apply -f $PROJECT_ROOT/config/samples/waf_v1alpha1_ruleset.yaml"
echo ""
echo "Expected flow:"
echo "  1. Client connects to server and receives initial snapshot"
echo "  2. When you create/update RuleSets, client receives push updates"
echo "  3. Client prints the full rules content for each RuleSet"
echo ""

step "Starting xDS client (connecting to localhost:18000)..."
info "Press Ctrl+C to stop the client"
echo ""

exec "$SCRIPT_DIR/xds-client"
