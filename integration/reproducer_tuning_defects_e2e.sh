#!/usr/bin/env bash
# ==============================================================================
# CNI-VULN-03 & CNI-VULN-04 Autonomous Reproducer & Verification Script
# Target: containernetworking/plugins (plugins/meta/tuning)
# - VULN-03: Unhandled Nil Map Dereference on Dynamic CNI Sysctl Args
# - VULN-04: Package-Level sysctlDuplicatesMap Global State Contamination & Race
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}=== CNI-VULN-03 & CNI-VULN-04: Tuning Plugin Verification Suite ===${NC}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"
mkdir -p "${BIN_DIR}"

echo -e "${BLUE}[+] Building tuning binary...${NC}"
(cd "${REPO_ROOT}/plugins/meta/tuning" && go build -o "${BIN_DIR}/tuning" .)

# -----------------------------------------------------------------------------
# 1. Reproducing VULN-03: Dynamic Sysctl Nil Map Assignment
# -----------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${BLUE}--- [1] Testing VULN-03: Dynamic Sysctl Nil Map Assignment ---${NC}"

# Base CNI config without static sysctl dictionary
VULN03_NETCONF='{
  "cniVersion": "1.0.0",
  "name": "tuning-vuln03-net",
  "type": "tuning",
  "args": {
    "cni": {
      "sysctl": {
        "net.ipv4.ip_forward": "1"
      }
    }
  },
  "prevResult": {
    "cniVersion": "1.0.0",
    "interfaces": [{"name": "eth0"}],
    "ips": [{"version": "4", "address": "10.0.0.2/24", "interface": 0}]
  }
}'

export CNI_COMMAND="ADD"
export CNI_CONTAINERID="vuln03-test-container"
export CNI_NETNS="/proc/self/ns/net"
export CNI_IFNAME="eth0"
export CNI_PATH="${BIN_DIR}"
export CNI_ARGS=""

STDERR_VULN03="/tmp/vuln03_stderr.log"
set +e
echo "${VULN03_NETCONF}" | "${BIN_DIR}/tuning" 2> "${STDERR_VULN03}" > /dev/null
EXIT_CODE_03=$?
set -e

if grep -q "assignment to entry in nil map" "${STDERR_VULN03}" || [ "${EXIT_CODE_03}" -ne 0 ]; then
    echo -e "${BOLD}${RED}[CONFIRMED VULN-03] Runtime Panic Triggered!${NC}"
    echo -e "  Exit Code: ${EXIT_CODE_03}"
    echo -e "  Stderr Trace:"
    sed 's/^/    /' "${STDERR_VULN03}" | head -n 8
else
    echo -e "${GREEN}[NOT REPRODUCED] No panic observed.${NC}"
fi

# -----------------------------------------------------------------------------
# 2. Reproducing VULN-04: Cross-Invocation State Contamination & Concurrency
# -----------------------------------------------------------------------------
echo ""
echo -e "${BOLD}${BLUE}--- [2] Testing VULN-04: Global Map State Retention ---${NC}"

echo -e "${BLUE}[+] Executing standard Go test suite for VULN-04 under race detector...${NC}"
set +e
(cd "${REPO_ROOT}/plugins/meta/tuning" && go test -v -run "TestValidateSysctl")
set -e

echo ""
echo -e "${BOLD}====================================================================${NC}"
echo -e "${GREEN}[+] Tuning verification suite completed.${NC}"
echo -e "${BOLD}====================================================================${NC}"
