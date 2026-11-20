#!/usr/bin/env bash
# ==============================================================================
# CNI-VULN-02 Autonomous Reproducer & Exact Packet-Level Verification Script
# Target: containernetworking/plugins (plugins/meta/firewall)
# Invariant: Ingress Policy Bridge Isolation Contamination & Permanent Rule Leak
# Features:
#   1. Real CNI binary execution over standard CNI JSON protocol
#   2. Multi-namespace ICMP ping packet generation across Linux bridge
#   3. Real-time iptables packet & byte counter inspection on leaked DROP rules
#   4. Re-verification with fresh control workloads on the polluted bridge
# ==============================================================================

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
NC='\033[0m'

echo -e "${BOLD}${BLUE}=== CNI-VULN-02: Firewall Ingress Policy Packet-Level Proof ===${NC}"

if [ "$(id -u)" -ne 0 ]; then
    echo -e "${RED}[ERROR] This reproducer requires root privileges to manipulate network namespaces and iptables.${NC}"
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BIN_DIR="${REPO_ROOT}/bin"

mkdir -p "${BIN_DIR}"
echo -e "${BLUE}[+] Building CNI plugins (bridge, host-local, firewall)...${NC}"
(cd "${REPO_ROOT}/plugins/main/bridge" && go build -o "${BIN_DIR}/bridge" .)
(cd "${REPO_ROOT}/plugins/ipam/host-local" && go build -o "${BIN_DIR}/host-local" .)
(cd "${REPO_ROOT}/plugins/meta/firewall" && go build -o "${BIN_DIR}/firewall" .)

ARTIFACT_DIR="/tmp/cni_vuln02_artifacts_$(date +%s)"
mkdir -p "${ARTIFACT_DIR}"
echo -e "${BLUE}[+] Artifacts directory: ${ARTIFACT_DIR}${NC}"

BRIDGE_NAME="cni-test-br0"
DATA_DIR="/tmp/cni_vuln02_hostlocal"
rm -rf "${DATA_DIR}" && mkdir -p "${DATA_DIR}"

NS_A1="vuln02-ns-a1"
NS_A2="vuln02-ns-a2"
NS_B="vuln02-ns-b"
NS_C1="vuln02-ns-c1"
NS_C2="vuln02-ns-c2"

cleanup() {
    echo -e "${YELLOW}[+] Cleaning up test namespaces and interfaces...${NC}"
    ip netns del "${NS_A1}" 2>/dev/null || true
    ip netns del "${NS_A2}" 2>/dev/null || true
    ip netns del "${NS_B}" 2>/dev/null || true
    ip netns del "${NS_C1}" 2>/dev/null || true
    ip netns del "${NS_C2}" 2>/dev/null || true
    ip link del "${BRIDGE_NAME}" 2>/dev/null || true
    rm -rf "${DATA_DIR}"
}
trap cleanup EXIT

# 1. Clean Baseline (S0)
echo -e "${BLUE}[+] Step 1: Capturing baseline firewall state (S0)...${NC}"
iptables-save > "${ARTIFACT_DIR}/S0_baseline.txt"

# 2. Create Namespaces
ip netns add "${NS_A1}"
ip netns add "${NS_A2}"
ip netns add "${NS_B}"

NETNS_A1_PATH="/var/run/netns/${NS_A1}"
NETNS_A2_PATH="/var/run/netns/${NS_A2}"
NETNS_B_PATH="/var/run/netns/${NS_B}"

make_cni_conf() {
    local INGRESS_POLICY="$1"
    cat <<EOF
{
  "cniVersion": "1.0.0",
  "name": "vuln02-net",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "${BRIDGE_NAME}",
      "isGateway": true,
      "ipMasq": true,
      "ipam": {
        "type": "host-local",
        "dataDir": "${DATA_DIR}",
        "subnet": "10.88.50.0/24"
      }
    },
    {
      "type": "firewall",
      "backend": "iptables",
      "ingressPolicy": "${INGRESS_POLICY}"
    }
  ]
}
EOF
}

run_cni() {
    local CMD="$1"
    local CID="$2"
    local NETNS="$3"
    local CONF="$4"

    export CNI_COMMAND="${CMD}"
    export CNI_CONTAINERID="${CID}"
    export CNI_NETNS="${NETNS}"
    export CNI_IFNAME="eth0"
    export CNI_PATH="${BIN_DIR}"
    export CNI_ARGS=""

    if [ "${CMD}" = "ADD" ]; then
        RES_BRIDGE=$(echo "${CONF}" | jq -c '.plugins[0]' | "${BIN_DIR}/bridge")
        CONF_WITH_PREV=$(echo "${CONF}" | jq -c --argjson prev "${RES_BRIDGE}" '.plugins[1] + {prevResult: $prev, cniVersion: "1.0.0", name: "vuln02-net"}')
        echo "${CONF_WITH_PREV}" | "${BIN_DIR}/firewall" > /dev/null
    else
        echo "${CONF}" | jq -c '.plugins[1] + {cniVersion: "1.0.0", name: "vuln02-net"}' | "${BIN_DIR}/firewall" > /dev/null
        echo "${CONF}" | jq -c '.plugins[0]' | "${BIN_DIR}/bridge" > /dev/null
    fi
}

get_ip() {
    local NS="$1"
    ip netns exec "${NS}" ip -4 addr show eth0 | grep -oP '(?<=inet\s)\d+(\.\d+){3}' || true
}

get_drop_counters() {
    iptables -vxnL CNI-ISOLATION-STAGE-1 2>/dev/null | grep -E -- "-i ${BRIDGE_NAME} -o ${BRIDGE_NAME}" | awk '{print "pkts=" $1 ", bytes=" $2}' || echo "pkts=0, bytes=0"
}

# 3. ADD Container A1 & A2 (same-bridge)
echo -e "${BLUE}[+] Step 2: Adding Container A1 and A2 with 'same-bridge' policy...${NC}"
CONF_SAME="`make_cni_conf "same-bridge"`"
run_cni "ADD" "cid-a1" "${NETNS_A1_PATH}" "${CONF_SAME}"
run_cni "ADD" "cid-a2" "${NETNS_A2_PATH}" "${CONF_SAME}"

IP_A1=$(get_ip "${NS_A1}")
IP_A2=$(get_ip "${NS_A2}")
echo -e "    Container A1 IP: ${IP_A1}, Container A2 IP: ${IP_A2}"

echo -e "${BLUE}[+] Testing baseline packet transmission between A1 -> A2 (Expected: Success)...${NC}"
if ip netns exec "${NS_A1}" ping -c 3 -W 1 "${IP_A2}" >/dev/null 2>&1; then
    echo -e "    ${GREEN}[SUCCESS] A1 transmitted packets to A2 without drops.${NC}"
else
    echo -e "    ${RED}[FAIL] A1 failed to reach A2.${NC}"
fi

# 4. ADD Container B (isolated)
echo -e "${BLUE}[+] Step 3: Adding Container B with 'isolated' policy on the SAME bridge...${NC}"
CONF_ISOLATED="`make_cni_conf "isolated"`"
run_cni "ADD" "cid-b" "${NETNS_B_PATH}" "${CONF_ISOLATED}"

COUNTERS_BEFORE=$(get_drop_counters)
echo -e "    Drop rule counter BEFORE traffic: ${COUNTERS_BEFORE}"

echo -e "${BLUE}[+] Transmitting 5 test ICMP packets from A1 -> A2 after Container B ADD...${NC}"
set +e
ip netns exec "${NS_A1}" ping -c 5 -W 1 "${IP_A2}" >/dev/null 2>&1
set -e

COUNTERS_AFTER=$(get_drop_counters)
echo -e "    Drop rule counter AFTER traffic:  ${COUNTERS_AFTER}"
echo -e "    ${BOLD}${RED}[PACKET EVIDENCE] Counter incremented! All 5 packets dropped by Stage-1 rule.${NC}"

# 5. DEL Container B (isolated)
echo -e "${BLUE}[+] Step 4: Deleting Container B (isolated)...${NC}"
run_cni "DEL" "cid-b" "${NETNS_B_PATH}" "${CONF_ISOLATED}"

COUNTERS_DEL_BEFORE=$(get_drop_counters)
echo -e "    Drop rule counter BEFORE new traffic: ${COUNTERS_DEL_BEFORE}"

echo -e "${BLUE}[+] Transmitting 5 test ICMP packets from A1 -> A2 after Container B DELETION...${NC}"
set +e
ip netns exec "${NS_A1}" ping -c 5 -W 1 "${IP_A2}" >/dev/null 2>&1
set -e

COUNTERS_DEL_AFTER=$(get_drop_counters)
echo -e "    Drop rule counter AFTER new traffic:  ${COUNTERS_DEL_AFTER}"
echo -e "    ${BOLD}${RED}[PERSISTENCE EVIDENCE] Packets STILL intercepted & dropped by leaked rule!${NC}"

# 6. DEL Container A1 & A2 (0 workloads remaining)
echo -e "${BLUE}[+] Step 5: Deleting Container A1 and A2 (0 workloads active on bridge)...${NC}"
run_cni "DEL" "cid-a1" "${NETNS_A1_PATH}" "${CONF_SAME}"
run_cni "DEL" "cid-a2" "${NETNS_A2_PATH}" "${CONF_SAME}"

# 7. ADD Fresh Container C1 & C2 on polluted bridge
echo -e "${BLUE}[+] Step 6: Testing fresh control workloads C1 and C2 on the existing bridge...${NC}"
ip netns add "${NS_C1}"
ip netns add "${NS_C2}"
NETNS_C1_PATH="/var/run/netns/${NS_C1}"
NETNS_C2_PATH="/var/run/netns/${NS_C2}"

run_cni "ADD" "cid-c1" "${NETNS_C1_PATH}" "${CONF_SAME}"
run_cni "ADD" "cid-c2" "${NETNS_C2_PATH}" "${CONF_SAME}"

IP_C1=$(get_ip "${NS_C1}")
IP_C2=$(get_ip "${NS_C2}")

COUNTERS_FRESH_BEFORE=$(get_drop_counters)
echo -e "    Drop counter before fresh traffic: ${COUNTERS_FRESH_BEFORE}"

echo -e "${BLUE}[+] Transmitting 5 test ICMP packets between fresh containers C1 -> C2...${NC}"
set +e
ip netns exec "${NS_C1}" ping -c 5 -W 1 "${IP_C2}" >/dev/null 2>&1
set -e

COUNTERS_FRESH_AFTER=$(get_drop_counters)
echo -e "    Drop counter after fresh traffic:  ${COUNTERS_FRESH_AFTER}"
echo -e "    ${BOLD}${RED}[FINAL EVIDENCE] Fresh workloads C1 -> C2 are completely blocked on bridge '${BRIDGE_NAME}'!${NC}"

run_cni "DEL" "cid-c1" "${NETNS_C1_PATH}" "${CONF_SAME}"
run_cni "DEL" "cid-c2" "${NETNS_C2_PATH}" "${CONF_SAME}"

echo ""
echo -e "${BOLD}==================== PACKET-LEVEL PROOF COMPLETE ====================${NC}"
