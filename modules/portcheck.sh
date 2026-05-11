#!/usr/bin/env bash
# ============================================================================
# PORTCHECK — Find open ports that shouldn't be
# ============================================================================
# Lists every LISTENING port. Compares against your whitelist.
# Anything not on the whitelist is flagged.
# This would have caught port 8080 open for 20 days.
#
# Usage:
#   portcheck.sh          — Full report
#   portcheck.sh quiet    — Alerts only (for watch mode)
#   portcheck.sh report   — Same as default (for sentinel.sh)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="${SENTINEL_ROOT}/config/sentinel.conf"

# Defaults
SENTINEL_DIR="${SENTINEL_DIR:-$HOME/.sentinel}"
LOG_FILE="${LOG_FILE:-$SENTINEL_DIR/sentinel.log}"
ALERT_METHOD="${ALERT_METHOD:-terminal,log}"
WHITELIST_PORTS=()

# Load config
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
fi

mkdir -p "$SENTINEL_DIR"

# Colors
RED="${RED:-\033[0;31m}"
YELLOW="${YELLOW:-\033[0;33m}"
GREEN="${GREEN:-\033[0;32m}"
BLUE="${BLUE:-\033[0;34m}"
BOLD="${BOLD:-\033[1m}"
DIM="${DIM:-\033[2m}"
RESET="${RESET:-\033[0m}"
if [[ ! -t 1 ]]; then
    RED="" YELLOW="" GREEN="" BLUE="" BOLD="" DIM="" RESET=""
fi

_pass()  { echo -e "  ${GREEN}[PASS]${RESET}  $*"; }
_warn()  { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }
_fail()  { echo -e "  ${RED}[FAIL]${RESET}  $*"; }
_info()  { echo -e "  ${BLUE}[INFO]${RESET}  $*"; }

_log() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[$ts] PORTCHECK: $*" >> "$LOG_FILE"
}

# ----------------------------------------------------------------------------
# GET LISTENING PORTS
# ----------------------------------------------------------------------------

get_listening_ports() {
    # Returns: PROCESS  PID  USER  ADDRESS:PORT  BIND_TYPE
    # BIND_TYPE: "localhost" (safe) or "all_interfaces" (exposed)

    if command -v lsof &>/dev/null; then
        lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | while read -r line; do
            local process pid user addr
            process=$(echo "$line" | awk '{print $1}')
            pid=$(echo "$line" | awk '{print $2}')
            user=$(echo "$line" | awk '{print $3}')
            addr=$(echo "$line" | awk '{print $9}')

            local port bind_type
            port="${addr##*:}"

            if [[ "$addr" == 127.0.0.1:* ]] || [[ "$addr" == *"[::1]:"* ]] || [[ "$addr" == "localhost:"* ]]; then
                bind_type="localhost"
            elif [[ "$addr" == "*:"* ]]; then
                bind_type="all_interfaces"
            else
                bind_type="specific"
            fi

            echo "${process}|${pid}|${user}|${addr}|${port}|${bind_type}"
        done
    elif command -v ss &>/dev/null; then
        # Linux fallback
        ss -tlnp 2>/dev/null | tail -n +2 | while read -r line; do
            local addr port process
            addr=$(echo "$line" | awk '{print $4}')
            port="${addr##*:}"
            process=$(echo "$line" | grep -oP 'users:\(\("\K[^"]+' || echo "unknown")

            local bind_type
            if [[ "$addr" == 127.0.0.1:* ]] || [[ "$addr" == "[::1]:*" ]]; then
                bind_type="localhost"
            else
                bind_type="all_interfaces"
            fi

            echo "${process}|-|-|${addr}|${port}|${bind_type}"
        done
    else
        # Last resort
        netstat -an 2>/dev/null | grep LISTEN | while read -r line; do
            local addr port
            addr=$(echo "$line" | awk '{print $4}')
            port="${addr##*.}"
            echo "unknown|-|-|${addr}|${port}|unknown"
        done
    fi
}

# ----------------------------------------------------------------------------
# CHECK PORTS
# ----------------------------------------------------------------------------

is_whitelisted() {
    local port="$1"
    for wp in "${WHITELIST_PORTS[@]:-}"; do
        [[ "$wp" == "$port" ]] && return 0
    done
    return 1
}

check_ports() {
    local mode="${1:-full}"
    local fails=0
    local warns=0

    if [[ "$mode" != "quiet" ]]; then
        echo -e "\n${BOLD}  PORT CHECK${RESET}"
        echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
        echo ""
    fi

    local ports_data
    ports_data="$(get_listening_ports)"

    if [[ -z "$ports_data" ]]; then
        if [[ "$mode" != "quiet" ]]; then
            _pass "No listening ports found"
        fi
        return 0
    fi

    # Check each port
    local seen_ports=""
    while IFS='|' read -r process pid user addr port bind_type; do
        # Skip duplicates (same port, different protocol versions)
        if echo "$seen_ports" | grep -q "|${port}|" 2>/dev/null; then
            continue
        fi
        seen_ports="${seen_ports}|${port}|"

        # Localhost is always OK
        if [[ "$bind_type" == "localhost" ]]; then
            if [[ "$mode" != "quiet" ]]; then
                _pass "Port ${port} (${process}) — localhost only"
            fi
            continue
        fi

        # All interfaces — check whitelist
        if [[ "$bind_type" == "all_interfaces" ]] || [[ "$bind_type" == "specific" ]]; then
            if is_whitelisted "$port"; then
                if [[ "$mode" != "quiet" ]]; then
                    _warn "Port ${port} (${process}) — exposed but whitelisted [PID:${pid}]"
                fi
                warns=$((warns + 1))
            else
                _fail "Port ${port} (${process}) — EXPOSED and NOT whitelisted [PID:${pid}] [${addr}]"
                _log "EXPOSED PORT: ${port} (${process}) PID:${pid} ADDR:${addr}"
                fails=$((fails + 1))
            fi
        fi
    done <<< "$ports_data"

    if [[ "$mode" != "quiet" ]]; then
        echo ""
        if (( fails > 0 )); then
            _fail "${fails} unwhitelisted port(s) exposed to the network"
            echo ""
            _info "To kill a process by PID: kill <PID>"
            _info "To whitelist a port: add it to WHITELIST_PORTS in config/sentinel.conf"
        elif (( warns > 0 )); then
            _warn "${warns} whitelisted port(s) exposed (verify these are intentional)"
        else
            _pass "All listening ports are localhost-only or whitelisted"
        fi
    fi

    # Compare against baseline if it exists
    if [[ -f "$SENTINEL_DIR/baseline_ports.txt" ]] && [[ "$mode" != "quiet" ]]; then
        local new_count=0
        while IFS='|' read -r process pid user addr port bind_type; do
            if ! grep -q ":${port}$\|:${port} " "$SENTINEL_DIR/baseline_ports.txt" 2>/dev/null; then
                if (( new_count == 0 )); then
                    echo ""
                    _info "New since baseline:"
                fi
                _warn "  NEW: port ${port} (${process})"
                new_count=$((new_count + 1))
            fi
        done <<< "$ports_data"
    fi

    return $fails
}

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

case "${1:-full}" in
    full|report|"") check_ports full ;;
    quiet)          check_ports quiet ;;
    *)              check_ports full ;;
esac
