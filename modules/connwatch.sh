#!/usr/bin/env bash
# ============================================================================
# CONNWATCH — Monitor active network connections
# ============================================================================
# Snapshots connections. Flags new external IPs, known-bad ports,
# unusual volume. Builds a baseline over time.
#
# Usage:
#   connwatch.sh          — Full report
#   connwatch.sh quiet    — Alerts only (for watch mode)
#   connwatch.sh report   — Same as default
#   connwatch.sh history  — Show connection history
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="${SENTINEL_ROOT}/config/sentinel.conf"

# Defaults
SENTINEL_DIR="${SENTINEL_DIR:-$HOME/.sentinel}"
LOG_FILE="${LOG_FILE:-$SENTINEL_DIR/sentinel.log}"
ALERT_METHOD="${ALERT_METHOD:-terminal,log}"
BAD_PORTS=()
CONN_TRUSTED_PROCESSES=()

# Load config
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
fi

mkdir -p "$SENTINEL_DIR"

KNOWN_IPS_FILE="$SENTINEL_DIR/known_ips.txt"
CONN_HISTORY="$SENTINEL_DIR/conn_history.log"

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
    echo "[$ts] CONNWATCH: $*" >> "$LOG_FILE"
}

# ----------------------------------------------------------------------------
# GET CONNECTIONS
# ----------------------------------------------------------------------------

get_connections() {
    # Returns: PROCESS|PID|LOCAL_ADDR|REMOTE_ADDR|REMOTE_PORT|STATE
    if command -v lsof &>/dev/null; then
        lsof -iTCP -P -n 2>/dev/null | tail -n +2 | grep -i 'ESTABLISHED\|SYN_SENT\|CLOSE_WAIT' | while read -r line; do
            local process pid local_addr remote_full state
            process=$(echo "$line" | awk '{print $1}')
            pid=$(echo "$line" | awk '{print $2}')

            # The connection info is in the last columns
            # Format: COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME
            local name_field state_field
            name_field=$(echo "$line" | awk '{print $9}')
            state_field=$(echo "$line" | awk '{print $10}')

            # Parse local->remote from name field
            if [[ "$name_field" == *"->"* ]]; then
                local_addr="${name_field%%->*}"
                local remote_addr="${name_field##*->}"
                local remote_port="${remote_addr##*:}"
                echo "${process}|${pid}|${local_addr}|${remote_addr}|${remote_port}|${state_field}"
            fi
        done
    else
        # Fallback: netstat
        netstat -an 2>/dev/null | grep ESTABLISHED | while read -r line; do
            local local_addr remote_addr remote_port
            local_addr=$(echo "$line" | awk '{print $4}')
            remote_addr=$(echo "$line" | awk '{print $5}')
            remote_port="${remote_addr##*.}"
            echo "unknown|-|${local_addr}|${remote_addr}|${remote_port}|ESTABLISHED"
        done
    fi
}

# ----------------------------------------------------------------------------
# CHECK FOR BAD PORTS
# ----------------------------------------------------------------------------

is_bad_port() {
    local port="$1"
    for bp in "${BAD_PORTS[@]:-}"; do
        [[ "$bp" == "$port" ]] && return 0
    done
    return 1
}

is_trusted_process() {
    local process="$1"
    for tp in "${CONN_TRUSTED_PROCESSES[@]:-}"; do
        # Case-insensitive partial match
        if echo "$process" | grep -qi "$tp" 2>/dev/null; then
            return 0
        fi
    done
    return 1
}

# ----------------------------------------------------------------------------
# EXTRACT REMOTE IP (strip port)
# ----------------------------------------------------------------------------

extract_ip() {
    local addr="$1"
    # Handle IPv4: a.b.c.d:port -> a.b.c.d
    # Handle IPv6: [::1]:port -> ::1
    if [[ "$addr" == "["*"]:"* ]]; then
        echo "${addr}" | sed 's/\[//;s/\]:.*//'
    else
        echo "${addr%:*}"
    fi
}

# ----------------------------------------------------------------------------
# CHECK CONNECTIONS
# ----------------------------------------------------------------------------

check_connections() {
    local mode="${1:-full}"
    local fails=0
    local warns=0
    local new_ips=0

    if [[ "$mode" != "quiet" ]]; then
        echo -e "\n${BOLD}  CONNECTION MONITOR${RESET}"
        echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
        echo ""
    fi

    # Load known IPs
    touch "$KNOWN_IPS_FILE"
    local known_ips
    known_ips="$(cat "$KNOWN_IPS_FILE" 2>/dev/null)"

    local conn_data
    conn_data="$(get_connections)"
    local total_conns
    total_conns=$(echo "$conn_data" | grep -c '.' || true)

    if [[ -z "$conn_data" ]] || (( total_conns == 0 )); then
        if [[ "$mode" != "quiet" ]]; then
            _pass "No active external connections"
        fi
        return 0
    fi

    # Record timestamp + count
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "${ts} connections:${total_conns}" >> "$CONN_HISTORY"

    # Analyze each connection
    local current_ips=""
    local bad_port_hits=""
    local new_ip_list=""

    while IFS='|' read -r process pid local_addr remote_addr remote_port state; do
        [[ -z "$remote_addr" ]] && continue

        local remote_ip
        remote_ip="$(extract_ip "$remote_addr")"

        # Skip localhost / link-local
        if [[ "$remote_ip" == "127."* ]] || [[ "$remote_ip" == "::1" ]] || [[ "$remote_ip" == "fe80:"* ]]; then
            continue
        fi

        current_ips="${current_ips}${remote_ip}\n"

        # Check for known-bad ports
        if is_bad_port "$remote_port"; then
            _fail "BAD PORT: ${process} (PID:${pid}) -> ${remote_addr} (port ${remote_port} is suspicious)"
            _log "BAD PORT CONNECTION: ${process} PID:${pid} -> ${remote_addr}"
            fails=$((fails + 1))
            bad_port_hits="${bad_port_hits}${remote_addr}\n"
            continue
        fi

        # Check for new IPs (only flag untrusted processes)
        if ! echo "$known_ips" | grep -qF "$remote_ip" 2>/dev/null; then
            if ! is_trusted_process "$process"; then
                if [[ "$mode" != "quiet" ]]; then
                    _warn "NEW IP: ${process} (PID:${pid}) -> ${remote_ip}:${remote_port}"
                fi
                warns=$((warns + 1))
                new_ip_list="${new_ip_list}${remote_ip}\n"
            fi
            new_ips=$((new_ips + 1))
        fi
    done <<< "$conn_data"

    # Update known IPs (merge new ones in)
    if [[ -n "$current_ips" ]]; then
        {
            cat "$KNOWN_IPS_FILE" 2>/dev/null
            echo -e "$current_ips"
        } | sort -u | grep -v '^$' > "${KNOWN_IPS_FILE}.tmp"
        mv "${KNOWN_IPS_FILE}.tmp" "$KNOWN_IPS_FILE"
    fi

    # Connection volume check (compare to baseline)
    if [[ -f "$SENTINEL_DIR/baseline_connections.txt" ]]; then
        local baseline_count
        baseline_count=$(wc -l < "$SENTINEL_DIR/baseline_connections.txt" | tr -d ' ')
        if (( total_conns > baseline_count * 3 )) && (( baseline_count > 5 )); then
            _fail "CONNECTION SPIKE: ${total_conns} active (baseline: ~${baseline_count})"
            _log "CONNECTION SPIKE: ${total_conns} vs baseline ${baseline_count}"
            fails=$((fails + 1))
        fi
    fi

    if [[ "$mode" != "quiet" ]]; then
        # Summary
        echo ""
        _info "Total connections: ${total_conns}"

        # Top destinations
        if (( total_conns > 0 )); then
            _info "Top remote endpoints:"
            echo "$conn_data" | while IFS='|' read -r process pid local_addr remote_addr remote_port state; do
                echo "$remote_addr"
            done | sort | uniq -c | sort -rn | head -5 | while read -r count addr; do
                echo -e "    ${DIM}${count}x${RESET} ${addr}"
            done
        fi

        # Known IPs count
        local known_count
        known_count=$(wc -l < "$KNOWN_IPS_FILE" | tr -d ' ')
        _info "Known IPs in database: ${known_count}"

        echo ""
        if (( fails > 0 )); then
            _fail "${fails} suspicious connection(s) found"
        elif (( warns > 0 )); then
            _warn "${warns} new IP(s) from untrusted processes"
        else
            _pass "All connections look normal"
        fi
    fi

    return $fails
}

# ----------------------------------------------------------------------------
# HISTORY
# ----------------------------------------------------------------------------

show_history() {
    echo -e "\n${BOLD}  CONNECTION HISTORY${RESET}"
    echo ""

    if [[ ! -f "$CONN_HISTORY" ]]; then
        _info "No history yet. Run connwatch a few times."
        return
    fi

    tail -20 "$CONN_HISTORY" | while read -r line; do
        echo "  $line"
    done
    echo ""

    local known_count
    known_count=$(wc -l < "$KNOWN_IPS_FILE" 2>/dev/null | tr -d ' ')
    _info "Known IPs: ${known_count}"
    _info "History file: ${CONN_HISTORY}"
}

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

case "${1:-full}" in
    full|report|"") check_connections full ;;
    quiet)          check_connections quiet ;;
    history)        show_history ;;
    *)              check_connections full ;;
esac
