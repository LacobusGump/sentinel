#!/usr/bin/env bash
# ============================================================================
# SENTINEL — Your computer is open right now and you don't know it.
# ============================================================================
# Free. Local. No cloud. No subscription. No data leaves your machine.
#
# Usage:
#   sentinel              — Run all checks (full report)
#   sentinel audit        — Full security audit
#   sentinel watch        — Continuous monitoring (Ctrl+C to stop)
#   sentinel tripwire     — Start honeypot monitoring
#   sentinel ports        — Check open ports against whitelist
#   sentinel connections  — Snapshot active connections
#   sentinel firewall     — Check/fix firewall settings
#   sentinel selfheal     — Start service watchdog
#   sentinel status       — Quick status check
#   sentinel baseline     — Save current state as baseline
#   sentinel deploy       — Install decoys + LaunchAgent
# ============================================================================

set -euo pipefail

# Where am I?
SENTINEL_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="$SENTINEL_ROOT/modules"
CONFIG_DIR="$SENTINEL_ROOT/config"
CONF_FILE="$CONFIG_DIR/sentinel.conf"

# Defaults (overridden by sentinel.conf)
SENTINEL_DIR="${HOME}/.sentinel"
LOG_FILE="${SENTINEL_DIR}/sentinel.log"
ALERT_METHOD="terminal,log"
MAX_LOG_SIZE=5242880

# Load config
if [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=/dev/null
    source "$CONF_FILE"
fi

# Ensure data directory (700 = owner only — security-sensitive data)
mkdir -p "$SENTINEL_DIR"
chmod 700 "$SENTINEL_DIR" 2>/dev/null || true

# ----------------------------------------------------------------------------
# COLORS & OUTPUT
# ----------------------------------------------------------------------------

RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

# Detect color support
if [[ ! -t 1 ]]; then
    RED="" YELLOW="" GREEN="" BLUE="" BOLD="" DIM="" RESET=""
fi

pass()  { echo -e "  ${GREEN}[PASS]${RESET}  $*"; }
warn()  { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }
fail()  { echo -e "  ${RED}[FAIL]${RESET}  $*"; }
info()  { echo -e "  ${BLUE}[INFO]${RESET}  $*"; }
header(){ echo -e "\n${BOLD}$*${RESET}"; echo -e "${DIM}$(printf '%.0s-' {1..60})${RESET}"; }

# Logging
log_msg() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[$ts] $*" >> "$LOG_FILE"
}

# Alert dispatcher
alert() {
    local level="$1"
    shift
    local msg="$*"

    if [[ "$ALERT_METHOD" == *"terminal"* ]]; then
        case "$level" in
            FAIL) fail "$msg" ;;
            WARN) warn "$msg" ;;
            PASS) pass "$msg" ;;
            *)    info "$msg" ;;
        esac
    fi

    if [[ "$ALERT_METHOD" == *"log"* ]]; then
        log_msg "[$level] $msg"
    fi

    if [[ "$ALERT_METHOD" == *"notify"* ]]; then
        if command -v osascript &>/dev/null; then
            # Escape quotes to prevent AppleScript injection
            local safe_msg="${msg//\"/\\\"}"
            osascript -e "display notification \"${safe_msg}\" with title \"Sentinel [${level}]\""
        fi
    fi
}

# Log rotation
rotate_log() {
    if [[ -f "$LOG_FILE" ]]; then
        local size
        size=$(wc -c < "$LOG_FILE" 2>/dev/null || echo 0)
        if (( size > MAX_LOG_SIZE )); then
            mv "$LOG_FILE" "${LOG_FILE}.old"
            log_msg "Log rotated (was ${size} bytes)"
        fi
    fi
}

# Platform detection
detect_platform() {
    case "$(uname -s)" in
        Darwin) echo "macos" ;;
        Linux)  echo "linux" ;;
        *)      echo "unknown" ;;
    esac
}

PLATFORM="$(detect_platform)"
export PLATFORM SENTINEL_DIR LOG_FILE ALERT_METHOD SENTINEL_ROOT MODULES_DIR CONFIG_DIR CONF_FILE
export RED YELLOW GREEN BLUE BOLD DIM RESET

# Export functions for subshells
export -f pass warn fail info header log_msg alert

# ----------------------------------------------------------------------------
# COMMANDS
# ----------------------------------------------------------------------------

cmd_report() {
    local start_time
    start_time=$(date +%s)
    local fails=0 warns=0 passes=0

    echo ""
    echo -e "${BOLD}  SENTINEL SECURITY REPORT${RESET}"
    echo -e "  ${DIM}$(date)${RESET}"
    echo -e "  ${DIM}$(uname -srm)${RESET}"
    echo ""

    # Run each module and count results
    # We capture output and parse for [FAIL] [WARN] [PASS]
    local output
    for module in firewall portcheck connwatch immune audit; do
        if [[ -f "$MODULES_DIR/${module}.sh" ]]; then
            output="$(bash "$MODULES_DIR/${module}.sh" report 2>&1)" || true
            echo "$output"
            fails=$((fails + $(echo "$output" | grep -c '\[FAIL\]' || true)))
            warns=$((warns + $(echo "$output" | grep -c '\[WARN\]' || true)))
            passes=$((passes + $(echo "$output" | grep -c '\[PASS\]' || true)))
        fi
    done

    # Summary
    local elapsed=$(( $(date +%s) - start_time ))
    echo ""
    header "SUMMARY"
    echo ""
    if (( fails > 0 )); then
        fail "${fails} critical issues found"
    fi
    if (( warns > 0 )); then
        warn "${warns} warnings"
    fi
    if (( passes > 0 )); then
        pass "${passes} checks passed"
    fi
    echo ""
    info "Completed in ${elapsed}s. Full log: ${LOG_FILE}"
    echo ""

    log_msg "Report complete: ${fails} fails, ${warns} warns, ${passes} passes"
    return $fails
}

cmd_watch() {
    echo ""
    echo -e "${BOLD}  SENTINEL — Continuous Monitoring${RESET}"
    echo -e "  ${DIM}Press Ctrl+C to stop${RESET}"
    echo ""

    # Save baseline if none exists
    if [[ ! -f "$SENTINEL_DIR/baseline_ports.txt" ]]; then
        info "No baseline found. Creating one now..."
        cmd_baseline
        echo ""
    fi

    local cycle=0
    trap 'echo -e "\n\n  Sentinel stopped after ${cycle} cycles.\n"; exit 0' INT

    while true; do
        cycle=$((cycle + 1))
        local ts
        ts="$(date +%H:%M:%S)"

        # Port check
        bash "$MODULES_DIR/portcheck.sh" quiet

        # Connection check
        bash "$MODULES_DIR/connwatch.sh" quiet

        # Heartbeat
        local port_count conn_count
        port_count=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
        conn_count=$(netstat -an 2>/dev/null | grep -c ESTABLISHED || true)
        echo -ne "  ${DIM}${ts} cycle:${cycle} ports:${port_count} conns:${conn_count}${RESET}\r"

        rotate_log
        sleep "${CONN_INTERVAL:-300}"
    done
}

cmd_baseline() {
    header "SAVING BASELINE"

    # Ports baseline
    lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | awk '{print $1, $9}' | sort > "$SENTINEL_DIR/baseline_ports.txt"
    local port_count
    port_count=$(wc -l < "$SENTINEL_DIR/baseline_ports.txt" | tr -d ' ')
    pass "Saved ${port_count} listening ports"

    # Connections baseline
    netstat -an 2>/dev/null | grep ESTABLISHED | awk '{print $5}' | sort -u > "$SENTINEL_DIR/baseline_connections.txt"
    local conn_count
    conn_count=$(wc -l < "$SENTINEL_DIR/baseline_connections.txt" | tr -d ' ')
    pass "Saved ${conn_count} unique remote endpoints"

    # LaunchAgents baseline (macOS)
    if [[ "$PLATFORM" == "macos" ]]; then
        local agents_file="$SENTINEL_DIR/baseline_agents.txt"
        : > "$agents_file"
        for d in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
            if [[ -d "$d" ]]; then
                ls "$d"/*.plist 2>/dev/null >> "$agents_file" || true
            fi
        done
        local agent_count
        agent_count=$(wc -l < "$agents_file" | tr -d ' ')
        pass "Saved ${agent_count} LaunchAgents/Daemons"
    fi

    # Process names baseline
    ps -eo comm= 2>/dev/null | sort -u > "$SENTINEL_DIR/baseline_processes.txt"
    local proc_count
    proc_count=$(wc -l < "$SENTINEL_DIR/baseline_processes.txt" | tr -d ' ')
    pass "Saved ${proc_count} unique process names"

    log_msg "Baseline saved: ${port_count} ports, ${conn_count} connections, ${proc_count} processes"
    info "Baseline saved to ${SENTINEL_DIR}/"
}

cmd_deploy() {
    header "DEPLOYING SENTINEL"

    # Create decoy files
    bash "$MODULES_DIR/tripwire.sh" deploy
    echo ""

    # Install LaunchAgent (macOS only)
    if [[ "$PLATFORM" == "macos" ]]; then
        local plist_src="$SENTINEL_ROOT/.launchd/com.sentinel.plist"
        local plist_dst="$HOME/Library/LaunchAgents/com.sentinel.plist"

        if [[ -f "$plist_src" ]]; then
            # Update paths in plist
            sed "s|__SENTINEL_ROOT__|${SENTINEL_ROOT}|g" "$plist_src" > "$plist_dst"
            info "LaunchAgent installed at ${plist_dst}"
            info "To activate: launchctl load ${plist_dst}"
            info "To deactivate: launchctl unload ${plist_dst}"
        fi
    else
        info "Linux detected. Add to crontab:"
        info "  */5 * * * * ${SENTINEL_ROOT}/sentinel.sh watch >> ${LOG_FILE} 2>&1"
    fi

    echo ""
    cmd_baseline
    echo ""
    pass "Sentinel deployed. Run 'sentinel watch' to start continuous monitoring."
}

cmd_status() {
    echo ""
    echo -e "${BOLD}  SENTINEL STATUS${RESET}"
    echo ""

    # Platform
    info "Platform: ${PLATFORM} ($(uname -srm))"

    # Listening ports
    local port_count exposed_count
    port_count=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | wc -l | tr -d ' ')
    exposed_count=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | grep -v '127\.0\.0\.1\|::1\|\*:' | wc -l | tr -d ' ')
    # Actually count non-localhost
    exposed_count=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | grep '\*:' | wc -l | tr -d ' ')
    info "Listening ports: ${port_count} (${exposed_count} on all interfaces)"

    # Connections
    local conn_count
    conn_count=$(netstat -an 2>/dev/null | grep -c ESTABLISHED || true)
    info "Active connections: ${conn_count}"

    # Baseline
    if [[ -f "$SENTINEL_DIR/baseline_ports.txt" ]]; then
        local bl_date
        bl_date=$(stat -f %Sm -t "%Y-%m-%d %H:%M" "$SENTINEL_DIR/baseline_ports.txt" 2>/dev/null || stat -c %y "$SENTINEL_DIR/baseline_ports.txt" 2>/dev/null | cut -d. -f1)
        pass "Baseline: ${bl_date}"
    else
        warn "No baseline saved. Run: sentinel baseline"
    fi

    # Decoys
    local decoy_count=0
    if [[ -f "$SENTINEL_DIR/decoy_manifest.txt" ]]; then
        decoy_count=$(wc -l < "$SENTINEL_DIR/decoy_manifest.txt" | tr -d ' ')
    fi
    if (( decoy_count > 0 )); then
        pass "Decoys deployed: ${decoy_count} files"
    else
        warn "No decoys deployed. Run: sentinel deploy"
    fi

    # Log size
    if [[ -f "$LOG_FILE" ]]; then
        local log_size
        log_size=$(wc -c < "$LOG_FILE" | tr -d ' ')
        local log_kb=$((log_size / 1024))
        info "Log size: ${log_kb}KB (${LOG_FILE})"
    fi

    echo ""
}

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

main() {
    local cmd="${1:-report}"

    case "$cmd" in
        report|"")     cmd_report ;;
        audit)         bash "$MODULES_DIR/audit.sh" ;;
        watch)         cmd_watch ;;
        tripwire)      bash "$MODULES_DIR/tripwire.sh" "${2:-watch}" ;;
        ports)         bash "$MODULES_DIR/portcheck.sh" ;;
        connections)   bash "$MODULES_DIR/connwatch.sh" ;;
        firewall)      bash "$MODULES_DIR/firewall.sh" ;;
        selfheal)      bash "$MODULES_DIR/selfheal.sh" ;;
        immune)        bash "$MODULES_DIR/immune.sh" "${2:-scan}" ;;
        status)        cmd_status ;;
        baseline)      cmd_baseline ;;
        deploy)        cmd_deploy ;;
        help|-h|--help)
            head -n 18 "${BASH_SOURCE[0]}" | tail -n +3 | sed 's/^# //' | sed 's/^#//'
            ;;
        *)
            echo "Unknown command: $cmd"
            echo "Run 'sentinel help' for usage."
            exit 1
            ;;
    esac
}

main "$@"
