#!/usr/bin/env bash
# ============================================================================
# SELFHEAL — Service watchdog
# ============================================================================
# Monitors services. Restarts them if they die.
# Reads service definitions from sentinel.conf.
#
# Usage:
#   selfheal.sh           — Run watchdog loop (continuous)
#   selfheal.sh once      — Check all services once
#   selfheal.sh status    — Show service status
#   selfheal.sh add NAME CHECK_CMD RESTART_CMD [INTERVAL]
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="${SENTINEL_ROOT}/config/sentinel.conf"

# Defaults
SENTINEL_DIR="${SENTINEL_DIR:-$HOME/.sentinel}"
LOG_FILE="${LOG_FILE:-$SENTINEL_DIR/sentinel.log}"
ALERT_METHOD="${ALERT_METHOD:-terminal,log}"

# Load config
SERVICES=()
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

_pass()  { echo -e "  ${GREEN}[PASS]${RESET}  $*"; }
_warn()  { echo -e "  ${YELLOW}[WARN]${RESET}  $*"; }
_fail()  { echo -e "  ${RED}[FAIL]${RESET}  $*"; }
_info()  { echo -e "  ${BLUE}[INFO]${RESET}  $*"; }

_log() {
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "[$ts] SELFHEAL: $*" >> "$LOG_FILE"
}

_alert() {
    local msg="$*"
    _fail "$msg"
    _log "ALERT: $msg"
    if [[ "$ALERT_METHOD" == *"notify"* ]] && command -v osascript &>/dev/null; then
        osascript -e "display notification \"$msg\" with title \"SENTINEL SELFHEAL\""
    fi
}

# ----------------------------------------------------------------------------
# CHECK ONE SERVICE
# ----------------------------------------------------------------------------

check_service() {
    local name="$1"
    local check_cmd="$2"
    local restart_cmd="$3"

    if eval "$check_cmd" &>/dev/null; then
        _pass "${name}: healthy"
        return 0
    else
        _alert "${name}: DEAD. Attempting restart..."
        _log "Service ${name} failed check. Restarting."

        if eval "$restart_cmd" &>/dev/null; then
            # Wait a moment, then re-check
            sleep 3
            if eval "$check_cmd" &>/dev/null; then
                _pass "${name}: restarted successfully"
                _log "Service ${name} restarted successfully"
                return 0
            else
                _fail "${name}: restart FAILED. Service still down."
                _log "Service ${name} restart FAILED"
                return 1
            fi
        else
            _fail "${name}: restart command failed"
            _log "Service ${name} restart command failed"
            return 1
        fi
    fi
}

# ----------------------------------------------------------------------------
# CHECK ALL SERVICES
# ----------------------------------------------------------------------------

check_all() {
    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        _warn "No services configured. Edit config/sentinel.conf to add services."
        echo ""
        _info "Example format in sentinel.conf:"
        echo '    SERVICES=('
        echo '        "nginx|curl -sf http://localhost:80 > /dev/null|sudo nginx -s reload|60"'
        echo '        "ollama|curl -sf http://localhost:11434 > /dev/null|ollama serve &|60"'
        echo '    )'
        return 0
    fi

    local failures=0
    for entry in "${SERVICES[@]}"; do
        IFS='|' read -r name check_cmd restart_cmd interval <<< "$entry"
        if ! check_service "$name" "$check_cmd" "$restart_cmd"; then
            failures=$((failures + 1))
        fi
    done

    return $failures
}

# ----------------------------------------------------------------------------
# WATCHDOG LOOP
# ----------------------------------------------------------------------------

watchdog_loop() {
    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        check_all  # This will print the "no services" message
        return
    fi

    echo -e "\n${BOLD}  SELFHEAL — Service Watchdog${RESET}"
    echo -e "  ${DIM}Monitoring ${#SERVICES[@]} service(s). Press Ctrl+C to stop.${RESET}"
    echo ""

    trap 'echo -e "\n  Watchdog stopped."; exit 0' INT

    while true; do
        local min_interval=999999

        for entry in "${SERVICES[@]}"; do
            IFS='|' read -r name check_cmd restart_cmd interval <<< "$entry"
            interval="${interval:-60}"

            if ! eval "$check_cmd" &>/dev/null; then
                _alert "${name}: DEAD. Restarting..."
                eval "$restart_cmd" &>/dev/null || true
                sleep 2
                if eval "$check_cmd" &>/dev/null; then
                    _pass "${name}: recovered"
                    _log "Service ${name} auto-recovered"
                else
                    _fail "${name}: still dead after restart"
                    _log "Service ${name} auto-recovery FAILED"
                fi
            fi

            if (( interval < min_interval )); then
                min_interval=$interval
            fi
        done

        local ts
        ts="$(date +%H:%M:%S)"
        echo -ne "  ${DIM}${ts} All services checked. Next check in ${min_interval}s${RESET}\r"
        sleep "$min_interval"
    done
}

# ----------------------------------------------------------------------------
# STATUS
# ----------------------------------------------------------------------------

show_status() {
    echo -e "\n${BOLD}  SERVICE STATUS${RESET}"
    echo ""

    if [[ ${#SERVICES[@]} -eq 0 ]]; then
        _warn "No services configured"
        return
    fi

    for entry in "${SERVICES[@]}"; do
        IFS='|' read -r name check_cmd restart_cmd interval <<< "$entry"
        if eval "$check_cmd" &>/dev/null; then
            _pass "${name}: UP"
        else
            _fail "${name}: DOWN"
        fi
    done
    echo ""
}

# ----------------------------------------------------------------------------
# ADD SERVICE (appends to config)
# ----------------------------------------------------------------------------

add_service() {
    local name="${1:-}"
    local check_cmd="${2:-}"
    local restart_cmd="${3:-}"
    local interval="${4:-60}"

    if [[ -z "$name" || -z "$check_cmd" || -z "$restart_cmd" ]]; then
        echo "Usage: selfheal.sh add NAME CHECK_CMD RESTART_CMD [INTERVAL]"
        echo ""
        echo "Example:"
        echo "  selfheal.sh add nginx 'curl -sf http://localhost:80' 'sudo nginx -s reload' 60"
        return 1
    fi

    local entry="    \"${name}|${check_cmd}|${restart_cmd}|${interval}\""

    # Check if SERVICES array exists in config
    if grep -q "^SERVICES=(" "$CONF_FILE" 2>/dev/null; then
        # Insert before the closing paren
        if [[ "$(uname)" == "Darwin" ]]; then
            sed -i '' "/^SERVICES=($/,/^)$/ { /^)$/i\\
${entry}
}" "$CONF_FILE"
        else
            sed -i "/^SERVICES=($/,/^)$/ { /^)$/i\\${entry}" "$CONF_FILE"
        fi
        _pass "Added service: ${name}"
    else
        echo "" >> "$CONF_FILE"
        echo "SERVICES=(" >> "$CONF_FILE"
        echo "$entry" >> "$CONF_FILE"
        echo ")" >> "$CONF_FILE"
        _pass "Added service: ${name} (created SERVICES section)"
    fi
}

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

case "${1:-loop}" in
    loop|"")   watchdog_loop ;;
    once)      check_all ;;
    status)    show_status ;;
    add)       shift; add_service "$@" ;;
    *)
        echo "Usage: selfheal.sh {loop|once|status|add}"
        exit 1
        ;;
esac
