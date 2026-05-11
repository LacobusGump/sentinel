#!/usr/bin/env bash
# ============================================================================
# FIREWALL — Check and fix firewall settings
# ============================================================================
# macOS: Uses socketfilterfw
# Linux: Uses ufw or iptables
#
# Usage:
#   firewall.sh           — Check firewall status
#   firewall.sh report    — Same as default
#   firewall.sh fix       — Attempt to fix issues (may need sudo)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="${SENTINEL_ROOT}/config/sentinel.conf"

# Defaults
SENTINEL_DIR="${SENTINEL_DIR:-$HOME/.sentinel}"
LOG_FILE="${LOG_FILE:-$SENTINEL_DIR/sentinel.log}"
PLATFORM="${PLATFORM:-$(uname -s | tr '[:upper:]' '[:lower:]')}"

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
    echo "[$ts] FIREWALL: $*" >> "$LOG_FILE"
}

# ============================================================================
# macOS FIREWALL
# ============================================================================

SOCKETFW="/usr/libexec/ApplicationFirewall/socketfilterfw"

check_macos_firewall() {
    local mode="${1:-report}"

    echo -e "\n${BOLD}  FIREWALL CHECK (macOS)${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    local fails=0

    # 1. Application Firewall (socketfilterfw)
    if [[ -x "$SOCKETFW" ]]; then
        local fw_status
        fw_status=$("$SOCKETFW" --getglobalstate 2>/dev/null || true)

        if echo "$fw_status" | grep -qi "enabled"; then
            _pass "Application Firewall: ENABLED"
        else
            _fail "Application Firewall: DISABLED"
            _log "Firewall is DISABLED"
            fails=$((fails + 1))

            if [[ "$mode" == "fix" ]]; then
                _info "Attempting to enable firewall (needs sudo)..."
                if sudo "$SOCKETFW" --setglobalstate on 2>/dev/null; then
                    _pass "Firewall ENABLED successfully"
                    _log "Firewall enabled by sentinel"
                else
                    _fail "Could not enable firewall. Run: sudo $SOCKETFW --setglobalstate on"
                fi
            else
                _info "Fix: sudo $SOCKETFW --setglobalstate on"
            fi
        fi

        # 2. Stealth Mode
        local stealth_status
        stealth_status=$("$SOCKETFW" --getstealthmode 2>/dev/null || true)

        if echo "$stealth_status" | grep -qi "enabled"; then
            _pass "Stealth Mode: ENABLED (invisible to port scans)"
        else
            _warn "Stealth Mode: DISABLED (machine responds to pings/scans)"
            fails=$((fails + 1))

            if [[ "$mode" == "fix" ]]; then
                _info "Attempting to enable stealth mode (needs sudo)..."
                if sudo "$SOCKETFW" --setstealthmode on 2>/dev/null; then
                    _pass "Stealth Mode ENABLED successfully"
                    _log "Stealth mode enabled by sentinel"
                else
                    _fail "Could not enable stealth mode. Run: sudo $SOCKETFW --setstealthmode on"
                fi
            else
                _info "Fix: sudo $SOCKETFW --setstealthmode on"
            fi
        fi

        # 3. Block all incoming
        local block_status
        block_status=$("$SOCKETFW" --getblockall 2>/dev/null || true)

        if echo "$block_status" | grep -qi "enabled"; then
            _pass "Block All Incoming: ENABLED (strict mode)"
        else
            _info "Block All Incoming: DISABLED (allows signed apps — normal for most users)"
        fi

        # 4. Signed apps auto-allow
        local allow_signed
        allow_signed=$("$SOCKETFW" --getallowsigned 2>/dev/null || true)

        if echo "$allow_signed" | grep -qi "enabled"; then
            _info "Auto-allow signed apps: ENABLED (standard)"
        else
            _pass "Auto-allow signed apps: DISABLED (stricter — manual approval needed)"
        fi

        # 5. Logging
        local log_status
        log_status=$("$SOCKETFW" --getloggingmode 2>/dev/null || true)

        if echo "$log_status" | grep -qi "throttled\|enabled\|detail"; then
            _pass "Firewall logging: ON"
        else
            _warn "Firewall logging: OFF"
            if [[ "$mode" == "fix" ]]; then
                sudo "$SOCKETFW" --setloggingmode on 2>/dev/null && _pass "Logging ENABLED" || true
            else
                _info "Fix: sudo $SOCKETFW --setloggingmode on"
            fi
        fi

    else
        _warn "socketfilterfw not found at expected path"
        _info "Your macOS version may use a different firewall path"
    fi

    echo ""

    # 6. SIP (System Integrity Protection)
    if command -v csrutil &>/dev/null; then
        local sip_status
        sip_status=$(csrutil status 2>/dev/null || true)

        if echo "$sip_status" | grep -qi "enabled"; then
            _pass "System Integrity Protection (SIP): ENABLED"
        else
            _fail "System Integrity Protection (SIP): DISABLED"
            _log "SIP is DISABLED — system files are not protected"
            _info "SIP can only be re-enabled from Recovery Mode"
            fails=$((fails + 1))
        fi
    fi

    # 7. Gatekeeper
    if command -v spctl &>/dev/null; then
        local gk_status
        gk_status=$(spctl --status 2>/dev/null || true)

        if echo "$gk_status" | grep -qi "enabled"; then
            _pass "Gatekeeper: ENABLED (blocks unsigned apps)"
        else
            _warn "Gatekeeper: DISABLED"
            _info "Fix: sudo spctl --master-enable"
            fails=$((fails + 1))
        fi
    fi

    # 8. FileVault
    if command -v fdesetup &>/dev/null; then
        local fv_status
        fv_status=$(fdesetup status 2>/dev/null || true)

        if echo "$fv_status" | grep -qi "on"; then
            _pass "FileVault (disk encryption): ON"
        else
            _fail "FileVault (disk encryption): OFF"
            _log "FileVault is OFF — disk is not encrypted"
            _info "Fix: System Settings > Privacy & Security > FileVault > Turn On"
            fails=$((fails + 1))
        fi
    fi

    # 9. Remote Login (SSH)
    local ssh_status
    if command -v systemsetup &>/dev/null; then
        # Avoid sudo hang: check if we have cached sudo, if not fall back to lsof
        if sudo -n true 2>/dev/null; then
            ssh_status=$(sudo systemsetup -getremotelogin 2>/dev/null || echo "unknown")
        else
            # No sudo cached — check via lsof instead
            if lsof -iTCP:22 -sTCP:LISTEN -P -n &>/dev/null 2>&1; then
                ssh_status="On"
            else
                ssh_status="Off"
            fi
        fi
    else
        # Check if sshd is listening
        if lsof -iTCP:22 -sTCP:LISTEN -P -n &>/dev/null; then
            ssh_status="On"
        else
            ssh_status="Off"
        fi
    fi

    if echo "$ssh_status" | grep -qi "off"; then
        _pass "Remote Login (SSH): DISABLED"
    elif echo "$ssh_status" | grep -qi "on"; then
        _warn "Remote Login (SSH): ENABLED"
        _info "Disable if not needed: System Settings > General > Sharing > Remote Login"
    fi

    echo ""
    return $fails
}

# ============================================================================
# LINUX FIREWALL
# ============================================================================

check_linux_firewall() {
    local mode="${1:-report}"

    echo -e "\n${BOLD}  FIREWALL CHECK (Linux)${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    local fails=0

    # 1. UFW
    if command -v ufw &>/dev/null; then
        local ufw_status
        ufw_status=$(sudo ufw status 2>/dev/null || ufw status 2>/dev/null || echo "unknown")

        if echo "$ufw_status" | grep -qi "active"; then
            _pass "UFW Firewall: ACTIVE"

            # Show rules summary
            _info "UFW Rules:"
            sudo ufw status numbered 2>/dev/null | head -20 | while read -r line; do
                echo "    $line"
            done
        elif echo "$ufw_status" | grep -qi "inactive"; then
            _fail "UFW Firewall: INACTIVE"
            fails=$((fails + 1))

            if [[ "$mode" == "fix" ]]; then
                _info "Enabling UFW..."
                if sudo ufw --force enable 2>/dev/null; then
                    _pass "UFW ENABLED"
                    _log "UFW enabled by sentinel"
                else
                    _fail "Could not enable UFW"
                fi
            else
                _info "Fix: sudo ufw enable"
            fi
        else
            _warn "UFW status unknown"
        fi
    fi

    # 2. iptables fallback
    if command -v iptables &>/dev/null && ! command -v ufw &>/dev/null; then
        local rule_count
        rule_count=$(sudo iptables -L -n 2>/dev/null | grep -c -v '^$\|^Chain\|^target' || true)

        if (( rule_count > 0 )); then
            _pass "iptables: ${rule_count} rules active"
        else
            _warn "iptables: no rules configured"
            _info "Consider installing ufw: sudo apt install ufw && sudo ufw enable"
            fails=$((fails + 1))
        fi
    fi

    # 3. SSH
    if systemctl is-active sshd &>/dev/null 2>&1 || systemctl is-active ssh &>/dev/null 2>&1; then
        _warn "SSH daemon: RUNNING"
        _info "Disable if not needed: sudo systemctl disable --now sshd"
    else
        _pass "SSH daemon: NOT RUNNING"
    fi

    # 4. Disk encryption
    if command -v lsblk &>/dev/null; then
        if lsblk -o TYPE 2>/dev/null | grep -q "crypt"; then
            _pass "Disk encryption: DETECTED (LUKS)"
        else
            _warn "Disk encryption: NOT DETECTED"
            _info "Consider LUKS full-disk encryption"
        fi
    fi

    echo ""
    return $fails
}

# ============================================================================
# MAIN
# ============================================================================

check_firewall() {
    local mode="${1:-report}"

    case "$(uname -s)" in
        Darwin) check_macos_firewall "$mode" ;;
        Linux)  check_linux_firewall "$mode" ;;
        *)
            _warn "Unknown platform: $(uname -s)"
            _info "Firewall check not available on this platform"
            ;;
    esac
}

case "${1:-report}" in
    report|"") check_firewall report ;;
    fix)       check_firewall fix ;;
    *)         check_firewall report ;;
esac
