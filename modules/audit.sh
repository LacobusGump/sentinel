#!/usr/bin/env bash
# ============================================================================
# AUDIT — Full security audit
# ============================================================================
# The sweep. Checks everything we wish we'd checked before port 8080
# sat open for 20 days.
#
# Usage:
#   audit.sh              — Full audit
#   audit.sh report       — Same (for sentinel.sh integration)
#   audit.sh quick        — Skip slow scans
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="${SENTINEL_ROOT}/config/sentinel.conf"

# Defaults
SENTINEL_DIR="${SENTINEL_DIR:-$HOME/.sentinel}"
LOG_FILE="${LOG_FILE:-$SENTINEL_DIR/sentinel.log}"
PLATFORM="${PLATFORM:-$(uname -s | tr '[:upper:]' '[:lower:]')}"
AUDIT_SCAN_DIRS=()
AUDIT_SENSITIVE_PATTERNS=()
AUDIT_CODE_DIRS=()
AUDIT_STALE_DAYS="${AUDIT_STALE_DAYS:-7}"

# Load config
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
fi

# Defaults if not set in config
if [[ ${#AUDIT_SCAN_DIRS[@]} -eq 0 ]]; then
    AUDIT_SCAN_DIRS=("$HOME/Downloads" "$HOME/Desktop" "/tmp")
fi
if [[ ${#AUDIT_SENSITIVE_PATTERNS[@]} -eq 0 ]]; then
    AUDIT_SENSITIVE_PATTERNS=("*.pem" "*.key" "*.p12" "*.pfx" "*.env" "id_rsa*" "id_ed25519*" "*.keystore")
fi
if [[ ${#AUDIT_CODE_DIRS[@]} -eq 0 ]]; then
    AUDIT_CODE_DIRS=("$HOME/Projects" "$HOME/Developer" "$HOME/code" "$HOME/src")
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
    echo "[$ts] AUDIT: $*" >> "$LOG_FILE"
}

# Track totals
TOTAL_PASS=0
TOTAL_WARN=0
TOTAL_FAIL=0

audit_pass()  { TOTAL_PASS=$((TOTAL_PASS + 1)); _pass "$@"; }
audit_warn()  { TOTAL_WARN=$((TOTAL_WARN + 1)); _warn "$@"; _log "WARN: $*"; }
audit_fail()  { TOTAL_FAIL=$((TOTAL_FAIL + 1)); _fail "$@"; _log "FAIL: $*"; }

# ============================================================================
# AUDIT CHECKS
# ============================================================================

# --- 1. SYSTEM HARDENING ---

check_system_hardening() {
    echo -e "\n${BOLD}  SYSTEM HARDENING${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    if [[ "$(uname)" == "Darwin" ]]; then
        # FileVault
        if command -v fdesetup &>/dev/null; then
            if fdesetup status 2>/dev/null | grep -qi "on"; then
                audit_pass "FileVault (disk encryption): ON"
            else
                audit_fail "FileVault (disk encryption): OFF"
            fi
        fi

        # SIP
        if command -v csrutil &>/dev/null; then
            if csrutil status 2>/dev/null | grep -qi "enabled"; then
                audit_pass "System Integrity Protection: ENABLED"
            else
                audit_fail "System Integrity Protection: DISABLED"
            fi
        fi

        # Gatekeeper
        if command -v spctl &>/dev/null; then
            if spctl --status 2>/dev/null | grep -qi "enabled"; then
                audit_pass "Gatekeeper: ENABLED"
            else
                audit_warn "Gatekeeper: DISABLED"
            fi
        fi

        # Firewall
        local FW="/usr/libexec/ApplicationFirewall/socketfilterfw"
        if [[ -x "$FW" ]]; then
            if "$FW" --getglobalstate 2>/dev/null | grep -qi "enabled"; then
                audit_pass "Firewall: ENABLED"
            else
                audit_fail "Firewall: DISABLED"
            fi

            if "$FW" --getstealthmode 2>/dev/null | grep -qi "enabled"; then
                audit_pass "Stealth Mode: ENABLED"
            else
                audit_warn "Stealth Mode: DISABLED"
            fi
        fi

        # SSH
        if lsof -iTCP:22 -sTCP:LISTEN -P -n &>/dev/null 2>&1; then
            audit_warn "SSH: LISTENING (disable if not needed)"
        else
            audit_pass "SSH: NOT LISTENING"
        fi

        # Screen lock
        if command -v sysadminctl &>/dev/null; then
            if defaults read com.apple.screensaver askForPassword 2>/dev/null | grep -q "1"; then
                audit_pass "Screen lock password: REQUIRED"
            else
                audit_warn "Screen lock password: NOT REQUIRED"
            fi
        fi

    elif [[ "$(uname)" == "Linux" ]]; then
        # UFW/iptables
        if command -v ufw &>/dev/null; then
            if sudo ufw status 2>/dev/null | grep -qi "active"; then
                audit_pass "UFW Firewall: ACTIVE"
            else
                audit_fail "UFW Firewall: INACTIVE"
            fi
        fi

        # LUKS
        if command -v lsblk &>/dev/null; then
            if lsblk -o TYPE 2>/dev/null | grep -q "crypt"; then
                audit_pass "Disk encryption: LUKS detected"
            else
                audit_warn "Disk encryption: not detected"
            fi
        fi

        # SSH
        if systemctl is-active sshd &>/dev/null 2>&1; then
            audit_warn "SSH daemon: RUNNING"
        else
            audit_pass "SSH daemon: NOT RUNNING"
        fi
    fi
}

# --- 2. OPEN PORTS ---

check_open_ports() {
    echo -e "\n${BOLD}  OPEN PORTS${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    # Delegate to portcheck module
    if [[ -f "$MODULES_DIR/portcheck.sh" ]]; then
        bash "$MODULES_DIR/portcheck.sh" report
    else
        # Inline check
        local exposed
        exposed=$(lsof -iTCP -sTCP:LISTEN -P -n 2>/dev/null | tail -n +2 | grep '\*:' || true)

        if [[ -z "$exposed" ]]; then
            audit_pass "No ports exposed on all interfaces"
        else
            local count
            count=$(echo "$exposed" | wc -l | tr -d ' ')
            audit_fail "${count} port(s) listening on all interfaces"
            echo "$exposed" | while read -r line; do
                local process port
                process=$(echo "$line" | awk '{print $1}')
                port=$(echo "$line" | awk '{print $9}')
                echo -e "    ${RED}${RESET}  ${process} on ${port}"
            done
        fi
    fi
}

# --- 3. STALE SENSITIVE FILES ---

check_stale_files() {
    echo -e "\n${BOLD}  STALE SENSITIVE FILES${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    local found=0

    for scan_dir in "${AUDIT_SCAN_DIRS[@]}"; do
        scan_dir="$(eval echo "$scan_dir")"
        [[ ! -d "$scan_dir" ]] && continue

        for pattern in "${AUDIT_SENSITIVE_PATTERNS[@]}"; do
            while IFS= read -r -d $'\0' f; do
                # Check age
                local file_age_days
                if [[ "$(uname)" == "Darwin" ]]; then
                    local mtime now
                    mtime=$(stat -f %m "$f" 2>/dev/null || echo 0)
                    now=$(date +%s)
                    file_age_days=$(( (now - mtime) / 86400 ))
                else
                    file_age_days=$(( ($(date +%s) - $(stat -c %Y "$f" 2>/dev/null || echo 0)) / 86400 ))
                fi

                if (( file_age_days > AUDIT_STALE_DAYS )); then
                    audit_warn "Stale sensitive file (${file_age_days}d old): ${f}"
                else
                    audit_warn "Sensitive file in exposed location: ${f}"
                fi
                found=$((found + 1))

                # Check permissions
                local perms
                if [[ "$(uname)" == "Darwin" ]]; then
                    perms=$(stat -f %Lp "$f" 2>/dev/null)
                else
                    perms=$(stat -c %a "$f" 2>/dev/null)
                fi
                if [[ "$perms" != "600" ]] && [[ "$perms" != "400" ]]; then
                    audit_warn "  Permissions too open: ${perms} (should be 600)"
                fi
            done < <(find "$scan_dir" -maxdepth 3 -name "$pattern" -print0 2>/dev/null)
        done
    done

    if (( found == 0 )); then
        audit_pass "No sensitive files found in exposed directories"
    fi
}

# --- 4. DIRECTORY PERMISSIONS ---

check_permissions() {
    echo -e "\n${BOLD}  DIRECTORY PERMISSIONS${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    # Check key directories
    local dirs_to_check=(
        "$HOME/.ssh:700"
        "$HOME/.gnupg:700"
        "$HOME/.config:755"
        "$HOME/.aws:700"
    )

    for entry in "${dirs_to_check[@]}"; do
        local dir expected_perms
        dir="${entry%%:*}"
        expected_perms="${entry##*:}"

        if [[ ! -d "$dir" ]]; then
            continue  # Directory doesn't exist — that's fine
        fi

        local actual_perms
        if [[ "$(uname)" == "Darwin" ]]; then
            actual_perms=$(stat -f %Lp "$dir" 2>/dev/null)
        else
            actual_perms=$(stat -c %a "$dir" 2>/dev/null)
        fi

        if [[ "$actual_perms" == "$expected_perms" ]] || (( actual_perms <= expected_perms )); then
            audit_pass "${dir}: permissions ${actual_perms}"
        else
            audit_warn "${dir}: permissions ${actual_perms} (recommended: ${expected_perms})"
        fi
    done

    # Check for world-readable files in sensitive dirs
    if [[ -d "$HOME/.ssh" ]]; then
        local world_readable
        world_readable=$(find "$HOME/.ssh" -type f \( -perm -040 -o -perm -004 \) 2>/dev/null | head -5 || true)
        if [[ -n "$world_readable" ]]; then
            audit_warn ".ssh has world/group-readable files:"
            echo "$world_readable" | while read -r f; do
                echo "    $f"
            done
        fi
    fi
}

# --- 5. ENV FILES WITH SECRETS ---

check_env_files() {
    echo -e "\n${BOLD}  ENVIRONMENT FILES${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    local found=0

    # Check common code directories
    for code_dir in "${AUDIT_CODE_DIRS[@]}"; do
        code_dir="$(eval echo "$code_dir")"
        [[ ! -d "$code_dir" ]] && continue

        while IFS= read -r -d $'\0' envfile; do
            # Check if it contains anything that looks like a secret
            if grep -qiE '(password|secret|key|token|api_key|private).*=' "$envfile" 2>/dev/null; then
                audit_warn ".env with secrets: ${envfile}"
                found=$((found + 1))

                # Check if it's gitignored
                local dir
                dir="$(dirname "$envfile")"
                if [[ -f "$dir/.gitignore" ]] && grep -q '\.env' "$dir/.gitignore" 2>/dev/null; then
                    _info "  (gitignored -- good)"
                else
                    audit_warn "  NOT in .gitignore!"
                fi
            fi
        done < <(find "$code_dir" -maxdepth 5 \( -name ".env" -o -name ".env.*" \) -print0 2>/dev/null)
    done

    # Also check home directory
    for envfile in "$HOME/.env" "$HOME/.env.local" "$HOME/.env.production"; do
        if [[ -f "$envfile" ]]; then
            audit_warn "Env file in home directory: ${envfile}"
            found=$((found + 1))
        fi
    done

    if (( found == 0 )); then
        audit_pass "No exposed .env files with secrets found"
    fi
}

# --- 6. GIT REPOS WITH COMMITTED SECRETS ---

check_git_secrets() {
    local mode="${1:-full}"
    echo -e "\n${BOLD}  GIT SECRET SCAN${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    if [[ "$mode" == "quick" ]]; then
        _info "Skipping git scan (quick mode)"
        return
    fi

    local found=0
    local checked=0

    for code_dir in "${AUDIT_CODE_DIRS[@]}"; do
        code_dir="$(eval echo "$code_dir")"
        [[ ! -d "$code_dir" ]] && continue

        # Find git repos (up to 3 levels deep)
        while IFS= read -r -d $'\0' gitdir; do
            local repo
            repo="$(dirname "$gitdir")"
            checked=$((checked + 1))

            # Check tracked files for obvious secrets
            local secrets
            secrets=$(cd "$repo" && git ls-files 2>/dev/null | while read -r f; do
                case "$f" in
                    *.env|*.env.*|.env.local|.env.production)
                        if [[ -f "$repo/$f" ]] && grep -qiE '(password|secret|key|token).*=' "$repo/$f" 2>/dev/null; then
                            echo "$f"
                        fi
                        ;;
                    *id_rsa*|*.pem|*.key|*.p12)
                        echo "$f"
                        ;;
                esac
            done)

            if [[ -n "$secrets" ]]; then
                audit_fail "Secrets committed in ${repo}:"
                echo "$secrets" | while read -r s; do
                    echo -e "    ${RED}${RESET}  $s"
                done
                found=$((found + 1))
            fi
        done < <(find "$code_dir" -maxdepth 4 -name ".git" -type d -print0 2>/dev/null)
    done

    if (( found == 0 )); then
        if (( checked > 0 )); then
            audit_pass "No committed secrets found in ${checked} repos"
        else
            _info "No git repos found in configured directories"
        fi
    fi
}

# --- 7. LAUNCHAGENTS/LAUNCHDAEMONS INVENTORY ---

check_launch_agents() {
    echo -e "\n${BOLD}  LAUNCH AGENTS & DAEMONS${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    if [[ "$(uname)" != "Darwin" ]]; then
        _info "LaunchAgent check is macOS only"

        # On Linux, check systemd user units
        if command -v systemctl &>/dev/null; then
            _info "Systemd user units:"
            systemctl --user list-units --type=service --state=running 2>/dev/null | head -10 | while read -r line; do
                echo "    $line"
            done
        fi
        return
    fi

    local suspicious=0

    for agent_dir in "$HOME/Library/LaunchAgents" "/Library/LaunchAgents" "/Library/LaunchDaemons"; do
        if [[ ! -d "$agent_dir" ]]; then
            continue
        fi

        _info "${agent_dir}:"

        for plist in "$agent_dir"/*.plist; do
            [[ ! -f "$plist" ]] && continue
            local name
            name="$(basename "$plist" .plist)"

            # Check if it's loaded
            local loaded="not loaded"
            if launchctl list 2>/dev/null | grep -q "$name"; then
                loaded="RUNNING"
            fi

            # Categorize
            if [[ "$name" == com.apple.* ]]; then
                # Apple system — skip unless verbose
                continue
            elif [[ "$name" == *sentinel* ]] || [[ "$name" == *gump* ]] || [[ "$name" == *begump* ]]; then
                audit_pass "  ${name} (${loaded}) — ours"
            elif [[ "$name" == com.google* ]] || [[ "$name" == com.microsoft* ]] || [[ "$name" == com.spotify* ]] || [[ "$name" == com.docker* ]]; then
                _info "  ${name} (${loaded}) — known vendor"
            else
                audit_warn "  ${name} (${loaded}) — REVIEW"
                suspicious=$((suspicious + 1))
            fi
        done
    done

    echo ""
    if (( suspicious > 0 )); then
        audit_warn "${suspicious} LaunchAgent(s) should be reviewed"
    else
        audit_pass "All LaunchAgents look expected"
    fi
}

# --- 8. CRONTAB ---

check_crontab() {
    echo -e "\n${BOLD}  SCHEDULED TASKS${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    local cron_entries
    cron_entries=$(crontab -l 2>/dev/null || true)

    if [[ -z "$cron_entries" ]] || echo "$cron_entries" | grep -qi "no crontab"; then
        audit_pass "No crontab entries"
    else
        _info "Crontab entries:"
        echo "$cron_entries" | while read -r line; do
            [[ "$line" == \#* ]] && continue
            [[ -z "$line" ]] && continue
            echo "    $line"
        done
        audit_warn "Review crontab entries above"
    fi

    # Check /etc/cron.d on Linux
    if [[ -d "/etc/cron.d" ]]; then
        local system_cron
        system_cron=$(ls /etc/cron.d/ 2>/dev/null | wc -l | tr -d ' ')
        _info "System cron jobs: ${system_cron} in /etc/cron.d/"
    fi
}

# --- 9. DNS CONFIGURATION ---

check_dns() {
    echo -e "\n${BOLD}  DNS CONFIGURATION${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    local dns_servers
    if [[ "$(uname)" == "Darwin" ]]; then
        dns_servers=$(scutil --dns 2>/dev/null | grep "nameserver\[" | awk '{print $3}' | sort -u || true)
    else
        dns_servers=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' || true)
    fi

    if [[ -z "$dns_servers" ]]; then
        audit_warn "Could not determine DNS servers"
        return
    fi

    _info "DNS servers:"
    local has_protection=0
    while read -r server; do
        [[ -z "$server" ]] && continue
        echo "    $server"
        case "$server" in
            9.9.9.9|149.112.112.112)   _info "    ^ Quad9 (malware blocking)"; has_protection=1 ;;
            1.1.1.2|1.0.0.2)           _info "    ^ Cloudflare (malware blocking)"; has_protection=1 ;;
            1.1.1.1|1.0.0.1)           _info "    ^ Cloudflare (no malware blocking)" ;;
            8.8.8.8|8.8.4.4)           _info "    ^ Google Public DNS" ;;
            192.168.*|10.*|172.1[6-9].*|172.2[0-9].*|172.3[0-1].*) _info "    ^ Router/LAN default" ;;
        esac
    done <<< "$dns_servers"

    if (( has_protection == 0 )); then
        audit_warn "No DNS-level malware blocking detected"
        _info "Recommended: Quad9 (9.9.9.9) or Cloudflare for Families (1.1.1.2)"
    else
        audit_pass "DNS malware protection detected"
    fi
}

# ============================================================================
# MAIN AUDIT
# ============================================================================

run_audit() {
    local mode="${1:-full}"

    echo ""
    echo -e "${BOLD}  SENTINEL SECURITY AUDIT${RESET}"
    echo -e "  ${DIM}$(date)${RESET}"
    echo -e "  ${DIM}$(uname -srm)${RESET}"
    echo ""

    check_system_hardening
    check_open_ports
    check_stale_files
    check_permissions
    check_env_files
    check_git_secrets "$mode"
    check_launch_agents
    check_crontab
    check_dns

    # Final summary
    echo ""
    echo -e "${BOLD}  AUDIT COMPLETE${RESET}"
    echo -e "  ${DIM}$(printf '%.0s-' {1..60})${RESET}"
    echo ""

    if (( TOTAL_FAIL > 0 )); then
        _fail "${TOTAL_FAIL} critical issue(s)"
    fi
    if (( TOTAL_WARN > 0 )); then
        _warn "${TOTAL_WARN} warning(s)"
    fi
    _pass "${TOTAL_PASS} check(s) passed"
    echo ""

    _log "Audit complete: ${TOTAL_FAIL} fails, ${TOTAL_WARN} warns, ${TOTAL_PASS} passes"

    # Save report
    local report_file="$SENTINEL_DIR/last_audit.txt"
    {
        echo "SENTINEL AUDIT — $(date)"
        echo "FAIL: ${TOTAL_FAIL}  WARN: ${TOTAL_WARN}  PASS: ${TOTAL_PASS}"
    } > "$report_file"

    return $TOTAL_FAIL
}

# MODULES_DIR might not be exported if run standalone
MODULES_DIR="${MODULES_DIR:-$(dirname "$SCRIPT_DIR")/modules}"

case "${1:-full}" in
    full|report|"") run_audit full ;;
    quick)          run_audit quick ;;
    *)              run_audit full ;;
esac
