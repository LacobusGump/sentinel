#!/usr/bin/env bash
# ============================================================================
# IMMUNE — Automated threat response
#
# The body doesn't build walls. It builds antibodies that target specific
# structures. This module detects attack patterns and deploys targeted
# countermeasures — the security equivalent of "apply charge to the
# aggregation hotspot."
#
# Detection → Analysis → Response. Like a protein drug.
# Find the structure. Find the weakness. Apply the counter.
# ============================================================================

# Source sentinel environment if running standalone
if [[ -z "$SENTINEL_DIR" ]]; then
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    source "$(dirname "$SCRIPT_DIR")/sentinel.sh" --source-only 2>/dev/null || {
        SENTINEL_DIR="${HOME}/.sentinel"
        mkdir -p "$SENTINEL_DIR"
        pass()  { echo "  [PASS]  $*"; }
        warn()  { echo "  [WARN]  $*"; }
        fail()  { echo "  [FAIL]  $*"; }
        info()  { echo "  [INFO]  $*"; }
        header(){ echo -e "\n$*"; }
        log_msg() { echo "[$(date -u +%Y-%m-%dT%H:%M:%SZ)] $*" >> "$SENTINEL_DIR/sentinel.log"; }
        alert() { local l="$1"; shift; case "$l" in FAIL) fail "$*";; WARN) warn "$*";; *) info "$*";; esac; log_msg "[$l] $*"; }
    }
fi

IMMUNE_DIR="$SENTINEL_DIR/immune"
IMMUNE_LOG="$IMMUNE_DIR/responses.log"
BLOCKED_IPS="$IMMUNE_DIR/blocked.txt"
THREAT_HISTORY="$IMMUNE_DIR/threats.tsv"
mkdir -p "$IMMUNE_DIR"
chmod 700 "$IMMUNE_DIR" 2>/dev/null || true

# ============================================================================
# DETECTION — What pattern is this?
# ============================================================================

# Detect port scanning (rapid connection attempts from one source)
detect_portscan() {
    local threshold="${1:-20}"  # connections from one IP in the snapshot
    local scans=0

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: use netstat
        netstat -an 2>/dev/null | grep -E 'SYN_RCVD|SYN_SENT' | \
            awk '{print $5}' | sed 's/\.[0-9]*$//' | sort | uniq -c | sort -rn | \
            while read -r count ip; do
                if (( count >= threshold )); then
                    echo "PORTSCAN|${ip}|${count}"
                    scans=$((scans + 1))
                fi
            done
    else
        # Linux: use ss
        ss -tn state syn-recv 2>/dev/null | awk 'NR>1 {print $5}' | \
            sed 's/:[0-9]*$//' | sort | uniq -c | sort -rn | \
            while read -r count ip; do
                if (( count >= threshold )); then
                    echo "PORTSCAN|${ip}|${count}"
                fi
            done
    fi
}

# Detect beaconing (periodic outbound connections to the same IP)
detect_beacon() {
    local history_file="$IMMUNE_DIR/conn_timestamps.tsv"

    # Need at least 2 snapshots
    if [[ ! -f "$history_file" ]] || (( $(wc -l < "$history_file") < 5 )); then
        return
    fi

    # For each IP seen 5+ times, check interval regularity
    awk -F'\t' '{print $2}' "$history_file" | sort | uniq -c | sort -rn | \
        while read -r count ip; do
            if (( count >= 5 )); then
                # Extract timestamps for this IP
                local times
                times=$(awk -F'\t' -v ip="$ip" '$2==ip {print $1}' "$history_file" | tail -10)
                local prev="" intervals="" n_intervals=0

                while read -r t; do
                    if [[ -n "$prev" ]]; then
                        local diff=$((t - prev))
                        intervals="${intervals} ${diff}"
                        n_intervals=$((n_intervals + 1))
                    fi
                    prev="$t"
                done <<< "$times"

                if (( n_intervals >= 3 )); then
                    # Compute coefficient of variation (CV)
                    # Low CV = regular intervals = beaconing
                    local stats
                    stats=$(echo "$intervals" | tr ' ' '\n' | grep -v '^$' | \
                        awk '{sum+=$1; sumsq+=($1)^2; n++} END {
                            if(n<2) {print "0 0 999"; exit}
                            mean=sum/n; var=sumsq/n-mean^2;
                            if(var<0) var=0; sd=sqrt(var);
                            cv=(mean>0)?sd/mean:999;
                            print mean, sd, cv
                        }')
                    local mean sd cv
                    read -r mean sd cv <<< "$stats"

                    # CV < 0.3 = suspiciously regular
                    if (( $(echo "$cv < 0.3" | bc -l 2>/dev/null || echo 0) )); then
                        echo "BEACON|${ip}|interval=${mean}s|cv=${cv}|count=${count}"
                    fi
                fi
            fi
        done
}

# Detect brute force (repeated failed SSH connections)
detect_bruteforce() {
    local threshold="${1:-5}"

    if [[ "$(uname)" == "Darwin" ]]; then
        # macOS: check auth log
        local failures
        failures=$(log show --last 5m --predicate 'process == "sshd" && eventMessage CONTAINS "Failed"' 2>/dev/null | \
            grep -c "Failed" || echo 0)
        if (( failures >= threshold )); then
            # Get the source IPs
            local ips
            ips=$(log show --last 5m --predicate 'process == "sshd" && eventMessage CONTAINS "Failed"' 2>/dev/null | \
                grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | sort | uniq -c | sort -rn)
            while read -r count ip; do
                if (( count >= threshold )); then
                    echo "BRUTEFORCE|${ip}|${count} failures in 5m"
                fi
            done <<< "$ips"
        fi
    else
        # Linux: check auth.log or journalctl
        if [[ -f /var/log/auth.log ]]; then
            grep "Failed password" /var/log/auth.log 2>/dev/null | tail -100 | \
                grep -oE 'from [0-9]+\.[0-9]+\.[0-9]+\.[0-9]+' | awk '{print $2}' | \
                sort | uniq -c | sort -rn | \
                while read -r count ip; do
                    if (( count >= threshold )); then
                        echo "BRUTEFORCE|${ip}|${count} failures"
                    fi
                done
        fi
    fi
}

# ============================================================================
# ANALYSIS — K/R/E/T scoring of the threat
# ============================================================================

analyze_threat() {
    local type="$1" ip="$2" details="$3"
    local k=0 r=0 e=0 t_score=0

    case "$type" in
        PORTSCAN)
            k=0.9    # highly coupled (systematic, sequential)
            r=0.8    # synchronized (fast, regular)
            e=0.7    # moderate energy (many connections)
            t_score=0.9  # high tension (active probing)
            ;;
        BEACON)
            k=0.95   # maximally coupled (phone-home pattern)
            r=0.95   # maximally synchronized (fixed interval)
            e=0.3    # low energy (quiet, persistent)
            t_score=0.95 # highest tension (active C2)
            ;;
        BRUTEFORCE)
            k=0.6    # moderate coupling (repetitive but crude)
            r=0.7    # moderate sync (fast attempts)
            e=0.9    # high energy (visible, noisy)
            t_score=0.8  # high tension (credential attack)
            ;;
    esac

    # Threat score: geometric mean of K, R, T (energy is informational)
    local score
    score=$(echo "scale=3; sqrt($k * $r * $t_score * 1000) / sqrt(1000)" | bc -l 2>/dev/null || echo "0.5")

    echo "${score}|${k}|${r}|${e}|${t_score}"
}

# ============================================================================
# RESPONSE — Apply charge at the aggregation hotspot
# ============================================================================

respond_to_threat() {
    local type="$1" ip="$2" score="$3" details="$4"
    local action="none"
    local ts
    ts="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

    # Don't respond to localhost or private ranges we trust
    if [[ "$ip" == 127.* ]] || [[ "$ip" == 192.168.* ]] || [[ "$ip" == 10.* ]]; then
        info "Threat from private IP ${ip} — monitoring only"
        return
    fi

    # Check if already blocked
    if grep -q "^${ip}$" "$BLOCKED_IPS" 2>/dev/null; then
        return
    fi

    # Score-based response (higher score = more aggressive response)
    if (( $(echo "$score > 0.8" | bc -l 2>/dev/null || echo 0) )); then
        # HIGH THREAT — block + alert
        action="BLOCK"

        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS: add to pf deny table
            if sudo -n true 2>/dev/null; then
                # Create deny rule if not exists
                echo "block drop from ${ip} to any" | sudo pfctl -a sentinel -f - 2>/dev/null && \
                    action="BLOCKED_PF"
            else
                # No sudo — log the recommended command
                action="RECOMMEND_BLOCK"
            fi
        else
            # Linux: iptables deny
            if sudo -n true 2>/dev/null; then
                sudo iptables -A INPUT -s "$ip" -j DROP 2>/dev/null && \
                    action="BLOCKED_IPTABLES"
            else
                action="RECOMMEND_BLOCK"
            fi
        fi

        echo "$ip" >> "$BLOCKED_IPS"
        fail "IMMUNE RESPONSE: ${type} from ${ip} — ${action}"
        alert FAIL "Immune response: ${type} from ${ip} (score=${score}) — ${action}"

    elif (( $(echo "$score > 0.5" | bc -l 2>/dev/null || echo 0) )); then
        # MODERATE THREAT — alert + monitor
        action="MONITOR"
        warn "THREAT DETECTED: ${type} from ${ip} (score=${score}) — monitoring"
        alert WARN "Threat: ${type} from ${ip} (score=${score}) — ${details}"

    else
        # LOW THREAT — log only
        action="LOG"
        info "Low-confidence detection: ${type} from ${ip} (score=${score})"
    fi

    # Record to threat history
    printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$ts" "$type" "$ip" "$score" "$action" "$details" >> "$THREAT_HISTORY"

    # Record connection timestamp for beacon analysis
    printf '%s\t%s\n' "$(date +%s)" "$ip" >> "$IMMUNE_DIR/conn_timestamps.tsv"
    # Keep last 1000 entries
    if [[ -f "$IMMUNE_DIR/conn_timestamps.tsv" ]]; then
        tail -1000 "$IMMUNE_DIR/conn_timestamps.tsv" > "$IMMUNE_DIR/conn_timestamps.tmp"
        mv "$IMMUNE_DIR/conn_timestamps.tmp" "$IMMUNE_DIR/conn_timestamps.tsv"
    fi
}

# ============================================================================
# COUNTER REPORT — what happened, what we did, what to check
# ============================================================================

immune_report() {
    header "IMMUNE SYSTEM"

    if [[ ! -f "$THREAT_HISTORY" ]] || (( $(wc -l < "$THREAT_HISTORY" 2>/dev/null || echo 0) == 0 )); then
        pass "No threats detected"
        return
    fi

    local total blocked monitored
    total=$(wc -l < "$THREAT_HISTORY" | tr -d ' ')
    blocked=$(grep -c "BLOCK" "$THREAT_HISTORY" 2>/dev/null || echo 0)
    monitored=$(grep -c "MONITOR" "$THREAT_HISTORY" 2>/dev/null || echo 0)

    info "Threat history: ${total} events, ${blocked} blocked, ${monitored} monitoring"

    # Show last 5 threats
    echo ""
    tail -5 "$THREAT_HISTORY" | while IFS=$'\t' read -r ts type ip score action details; do
        case "$action" in
            *BLOCK*) fail "${ts} ${type} ${ip} → ${action} (K/R/E/T score: ${score})" ;;
            MONITOR) warn "${ts} ${type} ${ip} → monitoring (score: ${score})" ;;
            *)       info "${ts} ${type} ${ip} → logged (score: ${score})" ;;
        esac
    done

    # Show blocked IPs
    if [[ -f "$BLOCKED_IPS" ]] && (( $(wc -l < "$BLOCKED_IPS" 2>/dev/null || echo 0) > 0 )); then
        echo ""
        local n_blocked
        n_blocked=$(wc -l < "$BLOCKED_IPS" | tr -d ' ')
        warn "${n_blocked} IPs currently blocked"
        info "Unblock: edit ${BLOCKED_IPS}"
    fi
}

# ============================================================================
# MAIN — Detect, Analyze, Respond
# ============================================================================

immune_scan() {
    header "IMMUNE SCAN — Detect, Analyze, Respond"

    local threats_found=0

    # 1. Port scan detection
    local scans
    scans=$(detect_portscan)
    if [[ -n "$scans" ]]; then
        while IFS='|' read -r type ip count; do
            local analysis
            analysis=$(analyze_threat "$type" "$ip" "$count")
            local score
            score=$(echo "$analysis" | cut -d'|' -f1)
            respond_to_threat "$type" "$ip" "$score" "$count"
            threats_found=$((threats_found + 1))
        done <<< "$scans"
    fi

    # 2. Brute force detection
    local brutes
    brutes=$(detect_bruteforce)
    if [[ -n "$brutes" ]]; then
        while IFS='|' read -r type ip details; do
            local analysis
            analysis=$(analyze_threat "$type" "$ip" "$details")
            local score
            score=$(echo "$analysis" | cut -d'|' -f1)
            respond_to_threat "$type" "$ip" "$score" "$details"
            threats_found=$((threats_found + 1))
        done <<< "$brutes"
    fi

    # 3. Beacon detection (needs history)
    local beacons
    beacons=$(detect_beacon)
    if [[ -n "$beacons" ]]; then
        while IFS='|' read -r type ip interval details; do
            local analysis
            analysis=$(analyze_threat "$type" "$ip" "${interval}|${details}")
            local score
            score=$(echo "$analysis" | cut -d'|' -f1)
            respond_to_threat "$type" "$ip" "$score" "${interval} ${details}"
            threats_found=$((threats_found + 1))
        done <<< "$beacons"
    fi

    if (( threats_found == 0 )); then
        pass "No active threats detected"
    else
        warn "${threats_found} threats detected and processed"
    fi

    echo ""
    immune_report
}

# ============================================================================
# ENTRY POINT
# ============================================================================

case "${1:-scan}" in
    scan)    immune_scan ;;
    report)  immune_report ;;
    reset)
        rm -f "$THREAT_HISTORY" "$BLOCKED_IPS" "$IMMUNE_DIR/conn_timestamps.tsv"
        pass "Immune system reset. History cleared."
        ;;
    *)
        echo "Usage: immune.sh [scan|report|reset]"
        ;;
esac
