#!/usr/bin/env bash
# ============================================================================
# TRIPWIRE — Honeypot decoy file system
# ============================================================================
# Creates fake sensitive files that look real. Monitors them.
# If anything touches them, you know someone is snooping.
#
# Usage:
#   tripwire.sh deploy   — Create decoy files in configured locations
#   tripwire.sh watch    — Monitor decoys (continuous, uses fswatch or polling)
#   tripwire.sh check    — One-time check if any decoys were touched
#   tripwire.sh list     — List all deployed decoys
#   tripwire.sh clean    — Remove all decoy files
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SENTINEL_ROOT="$(dirname "$SCRIPT_DIR")"
CONF_FILE="${SENTINEL_ROOT}/config/sentinel.conf"

# Defaults
SENTINEL_DIR="${SENTINEL_DIR:-$HOME/.sentinel}"
LOG_FILE="${LOG_FILE:-$SENTINEL_DIR/sentinel.log}"
ALERT_METHOD="${ALERT_METHOD:-terminal,log}"
DECOY_POLL_INTERVAL="${DECOY_POLL_INTERVAL:-30}"
MANIFEST="$SENTINEL_DIR/decoy_manifest.txt"
HASHES="$SENTINEL_DIR/decoy_hashes.txt"

# Load config
if [[ -f "$CONF_FILE" ]]; then
    source "$CONF_FILE"
fi

mkdir -p "$SENTINEL_DIR"

# Colors (inherit from parent or define)
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
    echo "[$ts] TRIPWIRE: $*" >> "$LOG_FILE"
}

_alert() {
    local msg="$*"
    _fail "TRIPWIRE ALERT: $msg"
    _log "ALERT: $msg"

    # macOS notification
    if [[ "$ALERT_METHOD" == *"notify"* ]] && command -v osascript &>/dev/null; then
        osascript -e "display notification \"$msg\" with title \"SENTINEL TRIPWIRE\" sound name \"Basso\""
    fi
}

# ----------------------------------------------------------------------------
# DECOY FILE GENERATORS
# These create realistic-looking files that an intruder would find valuable.
# None of them contain real credentials.
# ----------------------------------------------------------------------------

generate_crypto_wallet() {
    local dir="$1"
    mkdir -p "$dir"

    # Bitcoin wallet backup (fake but plausible format)
    cat > "$dir/wallet_backup.dat" << 'WALLET'
# Bitcoin Core Wallet Dump
# Created by Bitcoin Core v24.0.1
# * Created on 2025-09-14T02:34:18Z
# * Best block at time of backup was 812034
#   (00000000000000000002a7c4c1e48d76c5a37902165a270156b7a8d72f998cd1)

# extended private masterkey: xprv9s21ZrQH143K3GJpoapnV8SFfuZcECfSjBZ2dNEcqMQv7ZchYfgPe
# pVFRjb4SzJVpBJ27MN5sDiKAHTpzQwFUhkXm8SiJH64XwMRhCETF2p

# addr=1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa 2025-07-19T00:00:00Z label=cold-storage # addr=bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq 2025-07-19T00:00:00Z label=hot-wallet
# addr=3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy 2025-08-03T14:22:11Z label=exchange-deposit

KwDiBf89QgGbjEhKnhXJuH7LrciVrZi3qYjgd9M7rFU74sHUHy8S 2025-09-01T00:00:00Z label=savings # addr=1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2
L4rK1yDtCWekvXuE6oXD9jCYfFNV2cWRpVuPLBcCU2z8TrisoyY1 2025-09-14T02:20:00Z label=trading # addr=3Cbq7aT1tY8kMxWLbitaG7yT6bPbKChq64
WALLET

    # Ethereum keystore file (fake)
    cat > "$dir/UTC--2025-09-14T03-44-22.109Z--8ba1f109551bd432803012645ac136ddd64dba72" << 'KEYSTORE'
{"address":"8ba1f109551bd432803012645ac136ddd64dba72","crypto":{"cipher":"aes-128-ctr","ciphertext":"5318b4d5bcd28de64ee5559e671353e16f075ecae9f99c7a79a38af5f869aa46","cipherparams":{"iv":"6087dab2f9fdbbfaddc31a909735c1e6"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"ae3cd4e7013836a3df6bd7241b12db061dbe2c6785853cce422d148a624ce0bd"},"mac":"517ead924a9d0dc3124507e3393d175ce3ff7c1e96529c6c555ce9e51205e9b2"},"id":"e13b209c-3b2f-4327-bab0-3bef2e51630d","version":3}
KEYSTORE

    chmod 600 "$dir"/*
}

generate_passwords_file() {
    local dir="$1"
    mkdir -p "$dir"

    # passwords.txt that looks like someone's actual password dump
    cat > "$dir/passwords.txt" << 'PASSWORDS'
# Last updated: 2025-11-03
# DO NOT SHARE THIS FILE

== Email ==
gmail: margaret.chen.1987@gmail.com / Tr0ub4dor&3
outlook: mchen_work@outlook.com / CorrectHorseBatteryStaple!42

== Banking ==
chase: margaret.chen / Sunfl0wer$2025!
schwab: mchen_invest / BlueMountain#789

== Work ==
vpn: mchen / W1nt3rSolst1ce!2025
slack: margaret.chen@acmecorp.com / same as email
jira: mchen / R4inb0wDash#99

== Crypto ==
coinbase: margaret.chen.1987@gmail.com / D1am0nd_H4nds!Forever
binance: m.chen.trading@proton.me / M00nL4nding$2025

== SSH ==
prod-server: ssh mchen@10.0.1.50 -i ~/.ssh/id_prod
staging: ssh deploy@staging.acmecorp.internal -p 2222

== WiFi ==
home: "Chen Family Network" / Th3Qu1ckBr0wnF0x!
guest: "Chen Guest" / Welcome2025

== API Keys ==
# moved to .env.backup - too many to list here

== Recovery codes ==
google 2fa backup: 4829 1037 5928 4817 2938
github 2fa backup: a8f29c-b3d71e-c4e82f-d5f93a-e6a04b
PASSWORDS

    chmod 600 "$dir/passwords.txt"
}

generate_env_backup() {
    local dir="$1"
    mkdir -p "$dir"

    # .env.backup that looks like a real app's environment file
    cat > "$dir/.env.backup" << 'ENVFILE'
# Production Environment — LAST BACKUP 2025-10-28
# Restored from production after the outage on 10/27

NODE_ENV=production
PORT=3000

# Database
DATABASE_URL=postgresql://app_prod:kX9$mPw2!vNqR7@db-primary.us-east-1.rds.amazonaws.com:5432/acmecorp_prod
REDIS_URL=redis://:Hy7!kMn3$pQw@redis-prod.abc123.us-east-1.cache.amazonaws.com:6379/0

# Auth
JWT_SECRET=a7f8c9d2e4b6a1c3d5e7f9a2b4c6d8e0f1a3b5c7d9e1f3a5b7c9d1e3f5a7b9
SESSION_SECRET=x9y8z7w6v5u4t3s2r1q0p9o8n7m6l5k4

# AWS
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
AWS_REGION=us-east-1
S3_BUCKET=acmecorp-prod-assets

# Stripe
# Payment processor keys (DECOY — these are fake honeypot values)
PAYMENT_SECRET=rk_live_DECOY_51Hb3CmJw8z4qBc6vKx9nMpLr2tYuWxYz0000
PAYMENT_WEBHOOK=whk_DECOY_a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8
STRIPE_PRICE_ID=price_1Hb3CmJw8z4qBc6v

# Sendgrid
SENDGRID_API_KEY=SG.a1b2c3d4e5f6g7h8.i9j0k1l2m3n4o5p6q7r8s9t0u1v2w3x4y5z6a7b8c9d0

# Twilio
TWILIO_ACCOUNT_SID=AC1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6
TWILIO_AUTH_TOKEN=a1b2c3d4e5f6g7h8i9j0k1l2

# Sentry
SENTRY_DSN=https://a1b2c3d4e5f6g7h8@o123456.ingest.sentry.io/7654321

# Internal
ADMIN_EMAIL=ops@acmecorp.com
ADMIN_PASSWORD=Pr0duct10n!Adm1n#2025
ENVFILE

    chmod 600 "$dir/.env.backup"
}

generate_ssh_keys() {
    local dir="$1"
    mkdir -p "$dir"

    # Fake SSH private key (RSA format, NOT a real key)
    cat > "$dir/id_rsa_backup" << 'SSHKEY'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAACFwAAAAdz
c2gtcnNhAAAAAwEAAQAAAgEA0WkzV7rpGZsg5CYO3MFBG4d4K7G8Rk3zP8vH5x2w
Q9jN6mTkX5a2VpYGe0RcSF7OtD8K1L6M3N4P5Q6R7S8T9U0V1W2X3Y4Z5a6b7c8
d9e0f1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8B9C0
D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8V9W0X1Y2Z3a4b5c6d7e8f9g0h1i2
j3k4l5m6n7o8p9q0r1s2t3u4v5w6x7y8z9A0B1C2D3E4F5G6H7I8J9K0L1M2N3O4
P5Q6R7S8T9U0V1W2X3Y4Z5a6b7c8d9e0f1g2h3i4j5k6l7m8n9o0p1q2r3s4t5u6
v7w8x9y0z1A2B3C4D5E6F7G8H9I0J1K2L3M4N5O6P7Q8R9S0T1U2V3W4X5Y6Z7a8
b9c0d1e2f3g4h5i6j7k8l9m0n1o2p3q4r5s6t7u8v9w0x1y2z3A4B5C6D7E8F9G0H
1I2J3K4L5M6N7O8P9Q0R1S2T3U4V5W6X7Y8Z9a0b1c2d3e4f5g6h7i8j9k0l1m2n3
o4p5q6r7s8t9u0v1w2x3y4z5A6B7C8D9E0F1G2H3I4J5K6L7M8N9O0P1Q2R3S4T5U
6V7W8X9Y0Z1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p7q8r9s0t1u2v3w4x5y6z7A8
B9C0D1E2F3G4H5I6J7K8L9M0N1O2P3Q4R5S6T7U8V9W0X1Y2Z3a4b5c6d7e8f9g0
-----END OPENSSH PRIVATE KEY-----
SSHKEY

    cat > "$dir/id_rsa_backup.pub" << 'SSHPUB'
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAACAQDRaTNXuukZmyDkJg7cwUEbh3grsbxGTfM/y8fnHbBD2M3qZORflrZWlgZ7RFxIXs60Pwr0voPdBe6F9oL2gvaC9sH7QPthe2H7gXuh+4J8InyCfoN+hH6FfoZ+h36IfshAyEDYgOiA+MEIwhjDGMM4w0jDeMP0xEAAAAl backup@workstation
SSHPUB

    # known_hosts (makes the SSH dir look used)
    cat > "$dir/known_hosts" << 'KNOWN'
|1|a7B9c2D4e6F8g0H2i4J6k8L0=|m2N4o6P8q0R2s4T6u8V0w2X4= ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKHQLe0b2N4FprPnYJm4Q2R6S8T0U2V4W6X8Y0Z2a4B6
|1|c8D0e2F4g6H8i0J2k4L6m8N0=|o2P4q6R8s0T2u4V6w8X0y2Z4= ssh-rsa AAAAB3NzaC1yc2EAAAABIwAAAQEA0WkzV7rpGZsg5CYO3MFBG4d4K7G8Rk3zP8v
10.0.1.50 ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGhJk2L4m6N8o0P2q4R6s8T0u2V4w6X8y0Z2A4B6C8D0
staging.acmecorp.internal ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIEf2G4h6I8j0K2l4M6n8O0p2Q4r6S8t0U2v4W6x8Y0Z
KNOWN

    chmod 600 "$dir/id_rsa_backup"
    chmod 644 "$dir/id_rsa_backup.pub" "$dir/known_hosts"
}

generate_aws_credentials() {
    local dir="$1"
    mkdir -p "$dir"

    cat > "$dir/credentials" << 'AWSCRED'
[default]
aws_access_key_id = AKIAIOSFODNN7EXAMPLE
aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY

[production]
aws_access_key_id = AKIAI44QH8DHBEXAMPLE
aws_secret_access_key = je7MtGbClwBF/2Zp9Utk/h3yCo8nvbEXAMPLEKEY

[staging]
aws_access_key_id = AKIAIRSTACCOUNT7EXAM
aws_secret_access_key = 2K+W1v3xBf7CdEfGhIjKlMnOpQrStUvWxYzExAmPl
AWSCRED

    cat > "$dir/config" << 'AWSCONF'
[default]
region = us-east-1
output = json

[profile production]
region = us-east-1
output = json
role_arn = arn:aws:iam::123456789012:role/prod-deploy

[profile staging]
region = us-west-2
output = json
AWSCONF

    chmod 600 "$dir/credentials" "$dir/config"
}

# ----------------------------------------------------------------------------
# DEPLOY — Create decoy files
# ----------------------------------------------------------------------------

deploy_decoys() {
    echo -e "\n${BOLD:-}  DEPLOYING HONEYPOT DECOYS${RESET:-}"
    echo ""

    # Default locations if none configured
    local locations=("${DECOY_LOCATIONS[@]:-}")
    if [[ ${#locations[@]} -eq 0 ]] || [[ -z "${locations[0]:-}" ]]; then
        locations=(
            "$HOME/.config/backup"
            "$HOME/.ssh_backup"
            "$HOME/Documents/.vault"
        )
    fi

    # Expand ~ and $HOME
    local expanded_locations=()
    for loc in "${locations[@]}"; do
        expanded_locations+=("$(eval echo "$loc")")
    done

    : > "$MANIFEST"
    : > "$HASHES"

    for base_dir in "${expanded_locations[@]}"; do
        _info "Creating decoys in ${base_dir}"

        generate_crypto_wallet "${base_dir}/crypto"
        generate_passwords_file "${base_dir}"
        generate_env_backup "${base_dir}"
        generate_ssh_keys "${base_dir}/.ssh"
        generate_aws_credentials "${base_dir}/.aws"

        # Record all files
        find "$base_dir" -type f 2>/dev/null | while read -r f; do
            echo "$f" >> "$MANIFEST"
            # Store hash + mtime for tamper detection
            local hash mtime
            hash=$(shasum -a 256 "$f" 2>/dev/null | awk '{print $1}')
            if [[ "$(uname)" == "Darwin" ]]; then
                mtime=$(stat -f %m "$f" 2>/dev/null)
            else
                mtime=$(stat -c %Y "$f" 2>/dev/null)
            fi
            printf '%s\t%s\t%s\n' "$hash" "$mtime" "$f" >> "$HASHES"
        done

        # Stagger modification times to look natural
        if [[ "$(uname)" == "Darwin" ]]; then
            # macOS touch format
            touch -t 202509140234 "${base_dir}/crypto/wallet_backup.dat" 2>/dev/null || true
            touch -t 202510281400 "${base_dir}/.env.backup" 2>/dev/null || true
            touch -t 202511031022 "${base_dir}/passwords.txt" 2>/dev/null || true
            touch -t 202508190900 "${base_dir}/.ssh/id_rsa_backup" 2>/dev/null || true
            touch -t 202507221630 "${base_dir}/.aws/credentials" 2>/dev/null || true
        else
            # Linux touch format
            touch -d "2025-09-14 02:34" "${base_dir}/crypto/wallet_backup.dat" 2>/dev/null || true
            touch -d "2025-10-28 14:00" "${base_dir}/.env.backup" 2>/dev/null || true
            touch -d "2025-11-03 10:22" "${base_dir}/passwords.txt" 2>/dev/null || true
            touch -d "2025-08-19 09:00" "${base_dir}/.ssh/id_rsa_backup" 2>/dev/null || true
            touch -d "2025-07-22 16:30" "${base_dir}/.aws/credentials" 2>/dev/null || true
        fi
    done

    local total
    total=$(wc -l < "$MANIFEST" | tr -d ' ')
    _pass "Deployed ${total} decoy files across ${#expanded_locations[@]} locations"
    _log "Deployed ${total} decoys"
}

# ----------------------------------------------------------------------------
# WATCH — Monitor decoys for access
# ----------------------------------------------------------------------------

watch_decoys() {
    if [[ ! -f "$MANIFEST" ]]; then
        echo "No decoys deployed. Run: sentinel deploy"
        exit 1
    fi

    echo -e "\n${BOLD:-}  TRIPWIRE — Watching decoys${RESET:-}"
    echo -e "  ${DIM:-}Press Ctrl+C to stop${RESET:-}"
    echo ""

    local dirs=()
    while IFS= read -r f; do
        local d
        d="$(dirname "$f")"
        # Deduplicate
        local found=0
        for existing in "${dirs[@]:-}"; do
            [[ "$existing" == "$d" ]] && found=1 && break
        done
        (( found == 0 )) && dirs+=("$d")
    done < "$MANIFEST"

    # Prefer fswatch (macOS) or inotifywait (Linux)
    if command -v fswatch &>/dev/null; then
        _info "Using fswatch (realtime monitoring)"
        fswatch -r "${dirs[@]}" | while IFS= read -r touched_file; do
            # Is it one of our decoys?
            if grep -qF "$touched_file" "$MANIFEST" 2>/dev/null; then
                local opener
                opener="$(lsof "$touched_file" 2>/dev/null | tail -1 | awk '{print $1, $2}')" || true
                _alert "Decoy touched: ${touched_file} (by: ${opener:-unknown})"
            fi
        done
    elif command -v inotifywait &>/dev/null; then
        _info "Using inotifywait (realtime monitoring)"
        inotifywait -m -r -e access,modify,open "${dirs[@]}" 2>/dev/null | while IFS= read -r line; do
            local touched_file
            touched_file="$(echo "$line" | awk '{print $1$3}')"
            if grep -qF "$touched_file" "$MANIFEST" 2>/dev/null; then
                _alert "Decoy touched: ${touched_file}"
            fi
        done
    else
        _warn "Neither fswatch nor inotifywait found. Using polling (less responsive)."
        _info "Install fswatch: brew install fswatch (macOS) or apt install inotify-tools (Linux)"
        echo ""

        # Polling fallback: check hashes and mtimes
        while true; do
            check_decoys_once
            sleep "${DECOY_POLL_INTERVAL}"
        done
    fi
}

# ----------------------------------------------------------------------------
# CHECK — One-time decoy integrity check
# ----------------------------------------------------------------------------

check_decoys_once() {
    if [[ ! -f "$HASHES" ]]; then
        echo "No decoy hashes recorded. Run: sentinel deploy"
        return 1
    fi

    local tampered=0
    while IFS=$'\t' read -r orig_hash orig_mtime filepath; do
        if [[ ! -f "$filepath" ]]; then
            _alert "Decoy MISSING: ${filepath}"
            tampered=$((tampered + 1))
            continue
        fi

        local current_hash current_mtime
        current_hash=$(shasum -a 256 "$filepath" 2>/dev/null | awk '{print $1}')
        if [[ "$(uname)" == "Darwin" ]]; then
            current_mtime=$(stat -f %m "$filepath" 2>/dev/null)
        else
            current_mtime=$(stat -c %Y "$filepath" 2>/dev/null)
        fi

        if [[ "$current_hash" != "$orig_hash" ]]; then
            _alert "Decoy MODIFIED: ${filepath} (hash changed)"
            tampered=$((tampered + 1))
        elif [[ "$current_mtime" != "$orig_mtime" ]]; then
            _alert "Decoy TOUCHED: ${filepath} (mtime changed)"
            tampered=$((tampered + 1))
        fi
    done < "$HASHES"

    if (( tampered == 0 )); then
        _pass "All decoys intact"
    else
        _fail "${tampered} decoy(s) tampered with"
    fi

    return $tampered
}

# ----------------------------------------------------------------------------
# LIST — Show deployed decoys
# ----------------------------------------------------------------------------

list_decoys() {
    if [[ ! -f "$MANIFEST" ]]; then
        echo "No decoys deployed."
        return
    fi

    echo -e "\n${BOLD:-}  DEPLOYED DECOYS${RESET:-}"
    echo ""
    while IFS= read -r f; do
        if [[ -f "$f" ]]; then
            echo -e "  ${GREEN:-}+${RESET:-} ${f}"
        else
            echo -e "  ${RED:-}x${RESET:-} ${f} (missing)"
        fi
    done < "$MANIFEST"
    echo ""
    local total
    total=$(wc -l < "$MANIFEST" | tr -d ' ')
    _info "${total} decoy files total"
}

# ----------------------------------------------------------------------------
# CLEAN — Remove all decoys
# ----------------------------------------------------------------------------

clean_decoys() {
    if [[ ! -f "$MANIFEST" ]]; then
        echo "No decoys to clean."
        return
    fi

    echo -e "\n${BOLD:-}  REMOVING DECOYS${RESET:-}"
    local removed=0
    while IFS= read -r f; do
        if [[ -f "$f" ]]; then
            rm "$f"
            removed=$((removed + 1))
        fi
    done < "$MANIFEST"

    # Clean empty directories
    while IFS= read -r f; do
        local d
        d="$(dirname "$f")"
        rmdir "$d" 2>/dev/null || true
    done < "$MANIFEST"

    rm -f "$MANIFEST" "$HASHES"
    _pass "Removed ${removed} decoy files"
}

# ----------------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------------

case "${1:-watch}" in
    deploy)  deploy_decoys ;;
    watch)   watch_decoys ;;
    check)   check_decoys_once ;;
    list)    list_decoys ;;
    clean)   clean_decoys ;;
    *)
        echo "Usage: tripwire.sh {deploy|watch|check|list|clean}"
        exit 1
        ;;
esac
