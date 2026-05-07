#!/usr/bin/env bash
# ============================================================================
# SENTINEL INSTALLER
# ============================================================================
# One command: curl -fsSL https://raw.githubusercontent.com/LacobusGump/sentinel/main/install.sh | bash
#
# What this does:
#   1. Clones the repo (or downloads if git unavailable)
#   2. Makes scripts executable
#   3. Adds 'sentinel' to your PATH
#   4. Runs a first baseline
#   5. Deploys honeypot decoy files
#   6. Tells you what it found
#
# What this does NOT do:
#   - Send any data anywhere
#   - Install any daemons without asking
#   - Modify system files
#   - Require root/sudo (except for firewall fixes, which it asks first)
# ============================================================================

set -euo pipefail

INSTALL_DIR="${SENTINEL_INSTALL_DIR:-$HOME/.sentinel-app}"
REPO_URL="https://github.com/LacobusGump/sentinel.git"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
BOLD='\033[1m'
DIM='\033[2m'
RESET='\033[0m'

echo ""
echo -e "${BOLD}  SENTINEL INSTALLER${RESET}"
echo -e "  ${DIM}Free. Local. No cloud. No subscription.${RESET}"
echo ""

# --- PLATFORM CHECK ---

PLATFORM="$(uname -s)"
case "$PLATFORM" in
    Darwin)
        echo -e "  ${GREEN}[OK]${RESET}  macOS detected (full support)"
        ;;
    Linux)
        echo -e "  ${GREEN}[OK]${RESET}  Linux detected (full support)"
        ;;
    MINGW*|MSYS*|CYGWIN*)
        echo -e "  ${RED}[!!]${RESET}  Windows detected."
        echo ""
        echo "  Sentinel is bash-only and does not support Windows."
        echo "  Options:"
        echo "    - Use WSL (Windows Subsystem for Linux)"
        echo "    - Run in a Linux VM"
        echo "    - Use macOS or Linux"
        echo ""
        exit 1
        ;;
    *)
        echo -e "  ${YELLOW}[??]${RESET}  Unknown platform: $PLATFORM"
        echo "  Proceeding anyway..."
        ;;
esac

# --- DOWNLOAD ---

if [[ -d "$INSTALL_DIR" ]]; then
    echo -e "  ${BLUE}[..]${RESET}  Existing install found. Updating..."
    if [[ -d "$INSTALL_DIR/.git" ]]; then
        cd "$INSTALL_DIR" && git pull --quiet 2>/dev/null || true
    fi
else
    if command -v git &>/dev/null; then
        echo -e "  ${BLUE}[..]${RESET}  Cloning sentinel..."
        git clone --quiet "$REPO_URL" "$INSTALL_DIR" 2>/dev/null || {
            echo -e "  ${YELLOW}[!!]${RESET}  Git clone failed. Trying curl..."
            mkdir -p "$INSTALL_DIR"
            curl -fsSL "https://github.com/LacobusGump/sentinel/archive/refs/heads/main.tar.gz" | tar xz -C "$INSTALL_DIR" --strip-components=1
        }
    elif command -v curl &>/dev/null; then
        echo -e "  ${BLUE}[..]${RESET}  Downloading sentinel..."
        mkdir -p "$INSTALL_DIR"
        curl -fsSL "https://github.com/LacobusGump/sentinel/archive/refs/heads/main.tar.gz" | tar xz -C "$INSTALL_DIR" --strip-components=1
    else
        echo -e "  ${RED}[!!]${RESET}  Neither git nor curl found. Cannot download."
        exit 1
    fi
fi

echo -e "  ${GREEN}[OK]${RESET}  Installed to ${INSTALL_DIR}"

# --- MAKE EXECUTABLE ---

chmod +x "$INSTALL_DIR/sentinel.sh"
chmod +x "$INSTALL_DIR/modules/"*.sh 2>/dev/null || true
chmod +x "$INSTALL_DIR/install.sh"

echo -e "  ${GREEN}[OK]${RESET}  Scripts made executable"

# --- ADD TO PATH ---

SENTINEL_BIN="$HOME/.local/bin"
mkdir -p "$SENTINEL_BIN"

# Create a symlink or wrapper
cat > "$SENTINEL_BIN/sentinel" << WRAPPER
#!/usr/bin/env bash
exec "${INSTALL_DIR}/sentinel.sh" "\$@"
WRAPPER
chmod +x "$SENTINEL_BIN/sentinel"

# Check if PATH includes ~/.local/bin
if ! echo "$PATH" | grep -q "$SENTINEL_BIN"; then
    echo ""
    echo -e "  ${YELLOW}[!!]${RESET}  Add this to your shell profile (~/.zshrc or ~/.bashrc):"
    echo ""
    echo "    export PATH=\"\$HOME/.local/bin:\$PATH\""
    echo ""
    echo "  Then restart your terminal, or run:"
    echo "    source ~/.zshrc"
    echo ""

    # Offer to do it automatically
    SHELL_RC=""
    if [[ -f "$HOME/.zshrc" ]]; then
        SHELL_RC="$HOME/.zshrc"
    elif [[ -f "$HOME/.bashrc" ]]; then
        SHELL_RC="$HOME/.bashrc"
    elif [[ -f "$HOME/.bash_profile" ]]; then
        SHELL_RC="$HOME/.bash_profile"
    fi

    if [[ -n "$SHELL_RC" ]]; then
        if ! grep -q '.local/bin' "$SHELL_RC" 2>/dev/null; then
            read -r -p "  Add to ${SHELL_RC} automatically? [y/N] " response
            if [[ "$response" =~ ^[Yy]$ ]]; then
                echo '' >> "$SHELL_RC"
                echo '# Sentinel security tool' >> "$SHELL_RC"
                echo 'export PATH="$HOME/.local/bin:$PATH"' >> "$SHELL_RC"
                echo -e "  ${GREEN}[OK]${RESET}  Added to ${SHELL_RC}"
            fi
        fi
    fi
else
    echo -e "  ${GREEN}[OK]${RESET}  'sentinel' command available in PATH"
fi

# --- CHECK DEPENDENCIES ---

echo ""
echo -e "  ${BOLD}Checking dependencies...${RESET}"

# fswatch (macOS) or inotifywait (Linux) — needed for realtime tripwire
if [[ "$PLATFORM" == "Darwin" ]]; then
    if command -v fswatch &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET}  fswatch found (realtime file monitoring)"
    else
        echo -e "  ${YELLOW}[!!]${RESET}  fswatch not found. Tripwire will use polling (slower)."
        echo "        Install: brew install fswatch"
    fi
elif [[ "$PLATFORM" == "Linux" ]]; then
    if command -v inotifywait &>/dev/null; then
        echo -e "  ${GREEN}[OK]${RESET}  inotifywait found (realtime file monitoring)"
    else
        echo -e "  ${YELLOW}[!!]${RESET}  inotifywait not found. Tripwire will use polling (slower)."
        echo "        Install: sudo apt install inotify-tools"
    fi
fi

# lsof — needed for port scanning
if command -v lsof &>/dev/null; then
    echo -e "  ${GREEN}[OK]${RESET}  lsof found (port scanning)"
else
    echo -e "  ${YELLOW}[!!]${RESET}  lsof not found. Port checks will be limited."
fi

# --- FIRST RUN ---

echo ""
echo -e "  ${BOLD}Running first scan...${RESET}"
echo ""

# Run baseline
"$INSTALL_DIR/sentinel.sh" baseline

# Deploy decoys
"$INSTALL_DIR/sentinel.sh" deploy 2>/dev/null || true

echo ""
echo -e "  ${BOLD}  SENTINEL INSTALLED${RESET}"
echo ""
echo "  Commands:"
echo "    sentinel              Full security report"
echo "    sentinel audit        Deep security audit"
echo "    sentinel watch        Continuous monitoring"
echo "    sentinel ports        Check open ports"
echo "    sentinel connections  Monitor connections"
echo "    sentinel firewall     Check firewall"
echo "    sentinel status       Quick status"
echo "    sentinel deploy       Deploy honeypot decoys"
echo "    sentinel help         All commands"
echo ""
echo -e "  ${DIM}Your computer is open right now and you don't know it.${RESET}"
echo -e "  ${DIM}Now you will.${RESET}"
echo ""
