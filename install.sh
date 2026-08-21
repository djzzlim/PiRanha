#!/bin/sh
set -e

# PiRanha installer — installs the `piranha` launcher binary.
# Usage: curl -fsSL https://raw.githubusercontent.com/djzzlim/PiRanha/main/install.sh | sh
#
# Options:
#   --source       Build from source via bun (installs bun if needed)
#   --binary       Always install the prebuilt binary
#   --ref <ref>    Install a specific tag/commit/branch
#   -r <ref>       Shorthand for --ref
#
# After install, run `piranha doctor`, then `piranha install` to register the
# swarm skill with your harness (omp / pi or Claude Code).

REPO="${PIRANHA_REPO:-djzzlim/PiRanha}"
INSTALL_DIR="${PIRANHA_INSTALL_DIR:-$HOME/.local/bin}"
MIN_BUN_VERSION="1.3.14"

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

MODE=""
REF=""
while [ $# -gt 0 ]; do
    case "$1" in
        --source) MODE="source"; shift ;;
        --binary) MODE="binary"; shift ;;
        --ref)
            shift
            [ -z "$1" ] && { echo "Missing value for --ref"; exit 1; }
            REF="$1"; shift ;;
        --ref=*)
            REF="${1#*=}"
            [ -z "$REF" ] && { echo "Missing value for --ref"; exit 1; }
            shift ;;
        -r)
            shift
            [ -z "$1" ] && { echo "Missing value for -r"; exit 1; }
            REF="$1"; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

# A ref implies source install (releases are only cut for tags).
if [ -n "$REF" ] && [ -z "$MODE" ]; then
    MODE="source"
fi

printf "${CYAN}${BOLD}"
cat <<'BANNER'
██████╗ ██╗██████╗  █████╗ ███╗   ██╗██╗  ██╗ █████╗
██╔══██╗██║██╔══██╗██╔══██╗████╗  ██║██║  ██║██╔══██╗
██████╔╝██║██████╔╝███████║██╔██╗ ██║███████║███████║
██╔═══╝ ██║██╔══██╗██╔══██║██║╚██╗██║██╔══██║██╔══██║
██║     ██║██║  ██║██║  ██║██║ ╚████║██║  ██║██║  ██║
╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚═╝  ╚═╝
BANNER
printf "${NC}${BOLD}  🐟 PiRanha — the autonomous bug-bounty swarm${NC}\n\n"

has_bun() { command -v bun >/dev/null 2>&1; }
has_git() { command -v git >/dev/null 2>&1; }

version_ge() {
    current="$1"; minimum="$2"
    current_major="${current%%.*}"; current_rest="${current#*.}"
    current_minor="${current_rest%%.*}"; current_patch="${current_rest#*.}"; current_patch="${current_patch%%.*}"
    minimum_major="${minimum%%.*}"; minimum_rest="${minimum#*.}"
    minimum_minor="${minimum_rest%%.*}"; minimum_patch="${minimum_rest#*.}"; minimum_patch="${minimum_patch%%.*}"
    if [ "$current_major" -ne "$minimum_major" ]; then [ "$current_major" -gt "$minimum_major" ]; return $?; fi
    if [ "$current_minor" -ne "$minimum_minor" ]; then [ "$current_minor" -gt "$minimum_minor" ]; return $?; fi
    [ "$current_patch" -ge "$minimum_patch" ]
}

require_bun_version() {
    version_raw=$(bun --version 2>/dev/null || true)
    [ -z "$version_raw" ] && { echo "Failed to read bun version"; exit 1; }
    version_clean=${version_raw%%-*}
    if ! version_ge "$version_clean" "$MIN_BUN_VERSION"; then
        echo "Bun ${MIN_BUN_VERSION} or newer is required (found ${version_clean})."
        echo "Upgrade Bun: https://bun.sh/docs/installation"
        exit 1
    fi
}

install_bun() {
    echo "Installing bun..."
    if command -v bash >/dev/null 2>&1; then
        curl -fsSL https://bun.sh/install | bash
    else
        curl -fsSL https://bun.sh/install | sh
    fi
    export BUN_INSTALL="$HOME/.bun"
    export PATH="$BUN_INSTALL/bin:$PATH"
    require_bun_version
}

check_path() {
    case ":$PATH:" in
        *":$INSTALL_DIR:"*) : ;;
        *) printf "\n${BOLD}NOTE:${NC} ${INSTALL_DIR} is not on your PATH. Add it:\n  export PATH=\"${INSTALL_DIR}:\$PATH\"\n" ;;
    esac
}

install_from_source() {
    echo "Building piranha from source via bun..."
    has_git || { echo "git is required for the source install"; exit 1; }

    TMP_DIR="$(mktemp -d)"
    trap 'rm -rf "$TMP_DIR"' EXIT

    if [ -n "$REF" ]; then
        if git clone --depth 1 --branch "$REF" "https://github.com/${REPO}.git" "$TMP_DIR" >/dev/null 2>&1; then
            :
        else
            git clone "https://github.com/${REPO}.git" "$TMP_DIR"
            (cd "$TMP_DIR" && git checkout "$REF")
        fi
    else
        git clone --depth 1 "https://github.com/${REPO}.git" "$TMP_DIR"
    fi

    [ -f "$TMP_DIR/cli/piranha.ts" ] || { echo "Expected launcher at ${TMP_DIR}/cli/piranha.ts"; exit 1; }

    mkdir -p "$INSTALL_DIR"
    echo "Compiling piranha -> ${INSTALL_DIR}/piranha ..."
    ( cd "$TMP_DIR" && bun build ./cli/piranha.ts --compile --outfile "${INSTALL_DIR}/piranha" ) \
        || { echo "Compile failed"; exit 1; }
    chmod +x "${INSTALL_DIR}/piranha"
    printf "\n${GREEN}✓ Compiled and installed piranha to ${INSTALL_DIR}/piranha${NC}\n"

    check_path
}

install_binary() {
    OS="$(uname -s)"; ARCH="$(uname -m)"
    case "$OS" in
        Linux)  PLATFORM="linux" ;;
        Darwin) PLATFORM="darwin" ;;
        *) echo "Unsupported OS: $OS (use --source, or install.ps1 on Windows)"; exit 1 ;;
    esac
    case "$ARCH" in
        x86_64|amd64)  ARCH="x64" ;;
        arm64|aarch64) ARCH="arm64" ;;
        *) echo "Unsupported architecture: $ARCH"; exit 1 ;;
    esac

    BINARY="piranha-${PLATFORM}-${ARCH}"
    if [ -n "$REF" ]; then
        echo "Fetching release $REF..."
        RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/tags/${REF}") || {
            echo "Release tag not found: $REF (for a branch/commit, use --source --ref)"; exit 1; }
    else
        echo "Fetching latest release..."
        RELEASE_JSON=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest")
    fi
    LATEST=$(echo "$RELEASE_JSON" | grep '"tag_name"' | sed -E 's/.*"([^"]+)".*/\1/')
    [ -z "$LATEST" ] && { echo "Failed to fetch release tag"; exit 1; }
    echo "Using version: $LATEST"

    mkdir -p "$INSTALL_DIR"
    BINARY_URL="https://github.com/${REPO}/releases/download/${LATEST}/${BINARY}"
    echo "Downloading ${BINARY}..."
    curl -fsSL "$BINARY_URL" -o "${INSTALL_DIR}/piranha"
    chmod +x "${INSTALL_DIR}/piranha"
    printf "\n${GREEN}✓ Installed piranha to ${INSTALL_DIR}/piranha${NC}\n"

    check_path
}

case "$MODE" in
    source)
        has_bun || install_bun
        require_bun_version
        install_from_source
        ;;
    binary)
        install_binary
        ;;
    *)
        if has_bun; then
            require_bun_version
            install_from_source
        else
            install_binary
        fi
        ;;
esac

printf "\n${BOLD}Next steps:${NC}\n"
printf "  ${CYAN}1.${NC} Verify your environment:   ${BOLD}piranha doctor${NC}\n"
printf "  ${CYAN}2.${NC} Register the swarm skill:   ${BOLD}piranha install${NC}\n"
printf "  ${CYAN}3.${NC} Hunt:                       ${BOLD}piranha hunt https://your-target.com${NC}\n\n"
printf "${RED}${BOLD}Authorized testing only.${NC} Configure scope before hunting.\n\n"
