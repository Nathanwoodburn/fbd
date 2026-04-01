#!/usr/bin/env bash
#
# macos.sh - build fbd and install binaries on macOS.
#
# Usage:
#   ./install/macos.sh                  # install to /usr/local/bin (needs sudo)
#   ./install/macos.sh --prefix ~/bin   # install to ~/bin (no sudo)
#
# Requires Xcode or Command Line Tools (Swift 6.2+).

set -euo pipefail

PREFIX="/usr/local/bin"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --prefix DIR   Install binaries to DIR (default: /usr/local/bin)"
            echo "  -h, --help     Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Colors (if terminal)
if [ -t 1 ]; then
    BOLD='\033[1m'
    GREEN='\033[32m'
    CYAN='\033[36m'
    RED='\033[31m'
    RESET='\033[0m'
else
    BOLD='' GREEN='' CYAN='' RED='' RESET=''
fi

info()  { echo -e "${BOLD}${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
ok()    { echo -e "${GREEN} ok${RESET} $*"; }
err()   { echo -e "${RED}error:${RESET} $*" >&2; }
die()   { err "$@"; exit 1; }

# Check for Swift
if ! command -v swift &>/dev/null; then
    die "Swift not found. Install Xcode or Command Line Tools: xcode-select --install"
fi

swift_version=$(swift --version 2>&1 | head -1)
ok "$swift_version"

# Find repo root
script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_dir="$(cd "${script_dir}/.." && pwd)"

if [ ! -f "${repo_dir}/Package.swift" ]; then
    die "cannot find Package.swift - run this script from the fbd repository"
fi

# Build
cd "${repo_dir}"

# Generate build info (git hash)
HASH=$(git -C "${repo_dir}" rev-parse --short=7 HEAD 2>/dev/null || echo "unknown")
echo "/// Auto-generated at build time — do not edit." > "${repo_dir}/Sources/Base/BuildInfo.swift"
echo "let _buildHash: String = \"${HASH}\"" >> "${repo_dir}/Sources/Base/BuildInfo.swift"

info "Resolving dependencies..."
swift package resolve
ok "dependencies resolved"

info "Building fbd (release)..."
set +e
swift build -c release
rc=$?
set -e

if [ $rc -ne 0 ]; then
    die "build failed"
fi

build_dir="${repo_dir}/.build/release"
if [ ! -f "${build_dir}/fbd" ] || [ ! -f "${build_dir}/fbdctl" ]; then
    die "build failed - fbd or fbdctl binary not found"
fi

ok "build complete"

# Install
info "Installing to ${PREFIX}..."
mkdir -p "${PREFIX}"

if [ -w "${PREFIX}" ]; then
    cp "${build_dir}/fbd" "${PREFIX}/fbd"
    cp "${build_dir}/fbdctl" "${PREFIX}/fbdctl"
else
    sudo cp "${build_dir}/fbd" "${PREFIX}/fbd"
    sudo cp "${build_dir}/fbdctl" "${PREFIX}/fbdctl"
fi

ok "fbd    -> ${PREFIX}/fbd"
ok "fbdctl -> ${PREFIX}/fbdctl"

echo ""
echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
echo ""
echo "  fbd    - Fistbump full node"
echo "  fbdctl - JSON-RPC client"
echo ""
echo "  Start:  fbd --network main"
echo "  Help:   fbd --help"
echo ""
