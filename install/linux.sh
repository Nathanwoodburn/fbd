#!/usr/bin/env bash
#
# linux.sh — download Swift, build fbd, and install binaries on Linux.
#
# Usage:
#   ./install/linux.sh                  # install to /usr/local/bin (needs sudo)
#   ./install/linux.sh --prefix ~/bin   # install to ~/bin (no sudo)
#   ./install/linux.sh --deps-only      # install system deps + Swift, skip build
#

set -euo pipefail

SWIFT_VERSION="6.2.3"
SWIFT_TAG="swift-${SWIFT_VERSION}-RELEASE"
SWIFT_INSTALL_DIR="/usr/local/swift"
PREFIX="/usr/local/bin"
DEPS_ONLY=false
SKIP_SWIFT=false

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --prefix)
            PREFIX="$2"
            shift 2
            ;;
        --swift-version)
            SWIFT_VERSION="$2"
            SWIFT_TAG="swift-${SWIFT_VERSION}-RELEASE"
            shift 2
            ;;
        --deps-only)
            DEPS_ONLY=true
            shift
            ;;
        --skip-swift)
            SKIP_SWIFT=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --prefix DIR        Install binaries to DIR (default: /usr/local/bin)"
            echo "  --swift-version VER Swift version to install (default: ${SWIFT_VERSION})"
            echo "  --deps-only         Install dependencies and Swift only, skip build"
            echo "  --skip-swift        Skip Swift installation (already installed)"
            echo "  -h, --help          Show this help"
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
    DIM='\033[2m'
    GREEN='\033[32m'
    CYAN='\033[36m'
    RED='\033[31m'
    RESET='\033[0m'
else
    BOLD='' DIM='' GREEN='' CYAN='' RED='' RESET=''
fi

info()  { echo -e "${BOLD}${CYAN}==>${RESET} ${BOLD}$*${RESET}"; }
ok()    { echo -e "${GREEN} ok${RESET} $*"; }
err()   { echo -e "${RED}error:${RESET} $*" >&2; }
die()   { err "$@"; exit 1; }

# Detect architecture
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  ;;
    aarch64) ;;
    arm64)   ARCH="aarch64" ;;
    *)       die "unsupported architecture: $ARCH" ;;
esac

# Detect distro
detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO_ID="${ID}"
        DISTRO_VERSION="${VERSION_ID}"
        DISTRO_NAME="${PRETTY_NAME}"
    else
        die "cannot detect Linux distribution (no /etc/os-release)"
    fi
}

# Map distro to Swift platform slug
swift_platform() {
    case "${DISTRO_ID}" in
        ubuntu)
            case "${DISTRO_VERSION}" in
                20.04) echo "ubuntu2004" ;;
                22.04) echo "ubuntu2204" ;;
                24.04) echo "ubuntu2404" ;;
                *)     echo "ubuntu2404" ;; # newer versions use latest supported Swift build
            esac
            ;;
        debian)
            case "${DISTRO_VERSION}" in
                12) echo "debian12" ;;
                *)  die "unsupported Debian version: ${DISTRO_VERSION} (need 12)" ;;
            esac
            ;;
        fedora)
            if [ "${DISTRO_VERSION}" -ge 39 ] 2>/dev/null; then
                echo "fedora39"
            else
                die "unsupported Fedora version: ${DISTRO_VERSION} (need 39+)"
            fi
            ;;
        amzn)
            echo "amazonlinux2"
            ;;
        rhel|centos)
            echo "ubi9"
            ;;
        *)
            die "unsupported distribution: ${DISTRO_ID}. Supported: ubuntu, debian, fedora, amzn, rhel"
            ;;
    esac
}

# Install system dependencies
install_deps() {
    info "Installing system dependencies for ${DISTRO_NAME}..."

    case "${DISTRO_ID}" in
        ubuntu|debian)
            sudo apt-get update -qq
            sudo apt-get install -y -qq \
                binutils git gnupg2 libc6-dev libcurl4-openssl-dev libedit2 \
                libgcc-13-dev libncurses-dev libpython3-dev libsqlite3-0 \
                libstdc++-13-dev libxml2-dev libz3-dev pkg-config tzdata \
                zip unzip zlib1g-dev curl 2>/dev/null || \
            sudo apt-get install -y -qq \
                binutils git gnupg2 libc6-dev libcurl4-openssl-dev libedit2 \
                libgcc-12-dev libncurses-dev libpython3-dev libsqlite3-0 \
                libstdc++-12-dev libxml2-dev libz3-dev pkg-config tzdata \
                zip unzip zlib1g-dev curl
            ;;
        fedora|rhel|centos)
            sudo dnf install -y \
                binutils gcc git libcurl-devel libedit-devel libicu-devel \
                libuuid-devel libxml2-devel python3-devel sqlite-devel \
                zip unzip curl
            ;;
        amzn)
            sudo yum install -y \
                binutils gcc git libcurl-devel libedit-devel libicu-devel \
                libuuid-devel libxml2-devel python3-devel sqlite-devel \
                tar gzip curl
            ;;
    esac
    ok "system dependencies installed"
}

# Download and install Swift
install_swift() {
    # Check if Swift is already installed at the expected location
    if [ -x "${SWIFT_INSTALL_DIR}/usr/bin/swift" ]; then
        export PATH="${SWIFT_INSTALL_DIR}/usr/bin:${PATH}"
    fi
    if command -v swift &>/dev/null; then
        local current
        current=$(swift --version 2>&1 | head -1 | grep -oE '[0-9]+\.[0-9]+(\.[0-9]+)?' | head -1 || true)
        if [ "${current}" = "${SWIFT_VERSION}" ]; then
            ok "Swift ${SWIFT_VERSION} already installed"
            return
        fi
        info "Found Swift ${current}, installing ${SWIFT_VERSION}..."
    fi

    local platform
    platform=$(swift_platform)

    # Map distro to Swift filename component
    local swift_distro_version="${DISTRO_VERSION}"
    case "${DISTRO_ID}" in
        ubuntu)
            # Newer Ubuntu versions use latest supported Swift build
            case "${DISTRO_VERSION}" in
                20.04|22.04|24.04) ;;
                *) swift_distro_version="24.04" ;;
            esac
            ;;
    esac

    local filename="${SWIFT_TAG}-${DISTRO_ID}${swift_distro_version}"
    case "${DISTRO_ID}" in
        ubuntu) filename="${SWIFT_TAG}-ubuntu${swift_distro_version}" ;;
        debian) filename="${SWIFT_TAG}-debian${DISTRO_VERSION}" ;;
        fedora) filename="${SWIFT_TAG}-fedora39" ;;
        amzn)   filename="${SWIFT_TAG}-amazonlinux2" ;;
        rhel|centos) filename="${SWIFT_TAG}-ubi9" ;;
    esac

    # aarch64 uses a different filename and platform path suffix
    if [ "$ARCH" = "aarch64" ]; then
        filename="${filename}-aarch64"
        platform="${platform}-aarch64"
    fi

    local url="https://download.swift.org/swift-${SWIFT_VERSION}-release/${platform}/${SWIFT_TAG}/${filename}.tar.gz"

    info "Downloading Swift ${SWIFT_VERSION} for ${DISTRO_ID} ${DISTRO_VERSION} (${ARCH})..."
    echo "  ${url}"

    local tmpdir
    tmpdir=$(mktemp -d)
    trap "rm -rf ${tmpdir}" EXIT

    curl -fSL --progress-bar -o "${tmpdir}/swift.tar.gz" "${url}" \
        || die "download failed — check that Swift ${SWIFT_VERSION} supports ${DISTRO_ID} ${DISTRO_VERSION} (${ARCH})"

    info "Installing Swift to ${SWIFT_INSTALL_DIR}..."
    # Remove old install to avoid leftover files from previous versions
    if [ -d "${SWIFT_INSTALL_DIR}" ]; then
        sudo rm -rf "${SWIFT_INSTALL_DIR}"
    fi
    sudo mkdir -p "${SWIFT_INSTALL_DIR}"
    sudo tar xzf "${tmpdir}/swift.tar.gz" -C "${SWIFT_INSTALL_DIR}" --strip-components=1

    # Add to PATH if not already there
    if ! echo "$PATH" | grep -q "${SWIFT_INSTALL_DIR}/usr/bin"; then
        export PATH="${SWIFT_INSTALL_DIR}/usr/bin:${PATH}"

        # Persist in profile
        local profile_line="export PATH=${SWIFT_INSTALL_DIR}/usr/bin:\$PATH"
        for rc in "${HOME}/.bashrc" "${HOME}/.profile"; do
            if [ -f "$rc" ] && ! grep -qF "${SWIFT_INSTALL_DIR}/usr/bin" "$rc"; then
                echo "$profile_line" >> "$rc"
                info "Added Swift to PATH in $(basename $rc)"
                break
            fi
        done
    fi

    ok "Swift $(swift --version 2>&1 | head -1)"
}

# Build fbd
build_fbd() {
    # Find the repo root (install.sh is in install/)
    local script_dir
    script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    local repo_dir
    repo_dir="$(cd "${script_dir}/.." && pwd)"

    if [ ! -f "${repo_dir}/Package.swift" ]; then
        die "cannot find Package.swift — run this script from the fbd repository"
    fi

    cd "${repo_dir}"

    # Clean stale build artifacts if Swift version changed
    if [ -d .build ] && [ -f .build/.swift-version ]; then
        local built_with
        built_with=$(cat .build/.swift-version 2>/dev/null || true)
        local current_swift
        current_swift=$(swift --version 2>&1 | head -1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1 || true)
        if [ -n "$built_with" ] && [ "$built_with" != "$current_swift" ]; then
            info "Swift version changed ($built_with → $current_swift), cleaning build..."
            swift package clean
        fi
    fi

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
    local rc=$?
    set -e || true

    if [ $rc -ne 0 ]; then
        die "build failed"
    fi

    # Record which Swift version built this
    swift --version 2>&1 | head -1 | grep -oP '\d+\.\d+(\.\d+)?' | head -1 > .build/.swift-version 2>/dev/null || true

    local build_dir="${repo_dir}/.build/release"
    if [ ! -f "${build_dir}/fbd" ] || [ ! -f "${build_dir}/fbdctl" ]; then
        die "build failed — fbd or fbdctl binary not found"
    fi

    ok "build complete"

    # Install binaries
    info "Installing to ${PREFIX}..."
    mkdir -p "${PREFIX}"

    if [ -w "${PREFIX}" ]; then
        cp "${build_dir}/fbd" "${PREFIX}/fbd"
        cp "${build_dir}/fbdctl" "${PREFIX}/fbdctl"
    else
        sudo cp "${build_dir}/fbd" "${PREFIX}/fbd"
        sudo cp "${build_dir}/fbdctl" "${PREFIX}/fbdctl"
    fi

    ok "fbd    → ${PREFIX}/fbd"
    ok "fbdctl → ${PREFIX}/fbdctl"
}

# Main
main() {
    echo ""
    echo -e "${BOLD}fbd installer${RESET}"
    echo ""

    detect_distro
    info "Detected: ${DISTRO_NAME} (${ARCH})"

    install_deps

    if [ "$SKIP_SWIFT" = false ]; then
        install_swift
    else
        if ! command -v swift &>/dev/null; then
            die "swift not found in PATH (--skip-swift was set)"
        fi
        ok "using existing Swift: $(swift --version 2>&1 | head -1)"
    fi

    if [ "$DEPS_ONLY" = true ]; then
        echo ""
        ok "dependencies installed. Run 'swift build -c release' to build."
        exit 0
    fi

    build_fbd

    echo ""
    echo -e "${GREEN}${BOLD}Installation complete!${RESET}"
    echo ""
    echo "  fbd    — Fistbump full node"
    echo "  fbdctl — JSON-RPC client"
    echo ""
    echo "  Start:  fbd --network main"
    echo "  Help:   fbd --help"
    echo ""
}

main
