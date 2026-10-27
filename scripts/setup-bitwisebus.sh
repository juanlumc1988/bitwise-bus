#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.
#
# Prepares an Ubuntu 24.04 WSL2 distro to build, test and debug this project
# from VS Code on Windows (Remote - WSL). Idempotent: safe to re-run.
#
#   scripts/setup-bitwisebus.sh [--clone[=DIR]] [--no-vscode] [--no-verify]
#
# Can also be copied elsewhere and run standalone with --clone, to fetch the
# repository first.
#
# In order, it:
#   1. Checks the platform (Ubuntu 24.04, WSL2, not run through sudo).
#   2. Installs the toolchain with apt: GCC, Clang plus its sanitizer runtime,
#      CMake, Ninja, GDB, git, python3.
#   3. Probes both compilers: C++17, and ASan/UBSan, which CI runs.
#   4. Installs the VS Code extensions into WSL, when `code` is on the PATH.
#   5. Builds and tests the project with the README's commands, in a scratch
#      directory so it never collides with the build/ that CMake Tools manages.

set -Eeuo pipefail
trap 'printf "ERROR: command failed (line %s): %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

REPO_URL="https://github.com/juanlumc1988/bitwise-bus.git"
MIN_CMAKE="3.16"

# python3 is only used by CI's end-to-end step, which generates sample frames.
# curl: the VS Code Server installer in WSL needs wget or curl.
APT_PACKAGES=(build-essential cmake ninja-build clang gdb git python3 curl ca-certificates)
VSCODE_EXTENSIONS=(ms-vscode.cpptools ms-vscode.cmake-tools)

SUDO=()
ROOT=""
WARNINGS=()
DO_CLONE=0
CLONE_DIR=""
DO_VSCODE=1
DO_VERIFY=1

log()  { printf '\n==> %s\n' "$*"; }
warn() { printf 'WARNING: %s\n' "$*" >&2; WARNINGS+=("$*"); }
die()  { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

usage() {
    cat <<EOF
Usage: $0 [--clone[=DIR]] [--no-vscode] [--no-verify]

  --clone[=DIR]  Clone the repository into DIR (default: ~/bitwise-bus) when
                 the script is run standalone, outside a checkout.
  --no-vscode    Do not install VS Code extensions.
  --no-verify    Do not build and run the tests at the end.
  -h, --help     Show this help.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            --clone)     DO_CLONE=1 ;;
            --clone=*)   DO_CLONE=1; CLONE_DIR=${1#--clone=} ;;
            --no-vscode) DO_VSCODE=0 ;;
            --no-verify) DO_VERIFY=0 ;;
            -h|--help)   usage; exit 0 ;;
            *)           usage >&2; die "unknown option: $1" ;;
        esac
        shift
    done
    CLONE_DIR=${CLONE_DIR:-$HOME/bitwise-bus}
    CLONE_DIR=${CLONE_DIR/#\~\//$HOME/}   # --clone=~/x arrives unexpanded
}

# version_ge A B: true when A >= B.
version_ge() { printf '%s\n%s\n' "$2" "$1" | sort -V -C; }

# first_line CMD...: first line of a command's output. sed rather than head,
# so the producer is never killed by SIGPIPE under `pipefail`.
first_line() { "$@" 2>&1 | sed -n 1p; }

apt_install() { "${SUDO[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install -y "$@"; }

check_platform() {
    log "Checking platform"

    if [[ $EUID -eq 0 ]]; then
        [[ -z ${SUDO_USER:-} ]] || die "run as your normal user, not through sudo (the script calls sudo itself)"
    else
        command -v sudo >/dev/null || die "not root and sudo not found"
        SUDO=(sudo)
    fi
    command -v apt-get >/dev/null || die "apt-get not found: this script targets Ubuntu"

    local id="" version=""
    if [[ -r /etc/os-release ]]; then
        # shellcheck source=/dev/null
        id=$(. /etc/os-release && echo "${ID:-}")
        # shellcheck source=/dev/null
        version=$(. /etc/os-release && echo "${VERSION_ID:-}")
    fi
    if [[ $id != ubuntu || $version != 24.04 ]]; then
        warn "written for Ubuntu 24.04, found '${id:-?} ${version:-?}'"
    fi

    if ! grep -qi microsoft /proc/version; then
        warn "this does not look like WSL; continuing anyway"
    elif ! uname -r | grep -qi wsl2; then
        warn "WSL1 detected: file access is slow and sanitizers usually do not run. From PowerShell: wsl --set-version <distro> 2"
    fi
    echo "  ok"
}

install_packages() {
    log "Installing apt packages: ${APT_PACKAGES[*]}"
    "${SUDO[@]}" apt-get update
    apt_install "${APT_PACKAGES[@]}"

    # Ubuntu's `clang` ships no sanitizer runtime: without compiler-rt,
    # -fsanitize=address fails at link time. The package name carries clang's
    # major version, so derive it instead of hard-coding it.
    local major
    major=$(first_line clang --version | sed -n 's/^.*clang version \([0-9]\+\)\..*$/\1/p')
    [[ -n $major ]] || die "cannot determine the installed clang version"
    apt_install "libclang-rt-${major}-dev" \
        || warn "libclang-rt-${major}-dev not installed: Clang sanitizers will not link"
}

# probe CXX [FLAGS...]: build and run a trivial C++17 program, warnings fatal.
probe() {
    local cxx=$1 dir rc=0
    shift
    dir=$(mktemp -d)
    printf '%s\n' \
        '#include <optional>' \
        'int main() { std::optional<int> v; if constexpr (sizeof(int) >= 2) { v = 1; } return *v - 1; }' \
        >"$dir/p.cpp"
    "$cxx" -std=c++17 -Wall -Wextra -Werror "$@" "$dir/p.cpp" -o "$dir/p" >"$dir/log" 2>&1 \
        && "$dir/p" >>"$dir/log" 2>&1 || rc=$?
    if [[ $rc -ne 0 ]]; then
        sed 's/^/    /' "$dir/log" | sed -n 1,8p >&2
    fi
    rm -rf "$dir"
    return "$rc"
}

verify_toolchain() {
    log "Verifying toolchain"

    local v
    command -v cmake >/dev/null || die "cmake not found"
    v=$(first_line cmake --version | sed -n 's/^[^0-9]*\([0-9][0-9.]*\).*$/\1/p')
    version_ge "${v:-0}" "$MIN_CMAKE" || die "CMake ${v:-not found}: the project needs $MIN_CMAKE or newer"
    command -v ninja >/dev/null || die "ninja not found"
    probe g++ || die "g++ cannot build a C++17 program"

    # Not fatal: CI runs these, but nothing needs them to build or test locally.
    local asan_hint="if it dies at startup under WSL2, try: sudo sysctl vm.mmap_rnd_bits=28"
    probe g++ -fsanitize=address,undefined \
        || warn "g++ with ASan/UBSan does not work ($asan_hint)"
    probe clang++ \
        || warn "clang++ cannot build a C++17 program"
    probe clang++ -fsanitize=address,undefined \
        || warn "clang++ with ASan/UBSan does not work ($asan_hint)"

    printf '  %-8s %s\n' \
        cmake "$(first_line cmake --version)" \
        ninja "$(first_line ninja --version)" \
        g++   "$(first_line g++ --version)" \
        clang "$(first_line clang++ --version)" \
        gdb   "$(first_line gdb --version)"
}

is_repo_root() { [[ -f $1/CMakeLists.txt ]] && grep -q '^project(bitwise-bus' "$1/CMakeLists.txt"; }

resolve_repo() {
    local here
    here=$(cd -- "$(dirname -- "${BASH_SOURCE[0]:-$0}")/.." 2>/dev/null && pwd) || here=""

    if [[ -n $here ]] && is_repo_root "$here"; then
        ROOT=$here
        if [[ $DO_CLONE == 1 ]]; then
            echo "  already inside a checkout, ignoring --clone"
        fi
    elif [[ $DO_CLONE == 1 ]]; then
        log "Locating checkout in $CLONE_DIR"
        if is_repo_root "$CLONE_DIR"; then
            echo "  reusing existing checkout"
        elif [[ -n $(ls -A "$CLONE_DIR" 2>/dev/null) ]]; then
            die "$CLONE_DIR exists and is not a bitwise-bus checkout"
        else
            git clone "$REPO_URL" "$CLONE_DIR"
        fi
        ROOT=$(cd -- "$CLONE_DIR" && pwd)
    fi

    case $ROOT in
        /mnt/*) warn "$ROOT is on the Windows filesystem: builds are slow and permissions and line endings misbehave. Keep the checkout under your Linux home (~/) instead." ;;
    esac
}

install_vscode_extensions() {
    log "Installing VS Code extensions inside WSL"

    if ! command -v code >/dev/null; then
        warn "'code' is not on the PATH (VS Code not installed on Windows, or PATH interop disabled in /etc/wsl.conf): install ${VSCODE_EXTENSIONS[*]} from the Extensions view once VS Code is connected to WSL"
        return 0
    fi

    local installed ext
    installed=$(code --list-extensions 2>/dev/null) || installed=""
    for ext in "${VSCODE_EXTENSIONS[@]}"; do
        if grep -qixF "$ext" <<<"$installed"; then
            echo "  $ext: already installed"
        elif ! code --install-extension "$ext"; then
            warn "could not install $ext"
        fi
    done
}

# The README's commands, in a scratch directory: a stale or differently
# configured build/ (say, one CMake Tools made) can then never fail a re-run.
# The directory is kept on failure so the build can be inspected.
verify_build() {
    local dir
    dir=$(mktemp -d)
    log "Building and testing $ROOT (scratch build in $dir)"
    cmake -S "$ROOT" -B "$dir" -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
    cmake --build "$dir" -j "$(nproc)"
    # chdir rather than `ctest --test-dir`, which needs CMake 3.20 (we accept 3.16).
    cmake -E chdir "$dir" ctest --output-on-failure
    "$dir/bitwise" crc-catalog >/dev/null
    echo "  bitwise runs"
    rm -rf "$dir"
}

summary() {
    log "Done"
    if [[ ${#WARNINGS[@]} -gt 0 ]]; then
        printf '\n%d warning(s):\n' "${#WARNINGS[@]}"
        printf '  - %s\n' "${WARNINGS[@]}"
    fi

    printf '\nNext steps:\n'
    printf '  1. Windows, once: install VS Code and the "WSL" extension (ms-vscode-remote.remote-wsl).\n'
    if [[ -n $ROOT ]]; then
        printf '  2. From this shell: cd %q && code .\n' "$ROOT"
    else
        printf '  2. Clone under your Linux home, not /mnt/c: git clone %s ~/bitwise-bus\n' "$REPO_URL"
        printf '     then: cd ~/bitwise-bus && code .\n'
    fi
    printf '  3. In VS Code, let CMake Tools configure, pick the GCC kit, then Build / Test from the status bar.\n'
}

main() {
    parse_args "$@"
    check_platform
    install_packages
    verify_toolchain
    resolve_repo
    if [[ $DO_VSCODE == 1 ]]; then
        install_vscode_extensions
    fi
    if [[ $DO_VERIFY == 1 && -n $ROOT ]]; then
        verify_build
    fi
    summary
}

main "$@"
