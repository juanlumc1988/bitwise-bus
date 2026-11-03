#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.
#
# Builds, tests, installs and archives bitwise-bus for ONE platform. The
# Package workflow runs exactly this for every target, so any package can be
# reproduced locally.
#
#   scripts/package.sh PLATFORM [CMAKE_ARG...]
#
# PLATFORM names the archive: dist/bitwise-bus-PLATFORM.tar.gz (.zip on
# Windows). Extra arguments go to every cmake configure step -- generator,
# toolchain file, architectures -- so the library, the tests and the consumer
# check are all configured alike.
#
# What is checked is the archive, not the build tree: it is unpacked somewhere
# else, its CLI is run, and tests/package is built against it with
# find_package.
#
# Environment:
#   BW_CONFIGS      configurations to package, space separated (default
#                   Release). More than one needs a multi-config generator.
#   BW_ARCHIVE      tar.gz (default) or zip.
#   BW_EMULATOR     command that runs target binaries on this host, for cross
#                   builds: "qemu-arm -L /usr/arm-linux-gnueabihf".
#   BW_EXPECT_ARCH  extended regex that `file` must match on the packaged CLI.
#   BW_EXPECT_TAG   fail unless equal to v<project version> (release builds).

set -Eeuo pipefail
trap 'printf "ERROR: command failed (line %s): %s\n" "$LINENO" "$BASH_COMMAND" >&2' ERR

log() { printf '\n==> [%s] %s\n' "${platform:-?}" "$*"; }
die() { printf 'ERROR: %s\n' "$*" >&2; exit 1; }

[[ $# -ge 1 ]] || die "usage: $0 PLATFORM [CMAKE_ARG...]"
platform=$1
shift
cmake_args=("$@")

# pwd -W gives a Windows path under Git Bash/MSYS2, which native cmake needs;
# elsewhere it is not an option and the plain pwd takes over.
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && { pwd -W 2>/dev/null || pwd; })
cd "$root"

# A relative toolchain file is looked up against the build directory and then
# the *source* directory, which differs between the main build and the consumer
# check. Make it absolute so one argument means one file for both.
for ((i = 0; i < ${#cmake_args[@]}; i++)); do
    case ${cmake_args[i]} in
        -DCMAKE_TOOLCHAIN_FILE=/* | -DCMAKE_TOOLCHAIN_FILE=[A-Za-z]:*) ;;
        -DCMAKE_TOOLCHAIN_FILE=*)
            cmake_args[i]=-DCMAKE_TOOLCHAIN_FILE=$root/${cmake_args[i]#*=} ;;
    esac
done

read -r -a configs <<<"${BW_CONFIGS:-Release}"
archive=${BW_ARCHIVE:-tar.gz}
read -r -a emulator <<<"${BW_EMULATOR:-}"

version=$(sed -n 's/^project(bitwise-bus VERSION \([0-9][0-9.]*\).*$/\1/p' CMakeLists.txt)
[[ -n $version ]] || die "cannot read the project version from CMakeLists.txt"
if [[ -n ${BW_EXPECT_TAG:-} && $BW_EXPECT_TAG != "v$version" ]]; then
    die "tag $BW_EXPECT_TAG does not match the project version v$version"
fi

name=bitwise-bus-$version-$platform
asset=bitwise-bus-$platform.$archive
build=build-pkg/$platform
stage=dist/stage/$name
rm -rf "$build" "$build-consumer" "$build-unpacked" "$stage" "dist/$asset"
mkdir -p dist

# "${arr[@]+...}": an empty array is an unbound variable to bash < 4.4 (macOS).
emulator_cmake=()
if [[ ${#emulator[@]} -gt 0 ]]; then
    emulator_cmake=("-DCMAKE_CROSSCOMPILING_EMULATOR=$(IFS=';'; echo "${emulator[*]}")")
fi

# ---- Build and test, per configuration ------------------------------------
log "configure"
cmake -S . -B "$build" ${cmake_args[@]+"${cmake_args[@]}"} ${emulator_cmake[@]+"${emulator_cmake[@]}"} \
    -DCMAKE_BUILD_TYPE="${configs[0]}" -DCMAKE_INSTALL_LIBDIR=lib \
    -DBW_BUILD_TESTS=ON -DBW_WERROR=OFF -DBW_STATIC_CLI=ON

first=1
for cfg in "${configs[@]}"; do
    log "$cfg: build"
    cmake --build "$build" --config "$cfg" --parallel
    log "$cfg: test"
    cmake -E chdir "$build" ctest -C "$cfg" --output-on-failure
    log "$cfg: install"
    if [[ $first -eq 1 ]]; then
        cmake --install "$build" --config "$cfg" --prefix "$root/$stage"
        first=0
    else
        # The CLI is already there; only this configuration's library is new.
        cmake --install "$build" --config "$cfg" --prefix "$root/$stage" --component dev
    fi
done

# ---- Archive ---------------------------------------------------------------
log "archive dist/$asset"
case $archive in
    tar.gz) cmake -E chdir dist/stage cmake -E tar czf "../$asset" -- "$name" ;;
    zip)    cmake -E chdir dist/stage cmake -E tar cf "../$asset" --format=zip -- "$name" ;;
    *)      die "unknown archive format: $archive" ;;
esac

# ---- Verify the archive itself ---------------------------------------------
log "unpack and verify"
mkdir -p "$build-unpacked"
cmake -E chdir "$build-unpacked" cmake -E tar xf "$root/dist/$asset"
pkg=$build-unpacked/$name

cli=$pkg/bin/bitwise
[[ -f $cli ]] || cli=$cli.exe
[[ -f $cli ]] || die "no bitwise CLI in the archive"

if [[ -n ${BW_EXPECT_ARCH:-} ]]; then
    desc=$(file -b "$cli")
    echo "  $desc"
    grep -Eiq "$BW_EXPECT_ARCH" <<<"$desc" || die "CLI does not match /$BW_EXPECT_ARCH/"
fi

# Two real Modbus RTU requests; CRC-16/MODBUS has to come out of the bytes.
mkdir -p "$build-unpacked/frames"
printf '\x01\x03\x00\x00\x00\x0a\xc5\xcd' >"$build-unpacked/frames/f0.bin"
printf '\x01\x04\x00\x00\x00\x01\x31\xca' >"$build-unpacked/frames/f1.bin"
"${emulator[@]+"${emulator[@]}"}" "$cli" crc-catalog >/dev/null
found=$("${emulator[@]+"${emulator[@]}"}" "$cli" crc-find \
        "$build-unpacked/frames/f0.bin" "$build-unpacked/frames/f1.bin")
grep -q 'CRC-16/MODBUS' <<<"$found" || die "the packaged CLI did not identify CRC-16/MODBUS"
echo "  CLI identifies CRC-16/MODBUS"

log "consumer check (find_package against the unpacked archive)"
cmake -S tests/package -B "$build-consumer" ${cmake_args[@]+"${cmake_args[@]}"} ${emulator_cmake[@]+"${emulator_cmake[@]}"} \
    -DCMAKE_BUILD_TYPE="${configs[0]}" \
    -DCMAKE_PREFIX_PATH="$root/$build-unpacked/$name" -DBW_EXPECT_VERSION="$version"
for cfg in "${configs[@]}"; do
    cmake --build "$build-consumer" --config "$cfg" --parallel
    cmake -E chdir "$build-consumer" ctest -C "$cfg" --output-on-failure
done

log "done: dist/$asset"
