# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.
#
# 32-bit ARM Linux (armv7, hard float), cross-compiled on an x86-64
# Debian/Ubuntu host:
#
#   sudo apt install g++-arm-linux-gnueabihf qemu-user
#   cmake -S . -B build-armv7 \
#         -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/arm-linux-gnueabihf.cmake \
#         -DCMAKE_CROSSCOMPILING_EMULATOR="qemu-arm;-L;/usr/arm-linux-gnueabihf"
#
# The emulator is what lets ctest run the unit tests on the host.

set(CMAKE_SYSTEM_NAME      Linux)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_CXX_COMPILER     arm-linux-gnueabihf-g++)

# GCC 13 notes, once per translation unit, that vector's parameter passing
# changed in GCC 7.1. It only matters when linking against code built with an
# older GCC, which this project never does.
set(CMAKE_CXX_FLAGS_INIT "-Wno-psabi")
