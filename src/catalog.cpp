// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/catalog.h"

#include <cstring>

namespace bw {
namespace {

// Parameters and check values transcribed from the standard CRC catalogue
// and independently verified before being written here; tests/test_crc.cpp
// re-verifies every one of them on each run.
const CrcSpec kCatalog[] = {
    // name                width  poly        init        refin  refout xorout      check
    { "CRC-8",              8,     0x07,       0x00,       false, false, 0x00,       0xF4 },
    { "CRC-8/MAXIM-DOW",    8,     0x31,       0x00,       true,  true,  0x00,       0xA1 },
    { "CRC-8/SAE-J1850",    8,     0x1D,       0xFF,       false, false, 0xFF,       0x4B },
    { "CRC-8/AUTOSAR",      8,     0x2F,       0xFF,       false, false, 0xFF,       0xDF },

    // CAN and CAN-FD. Not byte-aligned, which is exactly why crc_compute
    // works a bit at a time rather than a byte at a time.
    { "CRC-15/CAN",         15,    0x4599,     0x0000,     false, false, 0x0000,     0x059E },
    { "CRC-17/CAN-FD",      17,    0x1685B,    0x00000,    false, false, 0x00000,    0x04F03 },
    { "CRC-21/CAN-FD",      21,    0x102899,   0x000000,   false, false, 0x000000,   0x0ED841 },

    { "CRC-16/ARC",         16,    0x8005,     0x0000,     true,  true,  0x0000,     0xBB3D },
    { "CRC-16/MODBUS",      16,    0x8005,     0xFFFF,     true,  true,  0x0000,     0x4B37 },
    { "CRC-16/USB",         16,    0x8005,     0xFFFF,     true,  true,  0xFFFF,     0xB4C8 },
    { "CRC-16/IBM-3740",    16,    0x1021,     0xFFFF,     false, false, 0x0000,     0x29B1 },
    { "CRC-16/XMODEM",      16,    0x1021,     0x0000,     false, false, 0x0000,     0x31C3 },
    { "CRC-16/KERMIT",      16,    0x1021,     0x0000,     true,  true,  0x0000,     0x2189 },
    { "CRC-16/GENIBUS",     16,    0x1021,     0xFFFF,     false, false, 0xFFFF,     0xD64E },
    { "CRC-16/DNP",         16,    0x3D65,     0x0000,     true,  true,  0xFFFF,     0xEA82 },

    { "CRC-32/ISO-HDLC",    32,    0x04C11DB7, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0xCBF43926 },
    { "CRC-32/BZIP2",       32,    0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF, 0xFC891918 },
    { "CRC-32/ISCSI",       32,    0x1EDC6F41, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0xE3069283 },
    { "CRC-32/MPEG-2",      32,    0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7 },
    { "CRC-32/AUTOSAR",     32,    0xF4ACFB13, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0x1697D06A }
};

} // namespace

const CrcSpec* catalog() {
    return kCatalog;
}

std::size_t catalog_size() {
    return sizeof(kCatalog) / sizeof(kCatalog[0]);
}

const CrcSpec* catalog_find(const char* name) {
    if (name == nullptr) {
        return nullptr;
    }
    for (std::size_t i = 0; i < catalog_size(); ++i) {
        if (std::strcmp(kCatalog[i].name, name) == 0) {
            return &kCatalog[i];
        }
    }
    return nullptr;
}

} // namespace bw
