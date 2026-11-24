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
    { "CRC-8/I-432-1",      8,     0x07,       0x00,       false, false, 0x55,       0xA1 },   // ITU, ATM HEC
    { "CRC-8/ROHC",         8,     0x07,       0xFF,       true,  true,  0x00,       0xD0 },
    { "CRC-8/DARC",         8,     0x39,       0x00,       true,  true,  0x00,       0x15 },
    { "CRC-8/TECH-3250",    8,     0x1D,       0xFF,       true,  true,  0x00,       0x97 },   // AES/EBU, EBU
    { "CRC-8/GSM-A",        8,     0x1D,       0x00,       false, false, 0x00,       0x37 },
    { "CRC-8/GSM-B",        8,     0x49,       0x00,       false, false, 0xFF,       0x94 },
    { "CRC-8/HITAG",        8,     0x1D,       0xFF,       false, false, 0x00,       0xB4 },
    { "CRC-8/I-CODE",       8,     0x1D,       0xFD,       false, false, 0x00,       0x7E },
    { "CRC-8/MIFARE-MAD",   8,     0x1D,       0xC7,       false, false, 0x00,       0x99 },
    { "CRC-8/CDMA2000",     8,     0x9B,       0xFF,       false, false, 0x00,       0xDA },
    { "CRC-8/LTE",          8,     0x9B,       0x00,       false, false, 0x00,       0xEA },
    { "CRC-8/WCDMA",        8,     0x9B,       0x00,       true,  true,  0x00,       0x25 },
    { "CRC-8/DVB-S2",       8,     0xD5,       0x00,       false, false, 0x00,       0xBC },
    { "CRC-8/NRSC-5",       8,     0x31,       0xFF,       false, false, 0x00,       0xF7 },
    { "CRC-8/OPENSAFETY",   8,     0x2F,       0x00,       false, false, 0x00,       0x3E },

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
    // The FCS of HDLC, PPP (RFC 1662) and X.25, also Bluetooth and PNG's cousins: CRC-16/X-25.
    { "CRC-16/IBM-SDLC",    16,    0x1021,     0xFFFF,     true,  true,  0xFFFF,     0x906E },
    { "CRC-16/MCRF4XX",     16,    0x1021,     0xFFFF,     true,  true,  0x0000,     0x6F91 },   // MAVLink's
    { "CRC-16/UMTS",        16,    0x8005,     0x0000,     false, false, 0x0000,     0xFEE8 },   // BUYPASS, VERIFONE
    { "CRC-16/MAXIM-DOW",   16,    0x8005,     0x0000,     true,  true,  0xFFFF,     0x44C2 },
    { "CRC-16/CMS",         16,    0x8005,     0xFFFF,     false, false, 0x0000,     0xAEE7 },
    { "CRC-16/DDS-110",     16,    0x8005,     0x800D,     false, false, 0x0000,     0x9ECF },
    { "CRC-16/SPI-FUJITSU", 16,    0x1021,     0x1D0F,     false, false, 0x0000,     0xE5CC },   // AUG-CCITT
    { "CRC-16/GSM",         16,    0x1021,     0x0000,     false, false, 0xFFFF,     0xCE3C },
    { "CRC-16/RIELLO",      16,    0x1021,     0xB2AA,     true,  true,  0x0000,     0x63D0 },
    { "CRC-16/TMS37157",    16,    0x1021,     0x89EC,     true,  true,  0x0000,     0x26B1 },
    { "CRC-16/EN-13757",    16,    0x3D65,     0x0000,     false, false, 0xFFFF,     0xC2B7 },   // wireless M-Bus
    { "CRC-16/T10-DIF",     16,    0x8BB7,     0x0000,     false, false, 0x0000,     0xD0DB },
    { "CRC-16/TELEDISK",    16,    0xA097,     0x0000,     false, false, 0x0000,     0x0FB3 },
    { "CRC-16/CDMA2000",    16,    0xC867,     0xFFFF,     false, false, 0x0000,     0x4C06 },
    { "CRC-16/PROFIBUS",    16,    0x1DCF,     0xFFFF,     false, false, 0xFFFF,     0xA819 },   // IEC 61158-2
    { "CRC-16/DECT-R",      16,    0x0589,     0x0000,     false, false, 0x0001,     0x007E },
    { "CRC-16/DECT-X",      16,    0x0589,     0x0000,     false, false, 0x0000,     0x007F },
    { "CRC-16/LJ1200",      16,    0x6F63,     0x0000,     false, false, 0x0000,     0xBDF4 },
    { "CRC-16/M17",         16,    0x5935,     0xFFFF,     false, false, 0x0000,     0x772B },
    { "CRC-16/NRSC-5",      16,    0x080B,     0xFFFF,     true,  true,  0x0000,     0xA066 },
    { "CRC-16/OPENSAFETY-A", 16,   0x5935,     0x0000,     false, false, 0x0000,     0x5D38 },
    { "CRC-16/OPENSAFETY-B", 16,   0x755B,     0x0000,     false, false, 0x0000,     0x20FE },

    { "CRC-32/ISO-HDLC",    32,    0x04C11DB7, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0xCBF43926 },
    { "CRC-32/BZIP2",       32,    0x04C11DB7, 0xFFFFFFFF, false, false, 0xFFFFFFFF, 0xFC891918 },
    { "CRC-32/ISCSI",       32,    0x1EDC6F41, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0xE3069283 },
    { "CRC-32/MPEG-2",      32,    0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000, 0x0376E6E7 },
    { "CRC-32/AUTOSAR",     32,    0xF4ACFB13, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0x1697D06A },
    { "CRC-32/JAMCRC",      32,    0x04C11DB7, 0xFFFFFFFF, true,  true,  0x00000000, 0x340BC6D9 },
    { "CRC-32/CKSUM",       32,    0x04C11DB7, 0x00000000, false, false, 0xFFFFFFFF, 0x765E7680 },   // POSIX cksum
    { "CRC-32/XFER",        32,    0x000000AF, 0x00000000, false, false, 0x00000000, 0xBD0BE338 },
    { "CRC-32/BASE91-D",    32,    0xA833982B, 0xFFFFFFFF, true,  true,  0xFFFFFFFF, 0x87315576 },   // CRC-32D
    { "CRC-32/AIXM",        32,    0x814141AB, 0x00000000, false, false, 0x00000000, 0x3010BF7F },   // CRC-32Q
    { "CRC-32/CD-ROM-EDC",  32,    0x8001801B, 0x00000000, true,  true,  0x00000000, 0x6EC2EDC4 },

    // The widest the model goes: a checksum of eight bytes.
    { "CRC-64/XZ",          64,    0x42F0E1EBA9EA3693ULL, 0xFFFFFFFFFFFFFFFFULL, true,  true,  0xFFFFFFFFFFFFFFFFULL, 0x995DC9BBDF1939FAULL },
    { "CRC-64/ECMA-182",    64,    0x42F0E1EBA9EA3693ULL, 0x0000000000000000ULL, false, false, 0x0000000000000000ULL, 0x6C40DF5F0B497347ULL },
    { "CRC-64/GO-ISO",      64,    0x000000000000001BULL, 0xFFFFFFFFFFFFFFFFULL, true,  true,  0xFFFFFFFFFFFFFFFFULL, 0xB90956C775A41001ULL }
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
