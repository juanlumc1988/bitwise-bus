// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "doctest.h"

#include <string>
#include <vector>

#include "bw/catalog.h"
#include "bw/crc.h"

using bw::u8;
using bw::u32;
using bw::u64;

namespace {

const u8 kCheck[9] = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };

} // namespace

TEST_CASE("every catalogue entry reproduces its published check value") {
    // The catalogue is a search space. A mistyped parameter does not fail
    // loudly -- it silently never matches, and the tool reports "nothing
    // found" for a protocol that is right there in the list. This is the
    // test that stops that happening.
    REQUIRE(bw::catalog_size() > 0);

    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& spec = bw::catalog()[i];
        CAPTURE(std::string(spec.name));
        CHECK(spec.width >= 1);
        CHECK(spec.width <= 64);
        CHECK(spec.check != 0);
        CHECK(bw::crc_compute(spec, kCheck, sizeof(kCheck)) == spec.check);
        CHECK(bw::crc_spec_self_test(spec));
    }
}

TEST_CASE("the catalogue covers the widths a bus actually uses") {
    bool has8 = false, has15 = false, has16 = false, has32 = false;
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        switch (bw::catalog()[i].width) {
            case 8:  has8  = true; break;
            case 15: has15 = true; break;
            case 16: has16 = true; break;
            case 32: has32 = true; break;
            default: break;
        }
    }
    CHECK(has8);
    CHECK(has16);
    CHECK(has32);
    CHECK(has15);   // CAN, and the reason crc_compute works bit at a time
}

TEST_CASE("widths that are not a multiple of eight work") {
    // The byte-wise CRC formulation everyone writes first cannot do these,
    // because it shifts a whole byte into the top of the register. CAN is
    // 15 bits and CAN-FD is 17 and 21, so getting this wrong would rule out
    // the buses this project exists for.
    const bw::CrcSpec* can = bw::catalog_find("CRC-15/CAN");
    REQUIRE(can != nullptr);
    CHECK(bw::crc_compute(*can, kCheck, sizeof(kCheck)) == 0x059Eu);

    const bw::CrcSpec* fd17 = bw::catalog_find("CRC-17/CAN-FD");
    REQUIRE(fd17 != nullptr);
    CHECK(bw::crc_compute(*fd17, kCheck, sizeof(kCheck)) == 0x04F03u);

    const bw::CrcSpec* fd21 = bw::catalog_find("CRC-21/CAN-FD");
    REQUIRE(fd21 != nullptr);
    CHECK(bw::crc_compute(*fd21, kCheck, sizeof(kCheck)) == 0x0ED841u);
}

TEST_CASE("a CRC never exceeds its width") {
    std::vector<u8> data(64);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<u8>(i * 7u + 3u);
    }
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& spec = bw::catalog()[i];
        CAPTURE(std::string(spec.name));
        const u64 value = bw::crc_compute(spec, data.data(), data.size());
        CHECK((value & ~bw::width_mask(spec.width)) == 0u);
    }
}

TEST_CASE("width_mask handles the whole range without shifting by 64") {
    CHECK(bw::width_mask(0) == 0u);
    CHECK(bw::width_mask(1) == 0x1u);
    CHECK(bw::width_mask(8) == 0xFFu);
    CHECK(bw::width_mask(15) == 0x7FFFu);
    CHECK(bw::width_mask(16) == 0xFFFFu);
    CHECK(bw::width_mask(32) == 0xFFFFFFFFu);
    CHECK(bw::width_mask(63) == 0x7FFFFFFFFFFFFFFFULL);
    CHECK(bw::width_mask(64) == 0xFFFFFFFFFFFFFFFFULL);
}

TEST_CASE("reflect reverses exactly the requested bits") {
    CHECK(bw::reflect(0x01u, 8) == 0x80u);
    CHECK(bw::reflect(0x80u, 8) == 0x01u);
    CHECK(bw::reflect(0xF0u, 8) == 0x0Fu);
    CHECK(bw::reflect(0x1234u, 16) == 0x2C48u);
    CHECK(bw::reflect(0u, 32) == 0u);
    CHECK(bw::reflect(0xFFFFFFFFu, 32) == 0xFFFFFFFFu);

    // Bits above the width are dropped, not carried along.
    CHECK(bw::reflect(0xFF01u, 8) == 0x80u);

    // Reflecting twice is the identity.
    for (u8 width = 1; width <= 32; ++width) {
        const u64 v = 0x9E3779B9ULL & bw::width_mask(width);
        CAPTURE(width);
        CHECK(bw::reflect(bw::reflect(v, width), width) == v);
    }
}

TEST_CASE("a CRC over no data is the init and xorout alone") {
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& spec = bw::catalog()[i];
        CAPTURE(std::string(spec.name));

        u64 expected = spec.init & bw::width_mask(spec.width);
        if (spec.refout) {
            expected = bw::reflect(expected, spec.width);
        }
        expected = (expected ^ spec.xorout) & bw::width_mask(spec.width);

        CHECK(bw::crc_compute(spec, nullptr, 0) == expected);
    }
}

TEST_CASE("a CRC detects every single-bit change") {
    // The property the whole idea rests on: if it did not, a matching
    // checksum would say nothing about the parameters.
    std::vector<u8> data(16);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<u8>(i * 11u);
    }

    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& spec = bw::catalog()[i];
        CAPTURE(std::string(spec.name));
        const u64 clean = bw::crc_compute(spec, data.data(), data.size());

        for (std::size_t byte = 0; byte < data.size(); ++byte) {
            for (u8 bit = 0; bit < 8u; ++bit) {
                data[byte] ^= static_cast<u8>(1u << bit);
                REQUIRE(bw::crc_compute(spec, data.data(), data.size()) != clean);
                data[byte] ^= static_cast<u8>(1u << bit);
            }
        }
    }
}

TEST_CASE("catalog_find is exact and does not invent entries") {
    CHECK(bw::catalog_find("CRC-16/MODBUS") != nullptr);
    CHECK(bw::catalog_find("CRC-32/ISO-HDLC") != nullptr);
    CHECK(bw::catalog_find("CRC-16/modbus") == nullptr);   // case matters
    CHECK(bw::catalog_find("CRC-16") == nullptr);          // not a prefix match
    CHECK(bw::catalog_find("") == nullptr);
    CHECK(bw::catalog_find(nullptr) == nullptr);
}

TEST_CASE("catalogue entries are distinct") {
    // Two entries with identical parameters would both match everything the
    // other does, making every search ambiguous for no reason.
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        for (std::size_t j = i + 1; j < bw::catalog_size(); ++j) {
            const bw::CrcSpec& a = bw::catalog()[i];
            const bw::CrcSpec& b = bw::catalog()[j];
            CAPTURE(std::string(a.name));
            CAPTURE(std::string(b.name));
            CHECK(std::string(a.name) != std::string(b.name));

            const bool identical = a.width == b.width && a.poly == b.poly
                                && a.init == b.init && a.refin == b.refin
                                && a.refout == b.refout && a.xorout == b.xorout;
            CHECK_FALSE(identical);
        }
    }
}

TEST_CASE("a malformed spec still produces a value within its width") {
    // CrcSpec is public, and nothing stops a caller typing a polynomial with
    // bits above the declared width -- a transcription slip, or a width
    // corrected without correcting the rest. The result must stay inside the
    // width regardless, because every caller treats it as a value of that
    // many bits. No catalogue entry exercises this, so without it the final
    // mask is untested code that looks load-bearing.
    std::vector<u8> data(12);
    for (std::size_t i = 0; i < data.size(); ++i) {
        data[i] = static_cast<u8>(i * 17u + 5u);
    }

    SUBCASE("polynomial wider than the width") {
        bw::CrcSpec bad = { "bogus", 8, 0xDEADBEEFu, 0x00, false, false, 0x00, 0 };
        const u64 value = bw::crc_compute(bad, data.data(), data.size());
        CHECK((value & ~0xFFull) == 0u);
    }
    SUBCASE("init wider than the width") {
        bw::CrcSpec bad = { "bogus", 8, 0x07, 0xFFFFFFFFu, false, false, 0x00, 0 };
        const u64 value = bw::crc_compute(bad, data.data(), data.size());
        CHECK((value & ~0xFFull) == 0u);
    }
    SUBCASE("xorout wider than the width") {
        bw::CrcSpec bad = { "bogus", 16, 0x1021, 0x0000, false, false, 0xFFFFFFFFu, 0 };
        const u64 value = bw::crc_compute(bad, data.data(), data.size());
        CHECK((value & ~0xFFFFull) == 0u);
    }
    SUBCASE("all three at once, reflected") {
        bw::CrcSpec bad = { "bogus", 12, 0xFFFFFFFFu, 0xFFFFFFFFu, true, true,
                            0xFFFFFFFFu, 0 };
        const u64 value = bw::crc_compute(bad, data.data(), data.size());
        CHECK((value & ~0xFFFull) == 0u);
    }
}

TEST_CASE("an out-of-range width yields zero rather than shifting by 64") {
    std::vector<u8> data(4, 0xA5);

    bw::CrcSpec zero_width = { "bogus", 0, 0x07, 0x00, false, false, 0x00, 0 };
    CHECK(bw::crc_compute(zero_width, data.data(), data.size()) == 0u);

    bw::CrcSpec too_wide = { "bogus", 65, 0x07, 0x00, false, false, 0x00, 0 };
    CHECK(bw::crc_compute(too_wide, data.data(), data.size()) == 0u);

    // 64 is the widest legal value and must work, not trip the guard.
    bw::CrcSpec widest = { "bogus", 64, 0x42F0E1EBA9EA3693ULL, 0x00,
                           false, false, 0x00, 0 };
    const u64 value = bw::crc_compute(widest, data.data(), data.size());
    CHECK(value != 0u);   // it computed something rather than bailing out
}
