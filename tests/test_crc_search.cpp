// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The golden tests. Synthesise a corpus using a known algorithm and a known
// layout, hand the search nothing but the bytes, and require it to recover
// both. If that works for every algorithm in the catalogue and every layout
// the options allow, the search is doing its job.

#include "doctest.h"

#include <string>
#include <vector>

#include "bw/crc_search.h"

using bw::u8;
using bw::u32;
using bw::u64;

namespace {

u64 g_rng = 0x243F6A8885A308D3ULL;

u8 next_byte() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return static_cast<u8>(g_rng & 0xFFu);
}

void reseed(u64 seed) {
    g_rng = seed ? seed : 0x9E3779B97F4A7C15ULL;
}

// Builds frames that genuinely carry `spec` at `layout`, the way a device
// on a bus would.
std::vector<bw::Frame> synthesise(const bw::CrcSpec& spec,
                                  const bw::Layout& layout,
                                  std::size_t count,
                                  std::size_t payload_len,
                                  u64 seed = 12345) {
    reseed(seed);
    std::vector<bw::Frame> frames;

    for (std::size_t f = 0; f < count; ++f) {
        const std::size_t len = layout.header_skip + payload_len
                              + layout.field_bytes() + layout.trailer_skip;
        bw::Frame frame;
        frame.bytes.resize(len);
        for (std::size_t i = 0; i < len; ++i) {
            frame.bytes[i] = next_byte();
        }

        const std::size_t at    = layout.checksum_offset(len);
        const u64         value = bw::crc_compute(
            spec, frame.bytes.data() + layout.covered_begin(),
            at - layout.covered_begin());

        const std::size_t n = layout.field_bytes();
        for (std::size_t i = 0; i < n; ++i) {
            const std::size_t shift = layout.big_endian ? (n - 1u - i) : i;
            frame.bytes[at + i] = static_cast<u8>((value >> (shift * 8u)) & 0xFFu);
        }
        frames.push_back(frame);
    }
    return frames;
}

bool contains(const bw::SearchReport& report, const char* name) {
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        if (std::string(report.candidates[i].spec->name) == name) {
            return true;
        }
    }
    return false;
}

} // namespace

TEST_CASE("every byte-aligned algorithm in the catalogue is recoverable") {
    // The exhaustive version of the claim. For each algorithm: build frames
    // that use it, then require the search to name it from the bytes alone.
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& spec = bw::catalog()[i];
        if (spec.width % 8u != 0) {
            continue;   // field extraction is byte-aligned; see the header
        }
        CAPTURE(std::string(spec.name));

        bw::Layout layout;
        layout.width      = spec.width;
        layout.big_endian = true;

        // Eight frames of sixteen payload bytes: far more evidence than the
        // 32-bit threshold needs, so a miss here is a real miss.
        const std::vector<bw::Frame> frames =
            synthesise(spec, layout, 8, 16, 0xABCD00u + i);

        const bw::SearchReport report = bw::search(frames);

        CHECK(report.frames == 8u);
        CHECK(report.layouts_tried > 0u);
        CHECK(contains(report, spec.name));
        CHECK(report.evidence_bits >= 32u);
    }
}

TEST_CASE("the layout is recovered, not just the algorithm") {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/MODBUS");
    REQUIRE(spec != nullptr);

    SUBCASE("checksum at the very end, covering everything") {
        bw::Layout layout;
        layout.width = 16;
        const bw::SearchReport report = bw::search(synthesise(*spec, layout, 6, 12));
        REQUIRE(report.confident());
        CHECK(std::string(report.candidates[0].spec->name) == "CRC-16/MODBUS");
        CHECK(report.candidates[0].layout.header_skip == 0u);
        CHECK(report.candidates[0].layout.trailer_skip == 0u);
        CHECK(report.candidates[0].layout.big_endian);
    }

    SUBCASE("a header outside the covered range") {
        // Common: a sync byte and an address that the CRC does not cover.
        bw::Layout layout;
        layout.width       = 16;
        layout.header_skip = 3;
        const bw::SearchReport report = bw::search(synthesise(*spec, layout, 6, 12));
        REQUIRE(report.confident());
        CHECK(report.candidates[0].layout.header_skip == 3u);
    }

    SUBCASE("bytes after the checksum") {
        bw::Layout layout;
        layout.width        = 16;
        layout.trailer_skip = 2;
        const bw::SearchReport report = bw::search(synthesise(*spec, layout, 6, 12));
        REQUIRE(report.confident());
        CHECK(report.candidates[0].layout.trailer_skip == 2u);
    }

    SUBCASE("little-endian checksum field") {
        bw::Layout layout;
        layout.width      = 16;
        layout.big_endian = false;
        const bw::SearchReport report = bw::search(synthesise(*spec, layout, 6, 12));
        REQUIRE(report.confident());
        CHECK_FALSE(report.candidates[0].layout.big_endian);
    }

    SUBCASE("header and trailer together") {
        bw::Layout layout;
        layout.width        = 16;
        layout.header_skip  = 2;
        layout.trailer_skip = 1;
        layout.big_endian   = false;
        const bw::SearchReport report = bw::search(synthesise(*spec, layout, 8, 20));
        REQUIRE(report.confident());
        CHECK(report.candidates[0].layout.header_skip == 2u);
        CHECK(report.candidates[0].layout.trailer_skip == 1u);
        CHECK_FALSE(report.candidates[0].layout.big_endian);
    }
}

TEST_CASE("frames of differing lengths are handled") {
    // A layout is expressed relative to the ends of the frame precisely so
    // that a real capture -- where frames vary in length -- needs no
    // special-casing.
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/IBM-3740");
    REQUIRE(spec != nullptr);

    bw::Layout layout;
    layout.width       = 16;
    layout.header_skip = 1;

    std::vector<bw::Frame> mixed;
    for (std::size_t payload = 4; payload <= 20; payload += 4) {
        const std::vector<bw::Frame> some =
            synthesise(*spec, layout, 2, payload, 900u + payload);
        mixed.insert(mixed.end(), some.begin(), some.end());
    }

    const bw::SearchReport report = bw::search(mixed);
    REQUIRE(report.confident());
    CHECK(std::string(report.candidates[0].spec->name) == "CRC-16/IBM-3740");
    CHECK(report.candidates[0].layout.header_skip == 1u);
}

TEST_CASE("random bytes yield no answer") {
    // The failure mode that matters most in a tool like this is confidently
    // reporting a protocol that is not there.
    reseed(777);
    std::vector<bw::Frame> noise;
    for (std::size_t f = 0; f < 8u; ++f) {
        bw::Frame frame;
        frame.bytes.resize(20);
        for (std::size_t i = 0; i < frame.bytes.size(); ++i) {
            frame.bytes[i] = next_byte();
        }
        noise.push_back(frame);
    }

    const bw::SearchReport report = bw::search(noise);
    CHECK(report.candidates.empty());
    CHECK_FALSE(report.confident());
    CHECK(report.layouts_tried > 0u);   // it did look
}

TEST_CASE("one narrow checksum is not evidence, and is not reported as such") {
    // A single 8-bit checksum over one frame is eight bits of evidence
    // against a search space of hundreds of candidates.
    //
    // Note what is NOT asserted here: that several algorithms match. Whether
    // any others happen to collide depends on the particular bytes, so
    // asserting it would be testing the random number generator. The single
    // candidate case is the dangerous one anyway -- one answer on thin
    // evidence looks exactly like one answer on good evidence, and only
    // evidence_bits tells them apart.
    const bw::CrcSpec* spec = bw::catalog_find("CRC-8");
    REQUIRE(spec != nullptr);

    bw::Layout layout;
    layout.width = 8;

    const bw::SearchReport report = bw::search(synthesise(*spec, layout, 1, 8));

    CHECK(report.evidence_bits == 8u);
    CHECK(contains(report, "CRC-8"));   // the true answer is in there
    CHECK_FALSE(report.confident());    // but the tool must not claim it
}

TEST_CASE("more frames turn a guess into an answer") {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-8/MAXIM-DOW");
    REQUIRE(spec != nullptr);

    bw::Layout layout;
    layout.width = 8;

    const bw::SearchReport few  = bw::search(synthesise(*spec, layout, 1, 8, 42));
    const bw::SearchReport many = bw::search(synthesise(*spec, layout, 12, 8, 42));

    CHECK(few.candidates.size() > many.candidates.size());
    CHECK_FALSE(few.confident());
    CHECK(many.confident());
    CHECK(std::string(many.candidates[0].spec->name) == "CRC-8/MAXIM-DOW");
}

TEST_CASE("one corrupt frame is enough to reject a candidate") {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-32/ISO-HDLC");
    REQUIRE(spec != nullptr);

    bw::Layout layout;
    layout.width = 32;

    std::vector<bw::Frame> frames = synthesise(*spec, layout, 6, 16);
    REQUIRE(bw::verify(frames, layout, *spec));

    frames[3].bytes[2] ^= 0x01u;
    CHECK_FALSE(bw::verify(frames, layout, *spec));

    const bw::SearchReport report = bw::search(frames);
    CHECK_FALSE(contains(report, "CRC-32/ISO-HDLC"));
}

TEST_CASE("degenerate input is refused rather than matched") {
    bw::Layout layout;
    layout.width = 16;

    SUBCASE("no frames") {
        const bw::SearchReport report = bw::search(std::vector<bw::Frame>());
        CHECK(report.candidates.empty());
        CHECK(report.frames == 0u);
        CHECK_FALSE(report.confident());
    }

    SUBCASE("frames too short to hold a checksum and any covered data") {
        std::vector<bw::Frame> tiny;
        for (std::size_t f = 0; f < 4u; ++f) {
            bw::Frame frame;
            frame.bytes.resize(1);   // not even an 8-bit field plus a byte
            tiny.push_back(frame);
        }
        const bw::SearchReport report = bw::search(tiny);
        CHECK(report.candidates.empty());
    }

    SUBCASE("identical frames are one observation, not many") {
        // A quiet bus sending the same heartbeat over and over. Several
        // algorithms will match a single short frame, and repeating it does
        // not make any of them more likely -- so the evidence must not grow
        // with the frame count.
        std::vector<bw::Frame> repeated;
        bw::Frame              beat;
        beat.bytes.resize(2, 0);   // CRC-8 of one zero byte is zero: a real,
                                   // and completely uninformative, match
        for (std::size_t f = 0; f < 40u; ++f) {
            repeated.push_back(beat);
        }

        const bw::SearchReport report = bw::search(repeated);
        CHECK(report.frames == 40u);
        CHECK(report.distinct_frames == 1u);
        CHECK(report.evidence_bits <= 16u);
        CHECK_FALSE(report.confident());
    }

    SUBCASE("a zero-length covered range never counts as a match") {
        // A CRC over nothing is a constant, so it would match every frame
        // that happened to carry that constant -- an answer that means
        // nothing.
        std::vector<bw::Frame> frames;
        bw::Frame frame;
        frame.bytes.resize(2, 0);
        frames.push_back(frame);

        bw::Layout zero;
        zero.width       = 16;
        zero.header_skip = 0;
        CHECK_FALSE(zero.fits(2));
    }
}

TEST_CASE("extract_checksum reads both byte orders") {
    bw::Frame frame;
    frame.bytes = { 0xAA, 0xBB, 0x12, 0x34 };

    bw::Layout big;
    big.width      = 16;
    big.big_endian = true;
    CHECK(bw::extract_checksum(frame, big) == 0x1234u);

    bw::Layout little;
    little.width      = 16;
    little.big_endian = false;
    CHECK(bw::extract_checksum(frame, little) == 0x3412u);

    bw::Layout wide;
    wide.width      = 32;
    wide.big_endian = true;
    CHECK_FALSE(wide.fits(frame.bytes.size()));   // nothing left to cover
}

TEST_CASE("a layout whose width is not a whole number of bytes is refused") {
    // field_bytes() is width/8, so a 15-bit CRC would claim a one-byte
    // field and extract_checksum would silently return eight bits of a
    // fifteen-bit value. search() skips these widths, but Layout,
    // extract_checksum and verify are public, and a caller building a
    // 15-bit layout by hand deserves a refusal rather than plausible
    // rubbish.
    bw::Layout can;
    can.width = 15;
    CHECK_FALSE(can.fits(32));

    bw::Layout fd;
    fd.width = 17;
    CHECK_FALSE(fd.fits(32));

    bw::Layout ok;
    ok.width = 16;
    CHECK(ok.fits(32));

    // And verify must not accept one either.
    const bw::CrcSpec* spec = bw::catalog_find("CRC-15/CAN");
    REQUIRE(spec != nullptr);
    std::vector<bw::Frame> frames;
    bw::Frame              frame;
    frame.bytes.resize(8, 0x5A);
    frames.push_back(frame);
    CHECK_FALSE(bw::verify(frames, can, *spec));
}

TEST_CASE("asking for only one byte order still finds a one-byte checksum") {
    // A one-byte field has no byte order, so the search collapses the two
    // into one pass. It must not collapse them onto an option the caller
    // switched off -- that would silently search nothing.
    const bw::CrcSpec* spec = bw::catalog_find("CRC-8");
    REQUIRE(spec != nullptr);

    bw::Layout layout;
    layout.width = 8;
    const std::vector<bw::Frame> frames = synthesise(*spec, layout, 8, 10);

    bw::SearchOptions little_only;
    little_only.try_big_endian    = false;
    little_only.try_little_endian = true;

    const bw::SearchReport report = bw::search(frames, little_only);
    CHECK(contains(report, "CRC-8"));

    // Symmetrically, big-endian only.
    bw::SearchOptions big_only;
    big_only.try_big_endian    = true;
    big_only.try_little_endian = false;
    CHECK(contains(bw::search(frames, big_only), "CRC-8"));

    // Neither is a caller error, and must find nothing rather than assume.
    bw::SearchOptions none;
    none.try_big_endian    = false;
    none.try_little_endian = false;
    CHECK(bw::search(frames, none).candidates.empty());
}

TEST_CASE("a truncated candidate list is not mistaken for a unique answer") {
    // max_candidates caps the list. If the cap is hit, the report holds
    // fewer candidates than were actually found -- and a cap of one would
    // make an ambiguous result look unique, which is the one conclusion the
    // caller must never draw by accident.
    // Frames of zeroes match CRC-8 (init 0, xorout 0) at every header skip,
    // because the CRC of any run of zero bytes is zero and so is the
    // checksum field. That is a genuinely ambiguous corpus, and a
    // deterministic one -- which is what this test needs, since asserting
    // that a truncation happened requires actually causing one.
    std::vector<bw::Frame> zeroes;
    for (std::size_t f = 0; f < 3u; ++f) {
        bw::Frame frame;
        frame.bytes.resize(6, 0x00);
        zeroes.push_back(frame);
    }

    // Raised well above what this corpus produces -- the default cap of 64
    // is not enough for frames of zeroes, which is itself worth knowing.
    bw::SearchOptions roomy;
    roomy.max_candidates = 100000;
    const bw::SearchReport full = bw::search(zeroes, roomy);
    REQUIRE(full.candidates.size() > 1u);   // genuinely ambiguous
    CHECK_FALSE(full.truncated);
    CHECK_FALSE(full.unique());

    bw::SearchOptions capped;
    capped.max_candidates = 1;
    const bw::SearchReport report = bw::search(zeroes, capped);

    CHECK(report.candidates.size() == 1u);
    CHECK(report.truncated);
    // The whole point: one candidate in the list, but not a unique answer.
    CHECK_FALSE(report.unique());
    CHECK_FALSE(report.confident());
}
