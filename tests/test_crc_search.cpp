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

// As synthesise, but the CRC is over what the layout covers and then one byte that is not in the frame.
std::vector<bw::Frame> synthesise_hidden(const bw::CrcSpec& spec, const bw::Layout& layout, std::size_t count,
                                         std::size_t payload_len, u8 hidden, u64 seed) {
    std::vector<bw::Frame> frames = synthesise(spec, layout, count, payload_len, seed);
    for (std::size_t f = 0; f < frames.size(); ++f) {
        bw::Frame&        frame = frames[f];
        const std::size_t at    = layout.checksum_offset(frame.bytes.size());
        std::vector<u8>   covered(frame.bytes.begin() + static_cast<std::ptrdiff_t>(layout.covered_begin()),
                                  frame.bytes.begin() + static_cast<std::ptrdiff_t>(at));
        covered.push_back(hidden);
        const u64         value = bw::crc_compute(spec, covered.data(), covered.size());
        const std::size_t n     = layout.field_bytes();
        for (std::size_t i = 0; i < n; ++i) {
            const std::size_t shift = layout.big_endian ? (n - 1u - i) : i;
            frame.bytes[at + i] = static_cast<u8>((value >> (shift * 8u)) & 0xFFu);
        }
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

TEST_CASE("every byte-aligned algorithm is told from all the others, at the lengths a bus has") {
    // Recoverable is not enough: with 60-odd entries, two that give the same value on every frame of a
    // length would make every search at that length ambiguous. Each one is the only answer, with the
    // layout it was built with, for payloads of 8 bytes to over a hundred (a payload shorter than the CRC
    // is not a case: the CRC of one byte has bytes that never change, and a narrower CRC explains those).
    // The one length with a pair of algorithms that are the same function is the next test's.
    const std::size_t lengths[] = { 8, 31, 126, 128 };
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& spec = bw::catalog()[i];
        if (spec.width % 8u != 0) {
            continue;
        }
        for (std::size_t l = 0; l < sizeof(lengths) / sizeof(lengths[0]); ++l) {
            CAPTURE(std::string(spec.name));
            CAPTURE(lengths[l]);
            bw::Layout layout;
            layout.width      = spec.width;
            layout.big_endian = true;
            const bw::SearchReport report = bw::search(synthesise(spec, layout, 8, lengths[l], 0x5EED00u + i));
            REQUIRE(report.candidates.size() == 1);
            CHECK(report.candidates[0].spec == &spec);
            CHECK(report.candidates[0].layout.header_skip == 0);
            CHECK(report.candidates[0].layout.trailer_skip == 0);
            CHECK(report.confident());
        }
    }
}

TEST_CASE("two algorithms that are the same function at one length are two candidates at that length") {
    // CRC-8/AUTOSAR and CRC-8/OPENSAFETY have the same polynomial, and differ in the initial value and the
    // final xor. The initial value's share of a CRC over n bytes is that value times x^(8n) modulo the
    // polynomial, and for this polynomial x has order 127: at 127 bytes it is the value itself, and the
    // two differences cancel. That is a fact about the algorithms and not a miss of the search.
    const bw::CrcSpec* autosar    = bw::catalog_find("CRC-8/AUTOSAR");
    const bw::CrcSpec* opensafety = bw::catalog_find("CRC-8/OPENSAFETY");
    REQUIRE(autosar != nullptr);
    REQUIRE(opensafety != nullptr);
    bw::Layout layout;
    layout.width = 8;
    for (std::size_t n = 125; n <= 129; ++n) {
        CAPTURE(n);
        const bw::SearchReport report = bw::search(synthesise(*autosar, layout, 12, n, 77));
        CHECK(contains(report, "CRC-8/AUTOSAR"));
        CHECK(contains(report, "CRC-8/OPENSAFETY") == (n == 127));
        CHECK(report.unique() == (n != 127));
        CHECK(report.confident() == (n != 127));
    }
}

TEST_CASE("a CRC that holds a narrower one is one answer, not two") {
    // The polynomial of CRC-16/LJ1200 is a multiple of the one of CRC-8/GSM-A, and neither starts from
    // anything nor ends with a xor; so a frame that ends in the first has, over the bytes before its last,
    // the second as well. CRC-64/ECMA-182 holds CRC-16/UMTS the same way. The narrower is a part of the
    // wider, and the evidence is the wider's.
    struct Row {
        const char* wide;
        const char* narrow;
    };
    const Row rows[] = { { "CRC-16/LJ1200", "CRC-8/GSM-A" }, { "CRC-64/ECMA-182", "CRC-16/UMTS" } };
    for (std::size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); ++r) {
        const bw::CrcSpec* wide   = bw::catalog_find(rows[r].wide);
        const bw::CrcSpec* narrow = bw::catalog_find(rows[r].narrow);
        REQUIRE(wide != nullptr);
        REQUIRE(narrow != nullptr);
        CAPTURE(std::string(rows[r].wide));
        for (std::size_t trailer = 0; trailer <= 2; ++trailer) {
            CAPTURE(trailer);
            bw::Layout layout;
            layout.width        = wide->width;
            layout.big_endian   = true;
            layout.trailer_skip = trailer;
            const std::vector<bw::Frame> frames = synthesise(*wide, layout, 12, 20, 0xFACE00u + trailer);
            // The narrower one does explain every frame, over the bytes up to its own last one...
            // ...as its field is the last byte or bytes of the wider's, and what it covers is the rest.
            bw::Layout inner;
            inner.width        = narrow->width;
            inner.big_endian   = true;
            inner.trailer_skip = trailer;
            REQUIRE(bw::verify(frames, inner, *narrow));
            // And the search, which finds both, gives one.
            const bw::SearchReport report = bw::search(frames);
            REQUIRE(report.candidates.size() == 1);
            CHECK(report.candidates[0].spec == wide);
            CHECK(report.evidence_bits == 12u * wide->width);
            CHECK(report.confident());
        }
    }
}

TEST_CASE("a CRC beside another CRC, not inside it, is another answer") {
    // A frame with a CRC-16 and, over everything before it, a CRC-8 (or the other way round) has two
    // checksums, and both are findings: neither is in the field of the other.
    const bw::CrcSpec* wide   = bw::catalog_find("CRC-16/MODBUS");
    const bw::CrcSpec* narrow = bw::catalog_find("CRC-8");
    REQUIRE(wide != nullptr);
    REQUIRE(narrow != nullptr);
    for (int order = 0; order < 2; ++order) {
        CAPTURE(order);
        reseed(0xC0DE00u + static_cast<u64>(order));
        std::vector<bw::Frame> frames;
        for (int f = 0; f < 12; ++f) {
            bw::Frame frame;
            for (int i = 0; i < 10; ++i) {
                frame.bytes.push_back(next_byte());
            }
            // order 0: the CRC-16, then the CRC-8 over both; order 1: the CRC-8, then the CRC-16 over both.
            const bw::CrcSpec& first  = order == 0 ? *wide : *narrow;
            const bw::CrcSpec& second = order == 0 ? *narrow : *wide;
            for (int pass = 0; pass < 2; ++pass) {
                const bw::CrcSpec& spec  = pass == 0 ? first : second;
                const u64          value = bw::crc_compute(spec, frame.bytes.data(), frame.bytes.size());
                for (int b = spec.width / 8 - 1; b >= 0; --b) {
                    frame.bytes.push_back(static_cast<u8>((value >> (8 * b)) & 0xFFu));
                }
            }
            frames.push_back(frame);
        }
        const bw::SearchReport report = bw::search(frames);
        CHECK(report.candidates.size() == 2);
        CHECK(contains(report, "CRC-16/MODBUS"));
        CHECK(contains(report, "CRC-8"));
        CHECK_FALSE(report.unique());
        CHECK(report.evidence_bits == 12u * 8u);            // the narrower of the two is the weaker claim
    }
}

TEST_CASE("a byte that is in no frame is found, with its value, when the search is asked for it") {
    // MAVLink's CRC: CRC-16/MCRF4XX over the frame and then over CRC_EXTRA, a number each message has and
    // both ends know. Asked to, the search tries every CRC with one more byte, of any value, after the
    // covered range, and the same byte has to explain every frame.
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/MCRF4XX");
    REQUIRE(spec != nullptr);
    const u8 values[] = { 0, 1, 50, 124, 127, 128, 217, 254, 255 };
    for (std::size_t v = 0; v < sizeof(values) / sizeof(values[0]); ++v) {
        CAPTURE(static_cast<unsigned>(values[v]));
        bw::Layout layout;
        layout.width      = 16;
        layout.big_endian = false;
        layout.header_skip = 1;
        const std::vector<bw::Frame> frames = synthesise_hidden(*spec, layout, 10, 20, values[v], 0xBEEF00u + v);

        // Not asked: nothing explains them.
        CHECK(bw::search(frames).candidates.empty());

        bw::SearchOptions options;
        options.hidden_byte = true;
        const bw::SearchReport report = bw::search(frames, options);
        REQUIRE(report.candidates.size() == 1);
        const bw::Candidate& found = report.candidates[0];
        CHECK(found.spec == spec);
        CHECK(found.seeded);
        CHECK(found.seed == values[v]);
        CHECK(found.layout.header_skip == 1);
        CHECK(found.layout.trailer_skip == 0);
        CHECK_FALSE(found.layout.big_endian);
        // 10 frames of 16 bits, less the 8 bits of the byte it was free to choose.
        CHECK(report.evidence_bits == 10u * 16u - 8u);
        CHECK(report.confident());
    }
}

TEST_CASE("asked for a byte nobody wrote, the search still finds a CRC that has none, as it is") {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/MODBUS");
    REQUIRE(spec != nullptr);
    bw::Layout layout;
    layout.width      = 16;
    layout.big_endian = false;
    const std::vector<bw::Frame> frames = synthesise(*spec, layout, 10, 20);
    bw::SearchOptions options;
    options.hidden_byte = true;
    const bw::SearchReport report = bw::search(frames, options);
    REQUIRE(report.candidates.size() == 1);
    CHECK(report.candidates[0].spec == spec);
    CHECK_FALSE(report.candidates[0].seeded);
    CHECK(report.evidence_bits == 10u * 16u);       // nothing was chosen: nothing is taken off
}

TEST_CASE("the bytes that make a CRC explain frames are all of those that do, and only those") {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/MCRF4XX");
    REQUIRE(spec != nullptr);
    bw::Layout layout;
    layout.width       = 16;
    layout.big_endian  = false;
    layout.header_skip = 1;
    const std::vector<bw::Frame> frames = synthesise_hidden(*spec, layout, 6, 12, 0xA5, 77);
    const std::vector<u8>        found  = bw::hidden_bytes(frames, layout, *spec);
    REQUIRE(found.size() == 1);
    CHECK(found[0] == 0xA5);

    // A CRC is a bijection of the byte that is put after what it covers, so a frame has at most one value of
    // it, and exactly one when a hidden byte explains it at all; with a single frame of 8 bits that is always
    // so, and each further frame leaves one value in 256.
    const bw::CrcSpec* crc8 = bw::catalog_find("CRC-8");
    REQUIRE(crc8 != nullptr);
    bw::Layout narrow;
    narrow.width = 8;
    const std::vector<bw::Frame> one = synthesise(*crc8, narrow, 1, 9, 5);       // a plain CRC-8, as it is
    CHECK(bw::hidden_bytes(one, narrow, *crc8).size() == 1);
    const std::vector<bw::Frame> more = synthesise_hidden(*crc8, narrow, 8, 9, 0x42, 6);
    const std::vector<u8>        eight = bw::hidden_bytes(more, narrow, *crc8);
    REQUIRE(eight.size() == 1);
    CHECK(eight[0] == 0x42);
    // The first frame alone is explained by one value and the second by one, and they are not the same one
    // (unless it is the right one): the frames are all asked.
    const std::vector<bw::Frame> first(more.begin(), more.begin() + 1);
    REQUIRE(bw::hidden_bytes(first, narrow, *crc8).size() == 1);
    CHECK(bw::hidden_bytes(first, narrow, *crc8)[0] == 0x42);

    // Nothing to explain, a layout that does not fit, and a spec of another width: none.
    CHECK(bw::hidden_bytes(std::vector<bw::Frame>(), layout, *spec).empty());
    bw::Layout too_long = layout;
    too_long.header_skip = 20;
    CHECK(bw::hidden_bytes(frames, too_long, *spec).empty());
    CHECK(bw::hidden_bytes(frames, narrow, *spec).empty());
    // A frame that is too short for the layout, among the rest, stops it.
    std::vector<bw::Frame> short_one = frames;
    short_one.push_back(bw::Frame());
    CHECK(bw::hidden_bytes(short_one, layout, *spec).empty());
}

TEST_CASE("what a candidate is worth is what its frames say, less the byte it chose") {
    bw::Candidate plain;
    bw::CrcSpec   spec = { "x", 16, 0x1021, 0, false, false, 0, 0 };
    plain.spec         = &spec;
    plain.layout.width = 16;
    CHECK(bw::candidate_evidence(plain, 5) == 80u);
    CHECK(bw::candidate_evidence(plain, 0) == 0u);
    bw::Candidate hidden = plain;
    hidden.seeded = true;
    hidden.seed   = 3;
    CHECK(bw::candidate_evidence(hidden, 5) == 72u);
    CHECK(bw::candidate_evidence(hidden, 1) == 8u);
    CHECK(bw::candidate_evidence(hidden, 0) == 0u);               // less than nothing is nothing
    bw::Candidate byte = hidden;
    byte.layout.width = 8;
    CHECK(bw::candidate_evidence(byte, 1) == 0u);                 // one frame of a byte: free to choose it
    CHECK(bw::candidate_evidence(byte, 5) == 32u);
}

TEST_CASE("a hidden byte on a single frame explains anything, and the search says so by not being sure") {
    // With one frame, every CRC of a byte has some value of the byte that explains it. Many candidates,
    // so many that the list is cut, and nothing to be confident of.
    const bw::CrcSpec* crc8 = bw::catalog_find("CRC-8");
    REQUIRE(crc8 != nullptr);
    bw::Layout layout;
    layout.width = 8;
    bw::SearchOptions options;
    options.hidden_byte = true;
    const bw::SearchReport report = bw::search(synthesise(*crc8, layout, 1, 12, 9), options);
    CHECK(report.candidates.size() == options.max_candidates);
    CHECK(report.truncated);
    CHECK_FALSE(report.confident());
}

TEST_CASE("a CRC that holds a narrower one is not two answers with a hidden byte either, if the byte is the same") {
    // CRC-16/LJ1200 and CRC-8/GSM-A, as before, with the same byte after what they cover: the byte is
    // in the message of both, and the narrower is still a part of the wider.
    const bw::CrcSpec* wide = bw::catalog_find("CRC-16/LJ1200");
    REQUIRE(wide != nullptr);
    bw::Layout layout;
    layout.width      = 16;
    layout.big_endian = true;
    const std::vector<bw::Frame> frames = synthesise_hidden(*wide, layout, 10, 20, 0x39, 4242);
    bw::SearchOptions options;
    options.hidden_byte = true;
    const bw::SearchReport report = bw::search(frames, options);
    REQUIRE(report.candidates.size() == 1);
    CHECK(report.candidates[0].spec == wide);
    CHECK(report.candidates[0].seed == 0x39);
    CHECK(report.candidates[0].seeded);
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

namespace {

// Frames of `payload` bytes, the first of which is `first`, and a CRC of the spec over all of them (header_skip 0,
// little-endian, at the end).
std::vector<bw::Frame> frames_starting_with(const bw::CrcSpec& spec, std::size_t count, std::size_t payload,
                                            const std::vector<u8>& leading, u64 seed) {
    reseed(seed);
    std::vector<bw::Frame> frames;
    for (std::size_t f = 0; f < count; ++f) {
        bw::Frame frame;
        for (std::size_t i = 0; i < payload; ++i) {
            frame.bytes.push_back(i < leading.size() ? leading[i] : next_byte());
        }
        const u64 value = bw::crc_compute(spec, frame.bytes.data(), frame.bytes.size());
        frame.bytes.push_back(static_cast<u8>(value & 0xFF));
        frame.bytes.push_back(static_cast<u8>(value >> 8));
        frames.push_back(frame);
    }
    return frames;
}

std::size_t count_of(const bw::SearchReport& report, const char* name) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        n += std::string(report.candidates[i].spec->name) == name ? 1 : 0;
    }
    return n;
}

} // namespace

TEST_CASE("zero_bytes: whether every frame has zeros in a range, and a range past the end is not zeros") {
    std::vector<bw::Frame> frames(3);
    for (std::size_t f = 0; f < 3; ++f) {
        frames[f].bytes = std::vector<u8>(4, 0);
        frames[f].bytes[3] = static_cast<u8>(1 + f);
    }
    CHECK(bw::zero_bytes(frames, 0, 3));
    CHECK(bw::zero_bytes(frames, 1, 3));
    CHECK(bw::zero_bytes(frames, 2, 2));                    // none: nothing is not a byte that is not zero
    CHECK_FALSE(bw::zero_bytes(frames, 0, 4));
    CHECK_FALSE(bw::zero_bytes(frames, 3, 4));
    CHECK_FALSE(bw::zero_bytes(frames, 0, 5));              // there is no fifth byte
    frames[1].bytes[1] = 7;
    CHECK_FALSE(bw::zero_bytes(frames, 0, 3));
    CHECK(bw::zero_bytes(frames, 2, 3));
    CHECK(bw::zero_bytes(std::vector<bw::Frame>(), 0, 5));  // no frames to say it is not
}

TEST_CASE("a checksum that starts after bytes that are always zero is the one that starts before them") {
    // A CRC that starts from zero, over frames whose first two bytes are zero: it explains them from the first byte, the
    // second and the third, which is one checksum and not three; the one that covers the zeros is kept.
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/XMODEM");
    REQUIRE(spec != nullptr);
    std::vector<u8> zeros(2, 0);
    const bw::SearchReport report = bw::search(frames_starting_with(*spec, 10, 10, zeros, 91));
    REQUIRE(count_of(report, "CRC-16/XMODEM") == 1);
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        if (std::string(report.candidates[i].spec->name) == "CRC-16/XMODEM") {
            CHECK(report.candidates[i].layout.header_skip == 0);
            CHECK(report.candidates[i].layout.trailer_skip == 0);
        }
    }
    // Bytes that are not zero but leave the register at zero, as the polynomial itself does (0x01 0x10 0x21, for
    // x^16 + 0x1021), are not zeros: with them first, the CRC from the first byte and the one from the fourth are two.
    std::vector<u8> polynomial(3, 0x10);
    polynomial[0] = 0x01;
    polynomial[2] = 0x21;
    const bw::SearchReport poly = bw::search(frames_starting_with(*spec, 10, 10, polynomial, 95));
    CHECK(count_of(poly, "CRC-16/XMODEM") == 2);
    // And one frame that has another byte in the zeros leaves the CRC that starts at the first byte, and not the others.
    std::vector<bw::Frame> mixed = frames_starting_with(*spec, 10, 10, zeros, 91);
    std::vector<bw::Frame> other = frames_starting_with(*spec, 1, 10, std::vector<u8>(), 92);
    mixed[4] = other[0];
    CHECK(count_of(bw::search(mixed), "CRC-16/XMODEM") == 1);
    // A CRC that does not start from zero is not the same from the second byte: the zeros are not nothing to it.
    const bw::CrcSpec* modbus = bw::catalog_find("CRC-16/MODBUS");
    REQUIRE(modbus != nullptr);
    const bw::SearchReport init = bw::search(frames_starting_with(*modbus, 10, 10, zeros, 93));
    REQUIRE(count_of(init, "CRC-16/MODBUS") == 1);
    for (std::size_t i = 0; i < init.candidates.size(); ++i) {
        if (std::string(init.candidates[i].spec->name) == "CRC-16/MODBUS") {
            CHECK(init.candidates[i].layout.header_skip == 0);
        }
    }
}

TEST_CASE("a CRC with a hidden byte that starts after zeros is the one that starts before them too") {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/XMODEM");
    REQUIRE(spec != nullptr);
    bw::Layout layout;
    layout.width = 16;
    std::vector<bw::Frame> frames = synthesise_hidden(*spec, layout, 10, 10, 77, 94);
    // Frames of 12 bytes with a CRC that has a byte of its own; their first byte made zero, and the CRC again.
    for (std::size_t f = 0; f < frames.size(); ++f) {
        frames[f].bytes[0] = 0;
        std::vector<u8> covered(frames[f].bytes.begin(), frames[f].bytes.end() - 2);
        covered.push_back(77);
        const u64 value = bw::crc_compute(*spec, covered.data(), covered.size());
        frames[f].bytes[10] = static_cast<u8>(value >> 8);
        frames[f].bytes[11] = static_cast<u8>(value & 0xFF);
    }
    bw::SearchOptions options;
    options.hidden_byte = true;
    const bw::SearchReport report = bw::search(frames, options);
    std::size_t seeded = 0;
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        const bw::Candidate& c = report.candidates[i];
        if (c.seeded && c.seed == 77 && std::string(c.spec->name) == "CRC-16/XMODEM") {
            ++seeded;
            CHECK(c.layout.header_skip == 0);
        }
    }
    CHECK(seeded == 1);
}
