// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 2 as the pipeline uses it: the CRC search over the frames of a
// segmentation. The search itself is tested in test_crc_search.cpp; what is
// checked here is what this stage adds: choosing the frames of one size,
// answering only when the search is confident, and putting the answer in plain
// types.

#include "doctest.h"

#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "bw/catalog.h"
#include "bw/checksum.h"
#include "bw/protocol.h"
#include "bw/segmentation.h"
#include "bw/sums.h"
#include "frame_fixtures.h"

using bw::ByteOrder;
using bw::Capture;
using bw::ChecksumFinding;
using bw::Segmentation;
using fixtures::Bytes;

namespace {

Segmentation cut(const Capture& c) {
    return bw::segment_by_gaps(c, bw::SegmentationOptions());
}

// A segmentation that says which frames there are, whatever the capture's timing.
Segmentation frames_of(const std::vector<bw::FrameSpan>& spans) {
    return Segmentation(bw::SegmentationInfo(), spans);
}

// payload bytes, then the CRC-16/MODBUS of the payload, low byte first; `before` bytes
// ahead of the payload that the CRC does not cover and `after` behind the CRC.
Bytes frame_with_crc(fixtures::Random* rng, std::size_t payload, std::size_t before, std::size_t after) {
    Bytes f;
    for (std::size_t i = 0; i < before + payload; ++i) {
        f.push_back(rng->byte());
    }
    const std::uint16_t crc = fixtures::crc16_modbus(f, before, f.size());
    f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
    f.push_back(static_cast<std::uint8_t>(crc >> 8));
    for (std::size_t i = 0; i < after; ++i) {
        f.push_back(rng->byte());
    }
    return f;
}

std::vector<Bytes> many(fixtures::Random* rng, std::size_t count, std::size_t payload,
                        std::size_t before = 0, std::size_t after = 0) {
    std::vector<Bytes> frames;
    for (std::size_t i = 0; i < count; ++i) {
        frames.push_back(frame_with_crc(rng, payload, before, after));
    }
    return frames;
}

} // namespace

TEST_CASE("checksum stage: a CRC at the end of every frame is found, with where and what") {
    fixtures::Random rng(11);
    const Capture c = fixtures::capture_of(many(&rng, 20, 6));
    const ChecksumFinding f = bw::find_checksum(c, cut(c), 8);
    REQUIRE(f.found);
    CHECK(f.frames == 20);
    CHECK(f.distinct_frames == 20);
    CHECK(f.candidates == 1);
    CHECK_FALSE(f.truncated);
    CHECK(f.evidence_bits == 20 * 16);
    CHECK(f.header_skip == 0);
    CHECK(f.trailer_skip == 0);
    CHECK(f.width_bits == 16);
    CHECK(f.byte_order == ByteOrder::Little);
    CHECK(bw::checksum_algorithm_name(f.algorithm) == "CRC-16/MODBUS");
}

TEST_CASE("checksum stage: bytes before the covered range and after the checksum are found too") {
    fixtures::Random rng(12);
    const Capture c = fixtures::capture_of(many(&rng, 20, 5, 2, 1));       // 2 + 5 + 2 + 1 = 10 bytes
    const ChecksumFinding f = bw::find_checksum(c, cut(c), 10);
    REQUIRE(f.found);
    CHECK(f.header_skip == 2);
    CHECK(f.trailer_skip == 1);
    CHECK(f.width_bits == 16);
    CHECK(f.byte_order == ByteOrder::Little);
}

TEST_CASE("checksum stage: only the frames of the size asked for are searched") {
    fixtures::Random rng(13);
    std::vector<Bytes> frames = many(&rng, 12, 6);                 // 8 bytes with a CRC
    const std::vector<Bytes> other = many(&rng, 9, 3);             // 5 bytes with a CRC
    frames.insert(frames.end(), other.begin(), other.end());
    Bytes unrelated;                                               // 7 bytes with no checksum
    for (int i = 0; i < 7; ++i) {
        unrelated.push_back(rng.byte());
    }
    frames.push_back(unrelated);
    frames.push_back(unrelated);                                   // twice, so it is not alone
    const Capture c = fixtures::capture_of(frames);
    const Segmentation s = cut(c);
    REQUIRE(s.info().found);

    const ChecksumFinding eight = bw::find_checksum(c, s, 8);
    CHECK(eight.found);
    CHECK(eight.frames == 12);
    const ChecksumFinding five = bw::find_checksum(c, s, 5);
    CHECK(five.found);
    CHECK(five.frames == 9);
    const ChecksumFinding seven = bw::find_checksum(c, s, 7);
    CHECK_FALSE(seven.found);
    CHECK(seven.frames == 2);
    CHECK(seven.distinct_frames == 1);
    const ChecksumFinding none = bw::find_checksum(c, s, 6);
    CHECK_FALSE(none.found);
    CHECK(none.frames == 0);
    CHECK(none.candidates == 0);
}

TEST_CASE("checksum stage: it answers only on enough evidence, and says how many frames it had") {
    fixtures::Random rng(14);
    // One frame of 16 bits is 16 bits of evidence, and the bar is 32.
    {
        const Capture c = fixtures::capture_of(many(&rng, 1, 6));
        bw::FrameSpan whole;
        whole.event_count = 8;
        const ChecksumFinding f =
            bw::find_checksum(c, frames_of(std::vector<bw::FrameSpan>(1, whole)), 8);
        CHECK_FALSE(f.found);
        CHECK(f.frames == 1);
        CHECK(f.candidates >= 1);
        // 16 bits, or 8 if one of the many checksums of a byte matched one frame by chance.
        CHECK(f.evidence_bits <= 16);
        CHECK(f.evidence_bits >= 8);
    }
    // Two different frames reach it exactly.
    {
        const Capture c = fixtures::capture_of(many(&rng, 2, 6));
        const ChecksumFinding f = bw::find_checksum(c, cut(c), 8);
        CHECK(f.evidence_bits == 32);
        CHECK(f.found);
    }
    // The same frame twice is one observation.
    {
        const Bytes frame = frame_with_crc(&rng, 6, 0, 0);
        const Capture c = fixtures::capture_of(std::vector<Bytes>(2, frame));
        const ChecksumFinding f = bw::find_checksum(c, cut(c), 8);
        CHECK(f.frames == 2);
        CHECK(f.distinct_frames == 1);
        CHECK(f.evidence_bits <= 16);
        CHECK(f.evidence_bits >= 8);
        CHECK_FALSE(f.found);
    }
}

TEST_CASE("checksum stage: a bad checksum in one frame, or none at all, is not found") {
    fixtures::Random rng(15);
    std::vector<Bytes> frames = many(&rng, 20, 6);
    frames[7][7] = static_cast<std::uint8_t>(frames[7][7] ^ 0x01);          // one wrong CRC byte
    const Capture bad = fixtures::capture_of(frames);
    const ChecksumFinding f = bw::find_checksum(bad, cut(bad), 8);
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 0);

    std::vector<Bytes> noise;
    for (int i = 0; i < 20; ++i) {
        Bytes b;
        for (int k = 0; k < 8; ++k) {
            b.push_back(rng.byte());
        }
        noise.push_back(b);
    }
    const Capture random = fixtures::capture_of(noise);
    const ChecksumFinding g = bw::find_checksum(random, cut(random), 8);
    CHECK_FALSE(g.found);
    CHECK(g.candidates == 0);
    CHECK(g.frames == 20);
}

TEST_CASE("checksum stage: the Modbus RTU generator's frames give its checksum") {
    bw::GenerateOptions options;
    options.seed   = 5;
    options.frames = 30;
    const bw::Dataset d = bw::generate_protocol("modbus-rtu", options);
    const ChecksumFinding f = bw::find_checksum(d.capture(), frames_of(d.frames()), 8);
    REQUIRE(f.found);
    CHECK(f.header_skip == 0);
    CHECK(f.trailer_skip == 0);
    CHECK(f.byte_order == ByteOrder::Little);
    CHECK(bw::checksum_algorithm_name(f.algorithm) == "CRC-16/MODBUS");
}

TEST_CASE("checksum stage: algorithm names are the catalogue's and then the sums', and an index outside throws") {
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        CHECK(bw::checksum_algorithm_name(static_cast<std::uint32_t>(i)) == bw::catalog()[i].name);
    }
    for (std::size_t i = 0; i < bw::sum_count(); ++i) {
        CHECK(bw::checksum_algorithm_name(static_cast<std::uint32_t>(bw::catalog_size() + i)) == bw::sums()[i].name);
    }
    CHECK_THROWS_AS(bw::checksum_algorithm_name(static_cast<std::uint32_t>(bw::catalog_size() + bw::sum_count())),
                    std::out_of_range);
    CHECK_THROWS_AS(bw::checksum_algorithm_name(std::numeric_limits<std::uint32_t>::max()), std::out_of_range);
}

TEST_CASE("checksum stage: an 8-bit checksum has no byte order") {
    // CRC-8 of the catalogue: polynomial 0x07, initial value 0, written bit by bit.
    fixtures::Random rng(16);
    std::vector<Bytes> frames;
    for (int i = 0; i < 20; ++i) {
        Bytes f;
        std::uint8_t crc = 0;
        for (int k = 0; k < 5; ++k) {
            f.push_back(rng.byte());
            crc = static_cast<std::uint8_t>(crc ^ f.back());
            for (int bit = 0; bit < 8; ++bit) {
                crc = static_cast<std::uint8_t>((crc & 0x80) ? (crc << 1) ^ 0x07 : (crc << 1));
            }
        }
        f.push_back(crc);
        frames.push_back(f);
    }
    const Capture c = fixtures::capture_of(frames);
    const ChecksumFinding f = bw::find_checksum(c, cut(c), 6);
    REQUIRE(f.found);
    CHECK(f.width_bits == 8);
    CHECK(f.byte_order == ByteOrder::NotApplicable);
    CHECK(f.evidence_bits == 20 * 8);
    CHECK(bw::checksum_algorithm_name(f.algorithm) == "CRC-8");
}

TEST_CASE("checksum stage: when too much matches it keeps no answer and says it was cut short") {
    // Frames of zeros have the checksum 0 under every CRC that starts from 0.
    const Capture c = fixtures::capture_of(std::vector<Bytes>(6, Bytes(8, 0)));
    const ChecksumFinding f = bw::find_checksum(c, cut(c), 8);
    CHECK_FALSE(f.found);
    CHECK(f.truncated);
    CHECK(f.candidates == 64);                 // as many as the search keeps
    CHECK(f.distinct_frames == 1);
}

TEST_CASE("checksum stage: a real checksum on one frame repeated is one of several") {
    fixtures::Random rng(17);
    const Bytes frame = frame_with_crc(&rng, 6, 0, 0);
    const Capture c = fixtures::capture_of(std::vector<Bytes>(5, frame));
    const ChecksumFinding f = bw::find_checksum(c, cut(c), 8);
    CHECK_FALSE(f.found);
    CHECK(f.candidates >= 1);                  // the real one is among them
    CHECK(f.evidence_bits <= 16);
    CHECK(f.frames == 5);
}

namespace {

// CRC-16/MCRF4XX of MAVLink, bit by bit and reflected, over bytes [from, to) and then over one byte more
// that is not in the frame; and a CRC-8 of the polynomial given, from zero and not reflected, likewise.
// Written here, so that the test does not rest on the code it tests.
std::uint16_t mcrf4xx(const Bytes& data, std::size_t from, std::size_t to, std::uint8_t extra) {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = from; i <= to; ++i) {
        crc = static_cast<std::uint16_t>(crc ^ (i < to ? data[i] : extra));
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1u) ? static_cast<std::uint16_t>((crc >> 1) ^ 0x8408u) : static_cast<std::uint16_t>(crc >> 1);
        }
    }
    return crc;
}

std::uint8_t crc8(const Bytes& data, std::size_t from, std::size_t to, std::uint8_t extra, std::uint8_t poly) {
    std::uint8_t crc = 0;
    for (std::size_t i = from; i <= to; ++i) {
        crc = static_cast<std::uint8_t>(crc ^ (i < to ? data[i] : extra));
        for (int bit = 0; bit < 8; ++bit) {
            crc = static_cast<std::uint8_t>((crc & 0x80) ? (crc << 1) ^ poly : (crc << 1));
        }
    }
    return crc;
}

// `count` frames: a start byte, `payload` random bytes, and the CRC-16 of the payload and `extra`, low byte first.
std::vector<Bytes> mavlink_like(fixtures::Random* rng, std::size_t count, std::size_t payload, std::uint8_t extra) {
    std::vector<Bytes> frames;
    for (std::size_t i = 0; i < count; ++i) {
        Bytes f(1, 0xFE);
        for (std::size_t k = 0; k < payload; ++k) {
            f.push_back(rng->byte());
        }
        const std::uint16_t crc = mcrf4xx(f, 1, f.size(), extra);
        f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
        f.push_back(static_cast<std::uint8_t>(crc >> 8));
        frames.push_back(f);
    }
    return frames;
}

} // namespace

TEST_CASE("checksum stage: a CRC with a byte that is in no frame is found when nothing else explains them") {
    fixtures::Random rng(41);
    const std::uint8_t extras[] = { 0, 50, 124, 217, 255 };
    for (std::size_t e = 0; e < sizeof(extras); ++e) {
        CAPTURE(static_cast<unsigned>(extras[e]));
        const std::vector<Bytes> frames = mavlink_like(&rng, 20, 14, extras[e]);
        const Capture c = fixtures::capture_of(frames);
        const ChecksumFinding f = bw::find_checksum(c, cut(c), static_cast<std::uint32_t>(frames[0].size()));
        REQUIRE(f.found);
        CHECK(bw::checksum_algorithm_name(f.algorithm) == "CRC-16/MCRF4XX");
        CHECK(f.seeded);
        CHECK(f.seed == extras[e]);
        CHECK(f.header_skip == 1);
        CHECK(f.trailer_skip == 0);
        CHECK(f.width_bits == 16);
        CHECK(f.byte_order == ByteOrder::Little);
        CHECK(f.candidates == 1);
        CHECK(f.evidence_bits == 20 * 16 - 8);            // the byte was chosen to fit: eight bits off
    }
}

TEST_CASE("checksum stage: a byte that is in no frame is looked for in three different frames or more") {
    fixtures::Random rng(42);
    const std::vector<Bytes> base = mavlink_like(&rng, 3, 14, 50);
    const std::uint32_t      size = static_cast<std::uint32_t>(base[0].size());
    // Three: 3 x 16 less 8 is 40 bits.
    {
        const Capture c = fixtures::capture_of(base);
        const ChecksumFinding f = bw::find_checksum(c, cut(c), size);
        REQUIRE(f.found);
        CHECK(f.seeded);
        CHECK(f.evidence_bits == 40);
    }
    // Two are not looked at: the answer would be a guess, and it is nothing.
    {
        const Capture c = fixtures::capture_of(std::vector<Bytes>(base.begin(), base.begin() + 2));
        const ChecksumFinding f = bw::find_checksum(c, cut(c), size);
        CHECK_FALSE(f.found);
        CHECK(f.candidates == 0);
        CHECK(f.evidence_bits == 0);
        CHECK(f.distinct_frames == 2);
    }
    // The same two, ten times each, are still two.
    {
        std::vector<Bytes> many;
        for (int i = 0; i < 10; ++i) {
            many.push_back(base[0]);
            many.push_back(base[1]);
        }
        const Capture c = fixtures::capture_of(many);
        const ChecksumFinding f = bw::find_checksum(c, cut(c), size);
        CHECK_FALSE(f.found);
        CHECK(f.candidates == 0);
        CHECK(f.distinct_frames == 2);
        CHECK(f.frames == 20);
    }
    // And three, ten times each, are three.
    {
        std::vector<Bytes> many;
        for (int i = 0; i < 10; ++i) {
            many.insert(many.end(), base.begin(), base.end());
        }
        const Capture c = fixtures::capture_of(many);
        const ChecksumFinding f = bw::find_checksum(c, cut(c), size);
        REQUIRE(f.found);
        CHECK(f.distinct_frames == 3);
        CHECK(f.evidence_bits == 40);
    }
}

TEST_CASE("checksum stage: a checksum of a byte with a hidden byte needs five frames, not four") {
    // 8 bits of checksum in each frame, less the 8 that the hidden byte was free to be: 32 bits are five.
    // CRC-8/DVB-S2 (polynomial 0xD5), the only one of the catalogue with that polynomial.
    fixtures::Random rng(43);
    for (std::size_t count = 3; count <= 6; ++count) {
        CAPTURE(count);
        std::vector<Bytes> frames;
        for (std::size_t i = 0; i < count; ++i) {
            Bytes f;
            for (int k = 0; k < 6; ++k) {
                f.push_back(rng.byte());
            }
            f.push_back(crc8(f, 0, f.size(), 0x5C, 0xD5));
            frames.push_back(f);
        }
        const Capture c = fixtures::capture_of(frames);
        const ChecksumFinding f = bw::find_checksum(c, cut(c), 7);
        CHECK(f.found == (count >= 5));
        CHECK(f.candidates >= 1);
        CHECK(f.evidence_bits == (count - 1) * 8);
        if (f.found) {
            CHECK(f.seeded);
            CHECK(f.seed == 0x5C);
            CHECK(bw::checksum_algorithm_name(f.algorithm) == "CRC-8/DVB-S2");
        }
    }
}

TEST_CASE("checksum stage: with a hidden byte, CRCs of a byte that differ only in the initial value or the xor are one") {
    // The byte put in front of the last step of a CRC of 8 bits is as wide as its register, so whatever a
    // CRC-8 starts from or ends with, there is a value of the byte that makes up the difference: CRC-8 and
    // CRC-8/I-432-1 (the same polynomial, a final xor of 0x55) explain the same frames, with two different
    // bytes. The search cannot tell them apart, and says so, however many frames it has.
    fixtures::Random rng(45);
    std::vector<Bytes> frames;
    for (int i = 0; i < 12; ++i) {
        Bytes f;
        for (int k = 0; k < 6; ++k) {
            f.push_back(rng.byte());
        }
        f.push_back(crc8(f, 0, f.size(), 0x5C, 0x07));
        frames.push_back(f);
    }
    const Capture c = fixtures::capture_of(frames);
    const ChecksumFinding f = bw::find_checksum(c, cut(c), 7);
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 2);
    CHECK(f.evidence_bits == 11 * 8);
}

TEST_CASE("checksum stage: what has a checksum as it is, is not said to have a hidden byte") {
    // A CRC, and a sum, as they are: nothing is added, and it is not searched.
    fixtures::Random rng(44);
    const Capture crc = fixtures::capture_of(many(&rng, 20, 6));
    const ChecksumFinding with_crc = bw::find_checksum(crc, cut(crc), 8);
    REQUIRE(with_crc.found);
    CHECK_FALSE(with_crc.seeded);
    CHECK(with_crc.seed == 0);
    CHECK(with_crc.evidence_bits == 20 * 16);

    // Frames of a CRC with a byte of its own, one frame wrong: it is nothing, and the byte does not make it so.
    std::vector<Bytes> frames = mavlink_like(&rng, 20, 14, 50);
    frames[9][5] = static_cast<std::uint8_t>(frames[9][5] ^ 1);
    const Capture bad = fixtures::capture_of(frames);
    const ChecksumFinding f = bw::find_checksum(bad, cut(bad), static_cast<std::uint32_t>(frames[0].size()));
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 0);
    CHECK(f.evidence_bits == 0);
}

TEST_CASE("checksum stage: random frames are not given a checksum, with the hidden byte in the search") {
    // The search with a byte that is in no frame has 2^8 more ways to be right by chance, which the
    // evidence it asks for has to pay for. Of many sets of random frames of different sizes and counts,
    // none has a candidate: the chance is 2^-24 for a set, or less.
    fixtures::Random rng(46);
    for (int trial = 0; trial < 20; ++trial) {
        CAPTURE(trial);
        const std::size_t count = 3 + static_cast<std::size_t>(trial % 6);
        const std::size_t size  = 9 + static_cast<std::size_t>(trial % 5);
        std::vector<Bytes> frames;
        for (std::size_t i = 0; i < count; ++i) {
            Bytes f;
            for (std::size_t k = 0; k < size; ++k) {
                f.push_back(rng.byte());
            }
            frames.push_back(f);
        }
        const Capture c = fixtures::capture_of(frames);
        const ChecksumFinding f = bw::find_checksum(c, cut(c), static_cast<std::uint32_t>(size));
        CHECK_FALSE(f.found);
        CHECK(f.candidates == 0);
    }
}
