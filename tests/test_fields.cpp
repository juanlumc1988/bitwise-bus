// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stages 4 and 5: where the fields of a message are and what they are. The
// frames are built by hand, so that each test knows the answer and the rule
// under test: how many distinct values make a byte constant, an enumeration or
// payload (at the exact boundary), when bytes are one field, what a counter is,
// and that nothing is claimed about frames too few to say anything.

#include "doctest.h"

#include <cstdint>
#include <cstring>
#include <functional>
#include <stdexcept>
#include <vector>

#include "bw/fields.h"
#include "frame_fixtures.h"

using bw::ByteOrder;
using bw::Capture;
using bw::ChecksumFinding;
using bw::FieldKind;
using bw::FieldMap;
using bw::FieldOptions;
using bw::FieldRegion;
using bw::FieldStructure;
using bw::Segmentation;
using fixtures::Bytes;

namespace {

Segmentation cut(const Capture& c) {
    return bw::segment_by_gaps(c, bw::SegmentationOptions());
}

ChecksumFinding no_checksum() {
    return ChecksumFinding();
}

// Discovery and typing of the frames, which are all of the same size.
FieldMap typed(const std::vector<Bytes>& frames, const ChecksumFinding& checksum = no_checksum(),
               const FieldOptions& options = FieldOptions()) {
    const Capture      c = fixtures::capture_of(frames);
    const Segmentation s = cut(c);
    REQUIRE(s.info().found);
    const FieldMap layout = bw::discover_fields(c, s, checksum,
                                                static_cast<std::uint32_t>(frames[0].size()), options);
    return bw::type_fields(layout, c, s);
}

FieldMap layout_of(const std::vector<Bytes>& frames, const ChecksumFinding& checksum = no_checksum(),
                   const FieldOptions& options = FieldOptions()) {
    const Capture      c = fixtures::capture_of(frames);
    const Segmentation s = cut(c);
    REQUIRE(s.info().found);
    return bw::discover_fields(c, s, checksum, static_cast<std::uint32_t>(frames[0].size()), options);
}

// n frames of `size` bytes; byte k of frame i is make(i, k).
template <typename F>
std::vector<Bytes> frames_by(std::size_t n, std::size_t size, F make) {
    std::vector<Bytes> out;
    for (std::size_t i = 0; i < n; ++i) {
        Bytes f;
        for (std::size_t k = 0; k < size; ++k) {
            f.push_back(static_cast<std::uint8_t>(make(i, k)));
        }
        out.push_back(f);
    }
    return out;
}

FieldRegion region(std::uint32_t offset, std::uint32_t size, FieldStructure structure) {
    FieldRegion r;
    r.byte_offset = offset;
    r.byte_size   = size;
    r.structure   = structure;
    return r;
}

// The structure of byte `at`, in frames where it takes `values` distinct values and
// every other byte is a constant.
FieldStructure structure_of(std::size_t frames, std::size_t values, const FieldOptions& options) {
    const std::vector<Bytes> f = frames_by(frames, 3, [&](std::size_t i, std::size_t k) {
        return k == 1 ? i % values : 9;
    });
    const FieldMap m = layout_of(f, no_checksum(), options);
    REQUIRE(m.region_count() == 3);
    return m.region(1).structure;
}

} // namespace

TEST_CASE("field map: the regions tile the frame, and a region that does not is refused") {
    FieldMap m(6, 10);
    CHECK(m.frame_bytes() == 6);
    CHECK(m.frames() == 10);
    CHECK(m.region_count() == 0);

    CHECK_THROWS_AS(m.add_region(region(1, 2, FieldStructure::Many)), std::invalid_argument);   // not at 0
    CHECK_THROWS_AS(m.add_region(region(0, 0, FieldStructure::Many)), std::invalid_argument);   // empty
    CHECK_THROWS_AS(m.add_region(region(0, 7, FieldStructure::Many)), std::invalid_argument);   // too long
    CHECK(m.region_count() == 0);

    m.add_region(region(0, 2, FieldStructure::Few));
    CHECK_THROWS_AS(m.add_region(region(1, 2, FieldStructure::Many)), std::invalid_argument);   // overlaps
    CHECK_THROWS_AS(m.add_region(region(3, 2, FieldStructure::Many)), std::invalid_argument);   // leaves a hole
    CHECK_THROWS_AS(m.add_region(region(2, 5, FieldStructure::Many)), std::invalid_argument);   // past the end
    CHECK(m.region_count() == 1);
    m.add_region(region(2, 4, FieldStructure::Many));                                           // up to the end
    CHECK(m.region_count() == 2);
    CHECK(m.region(1).byte_offset == 2);
    CHECK_THROWS_AS(m.region(2), std::out_of_range);
}

TEST_CASE("discovery: a byte is constant, one of a few, or many, by how many values it takes") {
    const FieldOptions options;     // 16 values at most, each on four frames or more on average
    CHECK(structure_of(20, 1, options) == FieldStructure::Constant);
    // Three values need twelve frames: four each.
    CHECK(structure_of(12, 3, options) == FieldStructure::Few);
    CHECK(structure_of(11, 3, options) == FieldStructure::Many);
    // Sixteen values need sixty-four frames, and seventeen are too many whatever the frames.
    CHECK(structure_of(64, 16, options) == FieldStructure::Few);
    CHECK(structure_of(63, 16, options) == FieldStructure::Many);
    CHECK(structure_of(200, 17, options) == FieldStructure::Many);
    // The limits are options.
    FieldOptions wider;
    wider.max_enum_values = 17;
    CHECK(structure_of(200, 17, wider) == FieldStructure::Few);
    FieldOptions narrower;
    narrower.max_enum_values = 2;
    CHECK(structure_of(40, 3, narrower) == FieldStructure::Many);
    CHECK(structure_of(40, 2, narrower) == FieldStructure::Few);
}

TEST_CASE("discovery: a run of bytes with no structure is one field, and the others one each") {
    // magic, enum, three random bytes, constant, a random byte.
    fixtures::Random rng(21);
    const std::vector<Bytes> frames = frames_by(60, 7, [&](std::size_t i, std::size_t k) -> unsigned {
        switch (k) {
            case 0:  return 0xA5;
            case 1:  return 1 + i % 3;
            case 2: case 3: case 4: return rng.byte();
            case 5:  return 0;
            default: return rng.byte();
        }
    });
    const FieldMap m = layout_of(frames);
    REQUIRE(m.region_count() == 5);
    CHECK(m.frames() == 60);
    CHECK(m.frame_bytes() == 7);
    const FieldStructure expected[5] = { FieldStructure::Constant, FieldStructure::Few,
                                         FieldStructure::Many, FieldStructure::Constant,
                                         FieldStructure::Many };
    const std::uint32_t offsets[5] = { 0, 1, 2, 5, 6 };
    const std::uint32_t sizes[5]   = { 1, 1, 3, 1, 1 };
    for (std::size_t i = 0; i < 5; ++i) {
        CHECK(m.region(i).structure == expected[i]);
        CHECK(m.region(i).byte_offset == offsets[i]);
        CHECK(m.region(i).byte_size == sizes[i]);
        CHECK(m.region(i).kind == FieldKind::Unknown);       // stage 5 has not run
    }
}

TEST_CASE("discovery: with fewer frames than min_frames nothing is claimed") {
    const std::vector<Bytes> three = frames_by(3, 4, [](std::size_t, std::size_t k) { return k; });
    CHECK(layout_of(three).region_count() == 0);
    CHECK(layout_of(three).frames() == 3);
    const std::vector<Bytes> four = frames_by(4, 4, [](std::size_t, std::size_t k) { return k; });
    CHECK(layout_of(four).region_count() == 4);
    FieldOptions stricter;
    stricter.min_frames = 5;
    CHECK(layout_of(four, no_checksum(), stricter).region_count() == 0);
    // Frames of another size are not these frames.
    const Capture c = fixtures::capture_of(four);
    CHECK(bw::discover_fields(c, cut(c), no_checksum(), 5, FieldOptions()).region_count() == 0);
    CHECK(bw::discover_fields(c, cut(c), no_checksum(), 5, FieldOptions()).frames() == 0);
}

TEST_CASE("typing: constants, enumerations, counters and payload, each with its evidence") {
    // 0: constant; 1: enum of three; 2: random; 3: constant; 4: counter, step 3; 5: constant; 6-7: random.
    fixtures::Random rng(22);
    const std::size_t n = 100;
    const FieldMap m = typed(frames_by(n, 8, [&](std::size_t i, std::size_t k) -> unsigned {
        switch (k) {
            case 0:  return 0xA5;
            case 1:  return 1 + i % 3;
            case 2:  return rng.byte();
            case 3:  return 0;
            case 4:  return i * 3;                    // 0, 3, 6, ... and over 255 it wraps
            case 5:  return 0xFF;
            default: return rng.byte();
        }
    }));
    REQUIRE(m.region_count() == 7);

    CHECK(m.region(0).kind == FieldKind::Constant);
    CHECK(m.region(0).constant == 0xA5);
    CHECK(m.region(0).evidence_bits == 8 * (n - 1));

    CHECK(m.region(1).kind == FieldKind::Enum);
    CHECK(m.region(1).evidence_bits == n * 6);               // 100 bytes of 8 bits, 2 bits to tell 3 apart

    CHECK(m.region(2).kind == FieldKind::Payload);
    CHECK(m.region(2).evidence_bits == 0);
    CHECK(m.region(2).byte_order == ByteOrder::NotApplicable);

    CHECK(m.region(3).kind == FieldKind::Constant);
    CHECK(m.region(3).constant == 0);

    CHECK(m.region(4).kind == FieldKind::Counter);
    CHECK(m.region(4).step == 3);
    CHECK(m.region(4).byte_order == ByteOrder::NotApplicable);      // one byte has no order
    CHECK(m.region(4).evidence_bits == 8 * (n - 2));

    CHECK(m.region(5).kind == FieldKind::Constant);
    CHECK(m.region(5).constant == 0xFF);

    CHECK(m.region(6).kind == FieldKind::Payload);
    CHECK(m.region(6).byte_size == 2);
}

TEST_CASE("typing: the evidence for an enumeration is what the values save over a whole byte") {
    // Two values, then four, then eight: one, two and three bits to tell them apart.
    const std::size_t n = 64;
    const FieldMap m = typed(frames_by(n, 7, [](std::size_t i, std::size_t k) -> unsigned {
        switch (k) {
            case 0:  return i % 2;
            case 1:  return 0;
            case 2:  return i % 4;
            case 3:  return 0;
            case 4:  return i % 8;
            case 5:  return 0;
            default: return i % 5 == 0 ? 7 : 3;       // two values again, unevenly
        }
    }));
    REQUIRE(m.region_count() == 7);
    CHECK(m.region(0).kind == FieldKind::Enum);
    CHECK(m.region(0).evidence_bits == n * 7);
    CHECK(m.region(2).evidence_bits == n * 6);
    CHECK(m.region(4).evidence_bits == n * 5);
    CHECK(m.region(6).evidence_bits == n * 7);
}

TEST_CASE("typing: a counter needs a step that never changes, and not zero") {
    const std::size_t n = 50;
    // Steps of 1 and of 200 (which wraps), at several starting points.
    const std::vector<Bytes> a = frames_by(n, 3, [](std::size_t i, std::size_t k) -> unsigned {
        return k == 1 ? 17 + i * 1 : 0;
    });
    CHECK(typed(a).region(1).kind == FieldKind::Counter);
    CHECK(typed(a).region(1).step == 1);
    const std::vector<Bytes> b = frames_by(n, 3, [](std::size_t i, std::size_t k) -> unsigned {
        return k == 1 ? 250 + i * 200 : 0;
    });
    CHECK(typed(b).region(1).kind == FieldKind::Counter);
    CHECK(typed(b).region(1).step == 200);

    // One step that differs breaks it.
    const std::vector<Bytes> broken = frames_by(n, 3, [](std::size_t i, std::size_t k) -> unsigned {
        return k == 1 ? (i < 30 ? i : i + 1) : 0;
    });
    CHECK(typed(broken).region(1).kind == FieldKind::Payload);
    // A step of 0 is a constant, which stage 4 already calls by its name.
    const std::vector<Bytes> flat = frames_by(n, 3, [](std::size_t, std::size_t) { return 5; });
    CHECK(typed(flat).region(1).kind == FieldKind::Constant);
    // Going down is a step too: 255 is -1.
    const std::vector<Bytes> down = frames_by(n, 3, [](std::size_t i, std::size_t k) -> unsigned {
        return k == 1 ? 200 - i : 0;
    });
    CHECK(typed(down).region(1).kind == FieldKind::Counter);
    CHECK(typed(down).region(1).step == 255);
}

TEST_CASE("typing: a counter of several bytes has its byte order, and the order it does not have is refused") {
    const std::size_t n = 100;
    // A 16-bit value that goes up by 0x1235 each frame: both bytes have many values.
    const auto value = [](std::size_t i) { return (i * 0x1235u + 7) & 0xFFFFu; };
    const std::vector<Bytes> little = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        switch (k) {
            case 0:  return 0;
            case 1:  return value(i) & 0xFF;       // low byte first
            case 2:  return value(i) >> 8;
            default: return 0;
        }
    });
    const FieldMap l = typed(little);
    REQUIRE(l.region_count() == 3);
    CHECK(l.region(1).kind == FieldKind::Counter);
    CHECK(l.region(1).byte_size == 2);
    CHECK(l.region(1).byte_order == ByteOrder::Little);
    CHECK(l.region(1).step == 0x1235);
    CHECK(l.region(1).evidence_bits == 16 * (n - 2));

    const std::vector<Bytes> big = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        switch (k) {
            case 0:  return 0;
            case 1:  return value(i) >> 8;         // high byte first
            case 2:  return value(i) & 0xFF;
            default: return 0;
        }
    });
    const FieldMap b = typed(big);
    CHECK(b.region(1).kind == FieldKind::Counter);
    CHECK(b.region(1).byte_order == ByteOrder::Big);
    CHECK(b.region(1).step == 0x1235);
}

TEST_CASE("typing: a counter needs at least three frames") {
    // 10, 17, 24, 31: four frames, the least stage 4 looks at. The evidence is what
    // the steps after the first one say: 8 bits each for the two that follow it.
    const std::vector<Bytes> four = frames_by(4, 3, [](std::size_t i, std::size_t k) -> unsigned {
        return k == 1 ? 10 + 7 * i : 0;
    });
    const FieldMap m = typed(four);
    CHECK(m.region(1).kind == FieldKind::Counter);
    CHECK(m.region(1).evidence_bits == 16);

    // Typing a layout by hand: three frames are enough, with 8 bits of evidence, and two are not.
    for (std::size_t frames = 2; frames <= 3; ++frames) {
        const Capture c = fixtures::capture_of(frames_by(frames, 3, [](std::size_t i, std::size_t k) -> unsigned {
            return k == 1 ? 10 + 7 * i : 0;
        }));
        FieldMap hand(3, static_cast<std::uint32_t>(frames));
        hand.add_region(region(0, 1, FieldStructure::Constant));
        hand.add_region(region(1, 1, FieldStructure::Many));
        hand.add_region(region(2, 1, FieldStructure::Constant));
        const FieldRegion r = bw::type_fields(hand, c, cut(c)).region(1);
        if (frames == 3) {
            CHECK(r.kind == FieldKind::Counter);
            CHECK(r.evidence_bits == 8);
        } else {
            CHECK(r.kind == FieldKind::Payload);
        }
    }
}

TEST_CASE("typing: random bytes give one payload and no claims") {
    // The negative control: nothing to find means one field of unknown structure.
    fixtures::Random rng(23);
    const FieldMap m = typed(frames_by(80, 12, [&](std::size_t, std::size_t) -> unsigned { return rng.byte(); }));
    REQUIRE(m.region_count() == 1);
    CHECK(m.region(0).byte_size == 12);
    CHECK(m.region(0).kind == FieldKind::Payload);
    CHECK(m.region(0).evidence_bits == 0);
}

TEST_CASE("typing: only single bytes are claimed as constants and enumerations") {
    // A region of two bytes marked Constant or Few by hand has no byte order to give.
    const Capture c = fixtures::capture_of(frames_by(10, 5, [](std::size_t, std::size_t) { return 1; }));
    const Segmentation s = cut(c);
    FieldMap hand(5, 10);
    hand.add_region(region(0, 2, FieldStructure::Constant));
    hand.add_region(region(2, 2, FieldStructure::Few));
    hand.add_region(region(4, 1, FieldStructure::Few));
    const FieldMap out = bw::type_fields(hand, c, s);
    CHECK(out.region(0).kind == FieldKind::Payload);
    CHECK(out.region(1).kind == FieldKind::Payload);
    CHECK(out.region(2).kind == FieldKind::Enum);
}

TEST_CASE("typing: a layout of other frames than the ones given is refused") {
    const Capture c = fixtures::capture_of(frames_by(10, 3, [](std::size_t, std::size_t) { return 1; }));
    const Segmentation s = cut(c);
    FieldMap wrong(3, 9);                         // 9 frames, and the capture has 10
    wrong.add_region(region(0, 3, FieldStructure::Many));
    CHECK_THROWS_AS(bw::type_fields(wrong, c, s), std::invalid_argument);
    FieldMap other(4, 10);                        // frames of 4 bytes, and there are none
    other.add_region(region(0, 4, FieldStructure::Many));
    CHECK_THROWS_AS(bw::type_fields(other, c, s), std::invalid_argument);
    // An empty layout is nothing claimed, and stays so.
    CHECK(bw::type_fields(FieldMap(3, 10), c, s).region_count() == 0);
}

namespace {

ChecksumFinding crc16_at(std::uint32_t header, std::uint32_t trailer) {
    ChecksumFinding f;
    f.found         = true;
    f.header_skip   = header;
    f.trailer_skip  = trailer;
    f.width_bits    = 16;
    f.byte_order    = ByteOrder::Little;
    f.evidence_bits = 160;
    return f;
}

std::vector<Bytes> random_frames(std::size_t size, std::uint64_t seed) {
    fixtures::Random rng(seed);
    return frames_by(40, size, [&](std::size_t, std::size_t) -> unsigned { return rng.byte(); });
}

} // namespace

TEST_CASE("discovery: the checksum is a region of its own, with what stage 2 found") {
    const FieldMap m = layout_of(random_frames(8, 31), crc16_at(0, 0));
    REQUIRE(m.region_count() == 2);
    CHECK(m.region(0).byte_offset == 0);
    CHECK(m.region(0).byte_size == 6);
    CHECK(m.region(0).structure == FieldStructure::Many);
    CHECK(m.region(1).byte_offset == 6);
    CHECK(m.region(1).byte_size == 2);
    CHECK(m.region(1).structure == FieldStructure::Checksum);
    CHECK(m.region(1).kind == FieldKind::Checksum);
    CHECK(m.region(1).byte_order == ByteOrder::Little);
    CHECK(m.region(1).evidence_bits == 160);
    // Typing leaves it as it is.
    const Capture c = fixtures::capture_of(random_frames(8, 31));
    const FieldMap typed_map = bw::type_fields(m, c, cut(c));
    CHECK(typed_map.region(1).kind == FieldKind::Checksum);
    CHECK(typed_map.region(1).evidence_bits == 160);
}

TEST_CASE("discovery: bytes are not one field across the places where the checksum's coverage begins and ends") {
    // Without a checksum these eight random bytes are one field; a checksum that covers
    // bytes 2 to 5 and sits in 6 and 7, with a trailer byte, cuts them at 2, 6 and 8.
    const FieldMap m = layout_of(random_frames(9, 32), crc16_at(2, 1));
    REQUIRE(m.region_count() == 4);
    CHECK(m.region(0).byte_offset == 0);
    CHECK(m.region(0).byte_size == 2);
    CHECK(m.region(1).byte_offset == 2);
    CHECK(m.region(1).byte_size == 4);
    CHECK(m.region(2).structure == FieldStructure::Checksum);
    CHECK(m.region(2).byte_offset == 6);
    CHECK(m.region(3).byte_offset == 8);
    CHECK(m.region(3).byte_size == 1);
    CHECK(layout_of(random_frames(9, 32)).region_count() == 1);
}

TEST_CASE("discovery: a checksum written as text keeps its separator, which it does not cover, as a field") {
    // A byte of header, six covered, a separator, two characters of checksum and two bytes after: all of
    // them random, so that only the checksum says where the fields end.
    ChecksumFinding f;
    f.found         = true;
    f.header_skip   = 1;
    f.gap_bytes     = 1;
    f.trailer_skip  = 2;
    f.width_bits    = 16;
    f.byte_order    = ByteOrder::Big;
    f.ascii_hex     = true;
    f.evidence_bits = 160;
    const FieldMap m = layout_of(random_frames(12, 34), f);
    REQUIRE(m.region_count() == 5);
    CHECK(m.region(0).byte_offset == 0);
    CHECK(m.region(0).byte_size == 1);
    CHECK(m.region(1).byte_offset == 1);
    CHECK(m.region(1).byte_size == 6);          // ends where the coverage does, not at the checksum
    CHECK(m.region(2).byte_offset == 7);
    CHECK(m.region(2).byte_size == 1);          // the separator
    CHECK(m.region(2).kind == FieldKind::Unknown);
    CHECK_FALSE(m.region(2).ascii_hex);
    CHECK(m.region(3).byte_offset == 8);
    CHECK(m.region(3).byte_size == 2);
    CHECK(m.region(3).kind == FieldKind::Checksum);
    CHECK(m.region(3).ascii_hex);
    CHECK(m.region(3).byte_order == ByteOrder::Big);
    CHECK(m.region(4).byte_offset == 10);
    CHECK(m.region(4).byte_size == 2);
    // One that is written as bytes has no text in it.
    CHECK_FALSE(layout_of(random_frames(9, 32), crc16_at(2, 1)).region(2).ascii_hex);
}

TEST_CASE("discovery: the separator counts towards a checksum fitting the frames") {
    const std::vector<Bytes> frames = random_frames(8, 35);
    const Capture            c      = fixtures::capture_of(frames);
    const Segmentation       s      = cut(c);
    const FieldOptions       o;
    ChecksumFinding          f = crc16_at(3, 2);          // 3 + 2 + 2 of 8: one byte to cover
    f.gap_bytes = 0;
    CHECK_NOTHROW(bw::discover_fields(c, s, f, 8, o));
    f.gap_bytes = 1;                                      // and no byte left to cover
    CHECK_THROWS_AS(bw::discover_fields(c, s, f, 8, o), std::invalid_argument);
    f = crc16_at(2, 2);
    f.gap_bytes = 1;
    CHECK_NOTHROW(bw::discover_fields(c, s, f, 8, o));
}

TEST_CASE("discovery: a checksum that cannot be in frames of this size is a mistake of the caller") {
    const std::vector<Bytes> frames = random_frames(8, 33);
    const Capture            c      = fixtures::capture_of(frames);
    const Segmentation       s      = cut(c);
    const FieldOptions       o;
    // 2 bytes of checksum in 8 leave 6 to cover, so 5 before and 2 after is too much.
    CHECK_NOTHROW(bw::discover_fields(c, s, crc16_at(5, 0), 8, o));
    CHECK_THROWS_AS(bw::discover_fields(c, s, crc16_at(6, 0), 8, o), std::invalid_argument);
    CHECK_THROWS_AS(bw::discover_fields(c, s, crc16_at(3, 3), 8, o), std::invalid_argument);
    CHECK_NOTHROW(bw::discover_fields(c, s, crc16_at(3, 2), 8, o));
    ChecksumFinding odd = crc16_at(0, 0);
    odd.width_bits = 12;
    CHECK_THROWS_AS(bw::discover_fields(c, s, odd, 8, o), std::invalid_argument);
    odd.width_bits = 0;
    CHECK_THROWS_AS(bw::discover_fields(c, s, odd, 8, o), std::invalid_argument);
    // A finding that says it found nothing is not looked at.
    ChecksumFinding none = crc16_at(7, 7);
    none.found = false;
    CHECK_NOTHROW(bw::discover_fields(c, s, none, 8, o));
}

TEST_CASE("typing: a region whose bytes never change is not a counter") {
    // Stage 4 would call it a constant; marked as having no structure by hand, it is
    // payload, because a step of 0 is no step.
    const Capture c = fixtures::capture_of(frames_by(10, 3, [](std::size_t, std::size_t) { return 5; }));
    FieldMap hand(3, 10);
    hand.add_region(region(0, 3, FieldStructure::Many));
    CHECK(bw::type_fields(hand, c, cut(c)).region(0).kind == FieldKind::Payload);
}

TEST_CASE("typing: a counter of eight bytes wraps at 64 bits") {
    const std::size_t   n    = 100;
    const std::uint64_t step = 0xF123456789ABCDEFULL;
    const FieldMap m = typed(frames_by(n, 8, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t value = 0x0102030405060708ULL + i * step;
        return static_cast<unsigned>((value >> (8 * k)) & 0xFF);          // little-endian
    }));
    REQUIRE(m.region_count() == 1);
    CHECK(m.region(0).byte_size == 8);
    CHECK(m.region(0).kind == FieldKind::Counter);
    CHECK(m.region(0).byte_order == ByteOrder::Little);
    CHECK(m.region(0).step == step);
    CHECK(m.region(0).evidence_bits == 64 * (n - 2));
}

TEST_CASE("typing: a layout that says it is of no frames is refused, even when a size matches") {
    const Capture c = fixtures::capture_of(frames_by(10, 3, [](std::size_t, std::size_t) { return 1; }));
    FieldMap none(4, 0);
    none.add_region(region(0, 4, FieldStructure::Many));
    CHECK_THROWS_AS(bw::type_fields(none, c, cut(c)), std::invalid_argument);
}

TEST_CASE("discovery: frames that are not there claim nothing, whatever min_frames is") {
    const Capture c = fixtures::capture_of(frames_by(10, 3, [](std::size_t, std::size_t) { return 1; }));
    FieldOptions zero;
    zero.min_frames = 0;
    CHECK(bw::discover_fields(c, cut(c), no_checksum(), 5, zero).region_count() == 0);
    CHECK(bw::discover_fields(c, cut(c), no_checksum(), 3, zero).region_count() == 3);
}

// ---- Numbers of several bytes ----------------------------------------------------------------------------

namespace {

// Stage 5 over a layout made by hand, so that the regions are the ones a test says and not what stage 4 makes of them.
FieldMap typed_by_hand(const std::vector<Bytes>& frames, const std::vector<FieldRegion>& regions) {
    const Capture c = fixtures::capture_of(frames);
    FieldMap      hand(static_cast<std::uint32_t>(frames[0].size()), static_cast<std::uint32_t>(frames.size()));
    for (std::size_t i = 0; i < regions.size(); ++i) {
        hand.add_region(regions[i]);
    }
    return bw::type_fields(hand, c, cut(c));
}

// One region of one byte each, from `first`: `kinds` gives the structure of each.
std::vector<FieldRegion> bytes_of(const std::vector<FieldStructure>& structures) {
    std::vector<FieldRegion> out;
    for (std::size_t i = 0; i < structures.size(); ++i) {
        out.push_back(region(static_cast<std::uint32_t>(i), 1, structures[i]));
    }
    return out;
}

const FieldStructure kC = FieldStructure::Constant;
const FieldStructure kF = FieldStructure::Few;
const FieldStructure kM = FieldStructure::Many;

// A 24-bit counter, 5,000,000 going up by 1000: its low two bytes have many values, the third takes two.
std::uint32_t counter24(std::size_t i) {
    return static_cast<std::uint32_t>(5000000 + 1000 * i);
}

float measurement(std::size_t i) {
    return 20.0f + 0.37f * static_cast<float>(i) + 0.013f * static_cast<float>((i * i) % 11);
}

void put_float(Bytes* f, float value, bool little) {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, 4);
    for (int k = 0; k < 4; ++k) {
        const int shift = little ? 8 * k : 8 * (3 - k);
        f->push_back(static_cast<std::uint8_t>((bits >> shift) & 0xFF));
    }
}

} // namespace

TEST_CASE("numbers: a counter that discovery cut into bytes is one counter, in either byte order") {
    const std::size_t n = 60;
    // [0xAA][a counter of 4 bytes, going up by 1000][0xBB]: the top byte never changes, the third takes two values.
    for (int big = 0; big < 2; ++big) {
        const std::vector<Bytes> frames = frames_by(n, 6, [&](std::size_t i, std::size_t k) -> unsigned {
            if (k == 0) return 0xAA;
            if (k == 5) return 0xBB;
            const unsigned shift = big ? 8 * (4 - k) : 8 * (k - 1);
            return (counter24(i) >> shift) & 0xFF;
        });
        const FieldMap m = typed(frames);
        CAPTURE(big);
        REQUIRE(m.region_count() == 3);
        CHECK(m.region(1).byte_offset == 1);
        CHECK(m.region(1).byte_size == 4);                         // with its top byte, which is a zero
        CHECK(m.region(1).kind == FieldKind::Counter);
        CHECK(m.region(1).byte_order == (big ? ByteOrder::Big : ByteOrder::Little));
        CHECK(m.region(1).step == 1000);
        CHECK(m.region(1).evidence_bits == 8 * 3 * (n - 2));       // what the three bytes that change say
        CHECK(m.region(0).kind == FieldKind::Constant);
        CHECK(m.region(2).kind == FieldKind::Constant);
    }
}

TEST_CASE("numbers: a counter takes the constant bytes that bring it to 4 or 8 bytes, and no others") {
    const std::size_t n = 60;
    // [counter of 3 bytes][constant][constant][constant]: one byte more makes it four, and the rest are not its.
    const std::vector<Bytes> little = frames_by(n, 6, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? (counter24(i) >> (8 * k)) & 0xFF : 7 + k;
    });
    const FieldMap m = typed_by_hand(little, bytes_of({ kM, kM, kF, kC, kC, kC }));
    REQUIRE(m.region_count() == 3);
    CHECK(m.region(0).byte_size == 4);
    CHECK(m.region(0).kind == FieldKind::Counter);
    CHECK(m.region(1).byte_offset == 4);
    CHECK(m.region(1).kind == FieldKind::Constant);
    CHECK(m.region(2).kind == FieldKind::Constant);

    // Big-endian, the constant bytes are before it.
    const std::vector<Bytes> big = frames_by(n, 6, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? 7 + k : (counter24(i) >> (8 * (5 - k))) & 0xFF;
    });
    const FieldMap b = typed_by_hand(big, bytes_of({ kC, kC, kC, kF, kM, kM }));
    REQUIRE(b.region_count() == 3);
    CHECK(b.region(0).kind == FieldKind::Constant);
    CHECK(b.region(1).kind == FieldKind::Constant);
    CHECK(b.region(2).byte_offset == 2);
    CHECK(b.region(2).byte_size == 4);
    CHECK(b.region(2).byte_order == ByteOrder::Big);
    CHECK(b.region(2).kind == FieldKind::Counter);

    // A counter of 7 bytes is one of 8 with one byte more, and one of 5 with three more.
    const std::vector<Bytes> seven = frames_by(n, 8, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 0x0011223344556677ULL + 0x0002030405060708ULL * i;
        return k < 7 ? (v >> (8 * k)) & 0xFF : 9;
    });
    const FieldMap s7 = typed_by_hand(seven, bytes_of({ kM, kM, kM, kM, kM, kM, kM, kC }));
    REQUIRE(s7.region_count() == 1);
    CHECK(s7.region(0).byte_size == 8);
    CHECK(s7.region(0).kind == FieldKind::Counter);
    CHECK(s7.region(0).step == 0x0002030405060708ULL);
    const std::vector<Bytes> five = frames_by(n, 8, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 1000000007ULL + 123456789ULL * i;          // up to 33 bits
        return (v >> (8 * k)) & 0xFF;
    });
    const FieldMap s5 = typed_by_hand(five, bytes_of({ kM, kM, kM, kM, kF, kC, kC, kC }));
    REQUIRE(s5.region_count() == 1);
    CHECK(s5.region(0).byte_size == 8);
    CHECK(s5.region(0).step == 123456789ULL);
    // Big-endian, five bytes that change have three before them: the top of a counter of eight.
    const std::vector<Bytes> five_be = frames_by(n, 8, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 1000000007ULL + 123456789ULL * i;
        return (v >> (8 * (7 - k))) & 0xFF;
    });
    const FieldMap b5 = typed_by_hand(five_be, bytes_of({ kC, kC, kC, kF, kM, kM, kM, kM }));
    REQUIRE(b5.region_count() == 1);
    CHECK(b5.region(0).byte_size == 8);
    CHECK(b5.region(0).byte_order == ByteOrder::Big);
    CHECK(b5.region(0).step == 123456789ULL);
    // A counter that is a region of its own, which typing found, takes the byte too.
    const std::vector<Bytes> region3 = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? (counter24(i) >> (8 * k)) & 0xFF : 0;
    });
    const FieldMap r3 = typed_by_hand(region3, { region(0, 3, kM), region(3, 1, kC) });
    REQUIRE(r3.region_count() == 1);
    CHECK(r3.region(0).byte_size == 4);
    CHECK(r3.region(0).kind == FieldKind::Counter);
    // Of eight bytes that all change there is nothing to take, and nine are not looked at.
    const std::vector<Bytes> eight = frames_by(n, 9, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 0x1122334455667788ULL + 0x0102030405060708ULL * i;
        return k < 8 ? (v >> (8 * k)) & 0xFF : 5;
    });
    const FieldMap e8 = typed_by_hand(eight, bytes_of({ kM, kM, kM, kM, kM, kM, kM, kM, kC }));
    REQUIRE(e8.region_count() == 2);
    CHECK(e8.region(0).byte_size == 8);
    CHECK(e8.region(0).kind == FieldKind::Counter);
    // Nine regions that change, of which the first eight make a counter: it is the eight, and the ninth is its own.
    const std::vector<Bytes> nine = frames_by(n, 9, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 0x1122334455667788ULL + 0x0102030405060708ULL * i;
        return k < 8 ? (v >> (8 * k)) & 0xFF : (i * 5 + 1) & 0xFF;
    });
    const FieldMap n9 = typed_by_hand(nine, bytes_of({ kM, kM, kM, kM, kM, kM, kM, kM, kM }));
    CHECK(n9.region(0).byte_size == 8);
    CHECK(n9.region(0).kind == FieldKind::Counter);
}

TEST_CASE("numbers: a counter is not padded when what is next to it is not exactly what it lacks") {
    const std::size_t n = 60;
    fixtures::Random  rng(73);
    // Three bytes and then a byte that takes a few values: nothing to take.
    const std::vector<Bytes> few = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? (counter24(i) >> (8 * k)) & 0xFF : i % 3;
    });
    const FieldMap f = typed_by_hand(few, bytes_of({ kM, kM, kF, kF }));
    CHECK(f.region(0).kind == FieldKind::Counter);
    CHECK(f.region(0).byte_size == 3);
    CHECK(f.region_count() == 2);

    // Five bytes (a counter of 40 bits, which is not a size) and two constants, and then bytes that change:
    // 5 + 1 is not 8 and 5 + 2 is not either, so it stays as it is.
    const std::vector<Bytes> five = frames_by(n, 8, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 0x0100000000ULL + 0x0101010101ULL * i;
        return k < 5 ? (v >> (8 * k)) & 0xFF : (k == 7 ? rng.byte() : 4);
    });
    const FieldMap m5 = typed_by_hand(five, { region(0, 5, kM), region(5, 1, kC), region(6, 1, kC), region(7, 1, kM) });
    CHECK(m5.region(0).byte_size == 5);
    CHECK(m5.region(0).kind == FieldKind::Counter);
    CHECK(m5.region_count() == 4);

    // Eight constant bytes would make two numbers: only what makes eight is taken, and 7 + 1 does.
    const std::vector<Bytes> over = frames_by(n, 9, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 1000000007ULL + 123456789ULL * i;
        return k < 7 ? (v >> (8 * k)) & 0xFF : 5;
    });
    const FieldMap o = typed_by_hand(over, { region(0, 7, kM), region(7, 1, kC), region(8, 1, kC) });
    CHECK(o.region(0).byte_size == 8);
    CHECK(o.region_count() == 2);

    // A constant region of two bytes next to a counter of 7 would make it nine: not taken.
    const std::vector<Bytes> wide = frames_by(n, 9, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint64_t v = 0x0011223344556677ULL + 0x0002030405060708ULL * i;
        return k < 7 ? (v >> (8 * k)) & 0xFF : 9;
    });
    const FieldMap wd = typed_by_hand(wide, { region(0, 1, kM), region(1, 1, kM), region(2, 1, kM), region(3, 1, kM),
                                              region(4, 1, kM), region(5, 1, kM), region(6, 1, kM), region(7, 2, kC) });
    CHECK(wd.region(0).byte_size == 7);
    CHECK(wd.region_count() == 2);

    // A top byte that does not stay constant while the rest wraps is not a part of a counter that does not carry.
    const std::vector<Bytes> carry = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? (counter24(i) >> (8 * k)) & 0xFF : 0x11;
    });
    // 24 bits wrap every 16777 frames, which these do not reach, so this one is a counter of 4.
    CHECK(typed_by_hand(carry, bytes_of({ kM, kM, kF, kC })).region(0).byte_size == 4);
    const std::vector<Bytes> wraps = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint32_t v = static_cast<std::uint32_t>(0xFFFFF0 + 0x10 * i) & 0xFFFFFF;   // wraps at 24 bits
        return k < 3 ? (v >> (8 * k)) & 0xFF : 0x11;
    });
    const FieldMap w = typed_by_hand(wraps, bytes_of({ kM, kM, kM, kC }));
    CHECK(w.region(0).byte_size == 3);                  // it wraps in 24 bits: with the byte on top it would carry
    CHECK(w.region(0).kind == FieldKind::Counter);
    CHECK(w.region(1).kind == FieldKind::Constant);
}

TEST_CASE("numbers: bytes that are not a counter together are left as they are") {
    const std::size_t n = 60;
    fixtures::Random  rng(71);
    // A counter of one byte and a byte of noise next to it: two fields, and the second is no part of the first.
    const std::vector<Bytes> noisy = frames_by(n, 3, [&](std::size_t i, std::size_t k) -> unsigned {
        return k == 0 ? 3 * i : (k == 1 ? rng.byte() : 1);
    });
    const FieldMap m = typed_by_hand(noisy, bytes_of({ kM, kM, kC }));
    REQUIRE(m.region_count() == 3);
    CHECK(m.region(0).kind == FieldKind::Counter);
    CHECK(m.region(0).byte_size == 1);
    CHECK(m.region(1).kind == FieldKind::Payload);

    // A window has to end in a byte that changes: a counter of one byte with a zero after it is a byte and a constant.
    const std::vector<Bytes> zero = frames_by(n, 3, [&](std::size_t i, std::size_t k) -> unsigned {
        return k == 0 ? 3 * i : (k == 1 ? 0 : 1);
    });
    const FieldMap z = typed_by_hand(zero, bytes_of({ kM, kC, kC }));
    REQUIRE(z.region_count() == 3);
    CHECK(z.region(0).byte_size == 1);
    CHECK(z.region(1).kind == FieldKind::Constant);

    // Fewer than three frames say nothing about a step.
    const std::vector<Bytes> two = frames_by(2, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? (counter24(i) >> (8 * k)) & 0xFF : 0;
    });
    const FieldMap t = typed_by_hand(two, bytes_of({ kM, kM, kF, kC }));
    for (std::size_t r = 0; r < t.region_count(); ++r) {
        CHECK(t.region(r).kind != FieldKind::Counter);
    }
}

TEST_CASE("numbers: the bytes of a checksum are no part of a number") {
    const std::size_t n = 60;
    const auto        checksum = [](std::uint32_t offset, std::uint32_t size) {
        FieldRegion r  = region(offset, size, FieldStructure::Checksum);
        r.kind          = FieldKind::Checksum;
        r.evidence_bits = 99;
        return r;
    };
    // A counter of three bytes, going up by 1000, with the byte in the middle given to a checksum: it is not
    // one counter of three bytes across it, though the bytes would be.
    const std::vector<Bytes> middle = frames_by(n, 3, [&](std::size_t i, std::size_t k) -> unsigned {
        return (counter24(i) >> (8 * k)) & 0xFF;
    });
    const FieldMap a = typed_by_hand(middle, { region(0, 1, kM), checksum(1, 1), region(2, 1, kF) });
    REQUIRE(a.region_count() == 3);
    CHECK(a.region(0).byte_size == 1);                              // a byte of its own (a counter of one byte)
    CHECK(a.region(1).kind == FieldKind::Checksum);
    CHECK(a.region(1).evidence_bits == 99);
    CHECK(a.region(2).kind == FieldKind::Enum);

    // A checksum after a counter of three bytes is not the byte that brings it to four, and before a big-endian one,
    // it is not either.
    const std::vector<Bytes> after = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k < 3 ? (counter24(i) >> (8 * k)) & 0xFF : 0;
    });
    const FieldMap b = typed_by_hand(after, { region(0, 1, kM), region(1, 1, kM), region(2, 1, kF), checksum(3, 1) });
    REQUIRE(b.region_count() == 2);
    CHECK(b.region(0).byte_size == 3);
    CHECK(b.region(0).kind == FieldKind::Counter);
    CHECK(b.region(1).kind == FieldKind::Checksum);

    const std::vector<Bytes> before = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k == 0 ? 0 : (counter24(i) >> (8 * (3 - k))) & 0xFF;
    });
    const FieldMap c = typed_by_hand(before, { checksum(0, 1), region(1, 1, kF), region(2, 1, kM), region(3, 1, kM) });
    REQUIRE(c.region_count() == 2);
    CHECK(c.region(0).kind == FieldKind::Checksum);
    CHECK(c.region(1).byte_size == 3);
    CHECK(c.region(1).byte_order == ByteOrder::Big);

    // And a checksum that is the first byte of a window is not the start of a counter or of a float.
    CHECK(typed_by_hand(middle, { checksum(0, 1), region(1, 1, kM), region(2, 1, kF) }).region(0).kind ==
          FieldKind::Checksum);
}

TEST_CASE("numbers: a float is four bytes that look like one, in either byte order") {
    const std::size_t n = 40;
    for (int little = 1; little >= 0; --little) {
        std::vector<Bytes> frames;
        for (std::size_t i = 0; i < n; ++i) {
            Bytes f;
            f.push_back(0xAA);
            put_float(&f, measurement(i), little != 0);
            f.push_back(0xBB);
            frames.push_back(f);
        }
        const FieldMap m = typed(frames);
        CAPTURE(little);
        REQUIRE(m.region_count() == 3);
        CHECK(m.region(1).byte_offset == 1);
        CHECK(m.region(1).byte_size == 4);
        CHECK(m.region(1).kind == FieldKind::Float);
        CHECK(m.region(1).byte_order == (little ? ByteOrder::Little : ByteOrder::Big));
        CHECK(m.region(1).evidence_bits == n);                      // one bit for each frame that agrees
    }
}

TEST_CASE("numbers: what is not a float is not called one") {
    const std::size_t n = 40;
    fixtures::Random  rng(72);
    const auto no_float = [](const FieldMap& m) {
        for (std::size_t r = 0; r < m.region_count(); ++r) {
            if (m.region(r).kind == FieldKind::Float) {
                return false;
            }
        }
        return true;
    };

    // Noise: the exponent of four random bytes is in the range one time in five.
    CHECK(no_float(typed(frames_by(n, 4, [&](std::size_t, std::size_t) -> unsigned { return rng.byte(); }))));

    // Flags, with a byte on top that makes them look like a float: the bytes below it have few values.
    CHECK(no_float(typed(frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k == 0 ? (i % 4) * 16 : (k == 1 ? (i % 3) * 8 : (k == 2 ? 0x40 : 0x49));
    }))));

    // Small integers have a zero exponent: the same four bytes as a float are denormals.
    CHECK(no_float(typed(frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        return k == 0 ? (i * 7) % 200 : (k == 1 ? (i * 13) % 100 : 0);
    }))));

    // Out of the range of measurements: floats of 1e20 and up (the exponent is 0xC0).
    std::vector<Bytes> huge;
    for (std::size_t i = 0; i < n; ++i) {
        Bytes f;
        put_float(&f, 1.0e20f * measurement(i), true);
        huge.push_back(f);
    }
    CHECK(no_float(typed(huge)));

    // Mostly zero: less than half the frames have a value.
    std::vector<Bytes> sparse;
    for (std::size_t i = 0; i < n; ++i) {
        Bytes f;
        put_float(&f, i % 4 == 0 ? measurement(i) : 0.0f, true);
        sparse.push_back(f);
    }
    CHECK(no_float(typed(sparse)));

    // Four digits of text, which as a float have an exponent in the range and bytes of mantissa of ten values: text.
    CHECK(no_float(typed(frames_by(n, 4, [&](std::size_t, std::size_t k) -> unsigned {
        return '0' + (k == 0 ? 4 + rng.byte() % 6 : rng.byte() % 10);
    }))));

    // Never changes: constants, and nothing is merged.
    std::vector<Bytes> still;
    for (std::size_t i = 0; i < n; ++i) {
        Bytes f;
        put_float(&f, 21.5f, true);
        still.push_back(f);
    }
    const FieldMap st = typed(still);
    CHECK(no_float(st));
    CHECK(st.region_count() == 4);
}

TEST_CASE("numbers: a float needs eight frames, and eight different values in its two lowest bytes") {
    const auto floats = [](std::size_t n) {
        std::vector<Bytes> frames;
        for (std::size_t i = 0; i < n; ++i) {
            Bytes f;
            put_float(&f, measurement(i), true);
            frames.push_back(f);
        }
        return frames;
    };
    // With 8 frames, as many as it asks for, it is a float; with 7 it is not looked at. (Stage 4 itself needs
    // 4 frames to say anything, and the float, 8.)
    CHECK(typed(floats(8)).region(0).kind == FieldKind::Float);
    for (std::size_t r = 0; r < typed(floats(7)).region_count(); ++r) {
        CHECK(typed(floats(7)).region(r).kind != FieldKind::Float);
    }

    // The two lowest bytes of mantissa take 10 values each over 20 frames, which is at least half the frames' worth:
    // a float. Taking 7 values, fewer than the 8 that are asked for, it is not.
    for (unsigned values = 6; values <= 9; ++values) {
        std::vector<Bytes> frames;
        for (std::size_t i = 0; i < 40; ++i) {
            Bytes f;
            std::uint32_t bits = 0x41A00000u;                      // 20.0
            bits |= static_cast<std::uint32_t>(((i % values) * 29 + 1) & 0xFF);          // the lowest byte
            bits |= static_cast<std::uint32_t>(((i % values) * 31 + 1) & 0xFF) << 8;     // the next
            bits |= static_cast<std::uint32_t>((i * 5) % 128) << 16;                     // the top of the mantissa
            for (int k = 0; k < 4; ++k) {
                f.push_back(static_cast<std::uint8_t>((bits >> (8 * k)) & 0xFF));
            }
            frames.push_back(f);
        }
        const FieldMap m = typed(frames);
        bool           is_float = false;
        for (std::size_t r = 0; r < m.region_count(); ++r) {
            is_float = is_float || m.region(r).kind == FieldKind::Float;
        }
        CAPTURE(values);
        CHECK(is_float == (values >= 8));
    }
}

TEST_CASE("numbers: the exponent of a float is in the range of measurements, in nearly all the frames that have a value") {
    const std::size_t n = 40;
    // The mantissa has bytes of all sorts; the exponent, the sign and which frames are zero are the test's.
    const auto mantissa = [](std::size_t i) -> std::uint32_t { return ((i + 1) * 2654435761u >> 5) & 0x7FFFFF; };
    const auto is_float = [](const std::vector<Bytes>& frames) {
        const FieldMap m = typed(frames);
        for (std::size_t r = 0; r < m.region_count(); ++r) {
            if (m.region(r).kind == FieldKind::Float) {
                return true;
            }
        }
        return false;
    };
    const auto frames_of = [&](const std::function<std::uint32_t(std::size_t)>& bits) {
        std::vector<Bytes> out;
        for (std::size_t i = 0; i < n; ++i) {
            Bytes f;
            const std::uint32_t b = bits(i);
            for (int k = 0; k < 4; ++k) {
                f.push_back(static_cast<std::uint8_t>((b >> (8 * k)) & 0xFF));
            }
            out.push_back(f);
        }
        return out;
    };
    // The ends of the range are in it, and one past either is not.
    for (std::uint32_t exponent = 0x66; exponent <= 0x9A; exponent += 1) {
        if (exponent != 0x67 && exponent != 0x68 && exponent != 0x98 && exponent != 0x99) {
            continue;
        }
        CAPTURE(exponent);
        CHECK(is_float(frames_of([&](std::size_t i) { return (exponent << 23) | mantissa(i); })) ==
              (exponent >= 0x68 && exponent <= 0x98));
    }
    // With the sign too: half of the values are negative.
    CHECK(is_float(frames_of([&](std::size_t i) { return ((i % 2) << 31) | (0x80u << 23) | mantissa(i); })));
    // 38 of 40 in the range is the 95% that it asks for; 37 is not.
    for (std::size_t outside = 1; outside <= 4; ++outside) {
        CAPTURE(outside);
        CHECK(is_float(frames_of([&](std::size_t i) {
                  return ((i < outside ? 0x40u : 0x80u) << 23) | mantissa(i);
              })) == (outside <= 2));
    }
    // Zero, of either sign, is no value: half of the frames being zero is enough, one fewer with a value is not.
    for (std::size_t values = 18; values <= 21; ++values) {
        CAPTURE(values);
        CHECK(is_float(frames_of([&](std::size_t i) {
                  return i < values ? ((0x80u << 23) | mantissa(i)) : (i % 2 ? 0x80000000u : 0u);
              })) == (values >= 20));
    }
}

TEST_CASE("numbers: how varied the two low bytes of a float are depends on how many frames there are") {
    // 10 frames ask for 5 values in each of the two lowest bytes (half of the frames), 4 are not enough; with
    // 40 or more the least is 8.
    const auto frames_with = [](std::size_t n, std::size_t values) {
        std::vector<Bytes> out;
        for (std::size_t i = 0; i < n; ++i) {
            const std::uint32_t bits = (0x80u << 23) | (static_cast<std::uint32_t>((i * 5) % 128) << 16) |
                                       (static_cast<std::uint32_t>(((i % values) * 41 + 3) & 0xFF) << 8) |
                                       static_cast<std::uint32_t>(((i % values) * 37 + 1) & 0xFF);
            Bytes f;
            for (int k = 0; k < 4; ++k) {
                f.push_back(static_cast<std::uint8_t>((bits >> (8 * k)) & 0xFF));
            }
            out.push_back(f);
        }
        return out;
    };
    const auto kind_of_all = [&](const std::vector<Bytes>& frames) {
        const FieldMap m = typed(frames);
        for (std::size_t r = 0; r < m.region_count(); ++r) {
            if (m.region(r).kind == FieldKind::Float) {
                return true;
            }
        }
        return false;
    };
    CHECK(kind_of_all(frames_with(10, 5)));
    CHECK_FALSE(kind_of_all(frames_with(10, 4)));
    CHECK(kind_of_all(frames_with(40, 8)));
    CHECK_FALSE(kind_of_all(frames_with(40, 7)));
}

TEST_CASE("numbers: a float is of four bytes exactly, and both of its low bytes of mantissa have to vary") {
    const std::size_t n = 40;
    std::vector<Bytes> frames;
    for (std::size_t i = 0; i < n; ++i) {
        Bytes f;
        put_float(&f, measurement(i), true);
        f.push_back(static_cast<std::uint8_t>(i * 7));                // a fifth byte, which changes too
        frames.push_back(f);
    }
    // Regions of 3 and 2 bytes: the first four bytes are a float, but they are not whole regions.
    const FieldMap m = typed_by_hand(frames, { region(0, 3, kM), region(3, 2, kM) });
    for (std::size_t r = 0; r < m.region_count(); ++r) {
        CHECK(m.region(r).kind != FieldKind::Float);
    }
    // The same regions as 3 and 1 and then the byte that changes: a float.
    const FieldMap f = typed_by_hand(frames, { region(0, 3, kM), region(3, 1, kM), region(4, 1, kM) });
    CHECK(f.region(0).kind == FieldKind::Float);
    CHECK(f.region(0).byte_size == 4);

    // The lowest byte of mantissa varied and the next one not (two values), in either byte order: not a float.
    for (int little = 1; little >= 0; --little) {
        std::vector<Bytes> poor;
        for (std::size_t i = 0; i < n; ++i) {
            std::uint32_t bits = (0x80u << 23) | (static_cast<std::uint32_t>((i * 5) % 128) << 16) |
                                 (static_cast<std::uint32_t>((i % 2) * 77 + 3) << 8) |
                                 static_cast<std::uint32_t>((i * 37 + 1) & 0xFF);
            Bytes fl;
            for (int k = 0; k < 4; ++k) {
                fl.push_back(static_cast<std::uint8_t>((bits >> (little ? 8 * k : 8 * (3 - k))) & 0xFF));
            }
            poor.push_back(fl);
        }
        const FieldMap p = typed(poor);
        CAPTURE(little);
        for (std::size_t r = 0; r < p.region_count(); ++r) {
            CHECK(p.region(r).kind != FieldKind::Float);
        }
    }
}

TEST_CASE("numbers: a float with a constant byte on top is a float in either byte order") {
    // 17 to 30: the sign and the top of the exponent, which is the first byte of a big-endian float and the last
    // of a little-endian one, is always 0x41. A window may start at it.
    const std::size_t n = 40;
    for (int little = 1; little >= 0; --little) {
        std::vector<Bytes> frames;
        for (std::size_t i = 0; i < n; ++i) {
            Bytes f;
            f.push_back(0xAA);
            put_float(&f, 17.0f + 0.3f * static_cast<float>(i) + 0.013f * static_cast<float>((i * i) % 11), little != 0);
            f.push_back(0xBB);
            frames.push_back(f);
        }
        const FieldMap m = typed(frames);
        CAPTURE(little);
        bool found = false;
        for (std::size_t r = 0; r < m.region_count(); ++r) {
            if (m.region(r).kind == FieldKind::Float) {
                found = true;
                CHECK(m.region(r).byte_offset == 1);
                CHECK(m.region(r).byte_size == 4);
                CHECK(m.region(r).byte_order == (little ? ByteOrder::Little : ByteOrder::Big));
            }
        }
        CHECK(found);
    }
}

TEST_CASE("numbers: the bytes of a checksum are not the last of a float") {
    // A big-endian float whose lowest byte is given to a checksum by hand: the three before it are not a float.
    const std::size_t  n = 40;
    std::vector<Bytes> frames;
    for (std::size_t i = 0; i < n; ++i) {
        Bytes f;
        put_float(&f, measurement(i), false);
        frames.push_back(f);
    }
    FieldRegion cs = region(3, 1, FieldStructure::Checksum);
    cs.kind          = FieldKind::Checksum;
    cs.evidence_bits = 8;
    const FieldMap m = typed_by_hand(frames, { region(0, 1, kF), region(1, 1, kM), region(2, 1, kM), cs });
    REQUIRE(m.region_count() == 4);
    for (std::size_t r = 0; r < m.region_count(); ++r) {
        CHECK(m.region(r).kind != FieldKind::Float);
    }
    CHECK(m.region(3).kind == FieldKind::Checksum);
}

TEST_CASE("numbers: bytes that are a counter and would also be a float are a counter") {
    // 0x41200000 going up by 0x00013579: the top byte stays at 0x41 or 0x42, the lowest two vary, and the step
    // is constant. Taken as a float it would be plausible; a step that never changes is the stronger claim.
    const std::size_t        n      = 40;
    const std::vector<Bytes> frames = frames_by(n, 4, [&](std::size_t i, std::size_t k) -> unsigned {
        const std::uint32_t v = 0x41200000u + 0x00013579u * static_cast<std::uint32_t>(i);
        return (v >> (8 * k)) & 0xFF;
    });
    const FieldMap m = typed(frames);
    REQUIRE(m.region_count() == 1);
    CHECK(m.region(0).kind == FieldKind::Counter);
    CHECK(m.region(0).byte_size == 4);
    CHECK(m.region(0).step == 0x00013579u);
}

TEST_CASE("numbers: four printable characters are text, to the last of them, and a byte that is not one makes them a float") {
    // One frame for each printable character in the lowest byte, from the space to the tilde; the top byte is 0x34 to
    // 0x43, so that as a float the exponent is in the range, and the other two bytes are characters. With a byte of
    // 0x1F or 0x7F in a frame (one before and one after the printable ones) they are not text in every frame.
    const std::size_t n = 95;
    const auto        frames_with = [&](unsigned odd) {
        std::vector<Bytes> out;
        for (std::size_t i = 0; i < n; ++i) {
            Bytes f;
            f.push_back(static_cast<std::uint8_t>(0x20 + i % 95));
            f.push_back(static_cast<std::uint8_t>(odd != 0 && i == 10 ? odd : 0x20 + (i * 7) % 95));
            f.push_back(static_cast<std::uint8_t>(0x20 + (i * 13) % 95));
            f.push_back(static_cast<std::uint8_t>(0x34 + i % 16));
            out.push_back(f);
        }
        return out;
    };
    const auto is_float = [](const std::vector<Bytes>& frames) {
        const FieldMap m = typed(frames);
        for (std::size_t r = 0; r < m.region_count(); ++r) {
            if (m.region(r).kind == FieldKind::Float) {
                return true;
            }
        }
        return false;
    };
    CHECK_FALSE(is_float(frames_with(0)));
    CHECK(is_float(frames_with(0x1F)));
    CHECK(is_float(frames_with(0x7F)));
}
