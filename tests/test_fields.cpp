// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stages 4 and 5: where the fields of a message are and what they are. The
// frames are built by hand, so that each test knows the answer and the rule
// under test: how many distinct values make a byte constant, an enumeration or
// payload (at the exact boundary), when bytes are one field, what a counter is,
// and that nothing is claimed about frames too few to say anything.

#include "doctest.h"

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
