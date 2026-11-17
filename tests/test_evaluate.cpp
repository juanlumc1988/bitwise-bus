// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The harness decides whether every later stage is any good, so its own
// arithmetic is pinned here case by case, with answers worked out by hand
// before the code was run: a scorer that is wrong makes every result wrong
// in a way that looks like progress.

#include "doctest.h"

#include <cstdint>
#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "bw/evaluate.h"
#include "bw/model.h"
#include "model_fixtures.h"

using bw::ByteOrder;
using bw::FieldKind;
using bw::FieldScore;
using bw::FrameSpan;
using bw::Model;
using bw::SegmentationScore;
using fixtures::fixed;

namespace {

FrameSpan span(std::uint64_t first, std::uint64_t count) {
    FrameSpan s;
    s.first_event = first;
    s.event_count = count;
    return s;
}

// Frames of eight events each, back to back: [0,8) [8,16) [16,24).
std::vector<FrameSpan> three_frames() {
    std::vector<FrameSpan> v;
    v.push_back(span(0, 8));
    v.push_back(span(8, 8));
    v.push_back(span(16, 8));
    return v;
}

} // namespace

// ---- Segmentation ----------------------------------------------------------

TEST_CASE("segmentation: a perfect answer scores everything") {
    const SegmentationScore s = bw::score_segmentation(three_frames(), three_frames());
    CHECK(s.truth_frames == 3);
    CHECK(s.found_frames == 3);
    CHECK(s.exact_frames == 3);
    CHECK(s.truth_boundaries == 4);            // 0, 8, 16, 24
    CHECK(s.found_boundaries == 4);
    CHECK(s.boundary_hits == 4);
}

TEST_CASE("segmentation: one cut a byte late costs two frames and one boundary") {
    std::vector<FrameSpan> found;
    found.push_back(span(0, 9));               // ends a byte late...
    found.push_back(span(9, 7));               // ...so the next one starts late and ends right
    found.push_back(span(16, 8));
    const SegmentationScore s = bw::score_segmentation(three_frames(), found);
    CHECK(s.exact_frames == 1);                // only the last
    CHECK(s.found_boundaries == 4);            // 0, 9, 16, 24
    CHECK(s.boundary_hits == 3);               // 0, 16, 24; the cut at 9 is not at 8
}

TEST_CASE("segmentation: two frames merged into one") {
    std::vector<FrameSpan> found;
    found.push_back(span(0, 16));
    found.push_back(span(16, 8));
    const SegmentationScore s = bw::score_segmentation(three_frames(), found);
    CHECK(s.found_frames == 2);
    CHECK(s.exact_frames == 1);
    CHECK(s.found_boundaries == 3);            // 0, 16, 24
    CHECK(s.boundary_hits == 3);               // all real: nothing wrong was cut, one cut was missed
    CHECK(s.truth_boundaries == 4);
}

TEST_CASE("segmentation: a frame split in two") {
    std::vector<FrameSpan> found;
    found.push_back(span(0, 4));
    found.push_back(span(4, 4));
    found.push_back(span(8, 8));
    found.push_back(span(16, 8));
    const SegmentationScore s = bw::score_segmentation(three_frames(), found);
    CHECK(s.found_frames == 4);
    CHECK(s.exact_frames == 2);
    CHECK(s.found_boundaries == 5);            // 0, 4, 8, 16, 24
    CHECK(s.boundary_hits == 4);
}

TEST_CASE("segmentation: finding nothing, or truth with nothing to find") {
    const std::vector<FrameSpan> none;
    const SegmentationScore found_nothing = bw::score_segmentation(three_frames(), none);
    CHECK(found_nothing.truth_frames == 3);
    CHECK(found_nothing.found_frames == 0);
    CHECK(found_nothing.exact_frames == 0);
    CHECK(found_nothing.truth_boundaries == 4);
    CHECK(found_nothing.found_boundaries == 0);
    CHECK(found_nothing.boundary_hits == 0);

    const SegmentationScore invented = bw::score_segmentation(none, three_frames());
    CHECK(invented.truth_frames == 0);
    CHECK(invented.found_frames == 3);
    CHECK(invented.exact_frames == 0);
    CHECK(invented.boundary_hits == 0);

    const SegmentationScore both = bw::score_segmentation(none, none);
    CHECK(both.truth_frames == 0);
    CHECK(both.boundary_hits == 0);
}

TEST_CASE("segmentation: a gap between frames is two boundaries, and a shared cut counts once") {
    std::vector<FrameSpan> truth;                 // [0,4) and [6,10): events 4 and 5 belong to no frame
    truth.push_back(span(0, 4));
    truth.push_back(span(6, 4));
    const SegmentationScore s = bw::score_segmentation(truth, truth);
    CHECK(s.truth_boundaries == 4);               // 0, 4, 6, 10

    std::vector<FrameSpan> touching;              // [0,4) and [4,8): the cut at 4 is one position
    touching.push_back(span(0, 4));
    touching.push_back(span(4, 4));
    CHECK(bw::score_segmentation(touching, touching).truth_boundaries == 3);
}

TEST_CASE("segmentation: a repeated found frame is counted each time, a boundary once") {
    std::vector<FrameSpan> found;
    found.push_back(span(0, 8));
    found.push_back(span(0, 8));
    const SegmentationScore s = bw::score_segmentation(three_frames(), found);
    CHECK(s.found_frames == 2);
    CHECK(s.exact_frames == 2);
    CHECK(s.found_boundaries == 2);               // 0 and 8
    CHECK(s.boundary_hits == 2);
}

TEST_CASE("segmentation: an empty frame has the one boundary, and a huge one does not overflow") {
    std::vector<FrameSpan> found;
    found.push_back(span(5, 0));
    CHECK(bw::score_segmentation(three_frames(), found).found_boundaries == 1);

    const std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
    std::vector<FrameSpan> huge;
    huge.push_back(span(max - 1, 10));            // would wrap to 8 without saturating
    const SegmentationScore s = bw::score_segmentation(three_frames(), huge);
    CHECK(s.found_boundaries == 2);               // max - 1 and max
    CHECK(s.boundary_hits == 0);                  // in particular, not the 8 a wrap would give
}

// ---- Fields ----------------------------------------------------------------

TEST_CASE("fields: a perfect answer scores everything and finds the checksum") {
    const FieldScore s = bw::score_fields(fixtures::request_model(), 0, fixtures::request_model(), 0);
    CHECK(s.truth_fields == 5);
    CHECK(s.found_fields == 5);
    CHECK(s.truth_boundaries == 6);               // 0 8 16 32 48 64
    CHECK(s.found_boundaries == 6);
    CHECK(s.boundary_hits == 6);
    CHECK(s.exact_fields == 5);
    CHECK(s.kind_hits == 5);
    CHECK(s.truth_has_checksum);
    CHECK(s.found_has_checksum);
    CHECK(s.checksum_match);
}

TEST_CASE("fields: two fields merged lose a boundary and two exact fields, not the rest") {
    Model found;
    const std::size_t t = found.add_message_type("request");
    found.add_field(t, "header",   fixed(FieldKind::Payload, 16), "");     // address and function as one
    found.add_field(t, "register", fixed(FieldKind::Payload, 16), "");
    found.add_field(t, "quantity", fixed(FieldKind::Payload, 16), "");
    found.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, 0, 2), "CRC-16/MODBUS");

    const FieldScore s = bw::score_fields(fixtures::request_model(), 0, found, 0);
    CHECK(s.found_fields == 4);
    CHECK(s.found_boundaries == 5);               // 0 16 32 48 64
    CHECK(s.boundary_hits == 5);                  // all real; the cuts at 8 were missed
    CHECK(s.exact_fields == 3);                   // register, quantity, crc
    CHECK(s.kind_hits == 3);
    CHECK(s.checksum_match);                      // 0..2 here and 0..3 in the truth, both bits 0 to 48
}

TEST_CASE("fields: a cut in the wrong place is a wrong boundary") {
    Model found;
    const std::size_t t = found.add_message_type("request");
    found.add_field(t, "address",  fixed(FieldKind::Enum, 8), "");
    found.add_field(t, "function", fixed(FieldKind::Enum, 8), "");
    found.add_field(t, "register", fixed(FieldKind::Payload, 16), "");
    found.add_field(t, "quantity", fixed(FieldKind::Payload, 24), "");     // a byte too long...
    found.add_field(t, "crc", fixtures::checksum(8, ByteOrder::NotApplicable, 0, 3), "CRC-16/MODBUS");

    const FieldScore s = bw::score_fields(fixtures::request_model(), 0, found, 0);
    CHECK(s.found_boundaries == 6);               // 0 8 16 32 56 64
    CHECK(s.boundary_hits == 5);                  // all but 56; 48 was missed
    CHECK(s.exact_fields == 3);                   // address, function, register
    CHECK(s.kind_hits == 3);
    CHECK(s.checksum_match == false);             // position and size differ
}

TEST_CASE("fields: the right place with the wrong kind is an exact field but not a kind hit") {
    const Model found = fixtures::request_model(ByteOrder::Little, 3, "CRC-16/MODBUS",
                                                FieldKind::Constant);
    const FieldScore s = bw::score_fields(fixtures::request_model(), 0, found, 0);
    CHECK(s.exact_fields == 5);
    CHECK(s.kind_hits == 4);
    CHECK(s.boundary_hits == 6);
    CHECK(s.checksum_match);
}

TEST_CASE("fields: a checksum covers bits, whatever the fields it covers are cut into") {
    const Model truth = fixtures::request_model();

    // The same bits cut finer: quantity is two bytes here, so the CRC covers 0..4.
    Model finer;
    std::size_t t = finer.add_message_type("request");
    finer.add_field(t, "address",  fixed(FieldKind::Enum, 8), "");
    finer.add_field(t, "function", fixed(FieldKind::Enum, 8), "");
    finer.add_field(t, "register", fixed(FieldKind::Payload, 16), "");
    finer.add_field(t, "quantity_high", fixed(FieldKind::Constant, 8), "");
    finer.add_field(t, "quantity_low", fixed(FieldKind::Payload, 8), "");
    finer.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, 0, 4), "CRC-16/MODBUS");
    CHECK(bw::score_fields(truth, 0, finer, 0).checksum_match);
    CHECK(bw::score_fields(finer, 0, truth, 0).checksum_match);        // and the other way round

    // Covering one byte less is a different checksum, however the fields are cut.
    Model shorter;
    t = shorter.add_message_type("request");
    shorter.add_field(t, "address",  fixed(FieldKind::Enum, 8), "");
    shorter.add_field(t, "function", fixed(FieldKind::Enum, 8), "");
    shorter.add_field(t, "register", fixed(FieldKind::Payload, 16), "");
    shorter.add_field(t, "quantity_high", fixed(FieldKind::Constant, 8), "");
    shorter.add_field(t, "quantity_low", fixed(FieldKind::Payload, 8), "");
    shorter.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, 0, 3), "CRC-16/MODBUS");
    CHECK_FALSE(bw::score_fields(truth, 0, shorter, 0).checksum_match);

    // Starting one byte later is too.
    Model later;
    t = later.add_message_type("request");
    later.add_field(t, "address",  fixed(FieldKind::Enum, 8), "");
    later.add_field(t, "function", fixed(FieldKind::Enum, 8), "");
    later.add_field(t, "register", fixed(FieldKind::Payload, 16), "");
    later.add_field(t, "quantity", fixed(FieldKind::Payload, 16), "");
    later.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, 1, 3), "CRC-16/MODBUS");
    CHECK_FALSE(bw::score_fields(truth, 0, later, 0).checksum_match);
}

TEST_CASE("fields: when what a checksum covers has no fixed place, its coverage is compared by field index") {
    // length | body, as long as the length says | crc over fields 0..last
    const auto build = [](std::uint32_t first, std::uint32_t last) {
        Model m;
        const std::size_t t = m.add_message_type("variable");
        m.add_field(t, "length", fixed(FieldKind::Length, 8), "");
        bw::FieldInfo body;
        body.kind       = FieldKind::Payload;
        body.size_kind  = bw::SizeKind::FromField;
        body.size_field = 0;
        m.add_field(t, "body", body, "");
        m.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, first, last), "CRC-16/MODBUS");
        return m;
    };
    CHECK(bw::score_fields(build(0, 1), 0, build(0, 1), 0).checksum_match);
    CHECK_FALSE(bw::score_fields(build(0, 1), 0, build(1, 1), 0).checksum_match);      // another first field
    CHECK_FALSE(bw::score_fields(build(0, 1), 0, build(0, 0), 0).checksum_match);      // placed against not placed
}

TEST_CASE("fields: coverage in bits and coverage by index are never the same thing, whatever the numbers") {
    // Covers fields 0..1, which is bits 0 to 16, and the checksum itself has no fixed place...
    Model placed;
    std::size_t t = placed.add_message_type("a");
    placed.add_field(t, "length", fixed(FieldKind::Length, 8), "");
    placed.add_field(t, "byte", fixed(FieldKind::Payload, 8), "");
    bw::FieldInfo body;
    body.kind       = FieldKind::Payload;
    body.size_kind  = bw::SizeKind::FromField;
    body.size_field = 0;
    placed.add_field(t, "body", body, "");
    placed.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, 0, 1), "CRC-16/MODBUS");

    // ...and here fields 0..16, in which the covered ones have no fixed place, so the
    // numbers 0 and 16 are indexes. They are the same numbers as bits 0 and 16.
    Model indexed;
    t = indexed.add_message_type("b");
    indexed.add_field(t, "length", fixed(FieldKind::Length, 8), "");
    indexed.add_field(t, "body", body, "");
    for (int i = 0; i < 15; ++i) {
        indexed.add_field(t, "byte" + std::to_string(i), fixed(FieldKind::Payload, 8), "");
    }
    indexed.add_field(t, "crc", fixtures::checksum(16, ByteOrder::Little, 0, 16), "CRC-16/MODBUS");

    CHECK_FALSE(bw::score_fields(placed, 0, indexed, 0).checksum_match);
    CHECK_FALSE(bw::score_fields(indexed, 0, placed, 0).checksum_match);
}

TEST_CASE("fields: a checksum matches only when position, size, order, coverage and algorithm all do") {
    const Model truth = fixtures::request_model();
    CHECK(bw::score_fields(truth, 0, fixtures::request_model(), 0).checksum_match);
    CHECK_FALSE(bw::score_fields(truth, 0, fixtures::request_model(ByteOrder::Big), 0).checksum_match);
    CHECK_FALSE(bw::score_fields(truth, 0, fixtures::request_model(ByteOrder::Little, 2), 0).checksum_match);
    CHECK_FALSE(bw::score_fields(truth, 0,
                fixtures::request_model(ByteOrder::Little, 3, "CRC-16/CCITT-FALSE"), 0).checksum_match);
    CHECK_FALSE(bw::score_fields(truth, 0,
                fixtures::request_model(ByteOrder::Little, 3, ""), 0).checksum_match);
}

TEST_CASE("fields: a checksum that differs in position alone, or in size alone, is not a match") {
    // The same CRC (16 bits, little-endian, covering 0..3, same algorithm) one byte later.
    Model later;
    const std::size_t a = later.add_message_type("request");
    later.add_field(a, "address",  fixed(FieldKind::Enum, 8), "");
    later.add_field(a, "function", fixed(FieldKind::Enum, 8), "");
    later.add_field(a, "register", fixed(FieldKind::Payload, 16), "");
    later.add_field(a, "quantity", fixed(FieldKind::Payload, 16), "");
    later.add_field(a, "pad",      fixed(FieldKind::Payload, 8), "");
    later.add_field(a, "crc", fixtures::checksum(16, ByteOrder::Little, 0, 3), "CRC-16/MODBUS");
    const FieldScore moved = bw::score_fields(fixtures::request_model(), 0, later, 0);
    CHECK(moved.truth_has_checksum);
    CHECK(moved.found_has_checksum);
    CHECK_FALSE(moved.checksum_match);

    // The same position, byte order, coverage and algorithm, but 32 bits wide.
    Model wider;
    const std::size_t b = wider.add_message_type("request");
    wider.add_field(b, "address",  fixed(FieldKind::Enum, 8), "");
    wider.add_field(b, "function", fixed(FieldKind::Enum, 8), "");
    wider.add_field(b, "register", fixed(FieldKind::Payload, 16), "");
    wider.add_field(b, "quantity", fixed(FieldKind::Payload, 16), "");
    wider.add_field(b, "crc", fixtures::checksum(32, ByteOrder::Little, 0, 3), "CRC-16/MODBUS");
    const FieldScore resized = bw::score_fields(fixtures::request_model(), 0, wider, 0);
    CHECK_FALSE(resized.checksum_match);

    // And a checksum with every attribute the same does match, in a model that has the extra field.
    CHECK(bw::score_fields(later, 0, later, 0).checksum_match);
}

TEST_CASE("fields: a checksum that is missing, or invented, is not a match") {
    Model without;
    const std::size_t t = without.add_message_type("request");
    without.add_field(t, "address",  fixed(FieldKind::Enum, 8), "");
    without.add_field(t, "function", fixed(FieldKind::Enum, 8), "");

    const FieldScore missed = bw::score_fields(fixtures::request_model(), 0, without, 0);
    CHECK(missed.truth_has_checksum);
    CHECK_FALSE(missed.found_has_checksum);
    CHECK_FALSE(missed.checksum_match);

    const FieldScore invented = bw::score_fields(without, 0, fixtures::request_model(), 0);
    CHECK_FALSE(invented.truth_has_checksum);
    CHECK(invented.found_has_checksum);
    CHECK_FALSE(invented.checksum_match);

    const FieldScore agreed = bw::score_fields(without, 0, without, 0);      // neither has one: they agree
    CHECK_FALSE(agreed.truth_has_checksum);
    CHECK_FALSE(agreed.found_has_checksum);
    CHECK(agreed.checksum_match);
}

TEST_CASE("fields: a field after something of no fixed size cannot be placed, and is only counted") {
    Model variable;
    const std::size_t t = variable.add_message_type("m");
    variable.add_field(t, "a", fixed(FieldKind::Enum, 8), "");
    variable.add_field(t, "len", fixed(FieldKind::Length, 8), "");
    bw::FieldInfo body;
    body.kind       = FieldKind::Payload;
    body.size_kind  = bw::SizeKind::FromField;
    body.size_field = 1;
    variable.add_field(t, "body", body, "");
    variable.add_field(t, "tail", fixed(FieldKind::Payload, 8), "");

    const FieldScore s = bw::score_fields(variable, 0, variable, 0);
    CHECK(s.truth_fields == 4);
    CHECK(s.found_fields == 4);
    CHECK(s.truth_boundaries == 3);               // a at 0..8, len at 8..16: 0, 8, 16. body and tail are not placed.
    CHECK(s.boundary_hits == 3);
    CHECK(s.exact_fields == 2);
    CHECK(s.kind_hits == 2);
}

TEST_CASE("fields: message types are chosen by index, and one that is missing is an error") {
    Model two_types = fixtures::request_model();
    const std::size_t t = two_types.add_message_type("other");
    two_types.add_field(t, "only", fixed(FieldKind::Payload, 32), "");

    const FieldScore second = bw::score_fields(two_types, 1, two_types, 1);
    CHECK(second.truth_fields == 1);
    CHECK(second.exact_fields == 1);
    CHECK(second.checksum_match);                 // neither has a checksum

    const FieldScore crossed = bw::score_fields(two_types, 0, two_types, 1);
    CHECK(crossed.truth_fields == 5);
    CHECK(crossed.found_fields == 1);
    CHECK(crossed.exact_fields == 0);

    CHECK_THROWS_AS(bw::score_fields(fixtures::request_model(), 1, fixtures::request_model(), 0),
                    std::out_of_range);
    CHECK_THROWS_AS(bw::score_fields(fixtures::request_model(), 0, fixtures::request_model(), 1),
                    std::out_of_range);
}
