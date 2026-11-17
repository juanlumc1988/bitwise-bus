// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The model is the ground truth of every later test and the result of every
// stage, so what matters is that it cannot be inconsistent. These tests try to
// build every kind of wrong model and require add_field() to refuse it and
// leave the model as it was.

#include "doctest.h"

#include <stdexcept>
#include <string>

#include "bw/model.h"
#include "model_fixtures.h"

using bw::ByteOrder;
using bw::FieldInfo;
using bw::FieldKind;
using bw::Model;
using bw::SizeKind;
using fixtures::fixed;

namespace {

bool mentions(const std::string& what, const std::string& part) {
    return what.find(part) != std::string::npos;
}

// Adds `info` as the next field of a model that already has the fields given
// by `build`, and returns what add_field said, or "" if it accepted the field.
// A refused field must leave the field count exactly as it was.
std::string refusal(Model& model, std::size_t type, const FieldInfo& info) {
    const std::size_t before = model.field_count(type);
    try {
        model.add_field(type, "probe", info, "");
    } catch (const std::invalid_argument& e) {
        CHECK(model.field_count(type) == before);
        return e.what();
    }
    return "";
}

} // namespace

TEST_CASE("a model is described exactly") {
    const Model model = fixtures::request_model();
    CHECK(bw::describe_model(model) ==
          "framing: idle gap, at least 4000000 ns\n"
          "message type 0 \"request\"\n"
          "  0 \"address\"  enum      8 bits @0\n"
          "  1 \"function\" enum      8 bits @8\n"
          "  2 \"register\" payload   16 bits @16\n"
          "  3 \"quantity\" payload   16 bits @32\n"
          "  4 \"crc\"      checksum  16 bits @48 little-endian covers 0..3 CRC-16/MODBUS\n");
}

TEST_CASE("every size kind, a constant and the evidence behind a field are described") {
    Model model;
    const std::size_t t = model.add_message_type("frame");
    FieldInfo magic = fixed(FieldKind::Constant, 8);
    magic.constant = 0x7E;
    model.add_field(t, "magic", magic, "");
    model.add_field(t, "length", fixed(FieldKind::Length, 8), "bytes");
    FieldInfo data;
    data.kind       = FieldKind::Payload;
    data.size_kind  = SizeKind::FromField;
    data.size_field = 1;
    model.add_field(t, "data", data, "");
    FieldInfo name;
    name.kind      = FieldKind::Text;
    name.size_kind = SizeKind::Delimited;
    name.delimiter = 0x0A;
    model.add_field(t, "name", name, "");
    FieldInfo rest;
    rest.kind          = FieldKind::Payload;
    rest.size_kind     = SizeKind::ToEnd;
    rest.evidence_bits = 24;
    model.add_field(t, "rest", rest, "");

    CHECK(bw::describe_model(model) ==
          "framing: unknown\n"
          "message type 0 \"frame\"\n"
          "  0 \"magic\"  constant  8 bits @0 = 0x7E\n"
          "  1 \"length\" length    8 bits @8 bytes\n"
          "  2 \"data\"   payload   sized by field 1 @16\n"
          "  3 \"name\"   text      up to 0xA @?\n"
          "  4 \"rest\"   payload   to the end @? evidence 24 bits\n");
}

TEST_CASE("the framing is described, and only idle-gap framing has a gap") {
    Model model;
    bw::FramingInfo framing;
    framing.kind = bw::FramingKind::ByEvent;
    model.set_framing(framing);
    CHECK(model.framing().kind == bw::FramingKind::ByEvent);
    CHECK(bw::describe_model(model) == "framing: one frame per event\n");

    framing.idle_gap_ns = 5;
    CHECK_THROWS_AS(model.set_framing(framing), std::invalid_argument);
    CHECK(model.framing().idle_gap_ns == 0);            // unchanged
    framing.kind = bw::FramingKind::IdleGap;
    model.set_framing(framing);
    CHECK(model.framing().idle_gap_ns == 5);
}

TEST_CASE("positions are fixed until something has no fixed size") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    model.add_field(t, "a", fixed(FieldKind::Enum, 8), "");
    model.add_field(t, "n", fixed(FieldKind::Length, 16, ByteOrder::Big), "");
    FieldInfo body;
    body.kind       = FieldKind::Payload;
    body.size_kind  = SizeKind::FromField;
    body.size_field = 1;
    model.add_field(t, "body", body, "");
    model.add_field(t, "tail", fixed(FieldKind::Payload, 8), "");

    CHECK(model.field_position(t, 0).fixed);
    CHECK(model.field_position(t, 0).bit_offset == 0);
    CHECK(model.field_position(t, 1).bit_offset == 8);
    CHECK(model.field_position(t, 2).fixed);                 // it starts at a known place...
    CHECK(model.field_position(t, 2).bit_offset == 24);
    CHECK_FALSE(model.field_position(t, 3).fixed);           // ...but what follows it does not
    CHECK(model.field_position(t, 3).bit_offset == 0);
}

TEST_CASE("fields are returned as they were added, with their names and details") {
    const Model model = fixtures::request_model();
    REQUIRE(model.message_type_count() == 1);
    CHECK(model.message_type_name(0) == "request");
    REQUIRE(model.field_count(0) == 5);
    CHECK(model.field_name(0, 4) == "crc");
    CHECK(model.field_detail(0, 4) == "CRC-16/MODBUS");
    CHECK(model.field_detail(0, 0) == "");
    const FieldInfo crc = model.field(0, 4);
    CHECK(crc.kind == FieldKind::Checksum);
    CHECK(crc.bit_size == 16);
    CHECK(crc.byte_order == ByteOrder::Little);
    CHECK(crc.covers_first == 0);
    CHECK(crc.covers_last == 3);
}

TEST_CASE("an index that is not there is an error") {
    const Model model = fixtures::request_model();
    CHECK_THROWS_AS(model.message_type_name(1), std::out_of_range);
    CHECK_THROWS_AS(model.field_count(1), std::out_of_range);
    CHECK_THROWS_AS(model.field(0, 5), std::out_of_range);
    CHECK_THROWS_AS(model.field(1, 0), std::out_of_range);
    CHECK_THROWS_AS(model.field_name(0, 5), std::out_of_range);
    CHECK_THROWS_AS(model.field_detail(0, 5), std::out_of_range);
    CHECK_THROWS_AS(model.field_position(0, 5), std::out_of_range);
    CHECK_THROWS_AS(model.field_position(1, 0), std::out_of_range);
}

TEST_CASE("a field cannot go on a message type that does not exist") {
    Model model;
    CHECK_THROWS_AS(model.add_field(0, "x", fixed(FieldKind::Enum, 8), ""), std::invalid_argument);
}

TEST_CASE("nothing can follow a field that runs to the end of the frame") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    FieldInfo rest;
    rest.kind      = FieldKind::Payload;
    rest.size_kind = SizeKind::ToEnd;
    model.add_field(t, "rest", rest, "");
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Enum, 8)), "runs to the end"));
}

TEST_CASE("sizes: a fixed field needs one, and only a fixed field has one") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Payload, 0)), "no bit_size"));
    FieldInfo to_end;
    to_end.kind      = FieldKind::Payload;
    to_end.size_kind = SizeKind::ToEnd;
    to_end.bit_size  = 8;
    CHECK(mentions(refusal(model, t, to_end), "not fixed-size"));
}

TEST_CASE("values that belong to one kind of field are refused on the others") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    model.add_field(t, "len", fixed(FieldKind::Length, 8), "");

    FieldInfo a = fixed(FieldKind::Payload, 8);
    a.size_field = 1;
    CHECK(mentions(refusal(model, t, a), "size_field"));
    FieldInfo b = fixed(FieldKind::Payload, 8);
    b.delimiter = 1;
    CHECK(mentions(refusal(model, t, b), "delimiter"));
    FieldInfo c = fixed(FieldKind::Enum, 8);
    c.constant = 1;
    CHECK(mentions(refusal(model, t, c), "constant"));
    FieldInfo d = fixed(FieldKind::Enum, 8);
    d.covers_last = 1;
    CHECK(mentions(refusal(model, t, d), "covers"));
    FieldInfo e = fixed(FieldKind::Enum, 8);
    e.covers_first = 1;
    CHECK(mentions(refusal(model, t, e), "covers"));
}

TEST_CASE("numbers are fixed-size, at most 64 bits, and say their byte order when it matters") {
    Model model;
    const std::size_t t = model.add_message_type("m");

    FieldInfo not_fixed;
    not_fixed.kind      = FieldKind::Counter;
    not_fixed.size_kind = SizeKind::ToEnd;
    CHECK(mentions(refusal(model, t, not_fixed), "must be fixed-size"));

    CHECK(mentions(refusal(model, t, fixed(FieldKind::Timestamp, 65, ByteOrder::Big)), "wider than 64"));
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Counter, 16)), "needs a byte order"));
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Counter, 8, ByteOrder::Big)), "has no byte order"));
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Payload, 16, ByteOrder::Big)), "not a number"));
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Text, 8, ByteOrder::Little)), "not a number"));

    CHECK(refusal(model, t, fixed(FieldKind::Timestamp, 64, ByteOrder::Big)).empty());
    CHECK(refusal(model, t, fixed(FieldKind::Counter, 12, ByteOrder::Little)).empty());   // 12 > 8: two bytes
    CHECK(refusal(model, t, fixed(FieldKind::Flags, 1)).empty());
    CHECK(refusal(model, t, fixed(FieldKind::Payload, 24)).empty());
}

TEST_CASE("a float is 32 or 64 bits") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Float, 16, ByteOrder::Big)), "32 or 64"));
    CHECK(mentions(refusal(model, t, fixed(FieldKind::Float, 8)), "32 or 64"));
    CHECK(refusal(model, t, fixed(FieldKind::Float, 32, ByteOrder::Little)).empty());
    CHECK(refusal(model, t, fixed(FieldKind::Float, 64, ByteOrder::Big)).empty());
}

TEST_CASE("a constant must fit in its size, including at 64 bits") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    FieldInfo too_big = fixed(FieldKind::Constant, 8);
    too_big.constant = 0x100;
    CHECK(mentions(refusal(model, t, too_big), "does not fit in 8 bits"));

    FieldInfo exact = fixed(FieldKind::Constant, 8);
    exact.constant = 0xFF;
    CHECK(refusal(model, t, exact).empty());

    FieldInfo widest = fixed(FieldKind::Constant, 64, ByteOrder::Big);
    widest.constant = 0xFFFFFFFFFFFFFFFFULL;         // shifting by 64 would be undefined
    CHECK(refusal(model, t, widest).empty());
}

TEST_CASE("a field sized from another must name an earlier Length field") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    model.add_field(t, "plain", fixed(FieldKind::Enum, 8), "");
    model.add_field(t, "len", fixed(FieldKind::Length, 8), "");

    FieldInfo data;
    data.kind      = FieldKind::Payload;
    data.size_kind = SizeKind::FromField;

    data.size_field = 0;                              // an Enum, not a Length
    CHECK(mentions(refusal(model, t, data), "not a Length"));
    data.size_field = 2;                              // itself: not before it
    CHECK(mentions(refusal(model, t, data), "does not come before"));
    data.size_field = 9;
    CHECK(mentions(refusal(model, t, data), "does not come before"));
    data.size_field = 1;
    CHECK(refusal(model, t, data).empty());
}

TEST_CASE("a checksum must cover a range of earlier fields") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    model.add_field(t, "a", fixed(FieldKind::Enum, 8), "");
    model.add_field(t, "b", fixed(FieldKind::Enum, 8), "");

    CHECK(mentions(refusal(model, t, fixtures::checksum(8, ByteOrder::NotApplicable, 0, 2)), "earlier fields"));   // itself
    CHECK(mentions(refusal(model, t, fixtures::checksum(8, ByteOrder::NotApplicable, 1, 0)), "earlier fields"));   // backwards
    CHECK(mentions(refusal(model, t, fixtures::checksum(8, ByteOrder::NotApplicable, 5, 6)), "earlier fields"));
    CHECK(refusal(model, t, fixtures::checksum(8, ByteOrder::NotApplicable, 1, 1)).empty());       // one field is a range
}

TEST_CASE("a refused field changes nothing, and the model carries on") {
    Model model;
    const std::size_t t = model.add_message_type("m");
    model.add_field(t, "a", fixed(FieldKind::Enum, 8), "");
    CHECK(model.add_field(t, "b", fixed(FieldKind::Enum, 8), "") == 1);
    CHECK_THROWS_AS(model.add_field(t, "bad", fixed(FieldKind::Counter, 16), ""), std::invalid_argument);
    CHECK(model.field_count(t) == 2);
    CHECK(model.add_field(t, "c", fixed(FieldKind::Enum, 8), "") == 2);     // the index did not skip
    CHECK(bw::describe_model(model).find("bad") == std::string::npos);
}

TEST_CASE("every kind has a name") {
    CHECK(bw::field_kind_name(FieldKind::Unknown) == "unknown");
    CHECK(bw::field_kind_name(FieldKind::Constant) == "constant");
    CHECK(bw::field_kind_name(FieldKind::Enum) == "enum");
    CHECK(bw::field_kind_name(FieldKind::Counter) == "counter");
    CHECK(bw::field_kind_name(FieldKind::Length) == "length");
    CHECK(bw::field_kind_name(FieldKind::Checksum) == "checksum");
    CHECK(bw::field_kind_name(FieldKind::Timestamp) == "timestamp");
    CHECK(bw::field_kind_name(FieldKind::Float) == "float");
    CHECK(bw::field_kind_name(FieldKind::Text) == "text");
    CHECK(bw::field_kind_name(FieldKind::Flags) == "flags");
    CHECK(bw::field_kind_name(FieldKind::Payload) == "payload");
}
