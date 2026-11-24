// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The Kaitai Struct exporter, as text: what each kind of field is written as,
// byte orders, constants, quoting, and what is refused. That a Kaitai compiler
// accepts the output and that the parser it makes reads the frames of a capture
// back into the same bytes is checked by tests/roundtrip/kaitai_roundtrip.py,
// which needs the compiler and so is not part of this suite.

#include "doctest.h"

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>

#include "bw/analyze.h"
#include "bw/kaitai.h"
#include "bw/protocol.h"
#include "kaitai_fixtures.h"
#include "model_fixtures.h"

using bw::ByteOrder;
using bw::FieldInfo;
using bw::FieldKind;
using bw::Model;
using fixtures::fixed;

namespace {

// A model with one message type "m" whose fields are given one at a time.
struct OneType {
    Model       model;
    std::size_t type;
    OneType() : type(model.add_message_type("m")) {}
    void add(const std::string& name, const FieldInfo& info, const std::string& detail = "") {
        model.add_field(type, name, info, detail);
    }
    std::string out(const std::string& id = "m") const { return bw::export_kaitai(model, type, id); }
};

// The line "    type: ..." or "    contents: ..." or "    size: ..." etc. of the only field.
std::string body(const std::string& ksy) {
    const std::string head = "seq:\n  - id: f\n";
    const std::size_t at   = ksy.find(head);
    REQUIRE(at != std::string::npos);
    const std::size_t doc = ksy.find("    doc: ", at);
    REQUIRE(doc != std::string::npos);
    return ksy.substr(at + head.size(), doc - at - head.size());
}

std::string doc_of(const std::string& ksy) {
    const std::size_t at = ksy.rfind("    doc: ");
    REQUIRE(at != std::string::npos);
    return ksy.substr(at + 9, ksy.size() - at - 10);       // without the newline
}

std::string read_corpus(const std::string& name) {
    const std::string path = std::string(BW_CORPUS_DIR) + "/" + name;
    std::ifstream in(path.c_str(), std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

FieldInfo constant(std::uint32_t bits, ByteOrder order, std::uint64_t value) {
    FieldInfo info = fixed(FieldKind::Constant, bits, order);
    info.constant  = value;
    return info;
}

} // namespace

TEST_CASE("kaitai: the Modbus RTU model of the generator") {
    const Model m = bw::protocol_model("modbus-rtu");
    CHECK(bw::export_kaitai(m, 0, "request") ==
          "meta:\n"
          "  id: request\n"
          "doc: \"Message type 'request'. Written by bitwise-bus. Frames are separated by silences of at least 4010415 ns.\"\n"
          "seq:\n"
          "  - id: address\n"
          "    type: u1\n"
          "    doc: \"enum\"\n"
          "  - id: function\n"
          "    type: u1\n"
          "    doc: \"enum\"\n"
          "  - id: register\n"
          "    size: 2\n"
          "    doc: \"payload\"\n"
          "  - id: quantity\n"
          "    size: 2\n"
          "    doc: \"payload\"\n"
          "  - id: crc\n"
          "    type: u2le\n"
          "    doc: \"checksum, CRC-16/MODBUS, over address to quantity (Kaitai does not check it)\"\n");
}

TEST_CASE("kaitai: what the pipeline infers from a capture checked in") {
    const bw::Analysis a =
        bw::analyze(bw::parse_capture_csv(read_corpus("synth_modbus_rtu_seed1_50frames_jitter300.csv")),
                    bw::AnalyzeOptions());
    CHECK(bw::export_kaitai(a.model(), 0, "type0") ==
          "meta:\n"
          "  id: type0\n"
          "doc: \"Message type 'type0'. Written by bitwise-bus. Frames are separated by silences of at least 6918373 ns.\"\n"
          "seq:\n"
          "  - id: field_0\n"
          "    type: u1\n"
          "    doc: \"enum; evidence 300 bits\"\n"
          "  - id: field_1\n"
          "    type: u1\n"
          "    doc: \"enum; evidence 350 bits\"\n"
          "  - id: field_2\n"
          "    size: 2\n"
          "    doc: \"payload\"\n"
          "  - id: field_4\n"
          "    contents: [0x00]\n"
          "    doc: \"constant; evidence 392 bits\"\n"
          "  - id: field_5\n"
          "    size: 1\n"
          "    doc: \"payload\"\n"
          "  - id: checksum\n"
          "    type: u2le\n"
          "    doc: \"checksum, CRC-16/MODBUS, over field_0 to field_5 (Kaitai does not check it); evidence 800 bits\"\n");
}

TEST_CASE("kaitai: what the pipeline infers from lines of text checked in") {
    // The third type of NMEA 0183, the velocity: the dollar and the address are contents, what varies is text up to
    // a comma, what does not is contents that ends with one, and the checksum is two characters.
    const bw::Analysis a =
        bw::analyze(bw::parse_capture_csv(read_corpus("synth_nmea0183_seed3_60frames_jitter300.csv")),
                    bw::AnalyzeOptions());
    REQUIRE(a.type_count() == 3);
    const std::string ksy = bw::export_kaitai(a.model(), 2, "velocity");
    CHECK(ksy.find("doc: \"Message type 'type2'. Written by bitwise-bus. A frame ends with the byte 0x0a.\"\n") !=
          std::string::npos);
    CHECK(ksy.find("  - id: field_0\n    contents: [0x24]\n") != std::string::npos);
    CHECK(ksy.find("  - id: field_1\n    contents: [0x47, 0x50, 0x56, 0x54, 0x47, 0x2c]\n") != std::string::npos);
    CHECK(ksy.find("  - id: field_2\n    type: str\n    terminator: 0x2c\n    include: true\n    encoding: ASCII\n"
                   "    doc: \"text; evidence 20 bits\"\n") != std::string::npos);
    CHECK(ksy.find("  - id: checksum\n    type: str\n    size: 2\n    encoding: ASCII\n"
                   "    doc: \"checksum, XOR-8, written as hexadecimal text, over field_1 to field_10 "
                   "(Kaitai does not check it); evidence 160 bits\"\n") != std::string::npos);
    CHECK(ksy.find("  - id: field_12\n    contents: [0x0d, 0x0a]\n") != std::string::npos);
}

TEST_CASE("kaitai: every kind of field, as the definition that the round trip compiles") {
    std::ifstream in((std::string(BW_ROUNDTRIP_DIR) + "/mapping.ksy").c_str(), std::ios::binary);
    REQUIRE(in.good());
    const std::string checked_in((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    CHECK(bw::export_kaitai(fixtures::every_field(), 0, "mapping") == checked_in);
}

TEST_CASE("kaitai: numbers are u and f types by width and byte order") {
    struct Case { FieldKind kind; std::uint32_t bits; ByteOrder order; const char* type; };
    const Case cases[] = {
        { FieldKind::Enum,      8,  ByteOrder::NotApplicable, "u1"   },
        { FieldKind::Flags,     8,  ByteOrder::NotApplicable, "u1"   },
        { FieldKind::Counter,   16, ByteOrder::Big,           "u2be" },
        { FieldKind::Counter,   16, ByteOrder::Little,        "u2le" },
        { FieldKind::Timestamp, 32, ByteOrder::Big,           "u4be" },
        { FieldKind::Timestamp, 32, ByteOrder::Little,        "u4le" },
        { FieldKind::Length,    64, ByteOrder::Big,           "u8be" },
        { FieldKind::Checksum,  64, ByteOrder::Little,        "u8le" },
        { FieldKind::Float,     32, ByteOrder::Little,        "f4le" },
        { FieldKind::Float,     32, ByteOrder::Big,           "f4be" },
        { FieldKind::Float,     64, ByteOrder::Big,           "f8be" },
        { FieldKind::Float,     64, ByteOrder::Little,        "f8le" },
    };
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CAPTURE(i);
        OneType t;
        FieldInfo info = fixed(cases[i].kind, cases[i].bits, cases[i].order);
        if (cases[i].kind == FieldKind::Checksum) {
            // A checksum covers earlier fields.
            t.add("g", fixed(FieldKind::Enum, 8));
            info.covers_first = 0;
            info.covers_last  = 0;
        }
        t.add("f", info);
        const std::string ksy = t.out();
        const std::size_t at  = ksy.find("  - id: f\n");
        REQUIRE(at != std::string::npos);
        CHECK(ksy.compare(at + 10, std::string(cases[i].type).size() + 11, std::string("    type: ") + cases[i].type + "\n") == 0);
    }
}

TEST_CASE("kaitai: a whole number of bytes that Kaitai has no integer for is read as bytes, with its byte order in the doc") {
    OneType t;
    t.add("f", fixed(FieldKind::Counter, 24, ByteOrder::Big));
    CHECK(body(t.out()) == "    size: 3\n");
    CHECK(doc_of(t.out()) == "\"counter, big-endian\"");
    OneType u;
    u.add("f", fixed(FieldKind::Timestamp, 40, ByteOrder::Little));
    CHECK(body(u.out()) == "    size: 5\n");
    CHECK(doc_of(u.out()) == "\"timestamp, little-endian\"");
}

TEST_CASE("kaitai: a constant is its bytes in the order the frame has them") {
    const struct { std::uint32_t bits; ByteOrder order; std::uint64_t value; const char* expected; } cases[] = {
        { 8,  ByteOrder::NotApplicable, 0x7E,               "[0x7e]"                   },
        { 8,  ByteOrder::NotApplicable, 0x00,               "[0x00]"                   },
        { 16, ByteOrder::Big,           0x1234,             "[0x12, 0x34]"             },
        { 16, ByteOrder::Little,        0x1234,             "[0x34, 0x12]"             },
        { 24, ByteOrder::Little,        0x010203,           "[0x03, 0x02, 0x01]"       },
        { 32, ByteOrder::Big,           0xDEADBEEF,         "[0xde, 0xad, 0xbe, 0xef]" },
        { 64, ByteOrder::Little,        0x0102030405060708ULL, "[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]" },
    };
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CAPTURE(i);
        OneType t;
        t.add("f", constant(cases[i].bits, cases[i].order, cases[i].value));
        CHECK(body(t.out()) == std::string("    contents: ") + cases[i].expected + "\n");
    }
}

TEST_CASE("kaitai: text, payload and unknown are strings and bytes of their size") {
    OneType text;
    text.add("f", fixed(FieldKind::Text, 32));
    CHECK(body(text.out()) == "    type: str\n    size: 4\n    encoding: ASCII\n");
    OneType payload;
    payload.add("f", fixed(FieldKind::Payload, 40));
    CHECK(body(payload.out()) == "    size: 5\n");
    OneType unknown;
    unknown.add("f", fixed(FieldKind::Unknown, 16));
    CHECK(body(unknown.out()) == "    size: 2\n");
    CHECK(doc_of(unknown.out()) == "\"unknown\"");
}

TEST_CASE("kaitai: text that ends with a byte is a string with that terminator, kept in it") {
    OneType t;
    FieldInfo line = fixed(FieldKind::Text, 0);
    line.size_kind = bw::SizeKind::Delimited;
    line.delimiter = 0x2A;
    t.add("f", line, "one of \"A\", \"D\"");
    CHECK(body(t.out()) == "    type: str\n    terminator: 0x2a\n    include: true\n    encoding: ASCII\n");
    CHECK(doc_of(t.out()) == "\"text, one of \\\"A\\\", \\\"D\\\"\"");
}

TEST_CASE("kaitai: the doc says what the model found, with the detail and the evidence") {
    OneType t;
    FieldInfo counter = fixed(FieldKind::Counter, 8);
    counter.evidence_bits = 304;
    t.add("f", counter, "step 3");
    CHECK(doc_of(t.out()) == "\"counter, step 3; evidence 304 bits\"");
    OneType plain;
    plain.add("f", fixed(FieldKind::Enum, 8));
    CHECK(doc_of(plain.out()) == "\"enum\"");
    OneType checked;
    checked.add("f", fixed(FieldKind::Enum, 8));
    checked.add("g", fixed(FieldKind::Payload, 16));
    FieldInfo crc = fixed(FieldKind::Checksum, 16, ByteOrder::Big);
    crc.covers_first = 0;
    crc.covers_last  = 1;
    checked.add("c", crc, "CRC-16/CCITT-FALSE");
    CHECK(doc_of(checked.out()) == "\"checksum, CRC-16/CCITT-FALSE, over f to g (Kaitai does not check it)\"");
}

TEST_CASE("kaitai: a checksum written as hexadecimal text is a string, not a number") {
    OneType t;
    t.add("f", fixed(FieldKind::Payload, 24));
    FieldInfo crc = fixed(FieldKind::Checksum, 16, ByteOrder::Big);
    crc.ascii_hex    = true;
    crc.covers_first = 0;
    crc.covers_last  = 0;
    t.add("c", crc, "XOR of the characters between $ and *");
    const std::string ksy = t.out();
    CHECK(ksy.find("  - id: c\n    type: str\n    size: 2\n    encoding: ASCII\n") != std::string::npos);
    CHECK(doc_of(ksy) ==
          "\"checksum, XOR of the characters between $ and *, written as hexadecimal text, over f to f (Kaitai does not check it)\"");
}

TEST_CASE("kaitai: text in a doc is written so that YAML reads it back as it is") {
    OneType t;
    t.add("f", fixed(FieldKind::Payload, 8), "say \"hi\"\\ \n\ttab \x01 end");
    CHECK(doc_of(t.out()) == "\"payload, say \\\"hi\\\"\\\\ \\n\\ttab \\x01 end\"");
    // A message type name with a quote does not break the line it is on.
    Model m;
    const std::size_t type = m.add_message_type("a\"b");
    CHECK(bw::export_kaitai(m, type, "x").find("doc: \"Message type 'a\\\"b'. Written by bitwise-bus.\"\n") !=
          std::string::npos);
}

TEST_CASE("kaitai: what the framing becomes") {
    Model unknown;
    std::size_t t = unknown.add_message_type("m");
    CHECK(bw::export_kaitai(unknown, t, "m") ==
          "meta:\n  id: m\ndoc: \"Message type 'm'. Written by bitwise-bus.\"\nseq: []\n");

    Model by_event;
    bw::FramingInfo framing;
    framing.kind = bw::FramingKind::ByEvent;
    by_event.set_framing(framing);
    t = by_event.add_message_type("m");
    CHECK(bw::export_kaitai(by_event, t, "m") ==
          "meta:\n  id: m\ndoc: \"Message type 'm'. Written by bitwise-bus. Each capture event is one frame.\"\nseq: []\n");
}

TEST_CASE("kaitai: the other framings are said in the doc") {
    const struct {
        bw::FramingKind kind;
        bool            escaped;
        const char*     sentence;
    } cases[] = {
        { bw::FramingKind::Contiguous, false, "Frames follow one another with nothing between them." },
        { bw::FramingKind::Terminated, false, "A frame ends with the byte 0x0a." },
        { bw::FramingKind::Flagged,    false, "A frame lies between two bytes 0x0a." },
        { bw::FramingKind::Flagged,    true,  "A frame lies between two bytes 0x0a. Inside it 0x0a is sent as 0x7d 0x5e and 0x7d as 0x7d 0x5d." },
    };
    for (std::size_t i = 0; i < sizeof(cases) / sizeof(cases[0]); ++i) {
        CAPTURE(i);
        Model m;
        bw::FramingInfo framing;
        framing.kind = cases[i].kind;
        if (cases[i].kind != bw::FramingKind::Contiguous) {
            framing.delimiter = 0x0A;
        }
        if (cases[i].escaped) {
            framing.escaped        = true;
            framing.escape         = 0x7D;
            framing.delimiter_code = 0x5E;
            framing.escape_code    = 0x5D;
        }
        m.set_framing(framing);
        const std::size_t t = m.add_message_type("m");
        CHECK(bw::export_kaitai(m, t, "m") ==
              std::string("meta:\n  id: m\ndoc: \"Message type 'm'. Written by bitwise-bus. ") + cases[i].sentence +
              "\"\nseq: []\n");
    }
}

TEST_CASE("kaitai: the same model gives the same bytes, and the other message types are not written") {
    Model m = bw::protocol_model("modbus-rtu");
    const std::size_t other = m.add_message_type("other");
    m.add_field(other, "only", fixed(FieldKind::Enum, 8), "");
    const std::string first = bw::export_kaitai(m, 0, "request");
    CHECK(bw::export_kaitai(m, 0, "request") == first);
    CHECK(first.find("only") == std::string::npos);
    CHECK(bw::export_kaitai(m, other, "other").find("  - id: only\n") != std::string::npos);
}

TEST_CASE("kaitai: an id has to be a Kaitai identifier") {
    OneType t;
    t.add("f", fixed(FieldKind::Enum, 8));
    CHECK_NOTHROW(t.out("a"));
    CHECK_NOTHROW(t.out("type0"));
    CHECK_NOTHROW(t.out("a_b1"));
    const char* bad[] = { "", "Type", "1abc", "_a", "a-b", "a b", "a.b", "aB", "é" };
    for (std::size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        CAPTURE(bad[i]);
        CHECK_THROWS_AS(t.out(bad[i]), std::invalid_argument);
    }
}

TEST_CASE("kaitai: field names have to be Kaitai identifiers, and different") {
    OneType upper;
    upper.add("Address", fixed(FieldKind::Enum, 8));
    CHECK_THROWS_AS(upper.out(), std::invalid_argument);
    OneType dash;
    dash.add("a-b", fixed(FieldKind::Enum, 8));
    CHECK_THROWS_AS(dash.out(), std::invalid_argument);
    OneType twice;
    twice.add("a", fixed(FieldKind::Enum, 8));
    twice.add("a", fixed(FieldKind::Enum, 8));
    CHECK_THROWS_AS(twice.out(), std::invalid_argument);
}

TEST_CASE("kaitai: what the exporter does not write yet is refused, and nothing is half written") {
    // Not a whole number of bytes.
    OneType bits;
    bits.add("f", fixed(FieldKind::Flags, 3));
    CHECK_THROWS_AS(bits.out(), std::invalid_argument);
    OneType eleven;
    eleven.add("f", fixed(FieldKind::Counter, 11, ByteOrder::Big));
    CHECK_THROWS_AS(eleven.out(), std::invalid_argument);

    // A size that depends on the frame, and is not a length that Kaitai has an integer for.
    OneType from_field;
    from_field.add("n", fixed(FieldKind::Length, 24, ByteOrder::Big));
    FieldInfo sized = fixed(FieldKind::Payload, 0);
    sized.size_kind  = bw::SizeKind::FromField;
    sized.size_field = 0;
    from_field.add("body", sized);
    CHECK_THROWS_AS(from_field.out(), std::invalid_argument);
    OneType to_end;
    FieldInfo rest = fixed(FieldKind::Payload, 0);
    rest.size_kind = bw::SizeKind::ToEnd;
    to_end.add("body", rest);
    CHECK_THROWS_AS(to_end.out(), std::invalid_argument);
    // Only text can end with a byte; something else that does is not written.
    OneType delimited;
    FieldInfo line = fixed(FieldKind::Payload, 0);
    line.size_kind = bw::SizeKind::Delimited;
    line.delimiter = 0x0A;
    delimited.add("line", line);
    CHECK_THROWS_AS(delimited.out(), std::invalid_argument);

    // Whatever comes before the field that is refused, nothing is returned: the
    // error names the field.
    OneType later;
    later.add("ok", fixed(FieldKind::Enum, 8));
    later.add("bad", fixed(FieldKind::Flags, 3));
    try {
        later.out();
        FAIL("no exception");
    } catch (const std::invalid_argument& e) {
        CHECK(std::string(e.what()).find("'bad'") != std::string::npos);
    }
}

TEST_CASE("kaitai: a payload sized by a length is `size:` and the name of the length") {
    // MAVLink 2's shape: a start byte, a length, a payload that it sizes, and a CRC after it.
    for (int width = 8; width <= 32; width += 8) {
        if (width == 24) {
            continue;
        }
        CAPTURE(width);
        OneType t;
        t.add("start", constant(8, ByteOrder::NotApplicable, 0xFD));
        t.add("length", fixed(FieldKind::Length, static_cast<std::uint32_t>(width),
                              width == 8 ? ByteOrder::NotApplicable : ByteOrder::Little));
        FieldInfo sized = fixed(FieldKind::Payload, 0);
        sized.size_kind  = bw::SizeKind::FromField;
        sized.size_field = 1;
        t.add("payload", sized);
        FieldInfo crc = fixed(FieldKind::Checksum, 16, ByteOrder::Little);
        crc.covers_first = 1;
        crc.covers_last  = 2;
        t.add("crc", crc);
        const std::string out = t.out();
        const std::string number = width == 8 ? "u1" : width == 16 ? "u2le" : "u4le";
        CHECK(out.find("  - id: length\n    type: " + number + "\n") != std::string::npos);
        CHECK(out.find("  - id: payload\n    size: length\n    doc: \"payload\"\n") != std::string::npos);
        // The CRC after it is read as it is, and the order of the fields is the model's.
        CHECK(out.find("  - id: crc\n    type: u2le\n") != std::string::npos);
        CHECK(out.find("id: payload") < out.find("id: crc"));
        CHECK(out.find("id: length") < out.find("id: payload"));
    }
}

TEST_CASE("kaitai: a message type the model does not have") {
    OneType t;
    t.add("f", fixed(FieldKind::Enum, 8));
    CHECK_THROWS_AS(bw::export_kaitai(t.model, 1, "m"), std::out_of_range);
    CHECK_THROWS_AS(bw::export_kaitai(Model(), 0, "m"), std::out_of_range);
}
