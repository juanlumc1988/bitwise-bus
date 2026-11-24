// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The pipeline from a capture to a model. The main test is the one the
// skeleton was built for: synthetic Modbus RTU captures of many seeds and
// timing noises go in, the evaluation harness scores the model that comes out
// against the generator's, and what it recovers is checked. Around it, what the
// pipeline must not do: invent a framing, a checksum or a structure that is not
// there, and keep frames of a size it has too few of.

#include "doctest.h"

#include <fstream>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/evaluate.h"
#include "bw/protocol.h"
#include "frame_fixtures.h"

using bw::Analysis;
using bw::AnalyzeOptions;
using bw::ByteOrder;
using bw::Capture;
using bw::FieldKind;
using bw::Model;
using fixtures::Bytes;

namespace {

bw::Dataset modbus(std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter) {
    bw::GenerateOptions options;
    options.seed            = seed;
    options.frames          = frames;
    options.jitter_permille = jitter;
    return bw::generate_protocol("modbus-rtu", options);
}

Analysis run(const Capture& capture) {
    return bw::analyze(capture, AnalyzeOptions());
}

std::string read_corpus(const std::string& name) {
    const std::string path = std::string(BW_CORPUS_DIR) + "/" + name;
    std::ifstream in(path.c_str(), std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

bool contains(const std::string& text, const std::string& part) {
    return text.find(part) != std::string::npos;
}

} // namespace

TEST_CASE("analyze: Modbus RTU captures give back its framing, its checksum and its field boundaries") {
    const std::uint32_t jitters[4] = { 0, 100, 300, 500 };
    for (std::uint64_t seed = 0; seed < 25; ++seed) {
        for (int j = 0; j < 4; ++j) {
            CAPTURE(seed);
            CAPTURE(jitters[j]);
            const bw::Dataset d = modbus(seed, 50, jitters[j]);
            const Analysis    a = run(d.capture());

            // Segmentation: every frame, exactly, and so every boundary.
            const bw::SegmentationScore seg = bw::score_segmentation(d.frames(), a.segmentation().frames());
            CHECK(seg.truth_frames == 50);
            CHECK(seg.found_frames == 50);
            CHECK(seg.exact_frames == 50);
            CHECK(seg.boundary_hits == seg.truth_boundaries);
            CHECK(seg.found_boundaries == seg.truth_boundaries);

            // One message type, which is the generator's.
            REQUIRE(a.type_count() == 1);
            CHECK(a.type_report(0).frame_bytes == 8);
            CHECK(a.type_report(0).frames == 50);
            CHECK(a.info().ignored_frames == 0);
            REQUIRE(a.model().message_type_count() == 1);

            // Fields: every true boundary, and the checksum exactly. One boundary more than
            // the truth: the high byte of the quantity is always 0, so it is a constant of
            // its own, and stage 4 cannot know that it belongs to the byte after it.
            const bw::FieldScore f = bw::score_fields(d.model(), 0, a.model(), 0);
            CHECK(f.truth_fields == 5);
            CHECK(f.found_fields == 6);
            CHECK(f.truth_boundaries == 6);
            CHECK(f.found_boundaries == 7);
            CHECK(f.boundary_hits == 6);
            CHECK(f.exact_fields == 4);
            CHECK(f.kind_hits == 4);
            CHECK(f.checksum_match);
        }
    }
}

TEST_CASE("analyze: what the Modbus RTU model says of each field") {
    const Analysis a = run(modbus(1, 50, 300).capture());
    const Model    m = a.model();
    REQUIRE(m.field_count(0) == 6);
    CHECK(m.framing().kind == bw::FramingKind::IdleGap);
    CHECK(m.message_type_name(0) == "type0");

    const FieldKind kinds[6] = { FieldKind::Enum, FieldKind::Enum, FieldKind::Payload,
                                 FieldKind::Constant, FieldKind::Payload, FieldKind::Checksum };
    const char*     names[6] = { "field_0", "field_1", "field_2", "field_4", "field_5", "checksum" };
    const unsigned  bits[6]  = { 8, 8, 16, 8, 8, 16 };
    for (std::size_t i = 0; i < 6; ++i) {
        CHECK(m.field(0, i).kind == kinds[i]);
        CHECK(m.field_name(0, i) == names[i]);
        CHECK(m.field(0, i).bit_size == bits[i]);
    }
    CHECK(m.field(0, 3).constant == 0);
    CHECK(m.field(0, 5).byte_order == ByteOrder::Little);
    CHECK(m.field(0, 5).covers_first == 0);
    CHECK(m.field(0, 5).covers_last == 4);
    CHECK(m.field_detail(0, 5) == "CRC-16/MODBUS");
    CHECK(m.field(0, 5).evidence_bits == 800);
}

TEST_CASE("analyze: a capture file checked in gives the report that is printed, to the byte") {
    // The generator's output, written by a second implementation. The gaps the report
    // gives (the shortest between frames, the longest inside one, how many of each) were
    // worked out from the file by a script, and the evidence from the rules: 50 frames of a
    // CRC-16 is 800 bits, a constant over 50 frames is 8 * 49, an enumeration of 3 values in
    // 50 bytes saves 6 bits a byte, and one of 2 values saves 7.
    const Analysis a = run(bw::parse_capture_csv(read_corpus("synth_modbus_rtu_seed1_50frames_jitter300.csv")));
    CHECK(bw::describe_analysis(a) ==
          "events     400 (400 bytes)\n"
          "framing    idle gap: a gap of at least 6918373 ns ends a frame (49 gaps between frames, 350 inside them, the longest 1464359 ns)\n"
          "frames     50\n"
          "type0      8 bytes, 50 frames; checksum CRC-16/MODBUS, 16 bits little-endian, evidence 800 bits\n"
          "framing: idle gap, at least 6918373 ns\n"
          "message type 0 \"type0\"\n"
          "  0 \"field_0\"  enum      8 bits @0 evidence 300 bits\n"
          "  1 \"field_1\"  enum      8 bits @8 evidence 350 bits\n"
          "  2 \"field_2\"  payload   16 bits @16\n"
          "  3 \"field_4\"  constant  8 bits @32 = 0x0 evidence 392 bits\n"
          "  4 \"field_5\"  payload   8 bits @40\n"
          "  5 \"checksum\" checksum  16 bits @48 little-endian covers 0..4 evidence 800 bits CRC-16/MODBUS\n");
    // And it is what the generator's own capture gives.
    CHECK(bw::describe_analysis(run(modbus(1, 50, 300).capture())) == bw::describe_analysis(a));
}

TEST_CASE("analyze: it says so when there is no framing to see") {
    // No times at all.
    Capture untimed;
    fixtures::Random rng(41);
    for (int i = 0; i < 100; ++i) {
        untimed.add_event(bw::EventInfo(), Bytes(1, rng.byte()));
    }
    const Analysis a = run(untimed);
    CHECK_FALSE(a.info().segmentation.found);
    CHECK(a.info().events == 100);
    CHECK(a.type_count() == 0);
    CHECK(a.model().message_type_count() == 0);
    CHECK(a.model().framing().kind == bw::FramingKind::Unknown);
    CHECK(a.segmentation().frame_count() == 0);
    CHECK(contains(bw::describe_analysis(a), "framing    none found"));

    // Random bytes at times that spread evenly from short to long.
    Capture spread;
    std::int64_t now = 0;
    for (int i = 0; i < 200; ++i) {
        bw::EventInfo info;
        info.has_time = true;
        info.time_ns  = now;
        spread.add_event(info, Bytes(1, rng.byte()));
        now += 1000 + static_cast<std::int64_t>(rng.next() % 1000);
    }
    CHECK_FALSE(run(spread).info().segmentation.found);

    // Nothing at all.
    CHECK_FALSE(run(Capture()).info().segmentation.found);
}

TEST_CASE("analyze: random frames in the right places give a framing, and no checksum and no structure") {
    // The negative control for the stages after segmentation.
    fixtures::Random rng(42);
    std::vector<Bytes> frames;
    for (int i = 0; i < 60; ++i) {
        Bytes f;
        for (int k = 0; k < 10; ++k) {
            f.push_back(rng.byte());
        }
        frames.push_back(f);
    }
    const Analysis a = run(fixtures::capture_of(frames));
    CHECK(a.info().segmentation.found);
    CHECK(a.info().frames == 60);
    REQUIRE(a.type_count() == 1);
    CHECK_FALSE(a.type_report(0).checksum.found);
    CHECK(a.type_report(0).checksum.candidates == 0);
    const Model m = a.model();
    REQUIRE(m.field_count(0) == 1);
    CHECK(m.field(0, 0).kind == FieldKind::Payload);
    CHECK(m.field(0, 0).bit_size == 80);
    CHECK(m.field(0, 0).evidence_bits == 0);
    CHECK(contains(bw::describe_analysis(a), "; no checksum found"));
}

namespace {

// n frames of `size` bytes, each [lead, 1 + i % 3, random...].
std::vector<Bytes> family(fixtures::Random* rng, std::size_t n, std::size_t size, std::uint8_t lead) {
    std::vector<Bytes> out;
    for (std::size_t i = 0; i < n; ++i) {
        // Written by index: a vector of one element that is then pushed to is what
        // gcc 15 reports at -O2 as an array subscript outside its bounds, wrongly.
        Bytes f(size);
        f[0] = lead;
        f[1] = static_cast<std::uint8_t>(1 + i % 3);
        for (std::size_t k = 2; k < size; ++k) {
            f[k] = rng->byte();
        }
        out.push_back(f);
    }
    return out;
}

} // namespace

TEST_CASE("analyze: frames of different sizes are different message types, most frequent first") {
    fixtures::Random rng(43);
    std::vector<Bytes> frames = family(&rng, 30, 6, 0x55);
    const std::vector<Bytes> small = family(&rng, 20, 4, 0xAA);
    frames.insert(frames.end(), small.begin(), small.end());
    // Interleave them, so that the order of the capture is not the order of the types.
    std::vector<Bytes> mixed;
    for (std::size_t i = 0; i < 30; ++i) {
        mixed.push_back(frames[i]);
        if (i < 20) {
            mixed.push_back(frames[30 + i]);
        }
    }
    const Analysis a = run(fixtures::capture_of(mixed));
    REQUIRE(a.type_count() == 2);
    CHECK(a.type_report(0).frame_bytes == 6);
    CHECK(a.type_report(0).frames == 30);
    CHECK(a.type_report(1).frame_bytes == 4);
    CHECK(a.type_report(1).frames == 20);
    CHECK(a.info().frames == 50);
    CHECK(a.info().ignored_frames == 0);
    const Model m = a.model();
    REQUIRE(m.message_type_count() == 2);
    CHECK(m.message_type_name(0) == "type0");
    CHECK(m.message_type_name(1) == "type1");
    CHECK(m.field(0, 0).kind == FieldKind::Constant);
    CHECK(m.field(0, 0).constant == 0x55);
    CHECK(m.field(1, 0).constant == 0xAA);
    CHECK(m.field(0, 1).kind == FieldKind::Enum);
    CHECK_THROWS_AS(a.type_report(2), std::out_of_range);

    // With as many frames of each, the smaller size comes first.
    std::vector<Bytes> equal = family(&rng, 20, 6, 0x55);
    const std::vector<Bytes> other = family(&rng, 20, 4, 0xAA);
    equal.insert(equal.end(), other.begin(), other.end());
    const Analysis e = run(fixtures::capture_of(equal));
    REQUIRE(e.type_count() == 2);
    CHECK(e.type_report(0).frame_bytes == 4);
    CHECK(e.type_report(1).frame_bytes == 6);
}

TEST_CASE("analyze: a size with too few frames is left out and counted, at the exact limit") {
    fixtures::Random rng(44);
    std::vector<Bytes> frames = family(&rng, 30, 6, 0x55);
    const std::vector<Bytes> few = family(&rng, 3, 3, 0xAA);
    frames.insert(frames.end(), few.begin(), few.end());
    const Analysis a = run(fixtures::capture_of(frames));
    CHECK(a.type_count() == 1);
    CHECK(a.info().frames == 33);
    CHECK(a.info().ignored_frames == 3);
    CHECK(contains(bw::describe_analysis(a), "frames     33 (3 of a size too rare to say anything about)"));

    // Four of them are enough...
    frames.push_back(few[0]);
    const Analysis b = run(fixtures::capture_of(frames));
    CHECK(b.type_count() == 2);
    CHECK(b.info().ignored_frames == 0);
    // ...unless the limit is higher.
    AnalyzeOptions options;
    options.fields.min_frames = 5;
    const Analysis c = bw::analyze(fixtures::capture_of(frames), options);
    CHECK(c.type_count() == 1);
    CHECK(c.info().ignored_frames == 4);
}

TEST_CASE("analyze: the options reach the stages") {
    const Capture c = modbus(3, 50, 300).capture();
    AnalyzeOptions picky;
    picky.segmentation.min_gap_ratio = 100000;
    CHECK_FALSE(bw::analyze(c, picky).info().segmentation.found);
    AnalyzeOptions few;
    few.fields.min_frames = 51;
    const Analysis a = bw::analyze(c, few);
    CHECK(a.info().segmentation.found);
    CHECK(a.type_count() == 0);
    CHECK(a.info().ignored_frames == 50);
}

TEST_CASE("analyze: a checksum with bytes before it and after it covers the fields in between") {
    // [0x7E] [address 1..3] [4 random bytes] [CRC-16/MODBUS of address and the 4 bytes] [0x0D]
    fixtures::Random rng(45);
    std::vector<Bytes> frames;
    for (int i = 0; i < 40; ++i) {
        Bytes f;
        f.push_back(0x7E);
        f.push_back(static_cast<std::uint8_t>(1 + i % 3));
        for (int k = 0; k < 4; ++k) {
            f.push_back(rng.byte());
        }
        const std::uint16_t crc = fixtures::crc16_modbus(f, 1, f.size());
        f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
        f.push_back(static_cast<std::uint8_t>(crc >> 8));
        f.push_back(0x0D);
        frames.push_back(f);
    }
    const Analysis a = run(fixtures::capture_of(frames));
    REQUIRE(a.type_count() == 1);
    CHECK(a.type_report(0).checksum.found);
    CHECK(a.type_report(0).checksum.header_skip == 1);
    CHECK(a.type_report(0).checksum.trailer_skip == 1);

    const Model m = a.model();
    REQUIRE(m.field_count(0) == 5);
    CHECK(m.field(0, 0).kind == FieldKind::Constant);          // 0x7E, not covered
    CHECK(m.field(0, 1).kind == FieldKind::Enum);
    CHECK(m.field(0, 2).kind == FieldKind::Payload);
    CHECK(m.field(0, 2).bit_size == 32);
    CHECK(m.field(0, 3).kind == FieldKind::Checksum);
    CHECK(m.field(0, 3).covers_first == 1);
    CHECK(m.field(0, 3).covers_last == 2);
    CHECK(m.field(0, 4).kind == FieldKind::Constant);          // 0x0D, after it
    CHECK(m.field(0, 4).constant == 0x0D);
    CHECK(m.field_position(0, 3).bit_offset == 48);

    // The same, said as a truth that cuts the covered bytes differently.
    Model truth;
    const std::size_t t = truth.add_message_type("frame");
    bw::FieldInfo sync; sync.kind = FieldKind::Constant; sync.bit_size = 8; sync.constant = 0x7E;
    bw::FieldInfo addr; addr.kind = FieldKind::Enum; addr.bit_size = 8;
    bw::FieldInfo body; body.kind = FieldKind::Payload; body.bit_size = 16;
    bw::FieldInfo crc;  crc.kind = FieldKind::Checksum; crc.bit_size = 16;
    crc.byte_order = ByteOrder::Little; crc.covers_first = 1; crc.covers_last = 3;
    bw::FieldInfo tail; tail.kind = FieldKind::Constant; tail.bit_size = 8; tail.constant = 0x0D;
    truth.add_field(t, "sync", sync, "");
    truth.add_field(t, "address", addr, "");
    truth.add_field(t, "first", body, "");
    truth.add_field(t, "second", body, "");
    truth.add_field(t, "crc", crc, "CRC-16/MODBUS");
    truth.add_field(t, "end", tail, "");
    const bw::FieldScore score = bw::score_fields(truth, 0, m, 0);
    CHECK(score.checksum_match);
    CHECK(score.boundary_hits == 6);
}

TEST_CASE("analysis: what it holds is what it was built with, and a mismatch is refused") {
    const Analysis empty;
    CHECK(empty.type_count() == 0);
    CHECK_FALSE(empty.info().segmentation.found);
    CHECK_THROWS_AS(empty.type_report(0), std::out_of_range);

    Model m;
    m.add_message_type("one");
    CHECK_THROWS_AS(Analysis(bw::AnalysisInfo(), bw::Segmentation(), m, std::vector<bw::MessageTypeReport>()),
                    std::invalid_argument);
    CHECK_NOTHROW(Analysis(bw::AnalysisInfo(), bw::Segmentation(), m,
                           std::vector<bw::MessageTypeReport>(1)));
}

TEST_CASE("analyze: a counter is named with its step") {
    fixtures::Random rng(46);
    std::vector<Bytes> frames;
    for (int i = 0; i < 40; ++i) {
        Bytes f;
        f.push_back(0x01);
        f.push_back(static_cast<std::uint8_t>(i * 3));
        f.push_back(0x02);
        frames.push_back(f);
    }
    const Model m = run(fixtures::capture_of(frames)).model();
    REQUIRE(m.field_count(0) == 3);
    CHECK(m.field(0, 1).kind == FieldKind::Counter);
    CHECK(m.field_detail(0, 1) == "step 3");
    CHECK(m.field(0, 1).evidence_bits == 8 * 38);
    CHECK(contains(bw::describe_model(m), "counter   8 bits @8 evidence 304 bits step 3"));
}

TEST_CASE("analyze: it says what it knows of a checksum it could not settle") {
    // Nothing but zeros: more candidates than the search keeps.
    const Analysis zeros = run(fixtures::capture_of(std::vector<Bytes>(6, Bytes(8, 0))));
    CHECK(contains(bw::describe_analysis(zeros),
                   "frames; no checksum found: 64 or more candidates that cannot be told apart\n"));

    // One frame repeated: several explanations, or one on thin evidence.
    bool several = false;
    bool one     = false;
    for (std::uint64_t seed = 100; seed < 160 && !(several && one); ++seed) {
        fixtures::Random rng(seed);
        Bytes f;
        for (int k = 0; k < 8; ++k) {
            f.push_back(rng.byte());
        }
        const Analysis a = run(fixtures::capture_of(std::vector<Bytes>(5, f)));
        REQUIRE(a.type_count() == 1);
        const bw::ChecksumFinding c = a.type_report(0).checksum;
        const std::string text = bw::describe_analysis(a);
        if (c.candidates == 1) {
            one = true;
            CHECK(contains(text, "; no checksum found: one candidate, but on thin evidence (" +
                                 std::to_string(c.evidence_bits) + " bits)\n"));
        } else if (c.candidates > 1) {
            several = true;
            CHECK(contains(text, "; no checksum found: " + std::to_string(c.candidates) +
                                 " candidates that cannot be told apart\n"));
        }
    }
    CHECK(several);
    CHECK(one);
}

namespace {

// A segmentation that is the true frames of a dataset: stage 3 taken out, to measure the others on their own.
bw::Segmentation true_frames(const bw::Dataset& d) {
    bw::SegmentationInfo info;
    info.found = true;
    return bw::Segmentation(info, d.frames());
}

// The message type of the truth that has frames of this many bytes, which for these protocols is only one.
std::size_t truth_type_of_size(const Model& truth, std::uint32_t bytes) {
    for (std::size_t t = 0; t < truth.message_type_count(); ++t) {
        const std::size_t last = truth.field_count(t) - 1;
        if ((truth.field_position(t, last).bit_offset + truth.field(t, last).bit_size) / 8 == bytes) {
            return t;
        }
    }
    FAIL("no message type of " << bytes << " bytes");
    return 0;
}

} // namespace

TEST_CASE("analyze_frames: the frames are taken as they are, and nothing is looked for") {
    const bw::Dataset d = modbus(2, 60, 300);
    const Analysis    a = bw::analyze_frames(d.capture(), true_frames(d), AnalyzeOptions());
    const Analysis    b = run(d.capture());                          // the same frames, found by their gaps
    CHECK(a.info().frames == 60);
    CHECK(a.info().segmentation.found);
    REQUIRE(a.type_count() == 1);
    CHECK(a.model().framing().kind == bw::FramingKind::Unknown);     // what cut them is not known
    CHECK(b.model().framing().kind == bw::FramingKind::IdleGap);
    // Everything but that is the same.
    const std::string with_gap    = bw::describe_model(b.model());
    const std::string without_gap = bw::describe_model(a.model());
    CHECK(with_gap.substr(with_gap.find('\n')) == without_gap.substr(without_gap.find('\n')));
    CHECK(contains(bw::describe_analysis(a), "framing    not looked for: the frames were given\n"));

    // A segmentation that found nothing is not analysed, and the count of its events is still told.
    const Analysis none = bw::analyze_frames(d.capture(), bw::Segmentation(), AnalyzeOptions());
    CHECK(none.type_count() == 0);
    CHECK(none.info().events == d.capture().event_count());
    CHECK_FALSE(none.info().segmentation.found);
}

TEST_CASE("wave 1 baseline: with the true frames, what the stages find in UBX and MAVLink 1") {
    // Where wave 1 starts: stage 3 finds no frames in these (the test of the protocols checks that),
    // and given the true ones, stage 2 finds Fletcher-8 in two of the three types of UBX, and no
    // checksum in MAVLink, which is a CRC with a hidden seed byte that the catalogue does not have;
    // the third type of UBX, the acknowledgement, has three different frames in 60, which Fletcher-8
    // and Fletcher-16 (the same sums, modulo 255) explain alike, so there it says it cannot tell.
    // Stage 4 finds every boundary there is, and some more, because a number of two bytes with a high
    // byte that never changes is two fields to it; and stage 5 types what it can see. The numbers are
    // those of 200 frames of seed 3, and each step of wave 1 that improves one of them changes this
    // table in the same pull request.
    struct Row {
        const char*   protocol;
        const char*   type;
        unsigned      truth_fields, found_fields, truth_boundaries, found_boundaries, hits, exact, kinds;
        unsigned      candidates;   // that stage 2 could not tell apart, or the one that it found
        bool          checksum;     // found
    };
    const Row rows[] = {
        { "ubx",      "ack_ack",    8,  10, 9,  11, 9,  6,  5, 2, false },
        { "ubx",      "cfg_rate",   9,  13, 10, 14, 10, 5,  5, 1, true },
        { "ubx",      "nav_status", 13, 21, 14, 22, 14, 9,  6, 1, true },
        { "mavlink1", "heartbeat",  13, 16, 14, 17, 14, 12, 8, 0, false },
        { "mavlink1", "sys_status", 20, 37, 21, 38, 20, 6,  4, 0, false },
        { "mavlink1", "attitude",   14, 23, 15, 24, 15, 7,  4, 0, false },
    };
    const char* protocols[2] = { "ubx", "mavlink1" };
    std::size_t checked = 0;
    for (int p = 0; p < 2; ++p) {
        const bw::Dataset d = [&] {
            bw::GenerateOptions o;
            o.seed   = 3;
            o.frames = 200;
            return bw::generate_protocol(protocols[p], o);
        }();
        const Analysis a = bw::analyze_frames(d.capture(), true_frames(d), AnalyzeOptions());
        REQUIRE(a.type_count() == 3);
        for (std::size_t ft = 0; ft < a.type_count(); ++ft) {
            const std::size_t tt = truth_type_of_size(d.model(), a.type_report(ft).frame_bytes);
            const std::string type = d.model().message_type_name(tt);
            CAPTURE(protocols[p]);
            CAPTURE(type);
            const bw::FieldScore s = bw::score_fields(d.model(), tt, a.model(), ft);
            for (std::size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); ++r) {
                if (std::string(rows[r].protocol) == protocols[p] && type == rows[r].type) {
                    ++checked;
                    CHECK(s.truth_fields == rows[r].truth_fields);
                    CHECK(s.found_fields == rows[r].found_fields);
                    CHECK(s.truth_boundaries == rows[r].truth_boundaries);
                    CHECK(s.found_boundaries == rows[r].found_boundaries);
                    CHECK(s.boundary_hits == rows[r].hits);
                    CHECK(s.exact_fields == rows[r].exact);
                    CHECK(s.kind_hits == rows[r].kinds);
                    CHECK(a.type_report(ft).checksum.found == rows[r].checksum);
                    CHECK(a.type_report(ft).checksum.candidates == rows[r].candidates);
                    CHECK(s.found_has_checksum == rows[r].checksum);
                    CHECK(s.checksum_match == rows[r].checksum);
                }
            }
        }
    }
    CHECK(checked == 6);
}
