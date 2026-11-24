// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 3, segmentation by lines of text: the sentences of NMEA 0183, which end with a line
// feed, and the carriage return before it. The cases are written so that each rule has one that
// fails if the rule is broken: the 95% of the bytes that are text, and each byte at the edge of
// what counts as text; the lines that are nothing; the bytes after the last line feed; the fewest
// frames; the few bytes a line starts with; then the frames of the NMEA generator, found exactly,
// the protocols that are not taken for text, and how the pipeline orders lines against gaps.

#include "doctest.h"

#include <cstdint>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/evaluate.h"
#include "bw/protocol.h"
#include "bw/segmentation.h"

using bw::Capture;
using bw::Dataset;
using bw::EventInfo;
using bw::FrameSpan;
using bw::Segmentation;
using bw::SegmentationOptions;

namespace {

typedef std::vector<std::uint8_t> Bytes;

Bytes bytes_of(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

Capture capture_of(const Bytes& bytes) {
    Capture c;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        c.add_event(EventInfo(), Bytes(1, bytes[i]));
    }
    return c;
}

Segmentation by_lines(const Bytes& bytes, std::uint32_t min_frames = 8) {
    SegmentationOptions options;
    options.min_line_frames = min_frames;
    return bw::segment_by_lines(capture_of(bytes), options);
}

FrameSpan span(std::uint64_t first, std::uint64_t count) {
    FrameSpan s;
    s.first_event = first;
    s.event_count = count;
    return s;
}

bool same_frames(const Segmentation& s, const std::vector<FrameSpan>& expected) {
    if (s.frame_count() != expected.size()) {
        return false;
    }
    for (std::size_t i = 0; i < expected.size(); ++i) {
        if (s.frame(i).first_event != expected[i].first_event || s.frame(i).event_count != expected[i].event_count) {
            return false;
        }
    }
    return true;
}

// Lines, and where they are: "$AB,<digit>,<letter>\r\n", nine bytes each.
struct Lines {
    Bytes                  bytes;
    std::vector<FrameSpan> frames;
};

Lines make_lines(std::size_t n, const char* ending = "\r\n", char first = '$') {
    Lines l;
    for (std::size_t i = 0; i < n; ++i) {
        std::string line(1, first);
        line += "AB,";
        line += static_cast<char>('0' + i % 10);
        line += ",";
        line += static_cast<char>('a' + i % 20);
        line += ending;
        const std::uint64_t at = l.bytes.size();
        const Bytes b = bytes_of(line);
        l.bytes.insert(l.bytes.end(), b.begin(), b.end());
        l.frames.push_back(span(at, b.size()));
    }
    return l;
}

Dataset make(const char* name, std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    bw::GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol(name, o);
}

} // namespace

TEST_CASE("lines: text that ends its frames with a line feed is cut there, the carriage return with it") {
    const Lines l = make_lines(20);
    const Segmentation s = by_lines(l.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().kind == bw::FramingKind::Terminated);
    CHECK(s.info().delimiter == 0x0A);
    CHECK(s.info().flags == 20);
    CHECK(s.info().idle_gap_ns == 0);
    CHECK(same_frames(s, l.frames));
    CHECK(s.frame(0).event_count == 9);                      // $AB,0,a and the carriage return and line feed

    // With the line feed alone, the same.
    const Lines bare = make_lines(20, "\n");
    CHECK(same_frames(by_lines(bare.bytes), bare.frames));
}

TEST_CASE("lines: the fewest lines is an option, and exact") {
    const Lines l = make_lines(8);
    CHECK(by_lines(l.bytes, 8).info().found);
    CHECK_FALSE(by_lines(l.bytes, 9).info().found);
    CHECK(by_lines(l.bytes, 1).info().found);
    CHECK(by_lines(l.bytes, 0).info().found);
    CHECK_FALSE(by_lines(make_lines(7).bytes, 8).info().found);
    CHECK(by_lines(make_lines(7).bytes, 7).info().found);
    // No lines at all, whatever is asked for.
    CHECK_FALSE(by_lines(bytes_of("nothing here to end a line"), 0).info().found);
    CHECK_FALSE(by_lines(Bytes(), 0).info().found);
    CHECK_FALSE(by_lines(bytes_of("\n\n\n\n\n\n\n\n\n\n"), 0).info().found);
    CHECK_FALSE(bw::segment_by_lines(Capture(), SegmentationOptions()).info().found);
}

TEST_CASE("lines: 95% of the bytes have to be text, and these are") {
    // 20 lines of 9 bytes are 180 bytes: nine of them may not be text, and ten may not. Bytes of one kind put into
    // the lines at places that are not their first byte or their end.
    struct Kind { std::uint8_t byte; bool text; };
    const Kind kinds[] = { { 0x1F, false }, { 0x20, true }, { 0x7E, true }, { 0x7F, false }, { 0x09, true },
                           { 0x0D, true }, { 0x00, false }, { 0x80, false }, { 0xFF, false } };
    for (std::size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); ++k) {
        for (std::size_t bad = 9; bad <= 10; ++bad) {
            Lines l = make_lines(20);
            std::size_t put = 0;
            for (std::size_t i = 0; i < l.frames.size() && put < bad; ++i) {
                l.bytes[l.frames[i].first_event + 2 + (put % 2)] = kinds[k].byte;
                ++put;
                if (put < bad && i % 2 == 0) {
                    l.bytes[l.frames[i].first_event + 6] = kinds[k].byte;
                    ++put;
                }
            }
            REQUIRE(put == bad);
            CAPTURE(static_cast<unsigned>(kinds[k].byte));
            CAPTURE(bad);
            // Nine bytes of 180 are 5%, and ten are more; a byte that is text is never any.
            CHECK(by_lines(l.bytes).info().found == (kinds[k].text || bad == 9));
        }
    }
}

TEST_CASE("lines: a line of nothing is not a frame, and bytes with no line feed after them are in none") {
    // Blank lines, with and without the carriage return, between 12 lines.
    Lines l;
    std::vector<FrameSpan> expected;
    const Lines base = make_lines(12);
    for (std::size_t i = 0; i < base.frames.size(); ++i) {
        const Bytes line(base.bytes.begin() + base.frames[i].first_event,
                         base.bytes.begin() + base.frames[i].first_event + base.frames[i].event_count);
        expected.push_back(span(l.bytes.size(), line.size()));
        l.bytes.insert(l.bytes.end(), line.begin(), line.end());
        if (i % 3 == 0) {
            l.bytes.push_back(0x0A);
        } else if (i % 3 == 1) {
            l.bytes.push_back(0x0D);
            l.bytes.push_back(0x0A);
        }
    }
    CHECK(same_frames(by_lines(l.bytes), expected));
    CHECK(by_lines(l.bytes).info().flags == 12 + 4 + 4);               // the line feeds of lines and of blank lines

    // A line of one byte is a line: it is only the empty one that is not. Among twenty lines, so that one that is
    // far shorter than the others is not more than the 5% that may be.
    {
        const Lines twenty = make_lines(20);
        Bytes with;
        std::vector<FrameSpan> want;
        for (std::size_t i = 0; i < twenty.frames.size(); ++i) {
            want.push_back(span(with.size(), twenty.frames[i].event_count));
            with.insert(with.end(), twenty.bytes.begin() + twenty.frames[i].first_event,
                        twenty.bytes.begin() + twenty.frames[i].first_event + twenty.frames[i].event_count);
            if (i == 5) {
                want.push_back(span(with.size(), 2));
                with.push_back('$');                                   // the same first byte as the others
                with.push_back(0x0A);
            }
        }
        CHECK(same_frames(by_lines(with), want));
    }

    // The start of a line that is cut and the end of one that is: the first is a frame of its own; the last is none.
    Bytes cut = bytes_of("B,3,z\r\n");
    cut.insert(cut.end(), base.bytes.begin(), base.bytes.end());
    const Bytes tail = bytes_of("$AB,7,");
    cut.insert(cut.end(), tail.begin(), tail.end());
    const Segmentation s = by_lines(cut);
    REQUIRE(s.info().found);
    CHECK(s.frame_count() == 13);
    CHECK(s.frame(0).first_event == 0);
    CHECK(s.frame(0).event_count == 7);
    CHECK(s.frame(12).first_event + s.frame(12).event_count == 7 + base.bytes.size());
}

TEST_CASE("lines: they start with a few bytes, and are about the same size, as the frames of a protocol do") {
    // Free text: a line that starts with whatever comes to mind is no frame of a protocol.
    Bytes free_text;
    const char* words[12] = { "alpha", "bravo", "charlie", "delta", "echo", "foxtrot", "golf", "hotel", "india", "juliet", "kilo", "lima" };
    for (int i = 0; i < 12; ++i) {
        const Bytes b = bytes_of(std::string(words[i]) + " and the rest of it\n");
        free_text.insert(free_text.end(), b.begin(), b.end());
    }
    CHECK_FALSE(by_lines(free_text).info().found);

    // Lines that start with one of four bytes are frames, and with five are not: 20 lines cycling through them.
    for (std::size_t values = 3; values <= 6; ++values) {
        Bytes bytes;
        for (std::size_t i = 0; i < 20; ++i) {
            const Bytes b = bytes_of(std::string(1, static_cast<char>('A' + i % values)) + "B,1,x\r\n");
            bytes.insert(bytes.end(), b.begin(), b.end());
        }
        CAPTURE(values);
        CHECK(by_lines(bytes).info().found == (values <= 4));
    }
    // And of sizes within a factor of four of the median, nearly always: 20 lines, two of them far longer.
    for (std::size_t long_lines = 1; long_lines <= 2; ++long_lines) {
        Bytes bytes;
        for (std::size_t i = 0; i < 20; ++i) {
            std::string line = "$AB,1,x";
            if (i < long_lines) {
                line += std::string(80, 'y');
            }
            const Bytes b = bytes_of(line + "\r\n");
            bytes.insert(bytes.end(), b.begin(), b.end());
        }
        CAPTURE(long_lines);
        CHECK(by_lines(bytes).info().found == (long_lines == 1));
    }
}

TEST_CASE("lines: the sentences of NMEA 0183 are found exactly") {
    for (std::uint64_t seed = 1; seed <= 4; ++seed) {
        for (unsigned jitter = 0; jitter <= 300; jitter += 300) {
            const Dataset d = make("nmea0183", seed, 200, jitter);
            const Segmentation s = bw::segment_by_lines(d.capture(), SegmentationOptions());
            INFO("seed " << seed << " jitter " << jitter);
            REQUIRE(s.info().found);
            CHECK(s.info().kind == bw::FramingKind::Terminated);
            CHECK(s.info().delimiter == 0x0A);
            CHECK(s.info().flags == 200);
            const bw::SegmentationScore score = bw::score_segmentation(d.frames(), s.frames());
            CHECK(score.exact_frames == 200);
            CHECK(score.found_frames == 200);
            CHECK(score.boundary_hits == score.truth_boundaries);
        }
    }
}

TEST_CASE("lines: no protocol of the corpus that is not text, and no noise, is taken for text in lines") {
    const char* names[6] = { "slip", "hdlc-ppp", "ubx", "mavlink1", "mavlink2", "modbus-rtu" };
    for (int n = 0; n < 6; ++n) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            const Dataset d = make(names[n], seed, 200, seed % 2 ? 0 : 300);
            INFO(names[n] << " seed " << seed);
            CHECK_FALSE(bw::segment_by_lines(d.capture(), SegmentationOptions()).info().found);
        }
    }
    Bytes noise;
    std::uint64_t x = 88172645463325252ULL;
    for (int i = 0; i < 8000; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        noise.push_back(static_cast<std::uint8_t>(x >> 24));
    }
    CHECK_FALSE(by_lines(noise).info().found);
    // Events of more than one byte are not a stream of bytes.
    const Lines l = make_lines(20);
    Capture two;
    for (std::size_t i = 0; i < l.bytes.size(); ++i) {
        two.add_event(EventInfo(), i == 7 ? Bytes(2, l.bytes[i]) : Bytes(1, l.bytes[i]));
    }
    CHECK_FALSE(bw::segment_by_lines(two, SegmentationOptions()).info().found);
}

TEST_CASE("lines: the pipeline cuts text into lines, where there are gaps too, and says so") {
    // NMEA at the pace of its line, with a second of silence after three sentences: the gaps find the seconds,
    // the lines the sentences, which cut at every place the gaps do and in more.
    const Dataset d = make("nmea0183", 3, 90);
    const Segmentation gaps = bw::segment_by_gaps(d.capture(), SegmentationOptions());
    REQUIRE(gaps.info().found);
    CHECK(gaps.frame_count() == 30);
    const Segmentation chosen = bw::segment_frames(d.capture(), SegmentationOptions());
    REQUIRE(chosen.info().found);
    CHECK(chosen.info().kind == bw::FramingKind::Terminated);
    CHECK(same_frames(chosen, d.frames()));

    const bw::Analysis a = bw::analyze(d.capture(), bw::AnalyzeOptions());
    CHECK(a.model().framing().kind == bw::FramingKind::Terminated);
    CHECK(a.model().framing().delimiter == 0x0A);
    CHECK(a.info().frames == 90);
    CHECK(bw::describe_analysis(a).find("framing    lines: each frame ends with the byte 0x0A (90 of them in the capture)\n") != std::string::npos);
    CHECK(bw::describe_model(a.model()).find("framing: ends with 0xA\n") != std::string::npos);

    // What the stages make of the sentences found is what they make of the true ones: the three kinds of sentence,
    // and not the many sizes that the widths of the fields give them.
    bw::SegmentationInfo info;
    info.found = true;
    const bw::Analysis given = bw::analyze_frames(d.capture(), bw::Segmentation(info, d.frames()), bw::AnalyzeOptions());
    const std::string found_model = bw::describe_model(a.model());
    const std::string given_model = bw::describe_model(given.model());
    REQUIRE(given_model.find("message type 0") != std::string::npos);
    CHECK(found_model.substr(found_model.find("message type 0")) == given_model.substr(given_model.find("message type 0")));
    CHECK(a.type_count() == given.type_count());
    CHECK(a.type_count() == 3);

    // Binary frames keep what they had: a sync byte and a length, when the capture is not text.
    CHECK(bw::segment_frames(make("ubx", 1, 90).capture(), SegmentationOptions()).info().kind == bw::FramingKind::Contiguous);
    CHECK(bw::segment_frames(make("modbus-rtu", 1, 50, 300).capture(), SegmentationOptions()).info().kind == bw::FramingKind::IdleGap);
}

namespace {

// The capture of `d` with the line feed that ends each of the given frames changed to a space.
Capture with_wrong_feeds(const Dataset& d, const std::vector<std::size_t>& frames) {
    std::vector<std::uint64_t> at;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        at.push_back(d.frame(frames[i]).first_event + d.frame(frames[i]).event_count - 1);
    }
    const Capture original = d.capture();
    Capture       out;
    for (std::uint32_t c = 1; c < original.channel_count(); ++c) {
        out.add_channel(original.channel_name(c));
    }
    for (std::size_t i = 0; i < original.event_count(); ++i) {
        bool wrong = false;
        for (std::size_t k = 0; k < at.size(); ++k) {
            wrong = wrong || at[k] == i;
        }
        out.add_event(original.event(i), wrong ? Bytes(1, 0x20) : original.event_bytes(i));
    }
    return out;
}

} // namespace

TEST_CASE("lines: line feeds that arrive wrong do not make the gaps the better evidence, until they are a tenth of the cuts") {
    // 93 sentences, three to the second: 31 bursts, and 60 places inside the capture where the gaps cut. A line feed that is
    // wrong at the end of a burst joins the sentence to the next, and loses two of them (where it ends and where the next starts).
    const Dataset d = make("nmea0183", 3, 93);
    std::vector<std::size_t> ends;
    for (std::size_t f = 5; ends.size() < 4; f += 3) {
        ends.push_back(f);
    }
    for (std::size_t wrong = 0; wrong <= 4; ++wrong) {
        const Capture noisy = with_wrong_feeds(d, std::vector<std::size_t>(ends.begin(), ends.begin() + static_cast<std::ptrdiff_t>(wrong)));
        const Segmentation chosen = bw::segment_frames(noisy, SegmentationOptions());
        INFO("wrong " << wrong);
        REQUIRE(chosen.info().found);
        if (wrong <= 3) {
            // Up to six of the sixty places: a tenth, which is allowed.
            CHECK(chosen.info().kind == bw::FramingKind::Terminated);
            CHECK(chosen.frame_count() == 93 - wrong);
        } else {
            // Eight of them are not: the silences, which cut the bursts, are what is believed.
            CHECK(chosen.info().kind != bw::FramingKind::Terminated);
            CHECK(chosen.frame_count() == 31);
        }
    }
}

TEST_CASE("lines: frames given as lines are described as such") {
    const Lines l = make_lines(20);
    bw::SegmentationInfo info;
    info.found     = true;
    info.kind      = bw::FramingKind::Terminated;
    info.delimiter = 0x0A;
    info.flags     = 20;
    const bw::Analysis a = bw::analyze_frames(capture_of(l.bytes), Segmentation(info, l.frames), bw::AnalyzeOptions());
    CHECK(a.model().framing().kind == bw::FramingKind::Terminated);
    CHECK(a.model().framing().delimiter == 0x0A);
    CHECK(bw::describe_analysis(a).find("framing    lines: each frame ends with the byte 0x0A (20 of them in the capture)\n") != std::string::npos);
}
