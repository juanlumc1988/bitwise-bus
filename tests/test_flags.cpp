// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 3, segmentation by flags: the frames of SLIP and of HDLC, which are bounded on
// both sides by a byte that cannot occur inside them. The cases are written so that each
// rule has one that fails if the rule is broken: a quarter of the flags followed by
// another one, the fewest frames, the four values a frame may start with and the 95% of
// frames they have to cover, the factor of four in size and its 95%, the tie between two
// flags, a flag that two frames share, an event of more than one byte; then the frames of
// the two generators, found exactly, and the other protocols, which are not taken for them.

#include "doctest.h"

#include <cstdint>
#include <set>
#include <string>
#include <utility>
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

Capture capture_of(const Bytes& bytes, bool timed = false) {
    Capture c;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        EventInfo info;
        info.has_time = timed;
        info.time_ns  = timed ? static_cast<std::int64_t>(1000 * i) : 0;
        c.add_event(info, Bytes(1, bytes[i]));
    }
    return c;
}

Segmentation by_flags(const Bytes& bytes, std::uint32_t min_frames = 8) {
    SegmentationOptions options;
    options.min_flag_frames = min_frames;
    return bw::segment_by_flags(capture_of(bytes), options);
}

FrameSpan span(std::uint64_t first, std::uint64_t count) {
    FrameSpan s;
    s.first_event = first;
    s.event_count = count;
    return s;
}

// A stream of frames bounded by `flag`, each with the given content, and where the frames and the
// flags are, as they were built. Between two frames there are two flags if `doubled` says so (the
// close of one and the open of the next) and one if not (a flag that they share, which belongs to
// the first).
struct Built {
    Bytes                  bytes;
    std::vector<FrameSpan> frames;
};

Built build(const std::vector<Bytes>& contents, const std::vector<bool>& doubled, std::uint8_t flag = 0xC0) {
    Built b;
    bool  own_open = true;
    for (std::size_t i = 0; i < contents.size(); ++i) {
        const std::uint64_t first = b.bytes.size();
        if (own_open) {
            b.bytes.push_back(flag);
        }
        b.bytes.insert(b.bytes.end(), contents[i].begin(), contents[i].end());
        b.bytes.push_back(flag);
        b.frames.push_back(span(first, b.bytes.size() - first));
        own_open = (i + 1 < contents.size()) ? doubled[i] : true;
    }
    return b;
}

// Content of `size` bytes that start with `start` and never hold a flag.
Bytes content_of(std::size_t i, std::size_t size, std::uint8_t start = 0x10) {
    Bytes c(1, start);
    for (std::size_t k = 1; k < size; ++k) {
        c.push_back(static_cast<std::uint8_t>(0x20 + (i * 7 + k * 13) % 0x40));
    }
    return c;
}

std::vector<Bytes> contents(std::size_t n, std::size_t size = 4) {
    std::vector<Bytes> out;
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(content_of(i, size));
    }
    return out;
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

Dataset make(const char* name, std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    bw::GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol(name, o);
}

} // namespace

TEST_CASE("flags: frames that are bounded on both sides are found, from flag to flag") {
    const Built b = build(contents(12), std::vector<bool>(11, true));
    const Segmentation s = by_flags(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().kind == bw::FramingKind::Flagged);
    CHECK(s.info().delimiter == 0xC0);
    CHECK(s.info().flags == 24);
    CHECK(s.info().idle_gap_ns == 0);
    CHECK(same_frames(s, b.frames));
    CHECK(s.frame(0).event_count == 6);                     // the flags, and the four bytes between them

    // The same with another flag, and with the bytes at times: timing plays no part.
    const Built other = build(contents(12), std::vector<bool>(11, true), 0x7E);
    CHECK(by_flags(other.bytes).info().delimiter == 0x7E);
    SegmentationOptions options;
    const Segmentation timed = bw::segment_by_flags(capture_of(b.bytes, true), options);
    CHECK(same_frames(timed, b.frames));
}

TEST_CASE("flags: a flag has to be followed by itself in a quarter of its occurrences, exactly") {
    // F frames with d of the F - 1 boundaries doubled: the flags are F + 1 + d, and d of them are followed by another.
    // 4d >= F + 1 + d, so with 11 frames four is enough and three is not.
    for (std::size_t d = 2; d <= 5; ++d) {
        std::vector<bool> doubled(10, false);
        for (std::size_t k = 0; k < d; ++k) {
            doubled[2 * k] = true;
        }
        const Built b = build(contents(11), doubled);
        const Segmentation s = by_flags(b.bytes);
        CAPTURE(d);
        CHECK(s.info().found == (d >= 4));
        if (d >= 4) {
            CHECK(same_frames(s, b.frames));
        }
    }
}

TEST_CASE("flags: a flag that two frames share belongs to the first, and the second starts after it") {
    // Four frames, three boundaries: doubled, shared, doubled.
    std::vector<bool> doubled(3);
    doubled[0] = true;
    doubled[1] = false;
    doubled[2] = true;
    const Built b = build(contents(4), doubled);
    const Segmentation s = by_flags(b.bytes, 4);
    REQUIRE(s.info().found);
    CHECK(same_frames(s, b.frames));
    CHECK(s.frame(0).event_count == 6);
    CHECK(s.frame(1).event_count == 6);
    CHECK(s.frame(2).event_count == 5);                     // without its opening flag
    CHECK(s.frame(3).event_count == 6);
}

TEST_CASE("flags: the fewest frames a flag has to bound is an option, and exact") {
    const Built b = build(contents(8), std::vector<bool>(7, true));
    CHECK(by_flags(b.bytes, 8).info().found);
    CHECK_FALSE(by_flags(b.bytes, 9).info().found);
    CHECK(by_flags(b.bytes, 1).info().found);
    const Built fewer = build(contents(7), std::vector<bool>(6, true));
    CHECK_FALSE(by_flags(fewer.bytes, 8).info().found);
    CHECK(by_flags(fewer.bytes, 7).info().found);
}

TEST_CASE("flags: at most four values start the frames, and 95% of them have to start with one") {
    // 20 frames: the first byte after the flag cycles through the values given.
    const std::vector<bool> doubled(19, true);
    for (std::size_t values = 3; values <= 6; ++values) {
        std::vector<Bytes> c;
        for (std::size_t i = 0; i < 20; ++i) {
            c.push_back(content_of(i, 4, static_cast<std::uint8_t>(0x10 + i % values)));
        }
        CAPTURE(values);
        CHECK(by_flags(build(c, doubled).bytes).info().found == (values <= 4));
    }
    // One frame in twenty may start with a fifth value, two may not.
    for (std::size_t odd = 0; odd <= 3; ++odd) {
        std::vector<Bytes> c;
        for (std::size_t i = 0; i < 20; ++i) {
            c.push_back(content_of(i, 4, static_cast<std::uint8_t>(i < odd ? 0x30 + i : 0x10 + i % 4)));
        }
        CAPTURE(odd);
        CHECK(by_flags(build(c, doubled).bytes).info().found == (odd <= 1));
    }
}

TEST_CASE("flags: the 95% is exact, in both rules") {
    // 34 frames with two odd ones are 94.1% and do not make it; 40 frames with two are 95% and do; with three, 92.5%.
    const std::size_t frames[3] = { 34, 40, 40 };
    const std::size_t odd[3]    = { 2, 2, 3 };
    for (int k = 0; k < 3; ++k) {
        const std::vector<bool> doubled(frames[k] - 1, true);
        std::vector<Bytes> starts, sizes;
        for (std::size_t i = 0; i < frames[k]; ++i) {
            starts.push_back(content_of(i, 4, static_cast<std::uint8_t>(i < odd[k] ? 0x30 + i : 0x10 + i % 4)));
            sizes.push_back(content_of(i, i < odd[k] ? 100 : 14));                // 102 bytes against a median of 16
        }
        CAPTURE(frames[k]);
        CAPTURE(odd[k]);
        const bool expected = frames[k] == 40 && odd[k] == 2;
        CHECK(by_flags(build(starts, doubled).bytes).info().found == expected);
        CHECK(by_flags(build(sizes, doubled).bytes).info().found == expected);
    }
}

TEST_CASE("flags: 95% of the frames have to be within a factor of four of the median size, at the edges") {
    const std::vector<bool> doubled(19, true);
    // The median frame is 16 bytes with its flags (14 between them). Four times that is 64, and a quarter is 4.
    struct Edge { std::size_t size; bool outlier; };
    const Edge edges[] = { { 64, false }, { 65, true }, { 4, false }, { 3, true } };
    for (std::size_t e = 0; e < 4; ++e) {
        for (std::size_t odd = 1; odd <= 2; ++odd) {
            std::vector<Bytes> c;
            for (std::size_t i = 0; i < 20; ++i) {
                c.push_back(content_of(i, i < odd ? edges[e].size - 2 : 14));
            }
            CAPTURE(edges[e].size);
            CAPTURE(odd);
            // One frame in twenty may be an outlier, two may not.
            const bool expected = !edges[e].outlier || odd == 1;
            CHECK(by_flags(build(c, doubled).bytes).info().found == expected);
        }
    }
}

TEST_CASE("flags: two flags that bound frames, the one with more wins and the lower byte takes a tie") {
    // 10 frames bounded by 0xC0 and then some bounded by 0x7E.
    const std::vector<bool> doubled(9, true);
    const Built first = build(contents(10), doubled, 0xC0);
    for (std::size_t second_frames = 9; second_frames <= 11; ++second_frames) {
        const Built second = build(contents(second_frames), std::vector<bool>(second_frames - 1, true), 0x7E);
        Bytes both = first.bytes;
        both.insert(both.end(), second.bytes.begin(), second.bytes.end());
        const Segmentation s = by_flags(both);
        CAPTURE(second_frames);
        REQUIRE(s.info().found);
        // 9 frames against 10: the 0xC0 ones. 10 against 10, the lower byte, 0x7E. 11 against 10: 0x7E.
        CHECK(s.info().delimiter == (second_frames == 9 ? 0xC0 : 0x7E));
        CHECK(s.frame_count() == (second_frames == 9 ? 10u : second_frames));
    }
}

TEST_CASE("flags: it is for captures of single bytes, and it says nothing was found when it is not") {
    const Built b = build(contents(12), std::vector<bool>(11, true));
    REQUIRE(by_flags(b.bytes).info().found);

    // An event of two bytes, and an event of none.
    Capture two;
    for (std::size_t i = 0; i < b.bytes.size(); ++i) {
        two.add_event(EventInfo(), i == 5 ? Bytes(2, b.bytes[i]) : Bytes(1, b.bytes[i]));
    }
    CHECK_FALSE(bw::segment_by_flags(two, SegmentationOptions()).info().found);
    Capture empty_event;
    for (std::size_t i = 0; i < b.bytes.size(); ++i) {
        empty_event.add_event(EventInfo(), i == 5 ? Bytes() : Bytes(1, b.bytes[i]));
    }
    CHECK_FALSE(bw::segment_by_flags(empty_event, SegmentationOptions()).info().found);

    CHECK_FALSE(bw::segment_by_flags(Capture(), SegmentationOptions()).info().found);
    CHECK(bw::segment_by_flags(Capture(), SegmentationOptions()).frame_count() == 0);
    // Nothing but a flag, over and over: there is nothing between them, whatever the fewest frames asked for.
    CHECK_FALSE(by_flags(Bytes(200, 0xC0)).info().found);
    CHECK_FALSE(by_flags(Bytes(200, 0xC0), 0).info().found);
    CHECK_FALSE(by_flags(Bytes(), 0).info().found);
    CHECK(by_flags(b.bytes, 0).info().found);
    // Flags that are not followed by themselves, and so are not told from a terminator: not here.
    CHECK_FALSE(by_flags(build(contents(40), std::vector<bool>(39, false)).bytes).info().found);
}

TEST_CASE("flags: when the capture has flags and gaps, the flags decide: they are the finer cut") {
    // Twelve frames, with a long silence before every third one: the gaps find four bursts of three frames,
    // and the flags the twelve.
    const Built b = build(contents(12), std::vector<bool>(11, true));
    Capture c;
    std::int64_t t = 0;
    std::size_t  next_frame = 0;
    for (std::size_t i = 0; i < b.bytes.size(); ++i) {
        if (next_frame < b.frames.size() && b.frames[next_frame].first_event == i) {
            t += (next_frame % 3 == 0 && next_frame > 0) ? 1000000 : 1000;
            ++next_frame;
        } else {
            t += 1000;
        }
        EventInfo info;
        info.has_time = true;
        info.time_ns  = t;
        c.add_event(info, Bytes(1, b.bytes[i]));
    }
    const Segmentation gaps = bw::segment_by_gaps(c, SegmentationOptions());
    REQUIRE(gaps.info().found);
    CHECK(gaps.frame_count() == 4);
    const Segmentation chosen = bw::segment_frames(c, SegmentationOptions());
    REQUIRE(chosen.info().found);
    CHECK(chosen.info().kind == bw::FramingKind::Flagged);
    CHECK(same_frames(chosen, b.frames));
}

TEST_CASE("flags: the stuffing of SLIP and of HDLC is found, as the capture shows it") {
    struct Expect { const char* name; std::uint8_t flag, escape, flag_code, escape_code; };
    const Expect expects[2] = { { "slip", 0xC0, 0xDB, 0xDC, 0xDD }, { "hdlc-ppp", 0x7E, 0x7D, 0x5E, 0x5D } };
    for (int n = 0; n < 2; ++n) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            const Segmentation s = bw::segment_by_flags(make(expects[n].name, seed, 200, seed % 2 ? 0 : 300).capture(),
                                                        SegmentationOptions());
            INFO(expects[n].name << " seed " << seed);
            REQUIRE(s.info().found);
            CHECK(s.info().escaped);
            CHECK(s.info().escape == expects[n].escape);
            CHECK(s.info().delimiter_code == expects[n].flag_code);
            CHECK(s.info().escape_code == expects[n].escape_code);
        }
    }
    // Frames with nothing to stuff in them have none to show.
    const Segmentation plain = by_flags(build(contents(12), std::vector<bool>(11, true)).bytes);
    REQUIRE(plain.info().found);
    CHECK_FALSE(plain.info().escaped);
    CHECK(plain.info().escape == 0);
    CHECK(plain.info().delimiter_code == 0);
    CHECK(plain.info().escape_code == 0);
}

// The content of every frame between its two flags, joined with one flag between frames: the usual HDLC.
Bytes shared_flags(const Dataset& d, std::uint8_t flag, std::vector<FrameSpan>* frames) {
    Bytes out(1, flag);
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes wire = bw::frame_bytes(d.capture(), d.frame(i));
        const std::uint64_t first = frames->empty() ? 0 : out.size();
        out.insert(out.end(), wire.begin() + 1, wire.end());           // the content and the closing flag
        frames->push_back(span(first, out.size() - first));
    }
    return out;
}

TEST_CASE("flags: a flag that two frames share is a flag when the capture shows its stuffing") {
    const char*   names[2] = { "slip", "hdlc-ppp" };
    const uint8_t flags[2] = { 0xC0, 0x7E };
    for (int n = 0; n < 2; ++n) {
        const Dataset d = make(names[n], 5, 200);
        std::vector<FrameSpan> expected;
        const Bytes stream = shared_flags(d, flags[n], &expected);
        const Segmentation s = by_flags(stream);
        INFO(names[n]);
        REQUIRE(s.info().found);
        CHECK(s.info().delimiter == flags[n]);
        CHECK(s.info().escaped);
        CHECK(s.info().flags == 201);
        CHECK(same_frames(s, expected));
        // The first has its opening flag and the others start after the one before.
        CHECK(s.frame(1).event_count + 1 == d.frame(1).event_count);

        // The pipeline says the same, in the model.
        const bw::Analysis a = bw::analyze(capture_of(stream), bw::AnalyzeOptions());
        CHECK(a.model().framing().kind == bw::FramingKind::Flagged);
        CHECK(a.model().framing().delimiter == flags[n]);
        CHECK(a.model().framing().escaped);
        CHECK(a.info().frames == 200);
    }
}

TEST_CASE("flags: stuffing is an escape byte that is always followed by a code, both codes seen, at least three times") {
    // Twelve frames that share their flags, with the escape and a code put in the first n of them: the two codes
    // take turns, so that n = 2 has one of each and n = 3 has three in all.
    for (std::size_t n = 2; n <= 4; ++n) {
        std::vector<Bytes> c = contents(12);
        for (std::size_t i = 0; i < n; ++i) {
            c[i].insert(c[i].begin() + 2, i % 2 ? 0x5D : 0x5E);
            c[i].insert(c[i].begin() + 2, 0x7D);
        }
        const Segmentation s = by_flags(build(c, std::vector<bool>(11, false), 0x7E).bytes);
        CAPTURE(n);
        CHECK(s.info().found == (n >= 3));
        if (n >= 3) {
            CHECK(s.info().escape == 0x7D);
            CHECK(s.info().delimiter_code == 0x5E);
            CHECK(s.info().escape_code == 0x5D);
        }
    }
    // One of the two codes only, however many times, is not stuffing: a line feed after a carriage return is as
    // good a flag with its bit 5 flipped (0x2A) as it gets.
    for (int code = 0; code < 2; ++code) {
        std::vector<Bytes> c = contents(12);
        for (std::size_t i = 0; i < 6; ++i) {
            c[i].insert(c[i].begin() + 2, code == 0 ? 0x5E : 0x5D);
            c[i].insert(c[i].begin() + 2, 0x7D);
        }
        CAPTURE(code);
        CHECK_FALSE(by_flags(build(c, std::vector<bool>(11, false), 0x7E).bytes).info().found);
    }
    // One escape followed by something that is not a code, and it is not stuffing.
    std::vector<Bytes> c = contents(12);
    for (std::size_t i = 0; i < 4; ++i) {
        c[i].insert(c[i].begin() + 2, i == 3 ? 0x20 : (i % 2 ? 0x5D : 0x5E));
        c[i].insert(c[i].begin() + 2, 0x7D);
    }
    CHECK_FALSE(by_flags(build(c, std::vector<bool>(11, false), 0x7E).bytes).info().found);
}

TEST_CASE("flags: text is not stuffing, however small the capture") {
    // NMEA has carriage returns, each of them followed by a line feed, which is 0x2A (the star) with bit 5 flipped.
    const std::uint32_t sizes[4] = { 9, 12, 30, 90 };
    for (int k = 0; k < 4; ++k) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            const Dataset d = make("nmea0183", seed, sizes[k], seed % 2 ? 0 : 300);
            INFO("nmea0183 " << sizes[k] << " sentences, seed " << seed);
            CHECK_FALSE(bw::segment_by_flags(d.capture(), SegmentationOptions()).info().found);
        }
    }
}

TEST_CASE("flags: the two ways of writing the stuffing that are known, and no others") {
    // Bit 5 of the flag and of the escape flipped: any flag and escape.
    {
        std::vector<Bytes> c = contents(12);
        for (std::size_t i = 0; i < 4; ++i) {
            c[i].insert(c[i].begin() + 2, i % 2 ? 0x90 : 0x80);              // 0xB0 ^ 0x20, and 0xA0 ^ 0x20
            c[i].insert(c[i].begin() + 2, 0xB0);
        }
        const Segmentation s = by_flags(build(c, std::vector<bool>(11, false), 0xA0).bytes);
        REQUIRE(s.info().found);
        CHECK(s.info().delimiter == 0xA0);
        CHECK(s.info().escape == 0xB0);
        CHECK(s.info().delimiter_code == 0x80);                              // 0xA0 ^ 0x20
        CHECK(s.info().escape_code == 0x90);
    }
    // C0 DB DC DD, the SLIP's, only for that flag and that escape.
    for (unsigned flag = 0xC0; flag <= 0xC1; ++flag) {
        std::vector<Bytes> c = contents(12);
        for (std::size_t i = 0; i < 4; ++i) {
            c[i].insert(c[i].begin() + 2, i % 2 ? 0xDD : 0xDC);
            c[i].insert(c[i].begin() + 2, 0xDB);
        }
        const Segmentation s = by_flags(build(c, std::vector<bool>(11, false), static_cast<std::uint8_t>(flag)).bytes);
        CAPTURE(flag);
        CHECK(s.info().found == (flag == 0xC0));
    }
    // And for that escape only: the same codes after another byte are not it.
    {
        std::vector<Bytes> c = contents(12);
        for (std::size_t i = 0; i < 4; ++i) {
            c[i].insert(c[i].begin() + 2, i % 2 ? 0xDD : 0xDC);
            c[i].insert(c[i].begin() + 2, 0xDA);
        }
        CHECK_FALSE(by_flags(build(c, std::vector<bool>(11, false), 0xC0).bytes).info().found);
    }
    // Two escapes that would do: the one the capture shows most, and the lower byte if equally.
    for (int more = 0; more <= 2; ++more) {
        std::vector<Bytes> c = contents(12);
        // 0x7D with codes 0x5E and 0x5D, and 0x90 with 0x5E and 0xB0: three or four of each, as `more` says.
        const std::size_t first_count  = more == 1 ? 4 : 3;
        const std::size_t second_count = more == 2 ? 4 : 3;
        for (std::size_t i = 0; i < first_count; ++i) {
            c[i].insert(c[i].begin() + 2, i % 2 ? 0x5D : 0x5E);
            c[i].insert(c[i].begin() + 2, 0x7D);
        }
        for (std::size_t i = 0; i < second_count; ++i) {
            c[6 + i].insert(c[6 + i].begin() + 2, i % 2 ? 0xB0 : 0x5E);
            c[6 + i].insert(c[6 + i].begin() + 2, 0x90);
        }
        const Segmentation s = by_flags(build(c, std::vector<bool>(11, false), 0x7E).bytes);
        CAPTURE(more);
        REQUIRE(s.info().found);
        CHECK(s.info().escape == (more == 2 ? 0x90 : 0x7D));            // 0 and 1: 3 and 3 (the lower), 4 and 3; 2: 3 and 4
    }
    // Two codes that are neither: the flag with bit 5 flipped is missing.
    std::vector<Bytes> c = contents(12);
    for (std::size_t i = 0; i < 4; ++i) {
        c[i].insert(c[i].begin() + 2, i % 2 ? 0x31 : 0x30);
        c[i].insert(c[i].begin() + 2, 0x7D);
    }
    CHECK_FALSE(by_flags(build(c, std::vector<bool>(11, false), 0x7E).bytes).info().found);
}

TEST_CASE("flags: the bytes before the first flag and after the last one are in no frame") {
    const Built b = build(contents(12), std::vector<bool>(11, true));
    Bytes padded(3, 0x55);
    padded.insert(padded.end(), b.bytes.begin(), b.bytes.end());
    padded.push_back(0x66);
    padded.push_back(0x67);
    const Segmentation s = by_flags(padded);
    REQUIRE(s.info().found);
    REQUIRE(s.frame_count() == 12);
    CHECK(s.frame(0).first_event == 3);
    CHECK(s.frame(11).first_event + s.frame(11).event_count == 3 + b.bytes.size());
}

TEST_CASE("flags: the frames of SLIP and of HDLC are found exactly, with the idle flags in none") {
    const char*   names[2]   = { "slip", "hdlc-ppp" };
    const uint8_t flags[2]   = { 0xC0, 0x7E };
    for (int n = 0; n < 2; ++n) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            for (unsigned jitter = 0; jitter <= 300; jitter += 300) {
                const Dataset d = make(names[n], seed, 200, jitter);
                const Segmentation s = bw::segment_by_flags(d.capture(), SegmentationOptions());
                INFO(names[n] << " seed " << seed << " jitter " << jitter);
                REQUIRE(s.info().found);
                CHECK(s.info().kind == bw::FramingKind::Flagged);
                CHECK(s.info().delimiter == flags[n]);
                const bw::SegmentationScore score = bw::score_segmentation(d.frames(), s.frames());
                CHECK(score.truth_frames == 200);
                CHECK(score.found_frames == 200);
                CHECK(score.exact_frames == 200);
                CHECK(score.boundary_hits == score.truth_boundaries);
                CHECK(score.found_boundaries == score.truth_boundaries);

                // The flags of the capture: two for each frame, and the idle ones of HDLC.
                std::uint64_t in_frames = 0;
                for (std::size_t i = 0; i < d.frame_count(); ++i) {
                    in_frames += d.frame(i).event_count;
                }
                std::uint64_t idle = d.capture().event_count() - in_frames;
                CHECK(s.info().flags == 2 * 200 + idle);
                CHECK((n == 0 ? idle == 0 : idle > 0));
            }
        }
    }
}

TEST_CASE("flags: no other protocol of the corpus, and no noise, has a byte that bounds its frames") {
    const char* names[5] = { "modbus-rtu", "ubx", "mavlink1", "mavlink2", "nmea0183" };
    for (int n = 0; n < 5; ++n) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            const Dataset d = make(names[n], seed, 200, seed % 2 ? 0 : 300);
            INFO(names[n] << " seed " << seed);
            CHECK_FALSE(bw::segment_by_flags(d.capture(), SegmentationOptions()).info().found);
        }
    }
    for (std::uint64_t seed = 1; seed <= 6; ++seed) {
        Bytes noise;
        std::uint64_t x = 88172645463325252ULL * seed;
        for (int i = 0; i < 8000; ++i) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            noise.push_back(static_cast<std::uint8_t>(x >> 24));
        }
        CAPTURE(seed);
        CHECK_FALSE(by_flags(noise).info().found);
    }
}

TEST_CASE("flags: the pipeline cuts by flags when it can and by gaps when it cannot") {
    // SLIP at the pace of the line has no gaps; by flags it is cut, and the model says so.
    const Dataset slip = make("slip", 3, 300);
    CHECK_FALSE(bw::segment_by_gaps(slip.capture(), SegmentationOptions()).info().found);
    const Segmentation by_flag = bw::segment_frames(slip.capture(), SegmentationOptions());
    REQUIRE(by_flag.info().found);
    CHECK(by_flag.info().kind == bw::FramingKind::Flagged);

    const bw::Analysis a = bw::analyze(slip.capture(), bw::AnalyzeOptions());
    REQUIRE(a.info().segmentation.found);
    CHECK(a.model().framing().kind == bw::FramingKind::Flagged);
    CHECK(a.model().framing().delimiter == 0xC0);
    CHECK(a.info().frames == 300);
    const std::string text = bw::describe_analysis(a);
    CHECK(text.find("framing    flags: the byte 0xC0 bounds each frame (600 of them in the capture), "
                    "stuffed: 0xC0 as 0xDB 0xDC and 0xDB as 0xDB 0xDD\n") != std::string::npos);
    CHECK(text.find("framing: between 0xC0, escape 0xDB: 0xC0 as 0xDB 0xDC, 0xDB as 0xDB 0xDD\n") != std::string::npos);
    CHECK(a.model().framing().escaped);
    CHECK(a.model().framing().escape == 0xDB);
    CHECK(a.model().framing().delimiter_code == 0xDC);
    CHECK(a.model().framing().escape_code == 0xDD);

    const Dataset hdlc = make("hdlc-ppp", 3, 300);
    const bw::Analysis h = bw::analyze(hdlc.capture(), bw::AnalyzeOptions());
    CHECK(h.model().framing().kind == bw::FramingKind::Flagged);
    CHECK(h.model().framing().delimiter == 0x7E);
    CHECK(h.model().framing().escaped);
    CHECK(h.model().framing().escape == 0x7D);
    CHECK(h.model().framing().delimiter_code == 0x5E);
    CHECK(h.model().framing().escape_code == 0x5D);
    CHECK(bw::describe_analysis(h).find(", stuffed: 0x7E as 0x7D 0x5E and 0x7D as 0x7D 0x5D\n") != std::string::npos);
    CHECK(h.info().frames == 300);

    // What the stages make of the frames that the flags found is what they made of the true ones
    // (the baseline of tests/test_stuffing.cpp): types by size, and no checksum.
    typedef std::set<std::pair<std::uint32_t, std::uint32_t> > Types;
    Types slip_types, hdlc_types;
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        slip_types.insert(std::make_pair(a.type_report(t).frame_bytes, a.type_report(t).frames));
        CHECK_FALSE(a.type_report(t).checksum.found);
    }
    for (std::size_t t = 0; t < h.type_count(); ++t) {
        hdlc_types.insert(std::make_pair(h.type_report(t).frame_bytes, h.type_report(t).frames));
        CHECK_FALSE(h.type_report(t).checksum.found);
    }
    Types slip_expected, hdlc_expected;
    slip_expected.insert(std::make_pair(21u, 148u));
    slip_expected.insert(std::make_pair(12u, 135u));
    slip_expected.insert(std::make_pair(22u, 14u));
    hdlc_expected.insert(std::make_pair(17u, 102u));
    hdlc_expected.insert(std::make_pair(18u, 100u));
    hdlc_expected.insert(std::make_pair(32u, 78u));
    hdlc_expected.insert(std::make_pair(33u, 15u));
    CHECK(slip_types == slip_expected);
    CHECK(hdlc_types == hdlc_expected);
    CHECK(a.info().ignored_frames == 3);
    CHECK(h.info().ignored_frames == 5);

    // Modbus RTU has no flag and has gaps: nothing changes.
    const Dataset modbus = make("modbus-rtu", 1, 50, 300);
    const Segmentation gaps = bw::segment_frames(modbus.capture(), SegmentationOptions());
    REQUIRE(gaps.info().found);
    CHECK(gaps.info().kind == bw::FramingKind::IdleGap);
    CHECK(gaps.info().idle_gap_ns > 0);
    CHECK(bw::analyze(modbus.capture(), bw::AnalyzeOptions()).model().framing().kind == bw::FramingKind::IdleGap);

    // And a capture that neither flags, gaps, a sync byte and a length nor lines cut says so, in a line that names them.
    Bytes noise;
    std::uint64_t x = 88172645463325252ULL;
    for (int i = 0; i < 4000; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        noise.push_back(static_cast<std::uint8_t>(x >> 24));
    }
    const bw::Analysis none = bw::analyze(capture_of(noise), bw::AnalyzeOptions());
    CHECK_FALSE(none.info().segmentation.found);
    CHECK(bw::describe_analysis(none).find("framing    none found: the gaps between events do not split into short and long ones, "
                                           "no byte bounds the frames as a flag, none starts them and says how long they are, and it is not text in lines\n") !=
          std::string::npos);
}

TEST_CASE("flags: frames given with a kind of flags are described as such, and without one as before") {
    const Dataset d = make("slip", 5, 40);
    bw::SegmentationInfo info;
    info.found     = true;
    info.kind      = bw::FramingKind::Flagged;
    info.delimiter = 0xC0;
    const bw::Analysis flagged = bw::analyze_frames(d.capture(), bw::Segmentation(info, d.frames()), bw::AnalyzeOptions());
    CHECK(flagged.model().framing().kind == bw::FramingKind::Flagged);
    CHECK(flagged.model().framing().delimiter == 0xC0);

    bw::SegmentationInfo given;
    given.found = true;
    CHECK(bw::analyze_frames(d.capture(), bw::Segmentation(given, d.frames()), bw::AnalyzeOptions()).model().framing().kind ==
          bw::FramingKind::Unknown);
    given.idle_gap_ns = 1000;                                  // as a caller did before there was a kind
    CHECK(bw::analyze_frames(d.capture(), bw::Segmentation(given, d.frames()), bw::AnalyzeOptions()).model().framing().kind ==
          bw::FramingKind::IdleGap);
}
