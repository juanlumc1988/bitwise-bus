// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The frames as the later stages read them: without the flags that bound them and with the
// stuffing that keeps the flag out of them undone, so that a checksum is taken over what the
// protocol sends and a field is of what it holds. The cases are written so that each rule has
// one that fails if it is broken: the two flags, a flag that two frames share, each of the two
// escapes, an escape that is followed by nothing it should be, the frames that are not flagged,
// the time and the channel of an event; then the frames of SLIP and of HDLC, which are what
// their models say once unstuffed, and what the stages find in them, which is the baseline.

#include "doctest.h"

#include <cstdint>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/checksum.h"
#include "bw/evaluate.h"
#include "bw/protocol.h"
#include "bw/segmentation.h"

using bw::Capture;
using bw::Dataset;
using bw::EventInfo;
using bw::FrameSpan;
using bw::Segmentation;
using bw::SegmentationInfo;

namespace {

typedef std::vector<std::uint8_t> Bytes;

FrameSpan span(std::uint64_t first, std::uint64_t count) {
    FrameSpan s;
    s.first_event = first;
    s.event_count = count;
    return s;
}

Capture one_byte_events(const Bytes& bytes) {
    Capture c;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        c.add_event(EventInfo(), Bytes(1, bytes[i]));
    }
    return c;
}

// The info of SLIP's flags and stuffing.
SegmentationInfo slip_info(bool escaped = true) {
    SegmentationInfo info;
    info.found          = true;
    info.kind           = bw::FramingKind::Flagged;
    info.delimiter      = 0xC0;
    info.escaped        = escaped;
    info.escape         = escaped ? 0xDB : 0;
    info.delimiter_code = escaped ? 0xDC : 0;
    info.escape_code    = escaped ? 0xDD : 0;
    return info;
}

Bytes content(const Capture& c, std::size_t i) {
    return c.event_bytes(i);
}

Bytes bytes_of(std::initializer_list<int> values) {
    Bytes out;
    for (std::initializer_list<int>::const_iterator it = values.begin(); it != values.end(); ++it) {
        out.push_back(static_cast<std::uint8_t>(*it));
    }
    return out;
}

Dataset make(const char* name, std::uint64_t seed, std::uint32_t frames) {
    bw::GenerateOptions o;
    o.seed   = seed;
    o.frames = frames;
    return bw::generate_protocol(name, o);
}

// The same, written again: the bytes between the flags of a frame as it is on the line.
Bytes unstuffed(const Bytes& wire, std::uint8_t flag, std::uint8_t escape, std::uint8_t flag_code, std::uint8_t escape_code) {
    Bytes out;
    for (std::size_t i = 1; i + 1 < wire.size(); ++i) {
        if (wire[i] == escape && wire[i + 1] == flag_code) {
            out.push_back(flag);
            ++i;
        } else if (wire[i] == escape && wire[i + 1] == escape_code) {
            out.push_back(escape);
            ++i;
        } else {
            out.push_back(wire[i]);
        }
    }
    return out;
}

} // namespace

TEST_CASE("contents: a frame loses its two flags, and each escape and its code are the byte they stand for") {
    // C0 | 10 DB DC 00 DB DD 7F | C0: an END and an ESC inside, as SLIP sends them.
    const Bytes line = bytes_of({ 0xC0, 0x10, 0xDB, 0xDC, 0x00, 0xDB, 0xDD, 0x7F, 0xC0 });
    const Capture c = one_byte_events(line);
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 9));
    const Capture out = bw::frame_contents(c, Segmentation(slip_info(), frames));
    REQUIRE(out.event_count() == 1);
    CHECK(content(out, 0) == bytes_of({ 0x10, 0xC0, 0x00, 0xDB, 0x7F }));

    // The codes mean nothing without the escape: they are bytes.
    const Capture plain = one_byte_events(bytes_of({ 0xC0, 0xDC, 0xDD, 0x01, 0xC0 }));
    std::vector<FrameSpan> f2;
    f2.push_back(span(0, 5));
    CHECK(content(bw::frame_contents(plain, Segmentation(slip_info(), f2)), 0) == bytes_of({ 0xDC, 0xDD, 0x01 }));

    // And without the stuffing said, the escape is a byte, with what follows it.
    const Capture unsaid = bw::frame_contents(c, Segmentation(slip_info(false), frames));
    CHECK(content(unsaid, 0) == bytes_of({ 0x10, 0xDB, 0xDC, 0x00, 0xDB, 0xDD, 0x7F }));
}

TEST_CASE("contents: a flag that is not there is not taken off, and stuffing that is not said is not undone") {
    // Frames given by hand without a closing flag, or without an opening one: only a flag that is there goes.
    const Capture c = one_byte_events(bytes_of({ 0xC0, 0x01, 0x02, 0x03, 0x04, 0xC0 }));
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 3));                              // C0 01 02: no closing flag
    frames.push_back(span(3, 3));                              // 03 04 C0: no opening one
    const Capture out = bw::frame_contents(c, Segmentation(slip_info(), frames));
    REQUIRE(out.event_count() == 2);
    CHECK(content(out, 0) == bytes_of({ 0x01, 0x02 }));
    CHECK(content(out, 1) == bytes_of({ 0x03, 0x04 }));
    // A frame of two bytes and no flag at all.
    std::vector<FrameSpan> bare;
    bare.push_back(span(1, 2));
    CHECK(content(bw::frame_contents(c, Segmentation(slip_info(), bare)), 0) == bytes_of({ 0x01, 0x02 }));

    // Stuffing that is not said leaves the escape and its code, whatever they would be: the zeros that a
    // segmentation that says nothing of it has in its fields are not the escape and its two codes.
    const Capture zeros = one_byte_events(bytes_of({ 0xC0, 0x00, 0x00, 0x01, 0xC0 }));
    std::vector<FrameSpan> one;
    one.push_back(span(0, 5));
    CHECK(content(bw::frame_contents(zeros, Segmentation(slip_info(false), one)), 0) == bytes_of({ 0x00, 0x00, 0x01 }));
}

TEST_CASE("contents: an escape that is not followed by a code, or by anything, stays as it is") {
    const Bytes line = bytes_of({ 0xC0, 0x41, 0xDB, 0x42, 0xDB, 0xDB, 0xDC, 0x43, 0xDB, 0xC0 });
    const Capture c = one_byte_events(line);
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 10));
    // 41, DB 42 (not a code), DB then DB DC (the second escape is the one that is followed by a code: the END), 43, and
    // an escape that is the last byte before the flag.
    CHECK(content(bw::frame_contents(c, Segmentation(slip_info(), frames)), 0) == bytes_of({ 0x41, 0xDB, 0x42, 0xDB, 0xC0, 0x43, 0xDB }));
}

TEST_CASE("contents: a flag that two frames share belongs to the first, and the second has none to lose") {
    // C0 | 01 | C0 | 02 | C0 | 03 | C0 : three frames, four flags.
    const Capture c = one_byte_events(bytes_of({ 0xC0, 0x01, 0xC0, 0x02, 0xC0, 0x03, 0xC0 }));
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 3));
    frames.push_back(span(3, 2));
    frames.push_back(span(5, 2));
    const Capture out = bw::frame_contents(c, Segmentation(slip_info(), frames));
    REQUIRE(out.event_count() == 3);
    CHECK(content(out, 0) == bytes_of({ 0x01 }));
    CHECK(content(out, 1) == bytes_of({ 0x02 }));
    CHECK(content(out, 2) == bytes_of({ 0x03 }));
}

TEST_CASE("contents: a frame of nothing between its flags, or of one flag, is an event of no bytes") {
    const Capture c = one_byte_events(bytes_of({ 0xC0, 0xC0, 0xC0 }));
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 2));
    frames.push_back(span(2, 1));
    const Capture out = bw::frame_contents(c, Segmentation(slip_info(), frames));
    REQUIRE(out.event_count() == 2);
    CHECK(out.event_size(0) == 0);
    CHECK(out.event_size(1) == 0);
    CHECK(bw::frame_contents(Capture(), Segmentation()).event_count() == 0);
}

TEST_CASE("contents: a frame of no events is an event of no bytes, and does not need the capture to have one there") {
    const Capture c = one_byte_events(bytes_of({ 0xC0, 0x01, 0xC0 }));
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 3));
    frames.push_back(span(3, 0));                              // after the last event of the capture
    const Capture out = bw::frame_contents(c, Segmentation(slip_info(), frames));
    REQUIRE(out.event_count() == 2);
    CHECK(content(out, 0) == bytes_of({ 0x01 }));
    CHECK(out.event_size(1) == 0);
    CHECK_FALSE(out.event(1).has_time);
    CHECK(out.event(1).channel == 0);
}

TEST_CASE("contents: frames that are not flagged are as they are, with their events joined") {
    // Two events of two bytes, and one of three: two frames.
    Capture c;
    c.add_event(EventInfo(), bytes_of({ 0xC0, 0x01 }));
    c.add_event(EventInfo(), bytes_of({ 0xDB, 0xDC }));
    c.add_event(EventInfo(), bytes_of({ 0xC0, 0x02, 0x03 }));
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 2));
    frames.push_back(span(2, 1));

    const bw::FramingKind kinds[4] = { bw::FramingKind::Unknown, bw::FramingKind::IdleGap, bw::FramingKind::Contiguous,
                                       bw::FramingKind::Terminated };
    for (int k = 0; k < 4; ++k) {
        SegmentationInfo info = slip_info();                        // with a flag and an escape that mean nothing here
        info.kind = kinds[k];
        if (kinds[k] != bw::FramingKind::Flagged) {
            info.escaped = true;
        }
        const Capture out = bw::frame_contents(c, Segmentation(info, frames));
        CAPTURE(k);
        REQUIRE(out.event_count() == 2);
        CHECK(content(out, 0) == bytes_of({ 0xC0, 0x01, 0xDB, 0xDC }));
        CHECK(content(out, 1) == bytes_of({ 0xC0, 0x02, 0x03 }));
    }
}

TEST_CASE("contents: an event is where its frame began: its time, its channel, and the channels of the capture") {
    Capture c;
    const std::uint32_t second = c.add_channel("second");
    const std::uint32_t third  = c.add_channel("third");
    const std::uint32_t ids[4]      = { 0, second, third, second };
    const std::int64_t  times[4]    = { 100, 200, 300, 400 };
    const Bytes         wire[4]     = { bytes_of({ 0xC0 }), bytes_of({ 0x11 }), bytes_of({ 0xC0 }), bytes_of({ 0x22, 0xC0 }) };
    for (int i = 0; i < 4; ++i) {
        EventInfo info;
        info.has_time  = true;
        info.time_ns   = times[i];
        info.channel   = ids[i];
        info.direction = bw::Direction::Rx;
        c.add_event(info, wire[i]);
    }
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 3));
    frames.push_back(span(3, 1));
    const Capture out = bw::frame_contents(c, Segmentation(slip_info(), frames));
    REQUIRE(out.event_count() == 2);
    CHECK(out.channel_count() == 3);
    CHECK(out.channel_name(1) == "second");
    CHECK(out.channel_name(2) == "third");
    CHECK(out.event(0).has_time);
    CHECK(out.event(0).time_ns == 100);
    CHECK(out.event(0).channel == 0);
    CHECK(out.event(1).time_ns == 400);
    CHECK(out.event(1).channel == second);
    CHECK(out.event(1).direction == bw::Direction::Rx);
    CHECK(content(out, 0) == bytes_of({ 0x11 }));
    CHECK(content(out, 1) == bytes_of({ 0x22 }));
}

TEST_CASE("contents: the frames of SLIP and of HDLC are what the models say once unstuffed") {
    struct Expect { const char* name; std::uint8_t flag, escape, flag_code, escape_code; };
    const Expect expects[2] = { { "slip", 0xC0, 0xDB, 0xDC, 0xDD }, { "hdlc-ppp", 0x7E, 0x7D, 0x5E, 0x5D } };
    for (int n = 0; n < 2; ++n) {
        const Dataset d = make(expects[n].name, 4, 300);
        const Segmentation s = bw::segment_by_flags(d.capture(), bw::SegmentationOptions());
        REQUIRE(s.info().found);
        const Capture out = bw::frame_contents(d.capture(), s);
        REQUIRE(out.event_count() == 300);
        const bw::Model m = d.model();
        for (std::size_t i = 0; i < 300; ++i) {
            const Bytes wire = bw::frame_bytes(d.capture(), d.frame(i));
            INFO(expects[n].name << " frame " << i);
            CHECK(content(out, i) == unstuffed(wire, expects[n].flag, expects[n].escape, expects[n].flag_code, expects[n].escape_code));
            // And as long as the model says.
            std::uint64_t bits = 0;
            const std::size_t t = d.frame_message_type(i);
            for (std::size_t f = 0; f < m.field_count(t); ++f) {
                bits += m.field(t, f).bit_size;
            }
            CHECK(out.event_size(i) == bits / 8);
        }
    }
}

TEST_CASE("contents: the stages read the frames unstuffed, whichever way the flags are sent") {
    // The same frames with a flag of their own each and with one flag between them: the same message types.
    const Dataset d = make("hdlc-ppp", 6, 200);
    Bytes shared(1, 0x7E);
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes wire = bw::frame_bytes(d.capture(), d.frame(i));
        shared.insert(shared.end(), wire.begin() + 1, wire.end());
    }
    const bw::Analysis own = bw::analyze(d.capture(), bw::AnalyzeOptions());
    const bw::Analysis one = bw::analyze(one_byte_events(shared), bw::AnalyzeOptions());
    REQUIRE(own.info().frames == 200);
    REQUIRE(one.info().frames == 200);
    const std::string a = bw::describe_model(own.model());
    const std::string b = bw::describe_model(one.model());
    CHECK(a == b);
    CHECK(a.find("CRC-16/IBM-SDLC") != std::string::npos);
    CHECK(own.type_count() == 3);
    for (std::size_t t = 0; t < 3; ++t) {
        CHECK(own.type_report(t).checksum.found);
        CHECK(one.type_report(t).checksum.found);
        CHECK(own.type_report(t).frames == one.type_report(t).frames);
    }

    // Flags and no stuffing said: the flags are off, and nothing else.
    SegmentationInfo info = slip_info(false);
    const Dataset slip = make("slip", 2, 40);
    const bw::Analysis flagged = bw::analyze_frames(slip.capture(), Segmentation(info, slip.frames()), bw::AnalyzeOptions());
    std::size_t sizes = 0;
    for (std::size_t t = 0; t < flagged.type_count(); ++t) {
        sizes += flagged.type_report(t).frame_bytes >= 10 ? 1 : 0;
        CHECK(flagged.type_report(t).frame_bytes <= 23);          // the content, which has no flags
    }
    CHECK(sizes >= 2);
}

TEST_CASE("wave 1 baseline: what the stages find in SLIP and in PPP, cut by their flags and unstuffed") {
    // Where the stuffed protocols start: stage 3 finds the frames, the stuffing is undone, stage 2 finds the FCS of
    // PPP in all three of its kinds (the catalogue has CRC-16/IBM-SDLC), and stages 4 and 5 find the boundaries
    // there are and some more. The numbers are those of 200 frames of seed 3; each step of wave 1 that improves one of
    // them changes this table in the same pull request.
    struct Row {
        const char* protocol;
        const char* type;
        unsigned    truth_fields, found_fields, truth_boundaries, found_boundaries, hits, exact, kinds;
        bool        checksum;
    };
    const Row rows[] = {
        { "slip",     "sample",       9,  6,  10, 7,  4,  1, 1, false },
        { "slip",     "status",       5,  9,  6,  10, 6,  2, 2, false },
        { "hdlc-ppp", "lcp_echo",     8,  13, 9,  14, 9,  5, 5, true },
        { "hdlc-ppp", "ipcp_request", 10, 15, 11, 16, 11, 7, 7, true },
        { "hdlc-ppp", "ip_datagram",  5,  6,  6,  7,  6,  4, 4, true },
    };
    std::size_t checked = 0;
    const char* protocols[2] = { "slip", "hdlc-ppp" };
    for (int p = 0; p < 2; ++p) {
        const Dataset d = make(protocols[p], 3, 200);
        const bw::Analysis a = bw::analyze(d.capture(), bw::AnalyzeOptions());
        REQUIRE(a.type_count() == (p == 0 ? 2u : 3u));
        for (std::size_t ft = 0; ft < a.type_count(); ++ft) {
            // The truth type whose frames are as long as these.
            std::size_t tt = d.model().message_type_count();
            for (std::size_t t = 0; t < d.model().message_type_count(); ++t) {
                std::uint64_t bits = 0;
                for (std::size_t f = 0; f < d.model().field_count(t); ++f) {
                    bits += d.model().field(t, f).bit_size;
                }
                if (bits / 8 == a.type_report(ft).frame_bytes) {
                    tt = t;
                }
            }
            REQUIRE(tt < d.model().message_type_count());
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
                    CHECK(s.truth_has_checksum == rows[r].checksum);
                    CHECK(s.found_has_checksum == rows[r].checksum);
                    CHECK(s.checksum_match);                               // the same, or neither has one
                }
            }
        }
    }
    CHECK(checked == 5);
}
