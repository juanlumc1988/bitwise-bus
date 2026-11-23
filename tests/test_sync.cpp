// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 3, segmentation by a sync byte and a length: the frames of UBX and MAVLink, which
// follow one another with nothing between them and say how long they are. The cases are
// written so that each rule has one that fails if the rule is broken: where the length is and
// how wide, what is added to it, a fixed size, a sync byte inside a payload, the fewest frames,
// the one break in 50 and the 90% of the capture, a frame cut short by the end, which of two
// readings of the same frames is chosen; then the frames of the three generators, found
// exactly, the protocols that are not taken for them, and how the pipeline orders flags,
// gaps and sync bytes.

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

Capture capture_of(const Bytes& bytes) {
    Capture c;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        c.add_event(EventInfo(), Bytes(1, bytes[i]));
    }
    return c;
}

Segmentation by_sync(const Bytes& bytes, std::uint32_t min_frames = 8) {
    SegmentationOptions options;
    options.min_sync_frames = min_frames;
    return bw::segment_by_sync(capture_of(bytes), options);
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

// Bytes that are never a sync byte of these tests (0xA5, 0xB5, 0xFE...), and never 0x62.
Bytes filler(std::size_t seed, std::size_t n) {
    Bytes b;
    for (std::size_t k = 0; k < n; ++k) {
        b.push_back(static_cast<std::uint8_t>(0x10 + (seed * 31 + k * 17) % 0x40));
    }
    return b;
}

// What a stream is built of: the bytes before the length (the sync byte first), where the length is,
// and what comes after it.
struct Layout {
    Bytes         head;                 // the bytes before the length, the sync byte first
    std::uint32_t width      = 1;       // of the length
    bool          big_endian = false;
    std::uint32_t trailer    = 2;       // bytes after the payload that the length does not count
    std::int64_t  adjust() const { return static_cast<std::int64_t>(head.size() + width + trailer); }
};

struct Built {
    Bytes                  bytes;
    std::vector<FrameSpan> frames;
};

// Frames with the payload lengths given, one after another, each as the layout says.
Built build(const Layout& layout, const std::vector<std::uint32_t>& payloads) {
    Built b;
    for (std::size_t i = 0; i < payloads.size(); ++i) {
        const std::uint64_t first = b.bytes.size();
        Bytes frame = layout.head;
        for (std::uint32_t k = 0; k < layout.width; ++k) {
            const std::uint32_t shift = 8 * (layout.big_endian ? layout.width - 1 - k : k);
            frame.push_back(static_cast<std::uint8_t>((payloads[i] >> shift) & 0xFF));
        }
        const Bytes body = filler(i, payloads[i] + layout.trailer);
        frame.insert(frame.end(), body.begin(), body.end());
        b.bytes.insert(b.bytes.end(), frame.begin(), frame.end());
        b.frames.push_back(span(first, frame.size()));
    }
    return b;
}

Layout simple(std::uint8_t sync = 0xA5) {
    Layout l;
    l.head.push_back(sync);
    l.head.push_back(0x01);                 // one more byte before the length: it is at offset 2
    return l;
}

// n payload lengths that cycle through the values given.
std::vector<std::uint32_t> lengths(std::size_t n, const std::vector<std::uint32_t>& values) {
    std::vector<std::uint32_t> out;
    for (std::size_t i = 0; i < n; ++i) {
        out.push_back(values[i % values.size()]);
    }
    return out;
}

std::vector<std::uint32_t> some(std::size_t n) {
    std::vector<std::uint32_t> values;
    values.push_back(3);
    values.push_back(6);
    values.push_back(4);
    return lengths(n, values);
}

Dataset make(const char* name, std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    bw::GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol(name, o);
}

Bytes noise_of(std::uint64_t seed, std::size_t n) {
    Bytes out;
    std::uint64_t x = 88172645463325252ULL * seed;
    for (std::size_t i = 0; i < n; ++i) {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        out.push_back(static_cast<std::uint8_t>(x >> 24));
    }
    return out;
}

} // namespace

TEST_CASE("sync: frames that start with a byte and say their length are followed from one to the next") {
    const Layout l = simple();
    const Built  b = build(l, some(12));
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().kind == bw::FramingKind::Contiguous);
    CHECK(s.info().sync == 0xA5);
    CHECK(s.info().length_offset == 2);
    CHECK(s.info().length_bytes == 1);
    CHECK_FALSE(s.info().length_big_endian);
    CHECK(s.info().length_adjust == 5);                     // the two bytes before the length, the length, the two after the payload
    CHECK(s.info().frame_size == 0);
    CHECK(s.info().breaks == 0);
    CHECK(s.info().idle_gap_ns == 0);
    CHECK(same_frames(s, b.frames));
}

TEST_CASE("sync: the length is found where it is, with what is added to it, whatever that is") {
    // At each offset of the first eight.
    for (std::uint32_t offset = 1; offset <= 8; ++offset) {
        Layout l;
        l.head.push_back(0xA5);
        for (std::uint32_t k = 1; k < offset; ++k) {
            l.head.push_back(static_cast<std::uint8_t>(0x20 + k));
        }
        const Built b = build(l, some(12));
        const Segmentation s = by_sync(b.bytes);
        CAPTURE(offset);
        REQUIRE(s.info().found);
        CHECK(s.info().length_offset == offset);
        CHECK(s.info().length_adjust == l.adjust());
        CHECK(same_frames(s, b.frames));
    }
    // At the ninth it is not looked for. A length there is read as the two bytes that end at it, from the eighth,
    // and the byte before it, which is always the same, is in what is added: the frames are the same.
    {
        Layout l;
        l.head.push_back(0xA5);
        for (std::uint32_t k = 1; k < 9; ++k) {
            l.head.push_back(static_cast<std::uint8_t>(0x20 + k));
        }
        const Built b = build(l, some(12));
        const Segmentation s = by_sync(b.bytes);
        REQUIRE(s.info().found);
        CHECK(s.info().sync == 0xA5);
        CHECK(s.info().length_offset == 8);
        CHECK(s.info().length_bytes == 2);
        CHECK(s.info().length_big_endian);
        CHECK(s.info().length_adjust == l.adjust() - 0x2800);               // the constant 0x28 is 0x2800 of the 16 bits
        CHECK(same_frames(s, b.frames));
    }
    // A length that counts the whole frame has nothing added; one that counts two bytes too many has less.
    for (int extra = 0; extra <= 1; ++extra) {
        Layout l = simple();
        l.trailer = 0;
        Built b;
        for (std::size_t i = 0; i < 12; ++i) {
            const std::uint32_t payload = some(12)[i];
            const std::uint32_t size    = 3 + payload;                     // sync, one byte, the length, the payload
            Bytes frame = l.head;
            frame.push_back(static_cast<std::uint8_t>(extra == 0 ? size : size + 2));
            const Bytes body = filler(i, payload);
            frame.insert(frame.end(), body.begin(), body.end());
            b.frames.push_back(span(b.bytes.size(), frame.size()));
            b.bytes.insert(b.bytes.end(), frame.begin(), frame.end());
        }
        const Segmentation s = by_sync(b.bytes);
        CAPTURE(extra);
        REQUIRE(s.info().found);
        CHECK(s.info().length_adjust == (extra == 0 ? 0 : -2));
        CHECK(same_frames(s, b.frames));
    }
}

TEST_CASE("sync: a length of two bytes, in either order, when it needs them") {
    // Payloads of 300 and 700 bytes do not fit in one.
    std::vector<std::uint32_t> values;
    values.push_back(300);
    values.push_back(5);
    values.push_back(700);
    for (int big = 0; big <= 1; ++big) {
        Layout l = simple();
        l.width      = 2;
        l.big_endian = big == 1;
        const Built b = build(l, lengths(12, values));
        const Segmentation s = by_sync(b.bytes);
        CAPTURE(big);
        REQUIRE(s.info().found);
        CHECK(s.info().length_bytes == 2);
        CHECK(s.info().length_big_endian == (big == 1));
        CHECK(s.info().length_offset == 2);
        CHECK(s.info().length_adjust == l.adjust());
        CHECK(same_frames(s, b.frames));
    }
    // With lengths that fit in one byte, a 16-bit length whose high byte is always 0 is found as the one byte:
    // little-endian at its place, big-endian one byte later.
    Layout l = simple();
    l.width = 2;
    const Segmentation little = by_sync(build(l, some(12)).bytes);
    REQUIRE(little.info().found);
    CHECK(little.info().length_bytes == 1);
    CHECK(little.info().length_offset == 2);
    l.big_endian = true;
    const Segmentation big = by_sync(build(l, some(12)).bytes);
    REQUIRE(big.info().found);
    CHECK(big.info().length_bytes == 1);
    CHECK(big.info().length_offset == 3);
}

TEST_CASE("sync: frames of one size are found as that, with no length to read") {
    const Layout l = simple();
    const Built  b = build(l, std::vector<std::uint32_t>(12, 4));
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().length_bytes == 0);
    CHECK(s.info().length_offset == 0);
    CHECK(s.info().length_adjust == 0);
    CHECK(s.info().frame_size == 9);                         // 2 + 1 + 4 + 2
    CHECK(same_frames(s, b.frames));
}

TEST_CASE("sync: a sync byte that is twice at the start is one, found at the first") {
    // Dynamixel 1.0: FF FF, an id, the length, then the rest; the second FF is not where the frame starts.
    Layout l;
    l.head.push_back(0xFF);
    l.head.push_back(0xFF);
    l.head.push_back(0x01);
    l.trailer = 1;
    const Built b = build(l, some(30));
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().sync == 0xFF);
    CHECK(s.info().length_offset == 3);
    CHECK(s.info().length_adjust == 5);
    CHECK(same_frames(s, b.frames));
}

TEST_CASE("sync: of frames of one size, the sync is where the byte before it stops being the same") {
    // Frames of 9 bytes that start 0xA5 0x01. The second byte makes as good a chain (a frame from the 0x01 on),
    // with as many frames when two bytes of garbage follow the last: the first is the sync, since what comes
    // before the 0x01 is always the same byte and what comes before the 0xA5 is not.
    const Built b = build(simple(), std::vector<std::uint32_t>(12, 4));
    Bytes bytes = b.bytes;
    bytes.push_back(0x77);
    bytes.push_back(0x78);
    const Segmentation s = by_sync(bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().sync == 0xA5);
    CHECK(s.info().frame_size == 9);
    CHECK(s.frame_count() == 11);                           // the last is followed by garbage and is not known to be one
    CHECK(s.frame(0).first_event == 0);
}

TEST_CASE("sync: of frames of one size whose last byte has two values, the sync is the first byte") {
    // The last byte of each frame is one of two values, so what is before the frame is a byte of two values, and
    // before a frame that starts a byte later it is always the same: the first byte is the sync.
    const Built b = build(simple(), std::vector<std::uint32_t>(12, 4));
    Bytes bytes = b.bytes;
    for (std::size_t i = 0; i < b.frames.size(); ++i) {
        bytes[b.frames[i].first_event + b.frames[i].event_count - 1] = i % 2 == 0 ? 0x55 : 0x56;
    }
    const Segmentation s = by_sync(bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().sync == 0xA5);
    CHECK(s.info().frame_size == 9);
    CHECK(s.frame_count() == 12);
}

TEST_CASE("sync: one frame over and over: every byte of it starts a chain, and the one that follows every frame is the sync") {
    // 12 times the same nine bytes, as a heartbeat repeated: each byte of the frame is a reading that explains the
    // capture, and the byte before it is always the same. Only the first reads the last frame to its end.
    Bytes frame = simple().head;
    frame.push_back(0x04);
    const Bytes body = filler(1, 6);
    frame.insert(frame.end(), body.begin(), body.end());
    Bytes bytes;
    for (int i = 0; i < 12; ++i) {
        bytes.insert(bytes.end(), frame.begin(), frame.end());
    }
    const Segmentation s = by_sync(bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().sync == 0xA5);
    CHECK(s.info().frame_size == 9);
    CHECK(s.frame_count() == 12);
    CHECK(s.frame(0).first_event == 0);
}

TEST_CASE("sync: when sync bytes in the payloads are what the pairs agree on most, the overhead is still found") {
    // 40 frames, three of every five with the sync byte at the same place in the payload: the distance from the
    // sync byte to that one, less the length, is the overhead that most pairs agree on, and the true one comes second.
    std::vector<std::uint32_t> values;
    values.push_back(3);
    values.push_back(3);
    values.push_back(3);
    values.push_back(6);
    values.push_back(4);
    const Layout l = simple();
    Built b = build(l, lengths(40, values));
    for (std::size_t i = 0; i < b.frames.size(); ++i) {
        if (i % 5 < 3) {
            b.bytes[b.frames[i].first_event + 4] = 0xA5;
        }
    }
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().length_adjust == 5);
    CHECK(s.info().breaks == 0);
    CHECK(same_frames(s, b.frames));
}

TEST_CASE("sync: a sync byte inside a payload breaks nothing, which is what a length is for") {
    const Layout l = simple();
    Built b = build(l, some(40));
    // Put the sync byte in every other payload, and twice in some.
    for (std::size_t i = 0; i < b.frames.size(); i += 2) {
        b.bytes[b.frames[i].first_event + 4] = 0xA5;
        b.bytes[b.frames[i].first_event + 5] = 0xA5;
    }
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().breaks == 0);
    CHECK(same_frames(s, b.frames));
}

TEST_CASE("sync: the fewest frames is an option, and exact") {
    const Built b = build(simple(), some(8));
    CHECK(by_sync(b.bytes, 8).info().found);
    CHECK_FALSE(by_sync(b.bytes, 9).info().found);
    CHECK(by_sync(b.bytes, 1).info().found);
    CHECK(by_sync(b.bytes, 0).info().found);
    const Built fewer = build(simple(), some(7));
    CHECK_FALSE(by_sync(fewer.bytes, 8).info().found);
    CHECK(by_sync(fewer.bytes, 7).info().found);
    // A sync byte that is not there enough times is not tried, and the options of nothing found.
    CHECK_FALSE(by_sync(Bytes(), 0).info().found);
    CHECK_FALSE(by_sync(Bytes(1, 0xA5), 0).info().found);
    CHECK_FALSE(by_sync(Bytes(200, 0xA5), 0).info().found);
}

TEST_CASE("sync: one break in 50 frames is the most, and a frame before a break is not counted") {
    // A frame followed by something that is not the sync byte is not known to be a frame: it is a break, and
    // the chain starts again at the next sync byte. Frames are counted without the ones before a break, so
    // two breaks need 100 frames that count, and one break 50.
    struct Case { std::size_t frames, broken; bool found; };
    const Case cases[4] = { { 102, 2, true }, { 101, 2, false }, { 51, 1, true }, { 50, 1, false } };
    const Layout l = simple();
    for (int c = 0; c < 4; ++c) {
        const Built b = build(l, some(cases[c].frames));
        Bytes bytes;
        std::vector<FrameSpan> expected;
        for (std::size_t i = 0; i < b.frames.size(); ++i) {
            const bool broken = i % 30 == 10 && i / 30 < cases[c].broken;           // frames 10 and 40
            if (!broken) {
                expected.push_back(span(bytes.size(), b.frames[i].event_count));
            }
            bytes.insert(bytes.end(), b.bytes.begin() + b.frames[i].first_event,
                         b.bytes.begin() + b.frames[i].first_event + b.frames[i].event_count);
            if (broken) {
                bytes.push_back(0x77);                                              // nowhere else in the stream
                bytes.push_back(0x78);
            }
        }
        const Segmentation s = by_sync(bytes);
        CAPTURE(cases[c].frames);
        CAPTURE(cases[c].broken);
        CHECK(s.info().found == cases[c].found);
        if (cases[c].found) {
            CHECK(s.info().breaks == cases[c].broken);
            CHECK(same_frames(s, expected));
        }
    }
}

TEST_CASE("sync: the chain has to cover 90% of the bytes, exactly") {
    // 12 frames of 9 bytes, 108 bytes, with garbage before them.
    const Built b = build(simple(), std::vector<std::uint32_t>(12, 4));
    for (std::size_t garbage = 11; garbage <= 13; ++garbage) {
        Bytes bytes(garbage, 0x77);
        bytes.insert(bytes.end(), b.bytes.begin(), b.bytes.end());
        const Segmentation s = by_sync(bytes);
        CAPTURE(garbage);
        CHECK(s.info().found == (garbage <= 12));                          // 108 of 120 is 90%; of 121 it is not
        if (garbage <= 12) {
            CHECK(s.frame(0).first_event == garbage);
        }
    }
}

TEST_CASE("sync: a capture that begins in the middle of a frame, and one that ends in the middle of one") {
    const Built b = build(simple(), some(30));
    Bytes cut(b.bytes.begin() + 4, b.bytes.end() - 3);                      // the first frame loses its start, the last its end
    const Segmentation s = by_sync(cut);
    REQUIRE(s.info().found);
    std::vector<FrameSpan> expected;
    for (std::size_t i = 1; i + 1 < b.frames.size(); ++i) {
        expected.push_back(span(b.frames[i].first_event - 4, b.frames[i].event_count));
    }
    CHECK(same_frames(s, expected));
    CHECK(s.info().breaks == 0);                            // the start is found, not broken; the end is the end
}

TEST_CASE("sync: a sync byte before the first frame, with a length that runs past the end, is not the end") {
    // The capture starts in the middle of a frame whose payload has the sync byte, and then a length of 255 in a
    // stream of about a hundred bytes. It is the start that is being looked for: no break, and the frames are found.
    const Built b = build(simple(), some(12));
    Bytes bytes = filler(7, 3);
    bytes.push_back(0xA5);
    bytes.push_back(0x01);
    bytes.push_back(0xFF);
    bytes.insert(bytes.end(), b.bytes.begin(), b.bytes.end());
    const Segmentation s = by_sync(bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().breaks == 0);
    std::vector<FrameSpan> expected;
    for (std::size_t i = 0; i < b.frames.size(); ++i) {
        expected.push_back(span(b.frames[i].first_event + 6, b.frames[i].event_count));
    }
    CHECK(same_frames(s, expected));
}

TEST_CASE("sync: a frame as short as its length field, and one at the very end of the capture") {
    // A frame with nothing after the length is a frame: sync, one byte, the length. The last of the capture is one.
    Layout l = simple();
    l.trailer = 0;
    std::vector<std::uint32_t> payloads;
    for (std::size_t i = 0; i < 12; ++i) {
        payloads.push_back(i % 3 == 2 ? 0 : 3 + i % 4);
    }
    payloads.push_back(0);
    const Built b = build(l, payloads);
    REQUIRE(b.frames.back().event_count == 3);
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().length_adjust == 3);
    CHECK(s.info().breaks == 0);
    CHECK(same_frames(s, b.frames));
}

TEST_CASE("sync: an overhead is tried when three pairs of sync bytes agree on it") {
    // Four frames are three pairs, and three frames are two.
    CHECK(by_sync(build(simple(), some(4)).bytes, 4).info().found);
    CHECK_FALSE(by_sync(build(simple(), some(3)).bytes, 3).info().found);
}

TEST_CASE("sync: of two readings of the same frames, the sync that comes first, the narrower length, the lower byte") {
    // A two-byte sync, as UBX has, with the length after two more bytes: 0xB5 at offset 0 and 0x62 at offset 1
    // both start a chain, and the first is the frame's start.
    Layout l;
    l.head.push_back(0xB5);
    l.head.push_back(0x62);
    l.head.push_back(0x10);
    l.head.push_back(0x20);
    l.trailer = 2;
    const Built b = build(l, some(30));
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().sync == 0xB5);
    CHECK(s.info().length_offset == 4);
    CHECK(same_frames(s, b.frames));
    // And the other order of the same two bytes, 0x62 first.
    l.head[0] = 0x62;
    l.head[1] = 0xB5;
    const Segmentation t = by_sync(build(l, some(30)).bytes);
    REQUIRE(t.info().found);
    CHECK(t.info().sync == 0x62);
    CHECK(t.info().length_offset == 4);
    // Three bytes that repeat: the sync that comes first, whichever has the lower value.
    l.head[0] = 0x70;
    l.head[1] = 0x71;
    l.head[2] = 0x72;
    const Segmentation u = by_sync(build(l, some(30)).bytes);
    REQUIRE(u.info().found);
    CHECK(u.info().sync == 0x70);
    CHECK(u.info().length_offset == 4);
}

TEST_CASE("sync: of two readings that differ only in the byte, the lower one") {
    // A sync byte that is two bytes: the same sync twice, the readings differ only in where they start, so the
    // first is the sync that comes first. A tie that remains is between bytes that start the same frames: none
    // can, so the rule is exercised with the same frame start through a stream where two bytes lead into one length.
    const Built b = build(simple(0x20), some(30));
    const Segmentation s = by_sync(b.bytes);
    REQUIRE(s.info().found);
    CHECK(s.info().sync == 0x20);
}

TEST_CASE("sync: the frames of UBX, MAVLink 1 and MAVLink 2 are found exactly") {
    struct Expect { const char* name; std::uint8_t sync; std::uint32_t offset; std::int32_t adjust; };
    const Expect expects[3] = { { "ubx", 0xB5, 4, 8 }, { "mavlink1", 0xFE, 1, 8 }, { "mavlink2", 0xFD, 1, 12 } };
    for (int n = 0; n < 3; ++n) {
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            for (unsigned jitter = 0; jitter <= 300; jitter += 300) {
                const Dataset d = make(expects[n].name, seed, 200, jitter);
                const Segmentation s = bw::segment_by_sync(d.capture(), SegmentationOptions());
                INFO(expects[n].name << " seed " << seed << " jitter " << jitter);
                REQUIRE(s.info().found);
                CHECK(s.info().kind == bw::FramingKind::Contiguous);
                CHECK(s.info().sync == expects[n].sync);
                CHECK(s.info().length_offset == expects[n].offset);
                CHECK(s.info().length_bytes == 1);
                CHECK(s.info().length_adjust == expects[n].adjust);
                CHECK(s.info().breaks == 0);
                const bw::SegmentationScore score = bw::score_segmentation(d.frames(), s.frames());
                CHECK(score.exact_frames == 200);
                CHECK(score.found_frames == 200);
                CHECK(score.boundary_hits == score.truth_boundaries);
            }
        }
    }
}

TEST_CASE("sync: nothing else of the corpus, and no noise, is taken for frames that say their length") {
    const char* names[5] = { "slip", "hdlc-ppp", "nmea0183", "modbus-rtu", "ubx" };
    for (int n = 0; n < 4; ++n) {                                           // not "ubx": it is the one that is
        for (std::uint64_t seed = 1; seed <= 4; ++seed) {
            const Dataset d = make(names[n], seed, 200, seed % 2 ? 0 : 300);
            INFO(names[n] << " seed " << seed);
            CHECK_FALSE(bw::segment_by_sync(d.capture(), SegmentationOptions()).info().found);
        }
    }
    for (std::uint64_t seed = 1; seed <= 6; ++seed) {
        CAPTURE(seed);
        CHECK_FALSE(by_sync(noise_of(seed, 8000)).info().found);
    }
    // Events of more than one byte, or of none, are not a stream of bytes.
    const Built b = build(simple(), some(30));
    Capture two, none;
    for (std::size_t i = 0; i < b.bytes.size(); ++i) {
        two.add_event(EventInfo(), i == 7 ? Bytes(2, b.bytes[i]) : Bytes(1, b.bytes[i]));
        none.add_event(EventInfo(), i == 7 ? Bytes() : Bytes(1, b.bytes[i]));
    }
    CHECK_FALSE(bw::segment_by_sync(two, SegmentationOptions()).info().found);
    CHECK_FALSE(bw::segment_by_sync(none, SegmentationOptions()).info().found);
    CHECK(by_sync(b.bytes).info().found);
}

TEST_CASE("sync: flags first, then gaps, and the sync bytes where there are no gaps or where they cut finer") {
    // Where there are no gaps: the sync bytes.
    const Dataset ubx = make("ubx", 3, 90);
    CHECK_FALSE(bw::segment_by_gaps(ubx.capture(), SegmentationOptions()).info().found);
    const Segmentation by_bytes = bw::segment_frames(ubx.capture(), SegmentationOptions());
    REQUIRE(by_bytes.info().found);
    CHECK(by_bytes.info().kind == bw::FramingKind::Contiguous);
    CHECK(same_frames(by_bytes, ubx.frames()));

    // Frames in bursts of three, with a silence before each burst: the gaps find the bursts, and the sync bytes
    // the frames, which cut at every place the gaps do and in more.
    {
        Capture c;
        std::int64_t t = 0;
        std::size_t  next = 0;
        for (std::size_t i = 0; i < ubx.capture().event_count(); ++i) {
            if (next < ubx.frames().size() && ubx.frames()[next].first_event == i) {
                t += next % 3 == 0 && next > 0 ? 1000000 : 1000;
                ++next;
            } else {
                t += 1000;
            }
            EventInfo info;
            info.has_time = true;
            info.time_ns  = t;
            c.add_event(info, ubx.capture().event_bytes(i));
        }
        const Segmentation gaps = bw::segment_by_gaps(c, SegmentationOptions());
        REQUIRE(gaps.info().found);
        CHECK(gaps.frame_count() == 30);
        const Segmentation chosen = bw::segment_frames(c, SegmentationOptions());
        CHECK(chosen.info().kind == bw::FramingKind::Contiguous);
        CHECK(same_frames(chosen, ubx.frames()));
    }

    // The same bursts with bytes before the first frame and a frame cut short at the end: the frames do not
    // cover the capture, and that is not a place where they differ from the gaps.
    {
        Capture c;
        std::int64_t t = 0;
        std::size_t  next = 0;
        const std::size_t lead = 3;
        const std::size_t cut  = 4;
        for (std::size_t i = 0; i < lead; ++i) {
            EventInfo info;
            info.has_time = true;
            info.time_ns  = t += 1000;
            c.add_event(info, Bytes(1, 0x77));
        }
        for (std::size_t i = 0; i + cut < ubx.capture().event_count(); ++i) {
            if (next < ubx.frames().size() && ubx.frames()[next].first_event == i) {
                t += next % 3 == 2 ? 1000000 : 1000;                         // so one is before the frame that is cut
                ++next;
            } else {
                t += 1000;
            }
            EventInfo info;
            info.has_time = true;
            info.time_ns  = t;
            c.add_event(info, ubx.capture().event_bytes(i));
        }
        const Segmentation chosen = bw::segment_frames(c, SegmentationOptions());
        CHECK(chosen.info().kind == bw::FramingKind::Contiguous);
        CHECK(chosen.frame_count() == 89);                                  // the last one is cut short
    }

    // A silence in the middle of every third frame: the gaps cut where the sync bytes do not.
    {
        Capture c;
        std::int64_t t = 0;
        std::size_t  frame = 0;
        for (std::size_t i = 0; i < ubx.capture().event_count(); ++i) {
            while (frame + 1 < ubx.frames().size() && ubx.frames()[frame].first_event + ubx.frames()[frame].event_count <= i) {
                ++frame;
            }
            const bool middle = frame % 3 == 0 && i == ubx.frames()[frame].first_event + ubx.frames()[frame].event_count / 2;
            t += middle ? 1000000 : 1000;
            EventInfo info;
            info.has_time = true;
            info.time_ns  = t;
            c.add_event(info, ubx.capture().event_bytes(i));
        }
        const Segmentation gaps = bw::segment_by_gaps(c, SegmentationOptions());
        REQUIRE(gaps.info().found);
        CHECK(gaps.frame_count() < 90);
        const Segmentation chosen = bw::segment_frames(c, SegmentationOptions());
        CHECK(chosen.info().kind == bw::FramingKind::IdleGap);
        CHECK(chosen.frame_count() == gaps.frame_count());
    }

    // A silence in the middle of each frame: the gaps cut where the sync bytes do not, so the gaps are the cut.
    {
        Capture c;
        std::int64_t t = 0;
        std::size_t  frame = 0;
        for (std::size_t i = 0; i < ubx.capture().event_count(); ++i) {
            while (frame + 1 < ubx.frames().size() && ubx.frames()[frame].first_event + ubx.frames()[frame].event_count <= i) {
                ++frame;
            }
            const bool middle = i == ubx.frames()[frame].first_event + ubx.frames()[frame].event_count / 2;
            t += middle ? 1000000 : 1000;
            EventInfo info;
            info.has_time = true;
            info.time_ns  = t;
            c.add_event(info, ubx.capture().event_bytes(i));
        }
        REQUIRE(bw::segment_by_sync(c, SegmentationOptions()).info().found);
        const Segmentation gaps = bw::segment_by_gaps(c, SegmentationOptions());
        REQUIRE(gaps.info().found);
        const Segmentation chosen = bw::segment_frames(c, SegmentationOptions());
        CHECK(chosen.info().kind == bw::FramingKind::IdleGap);
        CHECK(chosen.frame_count() == gaps.frame_count());
    }

    // A silence between every frame: the same frames either way, and the gaps are what is reported.
    {
        Capture c;
        std::int64_t t = 0;
        std::size_t  next = 0;
        for (std::size_t i = 0; i < ubx.capture().event_count(); ++i) {
            if (next < ubx.frames().size() && ubx.frames()[next].first_event == i) {
                t += 1000000;
                ++next;
            } else {
                t += 1000;
            }
            EventInfo info;
            info.has_time = true;
            info.time_ns  = t;
            c.add_event(info, ubx.capture().event_bytes(i));
        }
        const Segmentation chosen = bw::segment_frames(c, SegmentationOptions());
        CHECK(chosen.info().kind == bw::FramingKind::IdleGap);
        CHECK(chosen.frame_count() == 90);
    }

    // Text that is also frames that say their length: the sync byte and the length are the frames, and the lines,
    // which cut each of them at a line feed that is inside, are not. 'S', a length that is printable (the size of
    // the payload and 0x20, so that all is text), and a payload with a line feed in the middle and a tail of
    // zero to two bytes, so that the length is one.
    {
        Bytes text;
        std::vector<FrameSpan> frames;
        for (std::size_t i = 0; i < 40; ++i) {
            const std::size_t tail = i % 3;
            const std::uint64_t first = text.size();
            text.push_back('S');
            text.push_back(static_cast<std::uint8_t>(0x20 + 5 + tail));    // the payload: ab, the line feed, Z and the tail
            text.push_back(static_cast<std::uint8_t>('a' + i % 10));
            text.push_back(static_cast<std::uint8_t>('k' + i % 10));
            text.push_back(0x0A);
            text.push_back('Z');
            for (std::size_t k = 0; k < tail; ++k) {
                text.push_back(static_cast<std::uint8_t>('p' + (i + k) % 7));
            }
            frames.push_back(span(first, text.size() - first));
        }
        REQUIRE(bw::segment_by_lines(capture_of(text), SegmentationOptions()).info().found);
        REQUIRE(by_sync(text).info().found);
        const Segmentation chosen = bw::segment_frames(capture_of(text), SegmentationOptions());
        CHECK(chosen.info().kind == bw::FramingKind::Contiguous);
        CHECK(same_frames(chosen, frames));
    }

    // Modbus RTU: gaps, and no sync.
    const Dataset modbus = make("modbus-rtu", 1, 50, 300);
    CHECK(bw::segment_frames(modbus.capture(), SegmentationOptions()).info().kind == bw::FramingKind::IdleGap);
    // SLIP: flags.
    CHECK(bw::segment_frames(make("slip", 1, 50).capture(), SegmentationOptions()).info().kind == bw::FramingKind::Flagged);
}

TEST_CASE("sync: the pipeline names it in the model and in the report") {
    const char* names[3] = { "ubx", "mavlink1", "mavlink2" };
    const char* lines[3] = {
        "framing    sync byte 0xB5, frame size = the 1-byte length at offset 4 plus 8 (0 breaks in the chain)\n",
        "framing    sync byte 0xFE, frame size = the 1-byte length at offset 1 plus 8 (0 breaks in the chain)\n",
        "framing    sync byte 0xFD, frame size = the 1-byte length at offset 1 plus 12 (0 breaks in the chain)\n" };
    for (int n = 0; n < 3; ++n) {
        const Dataset d = make(names[n], 3, 300);
        const bw::Analysis a = bw::analyze(d.capture(), bw::AnalyzeOptions());
        INFO(names[n]);
        CHECK(a.model().framing().kind == bw::FramingKind::Contiguous);
        CHECK(a.info().frames == 300);
        CHECK(bw::describe_analysis(a).find(lines[n]) != std::string::npos);
        CHECK(bw::describe_model(a.model()).find("framing: contiguous, nothing between frames\n") != std::string::npos);
    }

    // What the later stages make of the frames that were found is what they make of the true ones (the baseline
    // of docs/roadmap.md): the same message types and fields, from the first of them on.
    for (int n = 0; n < 3; ++n) {
        const Dataset d = make(names[n], 3, 200);
        bw::SegmentationInfo info;
        info.found = true;
        const std::string given = bw::describe_model(bw::analyze_frames(d.capture(), Segmentation(info, d.frames()), bw::AnalyzeOptions()).model());
        const std::string found = bw::describe_model(bw::analyze(d.capture(), bw::AnalyzeOptions()).model());
        INFO(names[n]);
        REQUIRE(given.find("message type 0") != std::string::npos);
        CHECK(found.substr(found.find("message type 0")) == given.substr(given.find("message type 0")));
    }

    // Frames of one size, and a length of two bytes, in the report; and the plural of a break.
    const Segmentation fixed = by_sync(build(simple(), std::vector<std::uint32_t>(12, 4)).bytes);
    const bw::Analysis fa = bw::analyze_frames(capture_of(build(simple(), std::vector<std::uint32_t>(12, 4)).bytes), fixed,
                                               bw::AnalyzeOptions());
    CHECK(bw::describe_analysis(fa).find("framing    sync byte 0xA5, frames of 9 bytes (0 breaks in the chain)\n") != std::string::npos);

    bw::SegmentationInfo info;
    info.found             = true;
    info.kind              = bw::FramingKind::Contiguous;
    info.sync              = 0xC3;
    info.length_offset     = 3;
    info.length_bytes      = 2;
    info.length_big_endian = true;
    info.length_adjust     = -2;
    info.breaks            = 1;
    const Built given = build(simple(), some(12));
    const bw::Analysis ga = bw::analyze_frames(capture_of(given.bytes), Segmentation(info, given.frames), bw::AnalyzeOptions());
    CHECK(bw::describe_analysis(ga).find("framing    sync byte 0xC3, frame size = the big-endian 2-byte length at offset 3 minus 2 (1 break in the chain)\n") !=
          std::string::npos);
    info.length_big_endian = false;
    info.length_adjust     = 0;
    info.breaks            = 2;
    const bw::Analysis la = bw::analyze_frames(capture_of(given.bytes), Segmentation(info, given.frames), bw::AnalyzeOptions());
    CHECK(bw::describe_analysis(la).find("frame size = the little-endian 2-byte length at offset 3 plus 0 (2 breaks in the chain)\n") !=
          std::string::npos);
}
