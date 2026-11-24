// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Message kinds (bw/messages.h): a kind of message with frames of several sizes is
// found from a length field and a discriminator, and analyze() makes one type of it
// when a checksum explains all of its frames. The frames here are made in the test,
// in the shape of MAVLink 2 but with a plain CRC-16 where that is not the point:
//
//   0xAA | length | id | counter | payload (length bytes) | CRC-16/MODBUS of everything from the length
//
// so that size = length + 6, the id is at offset 2 and the counter changes in each frame.

#include "doctest.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/messages.h"
#include "bw/segmentation.h"
#include "frame_fixtures.h"

using fixtures::Bytes;

namespace {

Bytes make_frame(fixtures::Random* rng, std::uint8_t id, std::size_t payload, std::uint8_t counter,
                 int length_error = 0) {
    Bytes f;
    f.push_back(0xAA);
    f.push_back(static_cast<std::uint8_t>(payload + length_error));
    f.push_back(id);
    f.push_back(counter);
    for (std::size_t i = 0; i < payload; ++i) {
        f.push_back(rng->byte());
    }
    const std::uint16_t crc = fixtures::crc16_modbus(f, 1, f.size());
    f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
    f.push_back(static_cast<std::uint8_t>(crc >> 8));
    return f;
}

struct Spec {
    std::uint8_t id;
    std::size_t  payload;
    std::size_t  count;
};

// The frames of the specs, in an order that mixes them, with a counter that goes up in all.
std::vector<Bytes> make_frames(unsigned seed, const std::vector<Spec>& specs) {
    fixtures::Random rng(seed);
    std::vector<Spec> left = specs;
    std::vector<Bytes> out;
    std::uint8_t counter = 0;
    bool any = true;
    while (any) {
        any = false;
        for (std::size_t s = 0; s < left.size(); ++s) {
            if (left[s].count > 0) {
                out.push_back(make_frame(&rng, left[s].id, left[s].payload, counter++));
                --left[s].count;
                any = true;
            }
        }
    }
    return out;
}

bw::Segmentation segmentation_of(const bw::Capture& c) {
    return bw::segment_by_gaps(c, bw::SegmentationOptions());
}

bw::MessageKinds kinds_of(const std::vector<Bytes>& frames, std::uint32_t min_frames = 4) {
    const bw::Capture c = fixtures::capture_of(frames);
    return bw::find_message_kinds(c, segmentation_of(c), min_frames);
}

std::vector<Spec> two_messages() {
    std::vector<Spec> specs;
    specs.push_back({ 1, 3, 10 });
    specs.push_back({ 1, 5, 10 });
    specs.push_back({ 2, 4, 10 });
    specs.push_back({ 2, 8, 10 });
    specs.push_back({ 3, 6, 10 });
    return specs;
}

} // namespace

TEST_CASE("message kinds: the length, the key and the kinds of frames that differ in size") {
    const bw::MessageKinds k = kinds_of(make_frames(1, two_messages()));
    REQUIRE(k.found);
    CHECK(k.length.offset == 1);
    CHECK(k.length.bytes == 1);
    CHECK_FALSE(k.length.big_endian);
    CHECK(k.length.adjust == 6);                      // the 4 bytes before the payload and the 2 of the CRC
    CHECK(k.length.evidence_bits == 8 * 4);           // five sizes: the first sets the constant, four are predicted
    // The id is the key: constant in every size and not the same in all. The counter is not (it changes in
    // each frame), nor is the start byte (it is the same everywhere).
    REQUIRE(k.key_offsets.size() == 1);
    CHECK(k.key_offsets[0] == 2);
    // Two kinds, of two sizes each: the one of one size is not a kind.
    REQUIRE(k.kinds.size() == 2);
    CHECK(k.kinds[0].sizes == std::vector<std::uint32_t>({ 9, 11 }));         // sizes are payload + 6
    CHECK(k.kinds[0].key == Bytes(1, 1));
    CHECK(k.kinds[0].frames == 20);
    CHECK(k.kinds[1].sizes == std::vector<std::uint32_t>({ 10, 14 }));
    CHECK(k.kinds[1].key == Bytes(1, 2));
    CHECK(k.kinds[1].frames == 20);

    // Every frame knows its kind, or none.
    REQUIRE(k.frame_kind.size() == 50);
    std::size_t in_first = 0, in_second = 0, in_none = 0;
    for (std::size_t i = 0; i < k.frame_kind.size(); ++i) {
        in_first  += k.frame_kind[i] == 0;
        in_second += k.frame_kind[i] == 1;
        in_none   += k.frame_kind[i] == -1;
    }
    CHECK(in_first == 20);
    CHECK(in_second == 20);
    CHECK(in_none == 10);                             // message 3, of one size
}

TEST_CASE("message kinds: the length can be of two bytes, in either order, and any constant") {
    // 0xBB | id | length (2 bytes) | payload | 0xCC: size = length + 5. Payloads of 250 and 260 bytes are the
    // lengths that need both bytes: the low byte of 260 is 4, which is not what 250 and 260 differ by.
    for (int order = 0; order < 2; ++order) {
        CAPTURE(order);
        fixtures::Random rng(2);
        std::vector<Bytes> frames;
        for (std::size_t n = 0; n < 20; ++n) {
            const std::size_t payload = n % 2 == 0 ? 250 : 260;
            Bytes f;
            f.push_back(0xBB);
            f.push_back(static_cast<std::uint8_t>(n % 2 == 0 ? 7 : 8));      // the id: one for each size
            if (order == 0) {
                f.push_back(static_cast<std::uint8_t>(payload & 0xFF));
                f.push_back(static_cast<std::uint8_t>(payload >> 8));
            } else {
                f.push_back(static_cast<std::uint8_t>(payload >> 8));
                f.push_back(static_cast<std::uint8_t>(payload & 0xFF));
            }
            for (std::size_t i = 0; i < payload; ++i) {
                f.push_back(rng.byte());
            }
            f.push_back(0xCC);
            frames.push_back(f);
        }
        const bw::MessageKinds k = kinds_of(frames);
        // The id has the same value in every frame of a size, and sizes alternate: two sizes, two ids.
        REQUIRE(k.found);
        CHECK(k.length.offset == 2);
        CHECK(k.length.bytes == 2);
        CHECK(k.length.big_endian == (order == 1));
        CHECK(k.length.adjust == 5);
        CHECK(k.length.evidence_bits == 16 * 1);
        CHECK(k.kinds.empty());                       // one size for each id: nothing to put together
    }
}

TEST_CASE("message kinds: the narrower length and the lower offset win") {
    // A length of one byte followed by a zero byte is also a length of two bytes, little-endian, and a byte
    // of the same value in the next frame's... only the one byte, at its offset, is the length.
    std::vector<Bytes> frames;
    fixtures::Random   rng(3);
    for (int n = 0; n < 20; ++n) {
        const std::size_t payload = (n % 2 == 0) ? 4 : 7;
        Bytes f;
        f.push_back(0xAA);
        f.push_back(static_cast<std::uint8_t>(payload));       // the length at 1,
        f.push_back(0);                                         // and a zero after it
        f.push_back(static_cast<std::uint8_t>(n % 2 == 0 ? 1 : 2));
        for (std::size_t i = 0; i < payload; ++i) {
            f.push_back(rng.byte());
        }
        frames.push_back(f);
    }
    const bw::MessageKinds k = kinds_of(frames);
    REQUIRE(k.found);
    CHECK(k.length.offset == 1);
    CHECK(k.length.bytes == 1);
    CHECK(k.length.adjust == 4);
}

TEST_CASE("message kinds: no length, no kinds") {
    // Sizes that nothing in the bytes says: random frames of three sizes.
    fixtures::Random rng(4);
    std::vector<Bytes> frames;
    for (int n = 0; n < 30; ++n) {
        Bytes f;
        const std::size_t size = 6 + static_cast<std::size_t>(n % 3) * 2;
        for (std::size_t i = 0; i < size; ++i) {
            f.push_back(rng.byte());
        }
        frames.push_back(f);
    }
    const bw::MessageKinds k = kinds_of(frames);
    CHECK_FALSE(k.found);
    CHECK(k.kinds.empty());
    CHECK(k.frame_kind.size() == 30);
    for (std::size_t i = 0; i < k.frame_kind.size(); ++i) {
        CHECK(k.frame_kind[i] == -1);
    }

    // One size: any byte that does not change would be the length of it.
    std::vector<Spec> one;
    one.push_back({ 1, 4, 20 });
    const bw::MessageKinds only = kinds_of(make_frames(5, one));
    CHECK_FALSE(only.found);
    CHECK(only.kinds.empty());
    CHECK(only.length.bytes == 0);

    // Two sizes, and a byte that is a constant in each: it is the length only if it differs by the sizes' difference.
    std::vector<Bytes> two;
    for (int n = 0; n < 20; ++n) {
        Bytes f(n % 2 == 0 ? 6 : 9, 0x11);
        f[1] = static_cast<std::uint8_t>(n % 2 == 0 ? 10 : 20);     // 10 more for 3 more bytes
        two.push_back(f);
    }
    CHECK_FALSE(kinds_of(two).found);
}

TEST_CASE("message kinds: a size of too few frames is not looked at, and a frame that lies about its size is not a part") {
    std::vector<Spec> specs = two_messages();
    // Two frames of 13 bytes (payload 7) of message 1: too few to be a size of their own, and 13 is not a size
    // that the rest has; and two more of message 2 whose length says 10 and are of 15 bytes.
    specs.push_back({ 1, 7, 2 });
    std::vector<Bytes> frames = make_frames(6, specs);
    fixtures::Random   rng(60);
    frames.push_back(make_frame(&rng, 2, 9, 200, 1));                  // the length says 10, the frame is of 15
    frames.push_back(make_frame(&rng, 2, 9, 201, 1));
    const bw::MessageKinds k = kinds_of(frames);
    REQUIRE(k.found);
    REQUIRE(k.kinds.size() == 2);
    // The rare frames of message 1 are in its kind, and the sizes of the kind include theirs.
    CHECK(k.kinds[0].sizes == std::vector<std::uint32_t>({ 9, 11, 13 }));
    CHECK(k.kinds[0].frames == 22);
    // The ones whose length is wrong are not in the second kind.
    CHECK(k.kinds[1].sizes == std::vector<std::uint32_t>({ 10, 14 }));
    CHECK(k.kinds[1].frames == 20);
    // min_frames moves what is rare: with 2, the two frames of 13 bytes have a size of their own, and so do the two
    // that lie, which stops the length from holding for all.
    const bw::MessageKinds low = kinds_of(frames, 2);
    CHECK_FALSE(low.found);
}

TEST_CASE("message kinds: a size that two messages share has no id of its own, and nothing is put together") {
    std::vector<Spec> specs;
    specs.push_back({ 1, 3, 10 });
    specs.push_back({ 1, 5, 10 });
    specs.push_back({ 2, 5, 10 });            // the same size as the second of the first message
    specs.push_back({ 2, 8, 10 });
    const bw::MessageKinds k = kinds_of(make_frames(7, specs));
    REQUIRE(k.length.adjust == 6);
    CHECK_FALSE(k.found);                     // the id is not a single value in a size of 11
    CHECK(k.kinds.empty());
}

TEST_CASE("analyze: the sizes of a kind are one message type, with its length, its payload and its checksum") {
    const std::vector<Bytes> frames = make_frames(8, two_messages());
    const bw::Capture        c      = fixtures::capture_of(frames);
    const bw::Analysis       a      = bw::analyze_frames(c, segmentation_of(c), bw::AnalyzeOptions());
    REQUIRE(a.type_count() == 3);
    CHECK(a.info().ignored_frames == 0);

    // The two kinds, then the message of one size; most frames first, the smaller size first on a tie.
    CHECK(a.type_report(0).frames == 20);
    CHECK(a.type_report(0).frame_bytes == 9);
    CHECK(a.type_report(0).largest_frame_bytes == 11);
    CHECK(a.type_report(1).frames == 20);
    CHECK(a.type_report(1).frame_bytes == 10);
    CHECK(a.type_report(1).largest_frame_bytes == 14);
    CHECK(a.type_report(2).frames == 10);
    CHECK(a.type_report(2).frame_bytes == 12);
    CHECK(a.type_report(2).largest_frame_bytes == 12);
    for (std::size_t t = 0; t < 3; ++t) {
        const bw::ChecksumFinding& cs = a.type_report(t).checksum;
        REQUIRE(cs.found);
        CHECK(bw::checksum_algorithm_name(cs.algorithm) == "CRC-16/MODBUS");
        CHECK(cs.header_skip == 1);
        CHECK(cs.trailer_skip == 0);
        CHECK_FALSE(cs.seeded);
    }

    const bw::Model m = a.model();
    REQUIRE(m.message_type_count() == 3);
    // The first: 0xAA, the length, the id, the counter, the payload, the checksum.
    REQUIRE(m.field_count(0) == 6);
    CHECK(m.field(0, 0).kind == bw::FieldKind::Constant);
    CHECK(m.field(0, 0).constant == 0xAA);
    CHECK(m.field_name(0, 1) == "length");
    CHECK(m.field(0, 1).kind == bw::FieldKind::Length);
    CHECK(m.field(0, 1).bit_size == 8);
    CHECK(m.field(0, 1).byte_order == bw::ByteOrder::NotApplicable);
    CHECK(m.field(0, 1).evidence_bits == 8 * 4);
    CHECK(m.field(0, 2).kind == bw::FieldKind::Constant);
    CHECK(m.field(0, 2).constant == 1);
    CHECK(m.field_name(0, 4) == "payload");
    CHECK(m.field(0, 4).kind == bw::FieldKind::Payload);
    CHECK(m.field(0, 4).size_kind == bw::SizeKind::FromField);
    CHECK(m.field(0, 4).size_field == 1);
    CHECK(m.field_name(0, 5) == "checksum");
    CHECK(m.field(0, 5).kind == bw::FieldKind::Checksum);
    CHECK(m.field(0, 5).bit_size == 16);
    CHECK(m.field(0, 5).byte_order == bw::ByteOrder::Little);
    CHECK(m.field(0, 5).covers_first == 1);           // from the length
    CHECK(m.field(0, 5).covers_last == 4);            // to the payload
    CHECK(m.field_detail(0, 5) == "CRC-16/MODBUS");
    CHECK_FALSE(m.field_position(0, 5).fixed);        // after a payload of a size that varies

    // The message of one size is as it has been: every field of a size of its own, at its place.
    for (std::size_t i = 0; i < m.field_count(2); ++i) {
        CHECK(m.field(2, i).size_kind == bw::SizeKind::Fixed);
        CHECK(m.field_position(2, i).fixed);
    }

    const std::string text = bw::describe_analysis(a);
    CHECK(text.find("type0      9 to 11 bytes, 20 frames; checksum CRC-16/MODBUS") != std::string::npos);
    CHECK(text.find("type1      10 to 14 bytes, 20 frames; checksum CRC-16/MODBUS") != std::string::npos);
    CHECK(text.find("type2      12 bytes, 10 frames; checksum CRC-16/MODBUS") != std::string::npos);
}

TEST_CASE("analyze: without a checksum that explains the frames of all the sizes, each size is a type as before") {
    // No checksum: the bytes after the payload are random. A length and a key are found, and the sizes are not
    // put together, because where the payload starts needs to know what follows it.
    fixtures::Random rng(9);
    std::vector<Bytes> frames = make_frames(9, two_messages());
    for (std::size_t i = 0; i < frames.size(); ++i) {
        frames[i][frames[i].size() - 2] = rng.byte();
        frames[i][frames[i].size() - 1] = rng.byte();
    }
    const bw::Capture  c = fixtures::capture_of(frames);
    const bw::Analysis a = bw::analyze_frames(c, segmentation_of(c), bw::AnalyzeOptions());
    CHECK(bw::find_message_kinds(c, segmentation_of(c), 4).found);
    CHECK(a.type_count() == 5);
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        CHECK(a.type_report(t).frame_bytes == a.type_report(t).largest_frame_bytes);
        CHECK_FALSE(a.type_report(t).checksum.found);
    }
}

TEST_CASE("analyze: the rare frames of a kind are counted with it, and not left out") {
    std::vector<Spec> specs = two_messages();
    specs.push_back({ 1, 7, 2 });                     // two frames of a size of their own: too few for a type
    const std::vector<Bytes> frames = make_frames(10, specs);
    const bw::Capture        c      = fixtures::capture_of(frames);
    const bw::Analysis       a      = bw::analyze_frames(c, segmentation_of(c), bw::AnalyzeOptions());
    REQUIRE(a.type_count() == 3);
    CHECK(a.info().ignored_frames == 0);
    CHECK(a.type_report(0).frames == 22);
    CHECK(a.type_report(0).frame_bytes == 9);
    CHECK(a.type_report(0).largest_frame_bytes == 13);
    CHECK(a.info().frames == 52);
}

TEST_CASE("analyze: sizes that share a discriminator but not a checksum are not put together") {
    // Two messages with the same id byte, where the CRC of the second has one more byte after what it covers
    // (a hidden byte, MAVLink's CRC_EXTRA): the id does not tell them apart, and the CRC does.
    fixtures::Random rng(11);
    std::vector<Bytes> frames;
    for (int n = 0; n < 40; ++n) {
        const bool        second  = n % 2 == 1;
        const std::size_t payload = second ? 6 : 3;
        Bytes             f       = make_frame(&rng, 1, payload, static_cast<std::uint8_t>(n));
        if (second) {
            // CRC over the same bytes and one more that is in no frame.
            Bytes covered(f.begin() + 1, f.end() - 2);
            covered.push_back(0x5A);
            const std::uint16_t crc = fixtures::crc16_modbus(covered, 0, covered.size());
            f[f.size() - 2] = static_cast<std::uint8_t>(crc & 0xFF);
            f[f.size() - 1] = static_cast<std::uint8_t>(crc >> 8);
        }
        frames.push_back(f);
    }
    const bw::Capture  c = fixtures::capture_of(frames);
    const bw::Analysis a = bw::analyze_frames(c, segmentation_of(c), bw::AnalyzeOptions());
    // The id is constant in each size and the same in both, so there is no key and nothing to put together.
    CHECK_FALSE(bw::find_message_kinds(c, segmentation_of(c), 4).found);
    REQUIRE(a.type_count() == 2);
    for (std::size_t t = 0; t < 2; ++t) {
        CHECK(a.type_report(t).frame_bytes == a.type_report(t).largest_frame_bytes);
    }
}

namespace {

// A kind of message of the shape that a test needs: `before` bytes of 0x11, the length of the payload, one byte
// of id, and the payload, of the sizes given for each id; and `after` is what follows, made by the caller.
typedef Bytes (*Tail)(const Bytes& covered);

Bytes crc16_tail(const Bytes& covered) {
    const std::uint16_t crc = fixtures::crc16_modbus(covered, 0, covered.size());
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(crc & 0xFF));
    out.push_back(static_cast<std::uint8_t>(crc >> 8));
    return out;
}

Bytes hex_xor_tail(const Bytes& covered) {
    std::uint8_t x = 0;
    for (std::size_t i = 0; i < covered.size(); ++i) {
        x = static_cast<std::uint8_t>(x ^ covered[i]);
    }
    static const char digits[] = "0123456789ABCDEF";
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(digits[x >> 4]));
    out.push_back(static_cast<std::uint8_t>(digits[x & 15]));
    return out;
}

Bytes star_hex_xor_tail(const Bytes& covered) {
    Bytes out = hex_xor_tail(covered);
    out.insert(out.begin(), '*');
    return out;
}

Bytes crc16_then_end_tail(const Bytes& covered) {
    Bytes out = crc16_tail(covered);
    out.push_back(0x0D);
    return out;
}

// Frames of ids 1 and 2, `per_size` of each size, mixed: the start byte, the length (of the payload, or of everything
// after it if `length_counts_all`), the id, the payload, and the tail made of the bytes from the length on. The
// payloads of id 2 are one byte longer than the ones given, so that the two ids share no size.
std::vector<Bytes> shaped(unsigned seed, const std::vector<std::size_t>& payloads, std::size_t per_size, Tail tail,
                          bool length_counts_all = false) {
    fixtures::Random rng(seed);
    std::vector<Bytes> out;
    for (std::size_t n = 0; n < per_size; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t s = 0; s < payloads.size(); ++s) {
                const std::size_t payload = payloads[s] + (id == 2 ? 1 : 0);
                Bytes             f;
                f.push_back(0xAA);
                f.push_back(0);                                     // the length, below
                f.push_back(static_cast<std::uint8_t>(id));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const Bytes covered(f.begin() + 1, f.end());
                // The length is known only when the tail is: of the payload alone, or counting it.
                const Bytes after = tail(covered);
                f[1] = static_cast<std::uint8_t>(length_counts_all ? f.size() - 2 + after.size() : payload);
                const Bytes covered_now(f.begin() + 1, f.end());
                const Bytes again = tail(covered_now);
                f.insert(f.end(), again.begin(), again.end());
                out.push_back(f);
            }
        }
    }
    return out;
}

bw::Analysis analysis_of(const std::vector<Bytes>& frames) {
    const bw::Capture c = fixtures::capture_of(frames);
    return bw::analyze_frames(c, segmentation_of(c), bw::AnalyzeOptions());
}

} // namespace

TEST_CASE("message kinds: the length is looked for in the first 16 bytes, and not beyond") {
    // `before` bytes of 0x11, the length, the id and the payload: size = payload + before + 2.
    for (std::uint32_t before = 14; before <= 17; ++before) {
        CAPTURE(before);
        fixtures::Random   rng(20);
        std::vector<Bytes> frames;
        for (int n = 0; n < 10; ++n) {
            for (std::size_t id = 1; id <= 2; ++id) {
                for (std::size_t payload = 4 + id; payload <= 6 + id; payload += 2) {
                    Bytes f(before, 0x11);
                    f.push_back(static_cast<std::uint8_t>(payload));
                    f.push_back(static_cast<std::uint8_t>(id));
                    for (std::size_t i = 0; i < payload; ++i) {
                        f.push_back(rng.byte());
                    }
                    frames.push_back(f);
                }
            }
        }
        const bw::MessageKinds k = kinds_of(frames);
        CHECK(k.found == (before <= 15));
        if (k.found) {
            CHECK(k.length.offset == before);
            CHECK(k.length.adjust == static_cast<std::int64_t>(before) + 2);
            CHECK(k.kinds.size() == 2);
        } else {
            CHECK(k.kinds.empty());
            CHECK(k.length.bytes == 0);               // nothing is left of what was tried
        }
    }
}

TEST_CASE("message kinds: one frame of a size with a wrong length is no length at all") {
    // The length has to hold for every frame of every size there are enough of: it is not told from a byte that
    // happens to follow the size. (A capture with errors in it is for a tolerance that is not here yet.)
    std::vector<Bytes> frames = make_frames(21, two_messages());
    REQUIRE(kinds_of(frames).found);
    frames[17][1] = static_cast<std::uint8_t>(frames[17][1] + 1);
    CHECK_FALSE(kinds_of(frames).found);
    // And it is checked in all of the frames, not only the first of each size.
    Bytes& last = frames.back();
    last[1] = static_cast<std::uint8_t>(last[1] + 1);
    frames[17][1] = static_cast<std::uint8_t>(frames[17][1] - 1);
    CHECK_FALSE(kinds_of(frames).found);
}

TEST_CASE("message kinds: a number that leaves no room for itself in the frame is not its length") {
    // A byte that is the size less 3, at offset 3: the frame would end before the byte does.
    std::vector<Bytes> frames;
    for (int n = 0; n < 20; ++n) {
        const std::size_t size = n % 2 == 0 ? 8 : 12;
        Bytes f(size, 0x11);
        f[2] = static_cast<std::uint8_t>(n % 2 == 0 ? 1 : 2);        // an id of each size
        f[3] = static_cast<std::uint8_t>(size - 3);
        frames.push_back(f);
    }
    CHECK_FALSE(kinds_of(frames).found);
}

TEST_CASE("message kinds: the key is of the header, not of what is in the payload") {
    // A payload byte that is the same in each size and different in the sizes of a message, at an offset past
    // the 6 bytes of the header and the CRC, is no part of the key, or two sizes of a message would differ in it.
    fixtures::Random   rng(22);
    std::vector<Bytes> frames;
    for (int n = 0; n < 10; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 4 + id; payload <= 8 + id; payload += 4) {
                Bytes f;
                f.push_back(0xAA);
                f.push_back(static_cast<std::uint8_t>(payload));
                f.push_back(static_cast<std::uint8_t>(id));
                f.push_back(static_cast<std::uint8_t>(n));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(i == 3 ? static_cast<std::uint8_t>(payload) : rng.byte());    // offset 7: the size
                }
                const Bytes crc = crc16_tail(Bytes(f.begin() + 1, f.end()));
                f.insert(f.end(), crc.begin(), crc.end());
                frames.push_back(f);
            }
        }
    }
    const bw::MessageKinds k = kinds_of(frames);
    REQUIRE(k.found);
    CHECK(k.key_offsets == std::vector<std::uint32_t>({ 2 }));
    CHECK(k.kinds.size() == 2);
}

TEST_CASE("message kinds: the two bytes of a length of two bytes are both the length, and neither is a key") {
    // Two messages, each with payloads of 250 and 260 bytes: the high byte of the length differs between the sizes
    // of each, and it is the length's, not the id's.
    fixtures::Random   rng(23);
    std::vector<Bytes> frames;
    for (int n = 0; n < 6; ++n) {
        for (std::size_t id = 7; id <= 8; ++id) {
            for (std::size_t payload = 250 + id - 7; payload <= 260 + id - 7; payload += 10) {
                Bytes f;
                f.push_back(0xBB);
                f.push_back(static_cast<std::uint8_t>(id));
                f.push_back(static_cast<std::uint8_t>(payload & 0xFF));
                f.push_back(static_cast<std::uint8_t>(payload >> 8));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                f.push_back(0xCC);
                frames.push_back(f);
            }
        }
    }
    const bw::MessageKinds k = kinds_of(frames);
    REQUIRE(k.found);
    CHECK(k.length.bytes == 2);
    CHECK(k.key_offsets == std::vector<std::uint32_t>({ 1 }));
    CHECK(k.kinds.size() == 2);
}

TEST_CASE("message kinds: with a single size, nothing is found, and nothing is left of the search") {
    std::vector<Spec> one;
    one.push_back({ 1, 4, 20 });
    const bw::MessageKinds only = kinds_of(make_frames(5, one));
    CHECK_FALSE(only.found);
    CHECK(only.length.bytes == 0);
    CHECK(only.length.evidence_bits == 0);
    CHECK(only.key_offsets.empty());
}

TEST_CASE("analyze: a kind whose checksum is text, or has a separator, or bytes after it, is not put together") {
    const std::vector<std::size_t> payloads = { 4, 7 };
    struct Row {
        const char* what;
        Tail        tail;
        std::size_t extra;                 // bytes after the payload: the header is 3, the tail follows
    };
    const Row rows[] = {
        { "two characters of text", hex_xor_tail, 0 },
        { "text after a star", star_hex_xor_tail, 0 },
        { "a CRC and a byte after it", crc16_then_end_tail, 0 },
    };
    for (std::size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); ++r) {
        CAPTURE(rows[r].what);
        const std::vector<Bytes> frames = shaped(30 + static_cast<unsigned>(r), payloads, 8, rows[r].tail);
        const bw::Analysis a = analysis_of(frames);
        CHECK(bw::find_message_kinds(fixtures::capture_of(frames), segmentation_of(fixtures::capture_of(frames)), 4).found);
        // A type for each size, each with its own checksum, as before: a type of several sizes has the checksum last.
        REQUIRE(a.type_count() == 4);
        for (std::size_t t = 0; t < a.type_count(); ++t) {
            CHECK(a.type_report(t).frame_bytes == a.type_report(t).largest_frame_bytes);
            CHECK(a.type_report(t).checksum.found);
        }
    }
}

TEST_CASE("analyze: a length that counts the checksum too is not the length of a payload") {
    // [start][length of everything after it][id][payload][CRC]: size = length + 2, and the CRC is in the length.
    const std::vector<Bytes> frames = shaped(40, { 4, 7 }, 8, crc16_tail, true);
    const bw::Analysis a = analysis_of(frames);
    REQUIRE(a.type_count() == 4);
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        CHECK(a.type_report(t).frame_bytes == a.type_report(t).largest_frame_bytes);
    }
}

TEST_CASE("analyze: what the checksum covers can be the payload alone") {
    // [start][length][id][counter][payload][CRC of the payload]: the CRC covers from byte 4.
    fixtures::Random   rng(41);
    std::vector<Bytes> frames;
    std::uint8_t       counter = 0;
    for (int n = 0; n < 10; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 4 + id; payload <= 7 + id; payload += 3) {
                Bytes f;
                f.push_back(0xAA);
                f.push_back(static_cast<std::uint8_t>(payload));
                f.push_back(static_cast<std::uint8_t>(id));
                f.push_back(counter++);
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const Bytes crc = crc16_tail(Bytes(f.begin() + 4, f.end()));
                f.insert(f.end(), crc.begin(), crc.end());
                frames.push_back(f);
            }
        }
    }
    const bw::Analysis a = analysis_of(frames);
    REQUIRE(a.type_count() == 2);
    const bw::Model m = a.model();
    for (std::size_t t = 0; t < 2; ++t) {
        REQUIRE(a.type_report(t).checksum.found);
        CHECK(a.type_report(t).checksum.header_skip == 4);
        CHECK(a.type_report(t).frame_bytes < a.type_report(t).largest_frame_bytes);
        const std::size_t last = m.field_count(t) - 1;          // the checksum, after the payload
        CHECK(m.field(t, last).kind == bw::FieldKind::Checksum);
        CHECK(m.field(t, last).covers_first == last - 1);       // the payload
        CHECK(m.field(t, last).covers_last == last - 1);
        CHECK(m.field(t, last).evidence_bits == a.type_report(t).checksum.evidence_bits);
    }
}

TEST_CASE("analyze: a header that does not break where the checksum starts is not a header") {
    // Two bytes of no structure in front, the second of which the CRC does not cover and the first of which
    // it does not either: bytes 0 and 1 are one run, and the checksum would start inside it.
    fixtures::Random   rng(42);
    std::vector<Bytes> frames;
    for (int n = 0; n < 10; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 4 + id; payload <= 7 + id; payload += 3) {
                Bytes f;
                f.push_back(rng.byte());
                f.push_back(rng.byte());
                f.push_back(static_cast<std::uint8_t>(payload));
                f.push_back(static_cast<std::uint8_t>(id));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const Bytes crc = crc16_tail(Bytes(f.begin() + 1, f.end()));
                f.insert(f.end(), crc.begin(), crc.end());
                frames.push_back(f);
            }
        }
    }
    const bw::Analysis a = analysis_of(frames);
    // The CRC starts at byte 1, in the middle of the run of bytes 0 and 1, so the sizes are not put together.
    CHECK(a.type_count() == 4);
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        CHECK(a.type_report(t).frame_bytes == a.type_report(t).largest_frame_bytes);
    }
}

TEST_CASE("analyze: a length with too many values to be one of a few is still the length, next to a counter") {
    // 20 sizes of each of two messages: the length has 20 values, so on its own it is a run of bytes of no structure,
    // as the counter after it is, and the two would be one run. The length is a field of its own all the same, and
    // what is before it and after it is read apart.
    fixtures::Random   rng(43);
    std::vector<Bytes> frames;
    std::uint8_t       counter = 0;
    for (int n = 0; n < 4; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 4 + 20 * (id - 1); payload < 24 + 20 * (id - 1); ++payload) {
                Bytes f;
                f.push_back(0xAA);
                f.push_back(static_cast<std::uint8_t>(payload));
                f.push_back(counter);                              // changes in every frame, in 1..250
                counter = static_cast<std::uint8_t>(counter % 250 + 1);
                f.push_back(static_cast<std::uint8_t>(id));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const Bytes crc = crc16_tail(Bytes(f.begin() + 1, f.end()));
                f.insert(f.end(), crc.begin(), crc.end());
                frames.push_back(f);
            }
        }
    }
    const bw::Analysis a = analysis_of(frames);
    REQUIRE(a.type_count() == 2);                                  // a type for each message, not for each size
    const bw::Model m = a.model();
    REQUIRE(m.field_count(0) == 6);                                // 0xAA, length, counter, id, payload, checksum
    CHECK(m.field_name(0, 1) == "length");
    CHECK(m.field(0, 1).kind == bw::FieldKind::Length);
    CHECK(m.field(0, 1).bit_size == 8);
    CHECK(m.field_position(0, 1).bit_offset == 8);
    CHECK(m.field(0, 2).bit_size == 8);                            // the counter, as it is: not a part of the length
    CHECK(m.field_position(0, 2).bit_offset == 16);
    CHECK(m.field(0, 3).kind == bw::FieldKind::Constant);
    CHECK(m.field(0, 3).constant == 1);
}

TEST_CASE("analyze: a length of two bytes is written with its order, in the model and in what Kaitai reads") {
    // [start][id][length, 2 bytes][payload][CRC of everything from the id]: sizes of 250 and 260 bytes of payload,
    // for which the low byte of the length alone is not the length.
    for (int order = 0; order < 2; ++order) {
        CAPTURE(order);
        fixtures::Random   rng(50);
        std::vector<Bytes> frames;
        for (int n = 0; n < 6; ++n) {
            for (std::size_t id = 7; id <= 8; ++id) {
                for (std::size_t payload = 250 + id - 7; payload <= 260 + id - 7; payload += 10) {
                    Bytes f;
                    f.push_back(0xBB);
                    f.push_back(static_cast<std::uint8_t>(id));
                    f.push_back(static_cast<std::uint8_t>(order == 0 ? (payload & 0xFF) : (payload >> 8)));
                    f.push_back(static_cast<std::uint8_t>(order == 0 ? (payload >> 8) : (payload & 0xFF)));
                    for (std::size_t i = 0; i < payload; ++i) {
                        f.push_back(rng.byte());
                    }
                    const Bytes crc = crc16_tail(Bytes(f.begin() + 1, f.end()));
                    f.insert(f.end(), crc.begin(), crc.end());
                    frames.push_back(f);
                }
            }
        }
        const bw::Analysis a = analysis_of(frames);
        REQUIRE(a.type_count() == 2);
        const bw::Model m = a.model();
        for (std::size_t t = 0; t < 2; ++t) {
            CAPTURE(t);
            REQUIRE(m.field_count(t) == 5);                // the start, the id, the length, the payload, the CRC
            CHECK(m.field_name(t, 2) == "length");
            CHECK(m.field(t, 2).kind == bw::FieldKind::Length);
            CHECK(m.field(t, 2).bit_size == 16);
            CHECK(m.field(t, 2).byte_order == (order == 0 ? bw::ByteOrder::Little : bw::ByteOrder::Big));
            CHECK(m.field(t, 2).evidence_bits == 3 * 16);       // four sizes: three are predicted, two bytes each
            CHECK(m.field(t, 3).size_field == 2);
            CHECK(m.field(t, 3).size_kind == bw::SizeKind::FromField);
        }
    }
}

namespace {

std::uint32_t crc32_iso_hdlc(const Bytes& data) {
    std::uint32_t crc = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < data.size(); ++i) {
        crc ^= data[i];
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1u) ? (crc >> 1) ^ 0xEDB88320u : crc >> 1;
        }
    }
    return ~crc;
}

} // namespace

TEST_CASE("analyze: a length that counts a checksum of four bytes leaves less than the checksum for the header") {
    // [id][length][payload][CRC-32, low byte first]: size = length + 2, so the length counts the CRC, which is
    // 4 bytes, and what is left for the header (2 less 4) is less than nothing.
    fixtures::Random   rng(60);
    std::vector<Bytes> frames;
    for (int n = 0; n < 8; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 4 + id; payload <= 7 + id; payload += 3) {
                Bytes f;
                f.push_back(static_cast<std::uint8_t>(id));
                f.push_back(static_cast<std::uint8_t>(payload + 4));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const std::uint32_t crc = crc32_iso_hdlc(f);
                for (int b = 0; b < 4; ++b) {
                    f.push_back(static_cast<std::uint8_t>(crc >> (8 * b)));
                }
                frames.push_back(f);
            }
        }
    }
    const bw::Capture c = fixtures::capture_of(frames);
    const bw::MessageKinds k = bw::find_message_kinds(c, segmentation_of(c), 4);
    REQUIRE(k.found);
    CHECK(k.length.adjust == 2);
    const bw::Analysis a = analysis_of(frames);
    REQUIRE(a.type_count() == 4);
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        CHECK(a.type_report(t).frame_bytes == a.type_report(t).largest_frame_bytes);
        REQUIRE(a.type_report(t).checksum.found);
        CHECK(a.type_report(t).checksum.width_bits == 32);
    }
}

TEST_CASE("analyze: a length of two bytes that reaches into the payload is not put together") {
    // [length, 2 bytes][id][payload][CRC-16 of all of it]: size = length + 3, so the header would be one byte, less
    // than the length. Payloads of 250 and 260 bytes, for which the low byte alone is not the length.
    fixtures::Random   rng(61);
    std::vector<Bytes> frames;
    for (int n = 0; n < 5; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 249 + id; payload <= 259 + id; payload += 10) {
                Bytes f;
                const std::size_t length = payload + 2;                     // size less 3
                f.push_back(static_cast<std::uint8_t>(length & 0xFF));
                f.push_back(static_cast<std::uint8_t>(length >> 8));
                f.push_back(static_cast<std::uint8_t>(id));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const Bytes crc = crc16_tail(f);
                f.insert(f.end(), crc.begin(), crc.end());
                frames.push_back(f);
            }
        }
    }
    const bw::Capture c = fixtures::capture_of(frames);
    const bw::MessageKinds k = bw::find_message_kinds(c, segmentation_of(c), 4);
    REQUIRE(k.found);
    CHECK(k.length.bytes == 2);
    CHECK(k.length.adjust == 3);
    CHECK(k.kinds.size() == 2);
    const bw::Analysis a = analysis_of(frames);
    CHECK(a.type_count() == 4);                  // the sizes, as before
}

TEST_CASE("analyze: a run of bytes with no structure before the length does not take the length with it") {
    // [start][id][counter][length, 2 bytes][payload][CRC]: the counter and the low byte of the length (which has 20
    // values; the length is taken as the one byte it comes to, before the zeros of the other) would be one run of
    // bytes with no structure, which starts before the length does.
    fixtures::Random   rng(62);
    std::vector<Bytes> frames;
    std::uint8_t       counter = 0;
    for (int n = 0; n < 4; ++n) {
        for (std::size_t id = 1; id <= 2; ++id) {
            for (std::size_t payload = 4 + 20 * (id - 1); payload < 24 + 20 * (id - 1); ++payload) {
                Bytes f;
                f.push_back(0xAA);
                f.push_back(static_cast<std::uint8_t>(id));
                f.push_back(counter);
                counter = static_cast<std::uint8_t>(counter % 250 + 1);
                f.push_back(static_cast<std::uint8_t>(payload & 0xFF));
                f.push_back(static_cast<std::uint8_t>(payload >> 8));
                for (std::size_t i = 0; i < payload; ++i) {
                    f.push_back(rng.byte());
                }
                const Bytes crc = crc16_tail(Bytes(f.begin() + 1, f.end()));
                f.insert(f.end(), crc.begin(), crc.end());
                frames.push_back(f);
            }
        }
    }
    const bw::Capture c = fixtures::capture_of(frames);
    const bw::MessageKinds k = bw::find_message_kinds(c, segmentation_of(c), 4);
    REQUIRE(k.found);
    CHECK(k.length.offset == 3);
    const bw::Analysis a = analysis_of(frames);
    REQUIRE(a.type_count() == 2);
    const bw::Model m = a.model();
    REQUIRE(m.field_count(0) == 7);                                // 0xAA, id, counter, length, zero, payload, checksum
    CHECK(m.field(0, 2).kind == bw::FieldKind::Payload);
    CHECK(m.field(0, 2).bit_size == 8);                            // the counter, as it is: not a part of the length
    CHECK(m.field_name(0, 3) == "length");
    CHECK(m.field(0, 3).kind == bw::FieldKind::Length);
    CHECK(m.field(0, 3).bit_size == 8);
    CHECK(m.field_position(0, 3).bit_offset == 24);
    CHECK(m.field(0, 4).kind == bw::FieldKind::Constant);          // what is after it, apart
    CHECK(m.field(0, 4).constant == 0);
    CHECK(m.field(0, 6).covers_first == 1);                        // from the id
}

TEST_CASE("analyze: the length may be the first byte of the frame, or the last one of the header") {
    // [length][id][payload][CRC from the first byte] and [id][length][payload][CRC]: size = length + 4 in both, and
    // the header is the length and the id, with nothing before the length in one and nothing after it in the other.
    const std::size_t payloads[2][2] = { { 3, 5 }, { 4, 8 } };
    for (int first = 0; first < 2; ++first) {
        fixtures::Random   rng(81 + first);
        std::vector<Bytes> frames;
        for (int n = 0; n < 10; ++n) {
            for (std::size_t id = 1; id <= 2; ++id) {
                for (std::size_t p = 0; p < 2; ++p) {
                    const std::size_t payload = payloads[id - 1][p];
                    Bytes             f;
                    f.push_back(static_cast<std::uint8_t>(first ? payload : id));
                    f.push_back(static_cast<std::uint8_t>(first ? id : payload));
                    for (std::size_t i = 0; i < payload; ++i) {
                        f.push_back(rng.byte());
                    }
                    const std::uint16_t crc = fixtures::crc16_modbus(f, 0, f.size());
                    f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
                    f.push_back(static_cast<std::uint8_t>(crc >> 8));
                    frames.push_back(f);
                }
            }
        }
        CAPTURE(first);
        const bw::MessageKinds k = kinds_of(frames);
        REQUIRE(k.found);
        CHECK(k.length.offset == (first ? 0u : 1u));
        const bw::Analysis a = analysis_of(frames);
        REQUIRE(a.type_count() == 2);
        const bw::Model m = a.model();
        REQUIRE(m.field_count(0) == 4);                            // the length and the id, the payload, the checksum
        const std::size_t at = first ? 0 : 1;
        CHECK(m.field_name(0, at) == "length");
        CHECK(m.field(0, at).kind == bw::FieldKind::Length);
        CHECK(m.field(0, at).bit_size == 8);
        CHECK(m.field(0, 1 - at).kind == bw::FieldKind::Constant);
        CHECK(m.field_name(0, 2) == "payload");
        CHECK(m.field(0, 3).covers_first == 0);
    }
}

TEST_CASE("message kinds: a frame shorter than the header is in no kind, and is not read beyond its end") {
    // Two frames of 3 bytes among the rest: the key is at offset 2 and the length at 1, so the shortest of them
    // holds both, and a frame of 2 bytes holds neither. Under a sanitizer, a read past the end of either fails.
    std::vector<Bytes> frames = make_frames(70, two_messages());
    frames.push_back(Bytes({ 0xAA, 0x04, 0x01 }));
    frames.push_back(Bytes({ 0xAA, 0x05 }));
    frames.push_back(Bytes({ 0xAA }));
    const bw::MessageKinds k = kinds_of(frames);
    REQUIRE(k.found);
    REQUIRE(k.frame_kind.size() == frames.size());
    CHECK(k.frame_kind[50] == -1);                    // the shortest is shorter than the header: 3 bytes of 6
    CHECK(k.frame_kind[51] == -1);
    CHECK(k.frame_kind[52] == -1);
    CHECK(k.kinds[0].frames == 20);
    CHECK(k.kinds[1].frames == 20);
}
