// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// MAVLink 2: the same messages as MAVLink 1 with a longer header, a message id of
// three bytes, and payloads whose trailing zeros are not sent, so that one
// message has frames of several lengths. Checked as the others are: against
// values that follow from the definitions, against a CRC that is not the
// generator's, against what the model says, and, through the captures checked in,
// against the Python implementation of tests/mirror/mirror.py.

#include "doctest.h"

#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/crc.h"
#include "bw/evaluate.h"
#include "bw/protocol.h"
#include "bw/segmentation.h"
#include "golden.h"

using bw::Capture;
using bw::Dataset;
using bw::FieldKind;
using bw::GenerateOptions;

namespace {

typedef std::vector<std::uint8_t> Bytes;

const bw::CrcSpec kMcrf4xx = { "CRC-16/MCRF4XX", 16, 0x1021, 0xFFFF, true, true, 0x0000, 0x6F91 };

Dataset make(std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol("mavlink2", o);
}

Bytes frame_of(const Dataset& d, std::size_t i) {
    return bw::frame_bytes(d.capture(), d.frame(i));
}

std::uint64_t le(const Bytes& b, std::size_t at, std::size_t size) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < size; ++i) {
        v |= static_cast<std::uint64_t>(b[at + i]) << (8 * i);
    }
    return v;
}

std::string csv(const Dataset& d) {
    return bw::format_capture_csv(d.capture());
}

std::uint16_t crc_of(const Bytes& frame, std::size_t from, std::size_t to, std::uint8_t extra) {
    Bytes covered(frame.begin() + static_cast<std::ptrdiff_t>(from), frame.begin() + static_cast<std::ptrdiff_t>(to));
    covered.push_back(extra);
    return static_cast<std::uint16_t>(bw::crc_compute(kMcrf4xx, &covered[0], covered.size()));
}

std::uint8_t crc_extra_of(const std::string& definition) {
    const bw::u64 crc = bw::crc_compute(kMcrf4xx, reinterpret_cast<const bw::u8*>(definition.data()), definition.size());
    return static_cast<std::uint8_t>((crc & 0xFF) ^ (crc >> 8));
}

// A frame of MAVLink 2 that is right in itself: what the payload is, as it is sent.
// `length` is what the length byte says, which a test can make not what the payload is.
Bytes frame_with(std::uint32_t id, const Bytes& payload, std::uint8_t extra, std::uint8_t incompat = 0,
                 std::uint8_t compat = 0, int length = -1) {
    Bytes f;
    f.push_back(0xFD);
    f.push_back(static_cast<std::uint8_t>(length < 0 ? payload.size() : static_cast<std::size_t>(length)));
    f.push_back(incompat);
    f.push_back(compat);
    f.push_back(0);
    f.push_back(1);
    f.push_back(1);
    f.push_back(static_cast<std::uint8_t>(id & 0xFF));
    f.push_back(static_cast<std::uint8_t>((id >> 8) & 0xFF));
    f.push_back(static_cast<std::uint8_t>((id >> 16) & 0xFF));
    f.insert(f.end(), payload.begin(), payload.end());
    const std::uint16_t crc = crc_of(f, 1, f.size(), extra);
    f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
    f.push_back(static_cast<std::uint8_t>(crc >> 8));
    return f;
}

// The payload of a frame as the message has it: with the zeros that were not sent put back.
Bytes padded_payload(const Bytes& frame, std::size_t full) {
    Bytes payload(frame.begin() + 10, frame.end() - 2);
    payload.resize(full, 0);
    return payload;
}

} // namespace

TEST_CASE("mavlink2: the seed of PROTOCOL_VERSION counts the lengths of its arrays") {
    // The CRC_EXTRA of a message with arrays: after the name of each array comes its length, as a byte.
    std::string with_lengths = "PROTOCOL_VERSION uint16_t version uint16_t min_version uint16_t max_version "
                               "uint8_t spec_version_hash ";
    with_lengths += static_cast<char>(8);
    with_lengths += "uint8_t library_version_hash ";
    with_lengths += static_cast<char>(8);
    CHECK(crc_extra_of(with_lengths) == 217);
    // Without them it is another number, so the 217 is not a coincidence of the rest of the text.
    CHECK(crc_extra_of("PROTOCOL_VERSION uint16_t version uint16_t min_version uint16_t max_version "
                       "uint8_t spec_version_hash uint8_t library_version_hash ") != 217);
}

TEST_CASE("mavlink2: its model is the documented one") {
    const bw::Model m = bw::protocol_model("mavlink2");
    CHECK(m.framing().kind == bw::FramingKind::Contiguous);
    REQUIRE(m.message_type_count() == 4);
    const char*    names[4]  = { "heartbeat", "sys_status", "attitude", "protocol_version" };
    const unsigned ids[4]    = { 0, 1, 30, 300 };
    const unsigned extras[4] = { 50, 124, 39, 217 };
    for (std::size_t t = 0; t < 4; ++t) {
        CAPTURE(t);
        CHECK(m.message_type_name(t) == names[t]);
        REQUIRE(m.field_count(t) == 10);
        CHECK(m.field(t, 0).constant == 0xFD);
        CHECK(m.field(t, 1).kind == FieldKind::Length);
        CHECK(m.field(t, 2).constant == 0);                           // not signed
        CHECK(m.field(t, 3).constant == 0);
        CHECK(m.field(t, 4).kind == FieldKind::Counter);
        CHECK(m.field(t, 7).constant == ids[t]);
        CHECK(m.field(t, 7).bit_size == 24);                          // three bytes, little-endian
        CHECK(m.field(t, 7).byte_order == bw::ByteOrder::Little);
        // The payload is as long as the length says, so what follows it has no fixed place.
        CHECK(m.field(t, 8).kind == FieldKind::Payload);
        CHECK(m.field(t, 8).size_kind == bw::SizeKind::FromField);
        CHECK(m.field(t, 8).size_field == 1);
        CHECK_FALSE(m.field_position(t, 9).fixed);
        const bw::FieldInfo crc = m.field(t, 9);
        CHECK(crc.kind == FieldKind::Checksum);
        CHECK(crc.covers_first == 1);                                 // from the length
        CHECK(crc.covers_last == 8);                                  // to the end of the payload
        CHECK(m.field_detail(t, 9) == "CRC-16/MCRF4XX seeded with " + std::to_string(extras[t]));
    }
}

TEST_CASE("mavlink2: a seed is a capture, the same on every platform") {
    CHECK(golden::first_difference(csv(make(1, 30)), golden::read_file("synth_mavlink2_seed1_30frames.csv")) == "");
    CHECK(golden::first_difference(csv(make(3, 40, 300)),
                                   golden::read_file("synth_mavlink2_seed3_40frames_jitter300.csv")) == "");
}

TEST_CASE("mavlink2: every frame is a frame of the protocol, with the CRC of the catalogue's engine and the seed") {
    const Dataset d = make(41, 400);
    REQUIRE(d.frame_count() == 400);
    const unsigned    ids[4]     = { 0, 1, 30, 300 };
    const unsigned    extras[4]  = { 50, 124, 39, 217 };
    const std::size_t fulls[4]   = { 9, 31, 28, 22 };
    std::set<std::uint32_t> seen;
    std::map<std::uint32_t, std::set<std::size_t> > lengths;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes         f = frame_of(d, i);
        const std::uint32_t t = d.frame_message_type(i);
        seen.insert(t);
        lengths[t].insert(f.size());
        CAPTURE(i);
        CHECK(f[0] == 0xFD);
        CHECK(f[1] == f.size() - 12);                                 // the length is the payload's
        CHECK(f[2] == 0);
        CHECK(f[3] == 0);
        CHECK(f[4] == i % 256);
        CHECK(f[5] == 1);
        CHECK(f[6] == 1);
        CHECK(le(f, 7, 3) == ids[t]);
        CHECK(f[1] >= 1);
        CHECK(f[1] <= fulls[t]);
        // The zeros at the end are not sent: the last byte is not 0, unless it is the only one.
        CHECK((f[1] == 1 || f[9 + f[1]] != 0));
        CHECK(le(f, f.size() - 2, 2) == crc_of(f, 1, f.size() - 2, static_cast<std::uint8_t>(extras[t])));
        CHECK(le(f, f.size() - 2, 2) != bw::crc_compute(kMcrf4xx, &f[1], f.size() - 3));      // the seed matters
    }
    CHECK(seen.size() == 4);
    // HEARTBEAT ends in a byte that is never 0, so it is always whole; the others are cut, and some are cut by more.
    CHECK(lengths[0] == std::set<std::size_t>({21}));
    CHECK(lengths[1].size() >= 2);
    CHECK(lengths[2].size() >= 2);
}

TEST_CASE("mavlink2: what the payloads hold, once the zeros that were not sent are put back") {
    const Dataset d = make(42, 800);
    std::set<unsigned> modes, versions, highest;
    Bytes first_hashes;
    std::size_t cut_battery = 0, cut_yaw = 0, whole_battery = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes f = frame_of(d, i);
        CAPTURE(i);
        switch (d.frame_message_type(i)) {
            case 0: {
                const Bytes p = padded_payload(f, 9);
                modes.insert(static_cast<unsigned>(le(p, 0, 4)));
                CHECK((p[4] == 1 || p[4] == 2));
                CHECK(p[5] == 3);
                CHECK(p[8] == 3);
                break;
            }
            case 1: {
                const Bytes p = padded_payload(f, 31);
                CHECK((le(p, 4, 4) & ~le(p, 0, 4)) == 0);
                CHECK((le(p, 8, 4) & ~le(p, 4, 4)) == 0);
                CHECK(le(p, 12, 2) < 1000);
                CHECK(le(p, 14, 2) >= 10500);
                CHECK(le(p, 14, 2) < 12600);
                CHECK(le(p, 16, 2) < 3000);
                CHECK(le(p, 18, 2) < 50);
                for (std::size_t k = 20; k < 30; ++k) {
                    CHECK(p[k] == 0);                                  // the error counters
                }
                CHECK(p[30] <= 100);
                (p[30] == 0 ? cut_battery : whole_battery) += 1;
                CHECK((p[30] == 0) == (f[1] < 31));                    // the battery is what decides whether it is cut
                break;
            }
            case 2: {
                const Bytes p = padded_payload(f, 28);
                for (std::size_t k = 0; k < 3; ++k) {
                    const std::uint32_t e = (static_cast<std::uint32_t>(le(p, 4 + 4 * k, 4)) >> 23) & 0xFF;
                    CHECK((e >= 126 && e <= 128));
                }
                for (std::size_t k = 3; k < 5; ++k) {
                    const std::uint32_t e = (static_cast<std::uint32_t>(le(p, 4 + 4 * k, 4)) >> 23) & 0xFF;
                    CHECK((e >= 120 && e <= 123));
                }
                const std::uint32_t yaw = static_cast<std::uint32_t>(le(p, 24, 4));
                if (yaw == 0) {
                    ++cut_yaw;
                } else {
                    CHECK(((yaw >> 23) & 0xFF) >= 120);
                    CHECK(((yaw >> 23) & 0xFF) <= 123);
                }
                break;
            }
            default: {
                const Bytes p = padded_payload(f, 22);
                versions.insert(static_cast<unsigned>(le(p, 0, 2)));
                CHECK(le(p, 2, 2) == 100);
                highest.insert(static_cast<unsigned>(le(p, 4, 2)));
                if (first_hashes.empty()) {
                    first_hashes.assign(p.begin() + 6, p.end());
                } else {
                    CHECK(Bytes(p.begin() + 6, p.end()) == first_hashes);          // the hashes are those of the capture
                }
            }
        }
    }
    CHECK(modes == std::set<unsigned>({0, 3, 4, 5}));
    CHECK(versions == std::set<unsigned>({200, 300}));
    CHECK(highest == std::set<unsigned>({200, 300}));
    CHECK(cut_battery > 0);                                            // the battery is sometimes unknown
    CHECK(whole_battery > 0);
    CHECK(cut_yaw > 0);                                                // and the yaw speed sometimes exactly zero
}

TEST_CASE("mavlink2: PROTOCOL_VERSION has the hashes of the capture, none, one or both of them") {
    // The seeds are tried in order; which of the three a capture has depends on the seed alone.
    std::set<std::size_t> payload_sizes;
    for (std::uint64_t seed = 0; seed < 60; ++seed) {
        const Dataset d = make(seed, 40);
        for (std::size_t i = 0; i < d.frame_count(); ++i) {
            if (d.frame_message_type(i) == 3) {
                const Bytes f = frame_of(d, i);
                // With the highest version 300 the sixth byte is 1 and the frame ends there when no hash is set.
                if (f[1] > 6) {
                    payload_sizes.insert(f[1]);
                }
            }
        }
    }
    // Hashes set: 6 bytes of versions plus 8 (the spec's) or 16 (both), less the zeros the last one ends in.
    bool spec_only = false, both = false;
    for (std::set<std::size_t>::const_iterator it = payload_sizes.begin(); it != payload_sizes.end(); ++it) {
        spec_only = spec_only || (*it >= 7 && *it <= 14);
        both      = both || (*it >= 15 && *it <= 22);
    }
    CHECK(spec_only);
    CHECK(both);
}

TEST_CASE("mavlink2: frames follow one another a character apart") {
    const Capture c = make(43, 30, 0).capture();
    for (std::size_t i = 0; i < c.event_count(); ++i) {
        CHECK(c.event(i).time_ns == static_cast<std::int64_t>(i * 173611));       // 10 bits at 57600 baud
    }
}

TEST_CASE("mavlink2: the decoder refuses each way a frame can be wrong") {
    const Bytes good = frame_with(0, Bytes({0, 0, 0, 0, 2, 3, 81, 4, 3}), 50);
    REQUIRE(bw::protocol_conforms("mavlink2", good));
    for (std::size_t i = 0; i < good.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            Bytes bad = good;
            bad[i]    = static_cast<std::uint8_t>(bad[i] ^ (1u << bit));
            CHECK_FALSE(bw::protocol_conforms("mavlink2", bad));
        }
    }
    CHECK_FALSE(bw::protocol_conforms("mavlink2", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("mavlink2", Bytes(good.begin(), good.end() - 1)));

    // A message is its id and its seed.
    CHECK(bw::protocol_conforms("mavlink2", frame_with(1, Bytes({1, 0, 0, 0, 1}), 124)));
    CHECK(bw::protocol_conforms("mavlink2", frame_with(30, Bytes({1, 2, 3, 4}), 39)));
    CHECK(bw::protocol_conforms("mavlink2", frame_with(300, Bytes({200, 0, 100, 0, 200}), 217)));       // the id is 3 bytes
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1, 0, 0, 0, 1}), 124)));         // another message's seed
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(2, Bytes({1, 0, 0, 0, 1}), 50)));          // an id it does not have
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(300 + 65536, Bytes({1, 2}), 217)));         // the third byte counts
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(44, Bytes({200, 0, 100, 0, 200}), 217)));  // 300 mod 256

    // The payload is cut as the protocol cuts it: no zero at the end but the first byte, and never longer than the message.
    CHECK(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({0}), 50)));                            // all zeros: one byte
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1, 0}), 50)));                   // a zero that could have been cut
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes(), 50)));                         // no payload at all
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes(10, 1), 50)));                    // longer than HEARTBEAT
    CHECK(bw::protocol_conforms("mavlink2", frame_with(0, Bytes(9, 1), 50)));                           // as long as it is
    CHECK(bw::protocol_conforms("mavlink2", frame_with(1, Bytes(31, 1), 124)));
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(1, Bytes(32, 1), 124)));

    // Flags: frames that are signed, or that have a flag this decoder does not know, are not its frames.
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1}), 50, 1)));
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1}), 50, 0, 1)));              // with its CRC right
    CHECK(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1}), 50, 0, 0)));

    // What the length byte says is the length of the payload: more or less than that is refused, with the CRC right.
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1, 2, 3, 4, 5, 6, 7, 8, 9, 10}), 50, 0, 0, 9)));
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_with(0, Bytes({1, 2, 3, 4, 5, 6, 7, 8}), 50, 0, 0, 9)));

    // A frame of MAVLink 1 is not one of MAVLink 2.
    GenerateOptions one;
    one.frames = 1;
    CHECK_FALSE(bw::protocol_conforms("mavlink2", frame_of(bw::generate_protocol("mavlink1", one), 0)));
}

TEST_CASE("mavlink2 baseline: no gaps to cut at, and a type for each message whatever the size of its payload") {
    // Where this protocol starts: by gaps nothing is found, as with MAVLink 1. Given the true frames, there are seven
    // sizes for four messages in this capture (seed 3, 300 frames), because the payload is cut of its trailing
    // zeros. Stage 4 finds the length (the byte at offset 1 plus 12) and the message id (bytes 7 and 8, the same in
    // every frame of a message and different between messages), and the frames of the same message are one type:
    // four, in which the CRC is found with the byte of its message that the frames do not hold (CRC_EXTRA: 50,
    // 124, 39 or 217), as for MAVLink 1.
    const Dataset d = make(3, 300);
    CHECK_FALSE(bw::segment_by_gaps(d.capture(), bw::SegmentationOptions()).info().found);

    bw::SegmentationInfo info;
    info.found = true;
    const bw::Analysis a = bw::analyze_frames(d.capture(), bw::Segmentation(info, d.frames()), bw::AnalyzeOptions());
    REQUIRE(a.type_count() == 4);
    CHECK(a.info().ignored_frames == 0);
    std::uint32_t frames = 0;
    std::set<std::uint32_t> seeds;
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        const bw::MessageTypeReport r = a.type_report(t);
        const bw::ChecksumFinding& c = r.checksum;
        CAPTURE(t);
        frames += r.frames;
        REQUIRE(c.found);
        CHECK(bw::checksum_algorithm_name(c.algorithm) == "CRC-16/MCRF4XX");
        CHECK(c.seeded);
        seeds.insert(c.seed);
        CHECK(c.header_skip == 1);              // the start byte is not covered
        CHECK(c.trailer_skip == 0);
        CHECK(c.width_bits == 16);
        CHECK(c.byte_order == bw::ByteOrder::Little);
        CHECK(c.evidence_bits >= 32);
    }
    CHECK(frames == 300);
    CHECK(seeds == std::set<std::uint32_t>({ 50, 124, 39, 217 }));

    // The three messages that are cut have two sizes each, and the one that is not has one.
    std::map<std::uint32_t, std::uint32_t> largest;                  // by smallest size
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        largest[a.type_report(t).frame_bytes] = a.type_report(t).largest_frame_bytes;
    }
    std::map<std::uint32_t, std::uint32_t> expected;
    expected[17] = 18;                          // PROTOCOL_VERSION
    expected[21] = 21;                          // HEARTBEAT
    expected[31] = 43;                          // SYS_STATUS
    expected[36] = 40;                          // ATTITUDE
    CHECK(largest == expected);

    // Against the truth. A found type is of a message when the low byte of the id at offset 7 is the same. What the
    // three messages that are cut have in the model is what the truth has: a length, a payload that it sizes, and the
    // CRC after it; only the id, of three bytes, is three fields of a byte (one of them of the same value in all).
    // The numbers are fields of the truth and found, boundaries of the truth, found and hit, exact fields, kinds.
    struct Row {
        const char* message;
        unsigned    truth_fields, found_fields, truth_boundaries, found_boundaries, hits, exact, kinds;
    };
    const Row rows[] = {
        { "heartbeat",        10, 20, 9, 21, 9, 7, 5 },
        { "sys_status",       10, 12, 9, 11, 9, 7, 6 },
        { "attitude",         10, 12, 9, 11, 9, 7, 6 },
        { "protocol_version", 10, 12, 9, 11, 9, 7, 6 },
    };
    const bw::Model truth = d.model();
    const bw::Model found = a.model();
    std::size_t     checked = 0;
    for (std::size_t ft = 0; ft < a.type_count(); ++ft) {
        for (std::size_t tt = 0; tt < truth.message_type_count(); ++tt) {
            if (found.field(ft, 7).kind != FieldKind::Constant ||
                (truth.field(tt, 7).constant & 0xFF) != found.field(ft, 7).constant) {
                continue;
            }
            CAPTURE(truth.message_type_name(tt));
            const bw::FieldScore s = bw::score_fields(truth, tt, found, ft);
            for (std::size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); ++r) {
                if (truth.message_type_name(tt) == rows[r].message) {
                    ++checked;
                    CHECK(s.truth_fields == rows[r].truth_fields);
                    CHECK(s.found_fields == rows[r].found_fields);
                    CHECK(s.truth_boundaries == rows[r].truth_boundaries);
                    CHECK(s.found_boundaries == rows[r].found_boundaries);
                    CHECK(s.boundary_hits == rows[r].hits);
                    CHECK(s.exact_fields == rows[r].exact);
                    CHECK(s.kind_hits == rows[r].kinds);
                    CHECK(s.found_has_checksum);
                }
            }
        }
    }
    CHECK(checked == 4);
}
