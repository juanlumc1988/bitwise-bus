// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The first two protocols of wave 1, UBX and MAVLink 1: binary frames that follow
// one another with nothing between them, a length in the frame, a checksum that
// is not the CRC the catalogue has (Fletcher-8) or that has a seed nobody can
// see (CRC_EXTRA). What is checked is that the generators write what the
// protocols say: against values published with the protocols and against code
// that is not the generator's, and that the model they declare says what the
// frames hold. That the same bytes are written by a second implementation, in
// Python, is checked by tests/mirror/mirror.py.

#include "doctest.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

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

Dataset make(const char* name, std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol(name, o);
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

// What the model says each frame holds: its size, and every constant of it where it says.
void check_model_describes_frames(const Dataset& d) {
    const bw::Model model = d.model();
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes         frame = frame_of(d, i);
        const std::size_t   type  = d.frame_message_type(i);
        std::uint64_t       bits  = 0;
        for (std::size_t f = 0; f < model.field_count(type); ++f) {
            const bw::FieldInfo     info     = model.field(type, f);
            const bw::FieldPosition position = model.field_position(type, f);
            REQUIRE(position.fixed);
            bits += info.bit_size;
            if (info.kind == FieldKind::Constant) {
                const std::size_t at = static_cast<std::size_t>(position.bit_offset / 8);
                CHECK(le(frame, at, info.bit_size / 8) == info.constant);
            }
        }
        CHECK(frame.size() * 8 == bits);
    }
}

// ---- UBX -------------------------------------------------------------------

// The 8-bit Fletcher checksum of the UBX documentation, CK_A first.
Bytes fletcher(const Bytes& frame, std::size_t from, std::size_t to) {
    unsigned a = 0;
    unsigned b = 0;
    for (std::size_t i = from; i < to; ++i) {
        a = (a + frame[i]) % 256;
        b = (b + a) % 256;
    }
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(a));
    out.push_back(static_cast<std::uint8_t>(b));
    return out;
}

Bytes ubx_frame(std::uint8_t cls, std::uint8_t id, const Bytes& payload) {
    Bytes f;
    f.push_back(0xB5);
    f.push_back(0x62);
    f.push_back(cls);
    f.push_back(id);
    f.push_back(static_cast<std::uint8_t>(payload.size() & 0xFF));
    f.push_back(static_cast<std::uint8_t>(payload.size() >> 8));
    f.insert(f.end(), payload.begin(), payload.end());
    const Bytes ck = fletcher(f, 2, f.size());
    f.insert(f.end(), ck.begin(), ck.end());
    return f;
}

// ---- MAVLink 1 -------------------------------------------------------------

const bw::CrcSpec kMcrf4xx = { "CRC-16/MCRF4XX", 16, 0x1021, 0xFFFF, true, true, 0x0000, 0x6F91 };

std::uint16_t mavlink_crc(const Bytes& frame, std::size_t from, std::size_t to, std::uint8_t extra) {
    Bytes covered(frame.begin() + static_cast<std::ptrdiff_t>(from), frame.begin() + static_cast<std::ptrdiff_t>(to));
    covered.push_back(extra);
    return static_cast<std::uint16_t>(bw::crc_compute(kMcrf4xx, &covered[0], covered.size()));
}

// A frame of MAVLink 1 that is right in itself: the CRC over what it holds, with the seed given. `length`
// is what the length byte says, which a test can make not what the payload is.
Bytes mavlink_frame(std::uint8_t id, const Bytes& payload, std::uint8_t extra, int length = -1) {
    Bytes f;
    f.push_back(0xFE);
    f.push_back(static_cast<std::uint8_t>(length < 0 ? payload.size() : static_cast<std::size_t>(length)));
    f.push_back(0);
    f.push_back(1);
    f.push_back(1);
    f.push_back(id);
    f.insert(f.end(), payload.begin(), payload.end());
    const std::uint16_t crc = mavlink_crc(f, 1, f.size(), extra);
    f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
    f.push_back(static_cast<std::uint8_t>(crc >> 8));
    return f;
}

std::uint8_t crc_extra_of(const std::string& definition) {
    const bw::u64 crc = bw::crc_compute(kMcrf4xx, reinterpret_cast<const bw::u8*>(definition.data()), definition.size());
    return static_cast<std::uint8_t>((crc & 0xFF) ^ (crc >> 8));
}

} // namespace

TEST_CASE("ubx: the 8-bit Fletcher checksum agrees with the frames of the u-blox documentation") {
    // UBX-ACK-ACK for CFG-MSG, and the poll of UBX-CFG-PRT: two frames as they are written there.
    const Bytes ack = ubx_frame(0x05, 0x01, Bytes({0x06, 0x01}));
    CHECK(ack == Bytes({0xB5, 0x62, 0x05, 0x01, 0x02, 0x00, 0x06, 0x01, 0x0F, 0x38}));
    const Bytes poll = ubx_frame(0x06, 0x00, Bytes());
    CHECK(poll == Bytes({0xB5, 0x62, 0x06, 0x00, 0x00, 0x00, 0x06, 0x18}));

    // The decoder of the protocol accepts the first, and refuses the second only for being no message it knows.
    CHECK(bw::protocol_conforms("ubx", ack));
    CHECK_FALSE(bw::protocol_conforms("ubx", poll));
}

TEST_CASE("ubx: its model is the documented one") {
    const bw::Model m = bw::protocol_model("ubx");
    CHECK(m.framing().kind == bw::FramingKind::Contiguous);
    REQUIRE(m.message_type_count() == 3);
    const char*       names[3]   = { "ack_ack", "cfg_rate", "nav_status" };
    const std::size_t fields[3]  = { 8, 9, 13 };
    const unsigned    classes[3] = { 0x05, 0x06, 0x01 };
    const unsigned    ids[3]     = { 0x01, 0x08, 0x03 };
    const unsigned    sizes[3]   = { 2, 6, 16 };
    for (std::size_t t = 0; t < 3; ++t) {
        CAPTURE(t);
        CHECK(m.message_type_name(t) == names[t]);
        REQUIRE(m.field_count(t) == fields[t]);
        CHECK(m.field(t, 0).constant == 0xB5);
        CHECK(m.field(t, 1).constant == 0x62);
        CHECK(m.field(t, 2).constant == classes[t]);
        CHECK(m.field(t, 3).constant == ids[t]);
        CHECK(m.field(t, 4).kind == FieldKind::Length);
        CHECK(m.field(t, 4).bit_size == 16);
        CHECK(m.field(t, 4).byte_order == bw::ByteOrder::Little);
        const bw::FieldInfo ck = m.field(t, m.field_count(t) - 1);
        CHECK(ck.kind == FieldKind::Checksum);
        CHECK(ck.covers_first == 2);                                 // from the class
        CHECK(ck.covers_last == m.field_count(t) - 2);               // to the end of the payload
        CHECK(m.field_detail(t, m.field_count(t) - 1) == "FLETCHER-8");
        // The payload fields add up to the length the frame carries.
        std::uint64_t payload_bits = 0;
        for (std::size_t f = 5; f + 1 < m.field_count(t); ++f) {
            payload_bits += m.field(t, f).bit_size;
        }
        CHECK(payload_bits == 8 * sizes[t]);
    }
    CHECK(m.field_name(2, 5) == "itow");
    CHECK(m.field(2, 5).kind == FieldKind::Timestamp);
}

TEST_CASE("ubx: a seed is a capture, the same on every platform") {
    // Written by an independent implementation in Python, from the algorithm documented in ubx.cpp.
    CHECK(golden::first_difference(csv(make("ubx", 1, 30)), golden::read_file("synth_ubx_seed1_30frames.csv")) == "");
    CHECK(golden::first_difference(csv(make("ubx", 3, 40, 300)),
                                   golden::read_file("synth_ubx_seed3_40frames_jitter300.csv")) == "");
}

TEST_CASE("ubx: every frame is a frame of the protocol, and the model says what it holds") {
    const Dataset d = make("ubx", 11, 120);
    REQUIRE(d.frame_count() == 120);
    check_model_describes_frames(d);

    const std::size_t sizes[3] = { 10, 14, 24 };
    std::set<std::uint32_t> seen;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes f = frame_of(d, i);
        const std::uint32_t t = d.frame_message_type(i);
        seen.insert(t);
        CHECK(f.size() == sizes[t]);
        CHECK(le(f, 4, 2) == f.size() - 8);                          // the length is the payload's
        CHECK(Bytes(f.end() - 2, f.end()) == fletcher(f, 2, f.size() - 2));
    }
    CHECK(seen.size() == 3);
}

TEST_CASE("ubx: what the payloads hold") {
    const Dataset d = make("ubx", 12, 300);
    std::uint64_t last_itow = 0, last_msss = 0, ttff = 0;
    bool first = true;
    std::set<unsigned> rates, navs, fixes;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes f = frame_of(d, i);
        switch (d.frame_message_type(i)) {
            case 0: {                                            // ACK-ACK: one of three commands
                const unsigned pair = static_cast<unsigned>(f[6]) * 256 + f[7];
                CHECK((pair == 0x0601 || pair == 0x0608 || pair == 0x0600));
                break;
            }
            case 1:                                              // CFG-RATE
                rates.insert(static_cast<unsigned>(le(f, 6, 2)));
                navs.insert(static_cast<unsigned>(le(f, 8, 2)));
                CHECK(le(f, 10, 2) <= 1);
                break;
            default: {                                           // NAV-STATUS
                const std::uint64_t itow = le(f, 6, 4);
                const std::uint64_t msss = le(f, 18, 4);
                CHECK(itow % 1000 == 0);
                CHECK(itow < 604800000ULL);
                fixes.insert(f[10]);
                CHECK(f[11] < 16);                               // flags
                CHECK(f[12] % 64 == 0);                          // fixStat
                CHECK((f[13] % 8 == 0 && f[13] < 24));           // flags2
                if (first) {
                    ttff = le(f, 14, 4);
                    CHECK(ttff >= 20000);
                    CHECK(ttff < 40000);
                    first = false;
                } else {
                    CHECK(le(f, 14, 4) == ttff);                 // constant once known
                    CHECK(itow == (last_itow + 1000) % 604800000ULL);
                    CHECK(msss == last_msss + 1000);
                }
                last_itow = itow;
                last_msss = msss;
            }
        }
    }
    CHECK(rates == std::set<unsigned>({100, 200, 500, 1000}));
    CHECK(navs == std::set<unsigned>({1, 2, 5}));
    CHECK(fixes == std::set<unsigned>({0, 2, 3}));
}

TEST_CASE("ubx: the time of week wraps at the end of the week") {
    // Seed 187 starts its time of week 293 seconds before the end of the week (it was found by trying seeds
    // in order), so a capture of 1500 frames, about 500 of them NAV-STATUS, crosses it. The first time of
    // week is checked, so that a change of the generator that moves it says so here and not by passing.
    const Dataset d = make("ubx", 187, 1500);
    std::uint64_t last = 0;
    bool          first = true, wrapped = false;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        if (d.frame_message_type(i) != 2) {
            continue;
        }
        const std::uint64_t itow = le(frame_of(d, i), 6, 4);
        CHECK(itow < 604800000ULL);
        if (first) {
            REQUIRE(itow >= 604000000ULL);
        } else {
            CHECK(itow == (last + 1000) % 604800000ULL);
            wrapped = wrapped || itow < last;
        }
        first = false;
        last  = itow;
    }
    CHECK(wrapped);
}

TEST_CASE("ubx: frames follow one another a character apart, and with noise stay in order") {
    const Dataset quiet = make("ubx", 13, 40, 0);
    const Capture c     = quiet.capture();
    for (std::size_t i = 0; i < c.event_count(); ++i) {
        CHECK(c.event(i).time_ns == static_cast<std::int64_t>(i * 86805));      // 10 bits at 115200 baud
    }
    const Capture noisy = make("ubx", 13, 40, 500).capture();
    for (std::size_t i = 1; i < noisy.event_count(); ++i) {
        const std::int64_t gap = noisy.event(i).time_ns - noisy.event(i - 1).time_ns;
        CHECK(gap > 86805 / 2 - 1);
        CHECK(gap < 86805 * 3 / 2 + 1);
    }
}

TEST_CASE("ubx: the decoder refuses each way a frame can be wrong") {
    const Bytes good = ubx_frame(0x06, 0x08, Bytes({0xE8, 0x03, 0x01, 0x00, 0x01, 0x00}));     // CFG-RATE, 1 s
    REQUIRE(bw::protocol_conforms("ubx", good));
    for (std::size_t i = 0; i < good.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            Bytes bad = good;
            bad[i]    = static_cast<std::uint8_t>(bad[i] ^ (1u << bit));
            CHECK_FALSE(bw::protocol_conforms("ubx", bad));
        }
    }
    CHECK_FALSE(bw::protocol_conforms("ubx", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("ubx", Bytes(good.begin(), good.end() - 1)));
    Bytes longer = good;
    longer.push_back(0);
    CHECK_FALSE(bw::protocol_conforms("ubx", longer));
    // A frame that is consistent in itself but is a message of another length than this one has.
    CHECK_FALSE(bw::protocol_conforms("ubx", ubx_frame(0x06, 0x08, Bytes({1, 2, 3, 4}))));
    CHECK_FALSE(bw::protocol_conforms("ubx", ubx_frame(0x01, 0x07, Bytes(16, 0))));            // not NAV-STATUS
    // Each of class and id on its own, with the length and the checksum right for it.
    CHECK(bw::protocol_conforms("ubx", ubx_frame(0x05, 0x01, Bytes({0x06, 0x01}))));
    CHECK_FALSE(bw::protocol_conforms("ubx", ubx_frame(0x07, 0x01, Bytes({0x06, 0x01}))));      // another class
    CHECK_FALSE(bw::protocol_conforms("ubx", ubx_frame(0x05, 0x02, Bytes({0x06, 0x01}))));      // another id
    // A byte too many, inside the checksum: the frame is consistent in all but the length it says.
    Bytes body(good.begin() + 2, good.end() - 2);
    body.push_back(0);
    Bytes padded(good.begin(), good.begin() + 2);
    padded.insert(padded.end(), body.begin(), body.end());
    const Bytes ck = fletcher(padded, 2, padded.size());
    padded.insert(padded.end(), ck.begin(), ck.end());
    CHECK_FALSE(bw::protocol_conforms("ubx", padded));
}

TEST_CASE("mavlink1: the CRC is the published one, and the seed of each message follows from its definition") {
    CHECK(bw::crc_spec_self_test(kMcrf4xx));                     // 0x6F91 for "123456789"
    // CRC_EXTRA: the CRC of the message's name and then each field's type and name, in the order of
    // the wire, folded to a byte. Worked out here from the definitions.
    CHECK(crc_extra_of("HEARTBEAT uint32_t custom_mode uint8_t type uint8_t autopilot uint8_t base_mode "
                       "uint8_t system_status uint8_t mavlink_version ") == 50);
    CHECK(crc_extra_of("SYS_STATUS uint32_t onboard_control_sensors_present uint32_t onboard_control_sensors_enabled "
                       "uint32_t onboard_control_sensors_health uint16_t load uint16_t voltage_battery "
                       "int16_t current_battery uint16_t drop_rate_comm uint16_t errors_comm uint16_t errors_count1 "
                       "uint16_t errors_count2 uint16_t errors_count3 uint16_t errors_count4 "
                       "int8_t battery_remaining ") == 124);
    CHECK(crc_extra_of("ATTITUDE uint32_t time_boot_ms float roll float pitch float yaw float rollspeed "
                       "float pitchspeed float yawspeed ") == 39);
}

TEST_CASE("mavlink1: its model is the documented one") {
    const bw::Model m = bw::protocol_model("mavlink1");
    CHECK(m.framing().kind == bw::FramingKind::Contiguous);
    REQUIRE(m.message_type_count() == 3);
    const char*       names[3]  = { "heartbeat", "sys_status", "attitude" };
    const std::size_t fields[3] = { 13, 20, 14 };
    const unsigned    ids[3]    = { 0, 1, 30 };
    const unsigned    sizes[3]  = { 9, 31, 28 };
    const unsigned    extras[3] = { 50, 124, 39 };
    for (std::size_t t = 0; t < 3; ++t) {
        CAPTURE(t);
        CHECK(m.message_type_name(t) == names[t]);
        REQUIRE(m.field_count(t) == fields[t]);
        CHECK(m.field(t, 0).constant == 0xFE);
        CHECK(m.field(t, 1).kind == FieldKind::Length);
        CHECK(m.field(t, 2).kind == FieldKind::Counter);
        CHECK(m.field(t, 3).constant == 1);
        CHECK(m.field(t, 4).constant == 1);
        CHECK(m.field(t, 5).constant == ids[t]);
        const std::size_t   last = m.field_count(t) - 1;
        const bw::FieldInfo crc  = m.field(t, last);
        CHECK(crc.kind == FieldKind::Checksum);
        CHECK(crc.byte_order == bw::ByteOrder::Little);
        CHECK(crc.covers_first == 1);                                // from the length: not the STX
        CHECK(crc.covers_last == last - 1);
        CHECK(m.field_detail(t, last) == "CRC-16/MCRF4XX seeded with CRC_EXTRA " + std::to_string(extras[t]));
        std::uint64_t payload_bits = 0;
        for (std::size_t f = 6; f < last; ++f) {
            payload_bits += m.field(t, f).bit_size;
        }
        CHECK(payload_bits == 8 * sizes[t]);
    }
    // The fields of ATTITUDE are floats of 32 bits, little-endian.
    for (std::size_t f = 7; f <= 12; ++f) {
        CHECK(m.field(2, f).kind == FieldKind::Float);
        CHECK(m.field(2, f).bit_size == 32);
    }
}

TEST_CASE("mavlink1: a seed is a capture, the same on every platform") {
    CHECK(golden::first_difference(csv(make("mavlink1", 1, 30)),
                                   golden::read_file("synth_mavlink1_seed1_30frames.csv")) == "");
    CHECK(golden::first_difference(csv(make("mavlink1", 3, 40, 300)),
                                   golden::read_file("synth_mavlink1_seed3_40frames_jitter300.csv")) == "");
}

TEST_CASE("mavlink1: every frame is a frame of the protocol, with the CRC of the catalogue's engine and the seed") {
    const Dataset d = make("mavlink1", 21, 300);
    REQUIRE(d.frame_count() == 300);
    check_model_describes_frames(d);

    const std::size_t sizes[3]  = { 17, 39, 36 };
    const unsigned    extras[3] = { 50, 124, 39 };
    std::set<std::uint32_t> seen;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes         f = frame_of(d, i);
        const std::uint32_t t = d.frame_message_type(i);
        seen.insert(t);
        CHECK(f.size() == sizes[t]);
        CHECK(f[1] == f.size() - 8);                                // the length is the payload's
        CHECK(f[2] == i % 256);                                     // one more for each frame, whatever it is
        CHECK(le(f, f.size() - 2, 2) == mavlink_crc(f, 1, f.size() - 2, static_cast<std::uint8_t>(extras[t])));
        // Without the seed it is another number: the CRC is not checkable from the frame alone.
        CHECK(le(f, f.size() - 2, 2) != bw::crc_compute(kMcrf4xx, &f[1], f.size() - 3));
    }
    CHECK(seen.size() == 3);
}

TEST_CASE("mavlink1: what the payloads hold") {
    const Dataset d = make("mavlink1", 22, 600);
    std::set<unsigned> modes, vehicles, bases, statuses;
    std::int64_t last_boot = -1;
    std::size_t  last_index = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const Bytes f = frame_of(d, i);
        switch (d.frame_message_type(i)) {
            case 0:                                               // HEARTBEAT
                modes.insert(static_cast<unsigned>(le(f, 6, 4)));
                vehicles.insert(f[10]);
                CHECK(f[11] == 3);                                // autopilot
                bases.insert(f[12]);
                statuses.insert(f[13]);
                CHECK(f[14] == 3);                                // MAVLink version
                break;
            case 1: {                                             // SYS_STATUS
                const std::uint64_t present = le(f, 6, 4), enabled = le(f, 10, 4), health = le(f, 14, 4);
                CHECK((enabled & ~present) == 0);
                CHECK((health & ~enabled) == 0);
                CHECK(le(f, 18, 2) < 1000);                       // load
                CHECK(le(f, 20, 2) >= 10500);
                CHECK(le(f, 20, 2) < 12600);                      // voltage
                CHECK(le(f, 22, 2) < 3000);                       // current
                CHECK(le(f, 24, 2) < 50);                         // drop rate
                for (std::size_t k = 26; k < 36; ++k) {
                    CHECK(f[k] == 0);                             // the error counters
                }
                CHECK(f[36] <= 100);                              // battery remaining
                break;
            }
            default: {                                            // ATTITUDE
                const std::int64_t boot = static_cast<std::int64_t>(le(f, 6, 4));
                if (last_boot >= 0) {
                    CHECK(boot - last_boot == static_cast<std::int64_t>(20 * (i - last_index)));
                }
                last_boot  = boot;
                last_index = i;
                for (std::size_t k = 0; k < 6; ++k) {
                    const std::uint32_t bits     = static_cast<std::uint32_t>(le(f, 10 + 4 * k, 4));
                    const std::uint32_t exponent = (bits >> 23) & 0xFF;
                    if (k < 3) {
                        CHECK((exponent >= 126 && exponent <= 128));      // 0.5 to 4
                    } else {
                        CHECK((exponent >= 120 && exponent <= 123));
                    }
                }
            }
        }
    }
    CHECK(modes == std::set<unsigned>({0, 3, 4, 5}));
    CHECK(vehicles == std::set<unsigned>({1, 2}));
    CHECK(bases == std::set<unsigned>({81, 209, 217}));
    CHECK(statuses == std::set<unsigned>({3, 4}));
}

TEST_CASE("mavlink1: frames follow one another a character apart") {
    const Capture c = make("mavlink1", 23, 30, 0).capture();
    for (std::size_t i = 0; i < c.event_count(); ++i) {
        CHECK(c.event(i).time_ns == static_cast<std::int64_t>(i * 173611));     // 10 bits at 57600 baud
    }
}

TEST_CASE("mavlink1: the decoder refuses each way a frame can be wrong") {
    const Bytes good = frame_of(make("mavlink1", 24, 5), 0);
    REQUIRE(bw::protocol_conforms("mavlink1", good));
    for (std::size_t i = 0; i < good.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            Bytes bad = good;
            bad[i]    = static_cast<std::uint8_t>(bad[i] ^ (1u << bit));
            // The sequence, the system and the component are in no list and are covered by the CRC, so all fail.
            CHECK_FALSE(bw::protocol_conforms("mavlink1", bad));
        }
    }
    CHECK_FALSE(bw::protocol_conforms("mavlink1", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("mavlink1", Bytes(good.begin(), good.end() - 1)));
    // A message is its id and its length together, each with the seed of its own.
    CHECK(bw::protocol_conforms("mavlink1", mavlink_frame(0, Bytes(9, 0), 50)));
    CHECK(bw::protocol_conforms("mavlink1", mavlink_frame(1, Bytes(31, 0), 124)));
    CHECK(bw::protocol_conforms("mavlink1", mavlink_frame(30, Bytes(28, 0), 39)));
    CHECK_FALSE(bw::protocol_conforms("mavlink1", mavlink_frame(0, Bytes(9, 0), 124)));        // another message's seed
    CHECK_FALSE(bw::protocol_conforms("mavlink1", mavlink_frame(2, Bytes(9, 0), 50)));         // an id it does not have
    CHECK_FALSE(bw::protocol_conforms("mavlink1", mavlink_frame(0, Bytes(10, 0), 50)));        // HEARTBEAT, one byte long
    CHECK_FALSE(bw::protocol_conforms("mavlink1", mavlink_frame(0, Bytes(31, 0), 50)));        // and the length of another
    CHECK_FALSE(bw::protocol_conforms("mavlink1", mavlink_frame(0, Bytes(10, 0), 50, 9)));     // longer than it says
    CHECK_FALSE(bw::protocol_conforms("mavlink1", mavlink_frame(0, Bytes(8, 0), 50, 9)));      // shorter than it says
    // The CRC without the seed is not accepted.
    Bytes unseeded = good;
    const std::uint16_t plain = static_cast<std::uint16_t>(bw::crc_compute(kMcrf4xx, &good[1], good.size() - 3));
    unseeded[unseeded.size() - 2] = static_cast<std::uint8_t>(plain & 0xFF);
    unseeded[unseeded.size() - 1] = static_cast<std::uint8_t>(plain >> 8);
    CHECK_FALSE(bw::protocol_conforms("mavlink1", unseeded));
}

TEST_CASE("wave 1 so far: the stages that exist see nothing to cut at in a capture with nothing between its frames") {
    // The baseline that segmentation by gaps starts from, and that the next steps of wave 1 change: a
    // contiguous capture has no short gaps and long gaps, only gaps of a character, so nothing is found.
    // When something else cuts the frames, the later stages meet the next limit: Fletcher-8 and a seeded
    // CRC are not in the catalogue, so no checksum is found either (docs/roadmap.md, wave 1).
    const char* names[2] = { "ubx", "mavlink1" };
    for (int n = 0; n < 2; ++n) {
        for (unsigned jitter = 0; jitter <= 300; jitter += 300) {
            CAPTURE(names[n]);
            CAPTURE(jitter);
            const Dataset d = make(names[n], 5, 120, jitter);
            CHECK_FALSE(bw::segment_by_gaps(d.capture(), bw::SegmentationOptions()).info().found);
        }
    }
}
