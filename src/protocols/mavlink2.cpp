// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// MAVLink 2, on a 57600 baud 8N1 line (a telemetry radio), one event per byte.
// Four messages: the three of MAVLink 1 (see mavlink1.cpp) and one whose id does
// not fit in a byte, PROTOCOL_VERSION, id 300, 22 bytes, CRC_EXTRA 217.
//
// A frame is
//
//   0xFD | length | incompat flags | compat flags | sequence | system id | component id |
//   message id (3, little-endian) | payload | CRC (2, little-endian)
//
// The CRC is CRC-16/MCRF4XX over the bytes from the length to the end of the
// payload and then over the message's CRC_EXTRA, as in MAVLink 1: a seed that is
// not in the frame. It is written here with code of its own.
//
// What is new is that the payload is truncated: the trailing zero bytes of the
// message are not sent, except that the first byte always is, so the same message
// has frames of different lengths, and a message whose last fields are zero is
// short. Frames are not signed, so both flags are 0. The sequence goes up by one
// for each frame, and frames follow one another with nothing between them.
//
// The random draws, in order, so that anyone can regenerate a capture from its seed:
//   - once, before the first frame: the boot time of the first frame in ms, below(100000);
//     which of the hashes of PROTOCOL_VERSION are set, below(3): none (0), the
//     spec's (1), or both (2); and then the 8 bytes of the spec's hash and the 8
//     of the library's, each below(256), always, set or not;
//   - for each frame, its message: below(4), 0 for HEARTBEAT, 1 for SYS_STATUS,
//     2 for ATTITUDE, 3 for PROTOCOL_VERSION;
//   - then its payload, always every draw of the message:
//       HEARTBEAT:  as in MAVLink 1;
//       SYS_STATUS: as in MAVLink 1 up to the comm drop rate; then whether the battery
//                   is unknown, below(3) == 0, and its level 1 + below(100), which is
//                   0 when it is unknown. The error counters are 0;
//       ATTITUDE:   as in MAVLink 1 up to the pitch speed; then the yaw speed's bits,
//                   drawn as the others, and whether it is zero, below(4) == 0, which
//                   makes it 0.0;
//       PROTOCOL_VERSION: the version, [200, 200, 300][below(3)], and the highest
//                   version, 200 + 100 * below(2); the lowest is 100. The hashes are
//                   those of the start, the ones that are not set being zeros;
//   - then one draw per byte for its timing delay, always, so that the same seed
//     gives the same frames whatever the jitter.

#include "mavlink2.h"

#include "common.h"

namespace bw {

namespace {

const std::uint64_t kCharNs = 10ULL * 1000000000ULL / 57600ULL;      // 173611: 10 bits at 57600 baud

std::uint16_t crc16_mcrf4xx(const std::vector<std::uint8_t>& frame, std::size_t from, std::size_t to,
                            std::uint8_t extra) {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = from; i <= to; ++i) {
        const std::uint8_t byte = (i < to) ? frame[i] : extra;        // the seed is one byte past the end
        crc = static_cast<std::uint16_t>(crc ^ byte);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1u) ? static_cast<std::uint16_t>((crc >> 1) ^ 0x8408u)
                             : static_cast<std::uint16_t>(crc >> 1);
        }
    }
    return crc;
}

FieldInfo field(FieldKind kind, std::uint32_t bits, ByteOrder order) {
    FieldInfo info;
    info.kind       = kind;
    info.bit_size   = bits;
    info.byte_order = order;
    return info;
}

FieldInfo constant(std::uint64_t value, std::uint32_t bits, ByteOrder order) {
    FieldInfo info = field(FieldKind::Constant, bits, order);
    info.constant  = value;
    return info;
}

struct Message {
    const char*   name;
    std::uint32_t id;
    unsigned      payload;       // bytes, before the zeros at the end are cut
    std::uint8_t  crc_extra;
};

const Message kMessages[4] = {
    { "heartbeat",        0,   9,  50  },
    { "sys_status",       1,   31, 124 },
    { "attitude",         30,  28, 39  },
    { "protocol_version", 300, 22, 217 },
};

class Mavlink2 : public Protocol {
public:
    std::string name() const override { return "mavlink2"; }

    std::string summary() const override {
        return "MAVLink 2: HEARTBEAT, SYS_STATUS, ATTITUDE and PROTOCOL_VERSION, payloads without their trailing zeros, "
               "57600 baud 8N1, back to back, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind = FramingKind::Contiguous;
        model.set_framing(framing);

        for (std::size_t m = 0; m < 4; ++m) {
            const ByteOrder none = ByteOrder::NotApplicable;
            const std::size_t t = model.add_message_type(kMessages[m].name);
            model.add_field(t, "stx", constant(0xFD, 8, none), "");
            const std::size_t length = model.add_field(t, "length", field(FieldKind::Length, 8, none), "");
            model.add_field(t, "incompat_flags", constant(0, 8, none), "");
            model.add_field(t, "compat_flags", constant(0, 8, none), "");
            model.add_field(t, "sequence", field(FieldKind::Counter, 8, none), "step 1");
            model.add_field(t, "system_id", constant(1, 8, none), "");
            model.add_field(t, "component_id", constant(1, 8, none), "");
            model.add_field(t, "message_id", constant(kMessages[m].id, 24, ByteOrder::Little), "");
            // The payload is as long as the length says, and the layout of the message is its own: the fields at
            // the end of it may not be there.
            FieldInfo payload = field(FieldKind::Payload, 0, none);
            payload.size_kind  = SizeKind::FromField;
            payload.size_field = static_cast<std::uint32_t>(length);
            const std::size_t last = model.add_field(t, "payload", payload, "");
            FieldInfo crc = field(FieldKind::Checksum, 16, ByteOrder::Little);
            crc.covers_first = static_cast<std::uint32_t>(length);                // from the length: not the STX
            crc.covers_last  = static_cast<std::uint32_t>(last);
            model.add_field(t, "crc", crc,
                            "CRC-16/MCRF4XX seeded with " + std::to_string(kMessages[m].crc_extra));
        }
        return model;
    }

    Dataset generate(const GenerateOptions& options) const override {
        check_generate_options(options);

        Rng                 rng(options.seed);
        Capture             capture;
        const std::uint32_t channel   = capture.add_channel("uart");
        const std::uint64_t max_delay = kCharNs * options.jitter_permille / 1000;

        const std::uint64_t boot0 = rng.below(100000);
        const std::uint64_t hashes = rng.below(3);
        std::vector<std::uint8_t> spec_hash, library_hash;
        for (int k = 0; k < 8; ++k) {
            spec_hash.push_back(static_cast<std::uint8_t>(rng.below(256)));
        }
        for (int k = 0; k < 8; ++k) {
            library_hash.push_back(static_cast<std::uint8_t>(rng.below(256)));
        }

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              start  = 0;
        std::uint64_t              events = 0;
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            const std::uint64_t kind = rng.below(4);
            const Message&      m    = kMessages[kind];

            std::vector<std::uint8_t> payload;
            if (kind == 0) {
                static const unsigned modes[4] = { 0, 3, 4, 5 };
                static const unsigned bases[3] = { 81, 209, 217 };
                put_le(&payload, modes[rng.below(4)], 4);
                payload.push_back(static_cast<std::uint8_t>(1 + rng.below(2)));
                payload.push_back(3);
                payload.push_back(static_cast<std::uint8_t>(bases[rng.below(3)]));
                payload.push_back(static_cast<std::uint8_t>(3 + rng.below(2)));
                payload.push_back(3);
            } else if (kind == 1) {
                static const std::uint32_t present[3] = { 0x1FFFF, 0x1FFFF, 0xFFFF };
                static const std::uint32_t enabled[2] = { 0xFFFF, 0x3FFF };
                static const std::uint32_t health[2]  = { 0xFFFF, 0x7FFF };
                const std::uint32_t        sensors    = present[rng.below(3)];
                const std::uint32_t        on         = sensors & enabled[rng.below(2)];
                const std::uint32_t        ok         = on & health[rng.below(2)];
                put_le(&payload, sensors, 4);
                put_le(&payload, on, 4);
                put_le(&payload, ok, 4);
                put_le(&payload, rng.below(1000), 2);
                put_le(&payload, 10500 + rng.below(2100), 2);
                put_le(&payload, rng.below(3000), 2);
                put_le(&payload, rng.below(50), 2);
                put_le(&payload, 0, 2);                    // errors_comm
                put_le(&payload, 0, 8);                    // errors_count1 to 4
                const bool          unknown = rng.below(3) == 0;
                const std::uint64_t level   = 1 + rng.below(100);
                payload.push_back(static_cast<std::uint8_t>(unknown ? 0 : level));
            } else if (kind == 2) {
                put_le(&payload, (boot0 + 20 * static_cast<std::uint64_t>(i)) % 4294967296ULL, 4);
                for (int f = 0; f < 3; ++f) {
                    put_le(&payload, random_float_bits(&rng, 126, 3), 4);
                }
                for (int f = 0; f < 2; ++f) {
                    put_le(&payload, random_float_bits(&rng, 120, 4), 4);
                }
                const std::uint32_t yaw_speed = random_float_bits(&rng, 120, 4);
                const bool          zero      = rng.below(4) == 0;
                put_le(&payload, zero ? 0 : yaw_speed, 4);
            } else {
                static const unsigned versions[3] = { 200, 200, 300 };
                put_le(&payload, versions[rng.below(3)], 2);
                put_le(&payload, 100, 2);
                put_le(&payload, 200 + 100 * rng.below(2), 2);
                for (int k = 0; k < 8; ++k) {
                    payload.push_back(hashes >= 1 ? spec_hash[k] : 0);
                }
                for (int k = 0; k < 8; ++k) {
                    payload.push_back(hashes >= 2 ? library_hash[k] : 0);
                }
            }
            // The zeros at the end are not sent, but for the first byte.
            while (payload.size() > 1 && payload.back() == 0) {
                payload.pop_back();
            }

            std::vector<std::uint8_t> frame;
            frame.push_back(0xFD);
            frame.push_back(static_cast<std::uint8_t>(payload.size()));
            frame.push_back(0);
            frame.push_back(0);
            frame.push_back(static_cast<std::uint8_t>(i & 0xFF));
            frame.push_back(1);
            frame.push_back(1);
            put_le(&frame, m.id, 3);
            frame.insert(frame.end(), payload.begin(), payload.end());
            put_le(&frame, crc16_mcrf4xx(frame, 1, frame.size(), m.crc_extra), 2);

            start = emit_bytes(&capture, channel, start, kCharNs, max_delay, &rng, frame);

            FrameSpan span;
            span.first_event = events;
            span.event_count = frame.size();
            spans.push_back(span);
            types.push_back(static_cast<std::uint32_t>(kind));
            events += frame.size();
        }
        return Dataset(capture, model(), spans, types);
    }

    bool conforms(const std::vector<std::uint8_t>& frame) const override {
        if (frame.size() < 13 || frame[0] != 0xFD || frame[2] != 0 || frame[3] != 0 ||
            frame.size() != 12 + static_cast<std::size_t>(frame[1])) {
            return false;
        }
        const std::uint32_t id = frame[7] | (static_cast<std::uint32_t>(frame[8]) << 8) |
                                 (static_cast<std::uint32_t>(frame[9]) << 16);
        for (std::size_t m = 0; m < 4; ++m) {
            if (id != kMessages[m].id) {
                continue;
            }
            // Never longer than the message, and never ending in a zero that could have been cut. (One byte
            // at least, which the size above has already said.)
            const std::size_t length = frame[1];
            if (length > kMessages[m].payload || (length > 1 && frame[9 + length] == 0)) {
                return false;
            }
            const std::uint16_t crc = crc16_mcrf4xx(frame, 1, frame.size() - 2, kMessages[m].crc_extra);
            return frame[frame.size() - 2] == (crc & 0xFF) && frame[frame.size() - 1] == (crc >> 8);
        }
        return false;
    }
};

} // namespace

const Protocol& mavlink2_protocol() {
    static const Mavlink2 protocol;
    return protocol;
}

} // namespace bw
