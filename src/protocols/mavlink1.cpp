// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// MAVLink 1, the telemetry protocol of drones and their ground stations, on a
// 57600 baud 8N1 line (a telemetry radio), one event per byte. Three messages:
//
//   HEARTBEAT   id 0,  9 bytes, CRC_EXTRA 50
//   SYS_STATUS  id 1, 31 bytes, CRC_EXTRA 124
//   ATTITUDE    id 30, 28 bytes, CRC_EXTRA 39
//
// A frame is
//
//   0xFE | length | sequence | system id | component id | message id | payload | CRC (2, little-endian)
//
// The CRC is CRC-16/MCRF4XX (polynomial 0x1021 reflected, initial value 0xFFFF,
// no final xor) over the bytes from the length to the end of the payload, and
// then over one more byte that is not in the frame: the message's CRC_EXTRA, a
// number worked out from the definition of the message and known to both ends.
// That is a seed that nobody can read off a capture. It is written here with
// code of its own, not with the inference stages.
//
// Inside the payload the fields are in the order of the wire, which is not the
// order of the definition: the larger ones come first (u32 and float, then u16,
// then u8 and i8), and the order of the definition is kept among those of the
// same size.
//
// The sequence number goes up by one for each frame, whatever the message, and
// the frames follow one another with nothing between them. The random draws, in
// order, so that anyone can regenerate a capture from its seed:
//   - once, before the first frame: the boot time of the first frame, in ms, below(100000);
//   - for each frame, its message: below(3), 0 for HEARTBEAT, 1 for SYS_STATUS, 2 for ATTITUDE;
//   - then its payload, always every draw of the message:
//       HEARTBEAT:  custom_mode, [0, 3, 4, 5][below(4)]; type, 1 + below(2); base_mode,
//                   [81, 209, 217][below(3)]; system_status, 3 + below(2). The autopilot (3)
//                   and the MAVLink version (3) are constants;
//       SYS_STATUS: sensors present, [0x1FFFF, 0x1FFFF, 0xFFFF][below(3)]; enabled, present &
//                   [0xFFFF, 0x3FFF][below(2)]; health, enabled & [0xFFFF, 0x7FFF][below(2)];
//                   load, below(1000); battery voltage, 10500 + below(2100); battery current,
//                   below(3000); comm drop rate, below(50); battery remaining, below(101).
//                   The error counters stay at 0;
//       ATTITUDE:   the boot time is that of the first frame plus 20 ms for each frame so far;
//                   roll, pitch and yaw are floats of exponent 126 + below(3), the three rates
//                   of exponent 120 + below(4), each as its sign below(2), its exponent
//                   and then its mantissa below(2^23);
//   - then one draw per byte for its timing delay, always, so that the same seed
//     gives the same frames whatever the jitter.

#include "mavlink1.h"

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

FieldInfo constant(std::uint8_t value) {
    FieldInfo info = field(FieldKind::Constant, 8, ByteOrder::NotApplicable);
    info.constant  = value;
    return info;
}

const ByteOrder kNone   = ByteOrder::NotApplicable;
const ByteOrder kLittle = ByteOrder::Little;

struct Message {
    const char*  name;
    std::uint8_t id;
    unsigned     payload;      // bytes
    std::uint8_t crc_extra;
};

const Message kMessages[3] = {
    { "heartbeat",  0,  9,  50  },
    { "sys_status", 1,  31, 124 },
    { "attitude",   30, 28, 39  },
};

class Mavlink1 : public Protocol {
public:
    std::string name() const override { return "mavlink1"; }

    std::string summary() const override {
        return "MAVLink 1: HEARTBEAT, SYS_STATUS and ATTITUDE, 57600 baud 8N1, back to back, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind = FramingKind::Contiguous;
        model.set_framing(framing);

        for (std::size_t m = 0; m < 3; ++m) {
            const std::size_t t = model.add_message_type(kMessages[m].name);
            model.add_field(t, "stx", constant(0xFE), "");
            model.add_field(t, "length", field(FieldKind::Length, 8, kNone), "");
            model.add_field(t, "sequence", field(FieldKind::Counter, 8, kNone), "step 1");
            model.add_field(t, "system_id", constant(1), "");
            model.add_field(t, "component_id", constant(1), "");
            model.add_field(t, "message_id", constant(kMessages[m].id), "");
            std::size_t last = 5;
            switch (m) {
                case 0:
                    last = model.add_field(t, "custom_mode", field(FieldKind::Enum, 32, kLittle), "");
                    last = model.add_field(t, "type", field(FieldKind::Enum, 8, kNone), "");
                    last = model.add_field(t, "autopilot", constant(3), "");
                    last = model.add_field(t, "base_mode", field(FieldKind::Flags, 8, kNone), "");
                    last = model.add_field(t, "system_status", field(FieldKind::Enum, 8, kNone), "");
                    last = model.add_field(t, "mavlink_version", constant(3), "");
                    break;
                case 1: {
                    last = model.add_field(t, "sensors_present", field(FieldKind::Flags, 32, kLittle), "");
                    last = model.add_field(t, "sensors_enabled", field(FieldKind::Flags, 32, kLittle), "");
                    last = model.add_field(t, "sensors_health", field(FieldKind::Flags, 32, kLittle), "");
                    last = model.add_field(t, "load", field(FieldKind::Payload, 16, kNone), "");
                    last = model.add_field(t, "voltage_battery", field(FieldKind::Payload, 16, kNone), "");
                    last = model.add_field(t, "current_battery", field(FieldKind::Payload, 16, kNone), "");
                    last = model.add_field(t, "drop_rate_comm", field(FieldKind::Payload, 16, kNone), "");
                    last = model.add_field(t, "errors_comm", field(FieldKind::Counter, 16, kLittle), "");
                    const char* counters[4] = { "errors_count1", "errors_count2", "errors_count3", "errors_count4" };
                    for (int c = 0; c < 4; ++c) {
                        last = model.add_field(t, counters[c], field(FieldKind::Counter, 16, kLittle), "");
                    }
                    last = model.add_field(t, "battery_remaining", field(FieldKind::Payload, 8, kNone), "");
                    break;
                }
                default: {
                    last = model.add_field(t, "time_boot_ms", field(FieldKind::Timestamp, 32, kLittle), "");
                    const char* floats[6] = { "roll", "pitch", "yaw", "rollspeed", "pitchspeed", "yawspeed" };
                    for (int f = 0; f < 6; ++f) {
                        last = model.add_field(t, floats[f], field(FieldKind::Float, 32, kLittle), "");
                    }
                    break;
                }
            }
            FieldInfo crc = field(FieldKind::Checksum, 16, kLittle);
            crc.covers_first = 1;                                               // from the length
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

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              start  = 0;
        std::uint64_t              events = 0;
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            const std::uint64_t kind = rng.below(3);
            const Message&      m    = kMessages[kind];

            std::vector<std::uint8_t> frame;
            frame.push_back(0xFE);
            frame.push_back(static_cast<std::uint8_t>(m.payload));
            frame.push_back(static_cast<std::uint8_t>(i & 0xFF));
            frame.push_back(1);
            frame.push_back(1);
            frame.push_back(m.id);
            if (kind == 0) {
                static const unsigned modes[4] = { 0, 3, 4, 5 };
                static const unsigned bases[3] = { 81, 209, 217 };
                put_le(&frame, modes[rng.below(4)], 4);
                frame.push_back(static_cast<std::uint8_t>(1 + rng.below(2)));
                frame.push_back(3);
                frame.push_back(static_cast<std::uint8_t>(bases[rng.below(3)]));
                frame.push_back(static_cast<std::uint8_t>(3 + rng.below(2)));
                frame.push_back(3);
            } else if (kind == 1) {
                static const std::uint32_t present[3] = { 0x1FFFF, 0x1FFFF, 0xFFFF };
                static const std::uint32_t enabled[2] = { 0xFFFF, 0x3FFF };
                static const std::uint32_t health[2]  = { 0xFFFF, 0x7FFF };
                const std::uint32_t        sensors    = present[rng.below(3)];
                const std::uint32_t        on         = sensors & enabled[rng.below(2)];
                const std::uint32_t        ok         = on & health[rng.below(2)];
                put_le(&frame, sensors, 4);
                put_le(&frame, on, 4);
                put_le(&frame, ok, 4);
                put_le(&frame, rng.below(1000), 2);
                put_le(&frame, 10500 + rng.below(2100), 2);
                put_le(&frame, rng.below(3000), 2);
                put_le(&frame, rng.below(50), 2);
                put_le(&frame, 0, 2);                      // errors_comm
                put_le(&frame, 0, 8);                      // errors_count1 to 4
                frame.push_back(static_cast<std::uint8_t>(rng.below(101)));
            } else {
                put_le(&frame, (boot0 + 20 * static_cast<std::uint64_t>(i)) % 4294967296ULL, 4);
                for (int f = 0; f < 3; ++f) {
                    put_le(&frame, random_float_bits(&rng, 126, 3), 4);
                }
                for (int f = 0; f < 3; ++f) {
                    put_le(&frame, random_float_bits(&rng, 120, 4), 4);
                }
            }
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
        if (frame.size() < 8 || frame[0] != 0xFE || frame.size() != 8 + static_cast<std::size_t>(frame[1])) {
            return false;
        }
        for (std::size_t m = 0; m < 3; ++m) {
            if (frame[5] == kMessages[m].id && frame[1] == kMessages[m].payload) {
                const std::uint16_t crc = crc16_mcrf4xx(frame, 1, frame.size() - 2, kMessages[m].crc_extra);
                return frame[frame.size() - 2] == (crc & 0xFF) && frame[frame.size() - 1] == (crc >> 8);
            }
        }
        return false;
    }
};

} // namespace

const Protocol& mavlink1_protocol() {
    static const Mavlink1 protocol;
    return protocol;
}

} // namespace bw
