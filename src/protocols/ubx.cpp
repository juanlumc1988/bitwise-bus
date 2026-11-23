// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// u-blox UBX, the binary protocol of u-blox GNSS receivers, on a 115200 baud
// 8N1 line, one event per byte. Three messages, whose layouts are the ones of
// the u-blox interface description:
//
//   UBX-ACK-ACK    class 0x05 id 0x01, 2 bytes: the class and id that were acknowledged
//   UBX-CFG-RATE   class 0x06 id 0x08, 6 bytes: measRate, navRate, timeRef (u2 each)
//   UBX-NAV-STATUS class 0x01 id 0x03, 16 bytes: iTOW u4, gpsFix u1, flags x1,
//                  fixStat x1, flags2 x1, ttff u4, msss u4
//
// A frame is
//
//   0xB5 0x62 | class | id | length (2, little-endian) | payload | CK_A CK_B
//
// where the checksum is the 8-bit Fletcher checksum of the bytes from the class
// to the end of the payload: CK_A += byte, CK_B += CK_A, both modulo 256, from 0.
// It is written here with code of its own, not with the inference stages.
//
// Frames follow one another with nothing between them, at the pace of the line:
// there is no silence to find. The random draws, in order, so that anyone can
// regenerate a capture from its seed:
//   - once, before the first frame: the first iTOW, 1000 * below(604800); the
//     time to first fix, 20000 + below(20000), which then stays what it is; and
//     the first msss, 60000 + below(60000);
//   - for each frame, its message: below(3), 0 for ACK-ACK, 1 for CFG-RATE, 2 for NAV-STATUS;
//   - then its payload, always every draw of the message:
//       ACK-ACK:    which command is acknowledged, below(3): CFG-MSG (6, 1), CFG-RATE (6, 8), CFG-PRT (6, 0);
//       CFG-RATE:   measRate, [100, 200, 500, 1000][below(4)]; navRate, [1, 2, 5][below(3)]; timeRef, below(2);
//       NAV-STATUS: gpsFix, [0, 2, 3, 3, 3][below(5)]; flags, below(16); fixStat, 64 * below(4);
//                   flags2, 8 * below(3). iTOW and msss go up by 1000 for each NAV-STATUS
//                   frame of the capture, iTOW modulo 604800000;
//   - then one draw per byte for its timing delay, always, so that the same seed
//     gives the same frames whatever the jitter.

#include "ubx.h"

#include "common.h"

namespace bw {

namespace {

const std::uint64_t kCharNs = 10ULL * 1000000000ULL / 115200ULL;     // 86805: 10 bits at 115200 baud

std::uint16_t fletcher8(const std::vector<std::uint8_t>& frame, std::size_t from, std::size_t to) {
    std::uint8_t a = 0;
    std::uint8_t b = 0;
    for (std::size_t i = from; i < to; ++i) {
        a = static_cast<std::uint8_t>(a + frame[i]);
        b = static_cast<std::uint8_t>(b + a);
    }
    return static_cast<std::uint16_t>((static_cast<unsigned>(b) << 8) | a);        // CK_A first on the wire
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

struct Message {
    const char*  name;
    std::uint8_t cls;
    std::uint8_t id;
    unsigned     payload;      // bytes
};

const Message kMessages[3] = {
    { "ack_ack",    0x05, 0x01, 2  },
    { "cfg_rate",   0x06, 0x08, 6  },
    { "nav_status", 0x01, 0x03, 16 },
};

class Ubx : public Protocol {
public:
    std::string name() const override { return "ubx"; }

    std::string summary() const override {
        return "u-blox UBX: ACK-ACK, CFG-RATE and NAV-STATUS, 115200 baud 8N1, back to back, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind = FramingKind::Contiguous;
        model.set_framing(framing);

        for (std::size_t m = 0; m < 3; ++m) {
            const std::size_t t = model.add_message_type(kMessages[m].name);
            model.add_field(t, "sync1", constant(0xB5), "");
            model.add_field(t, "sync2", constant(0x62), "");
            model.add_field(t, "class", constant(kMessages[m].cls), "");
            model.add_field(t, "id", constant(kMessages[m].id), "");
            model.add_field(t, "length", field(FieldKind::Length, 16, ByteOrder::Little), "");
            std::size_t last = 4;
            switch (m) {
                case 0:
                    last = model.add_field(t, "cls_id", field(FieldKind::Enum, 8, ByteOrder::NotApplicable), "");
                    last = model.add_field(t, "msg_id", field(FieldKind::Enum, 8, ByteOrder::NotApplicable), "");
                    break;
                case 1:
                    last = model.add_field(t, "meas_rate", field(FieldKind::Enum, 16, ByteOrder::Little), "");
                    last = model.add_field(t, "nav_rate", field(FieldKind::Enum, 16, ByteOrder::Little), "");
                    last = model.add_field(t, "time_ref", field(FieldKind::Enum, 16, ByteOrder::Little), "");
                    break;
                default:
                    last = model.add_field(t, "itow", field(FieldKind::Timestamp, 32, ByteOrder::Little), "");
                    last = model.add_field(t, "gps_fix", field(FieldKind::Enum, 8, ByteOrder::NotApplicable), "");
                    last = model.add_field(t, "flags", field(FieldKind::Flags, 8, ByteOrder::NotApplicable), "");
                    last = model.add_field(t, "fix_stat", field(FieldKind::Flags, 8, ByteOrder::NotApplicable), "");
                    last = model.add_field(t, "flags2", field(FieldKind::Flags, 8, ByteOrder::NotApplicable), "");
                    last = model.add_field(t, "ttff", field(FieldKind::Timestamp, 32, ByteOrder::Little), "");
                    last = model.add_field(t, "msss", field(FieldKind::Timestamp, 32, ByteOrder::Little), "");
                    break;
            }
            FieldInfo checksum = field(FieldKind::Checksum, 16, ByteOrder::Little);
            checksum.covers_first = 2;                                          // from the class
            checksum.covers_last  = static_cast<std::uint32_t>(last);
            model.add_field(t, "checksum", checksum, "Fletcher-8 (UBX)");
        }
        return model;
    }

    Dataset generate(const GenerateOptions& options) const override {
        check_generate_options(options);

        Rng                 rng(options.seed);
        Capture             capture;
        const std::uint32_t channel   = capture.add_channel("uart");
        const std::uint64_t max_delay = kCharNs * options.jitter_permille / 1000;

        const std::uint64_t itow0 = 1000 * rng.below(604800);
        const std::uint64_t ttff  = 20000 + rng.below(20000);
        const std::uint64_t msss0 = 60000 + rng.below(60000);
        std::uint64_t       status_frames = 0;

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              start = 0;
        std::uint64_t              events = 0;
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            const std::uint64_t kind = rng.below(3);
            const Message&      m    = kMessages[kind];

            std::vector<std::uint8_t> frame;
            frame.push_back(0xB5);
            frame.push_back(0x62);
            frame.push_back(m.cls);
            frame.push_back(m.id);
            put_le(&frame, m.payload, 2);
            if (kind == 0) {
                static const std::uint8_t acked[3][2] = { {6, 1}, {6, 8}, {6, 0} };
                const std::uint64_t       which       = rng.below(3);
                frame.push_back(acked[which][0]);
                frame.push_back(acked[which][1]);
            } else if (kind == 1) {
                static const unsigned rates[4]  = { 100, 200, 500, 1000 };
                static const unsigned navs[3]   = { 1, 2, 5 };
                put_le(&frame, rates[rng.below(4)], 2);
                put_le(&frame, navs[rng.below(3)], 2);
                put_le(&frame, rng.below(2), 2);
            } else {
                static const unsigned fixes[5] = { 0, 2, 3, 3, 3 };
                const unsigned        fix      = fixes[rng.below(5)];
                const std::uint64_t   flags    = rng.below(16);
                const std::uint64_t   stat     = 64 * rng.below(4);
                const std::uint64_t   flags2   = 8 * rng.below(3);
                put_le(&frame, (itow0 + 1000 * status_frames) % 604800000ULL, 4);
                frame.push_back(static_cast<std::uint8_t>(fix));
                frame.push_back(static_cast<std::uint8_t>(flags));
                frame.push_back(static_cast<std::uint8_t>(stat));
                frame.push_back(static_cast<std::uint8_t>(flags2));
                put_le(&frame, ttff, 4);
                put_le(&frame, msss0 + 1000 * status_frames, 4);
                ++status_frames;
            }
            put_le(&frame, fletcher8(frame, 2, frame.size()), 2);

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
        if (frame.size() < 8 || frame[0] != 0xB5 || frame[1] != 0x62) {
            return false;
        }
        const std::size_t length = static_cast<std::size_t>(frame[4]) | (static_cast<std::size_t>(frame[5]) << 8);
        if (frame.size() != 8 + length) {
            return false;
        }
        bool known = false;
        for (std::size_t m = 0; m < 3; ++m) {
            known = known || (frame[2] == kMessages[m].cls && frame[3] == kMessages[m].id &&
                              length == kMessages[m].payload);
        }
        const std::uint16_t ck = fletcher8(frame, 2, frame.size() - 2);
        return known && frame[frame.size() - 2] == (ck & 0xFF) && frame[frame.size() - 1] == (ck >> 8);
    }
};

} // namespace

const Protocol& ubx_protocol() {
    static const Ubx protocol;
    return protocol;
}

} // namespace bw
