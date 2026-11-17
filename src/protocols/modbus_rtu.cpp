// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Modbus RTU requests for functions 3 (read holding registers) and 4 (read
// input registers), on a 9600 baud 8N1 line, one event per byte.
//
// Both functions have the same eight-byte layout:
//
//   address | function | first register (2, big-endian) | quantity (2, big-endian) | CRC (2, little-endian)
//
// The CRC is CRC-16/MODBUS over the first six bytes. It is computed here with
// code of its own and not with the catalogue the inference stage searches:
// see bw/protocol.h.
//
// The random draws, in order, for each frame, so that anyone can regenerate a
// capture from its seed:
//   - from the second frame on: the silence before it, 5 + below(16) character times;
//   - the address, 1 + below(3);
//   - the function, 3 + below(2);
//   - the first register, below(65536);
//   - the quantity, 1 + below(125);
//   - then one draw per byte for its timing delay, always, so that the same
//     seed gives the same frames whatever the jitter.

#include "modbus_rtu.h"

#include "common.h"

namespace bw {

namespace {

const std::uint64_t kCharNs    = 11ULL * 1000000000ULL / 9600ULL;   // 1145833: 11 bits at 9600 baud
const std::size_t   kFrameSize = 8;

// CRC-16/MODBUS: polynomial 0xA001 reflected, initial value 0xFFFF, no final xor.
std::uint16_t crc16_modbus(const std::uint8_t* data, std::size_t size) {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = 0; i < size; ++i) {
        crc = static_cast<std::uint16_t>(crc ^ data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1u) ? static_cast<std::uint16_t>((crc >> 1) ^ 0xA001u)
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

class ModbusRtu : public Protocol {
public:
    std::string name() const override { return "modbus-rtu"; }

    std::string summary() const override {
        return "Modbus RTU requests for functions 3 and 4, 9600 baud 8N1, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind        = FramingKind::IdleGap;
        framing.idle_gap_ns = kCharNs * 7 / 2;      // 3.5 character times
        model.set_framing(framing);

        const std::size_t t = model.add_message_type("request");
        model.add_field(t, "address",  field(FieldKind::Enum, 8, ByteOrder::NotApplicable), "");
        model.add_field(t, "function", field(FieldKind::Enum, 8, ByteOrder::NotApplicable), "");
        model.add_field(t, "register", field(FieldKind::Payload, 16, ByteOrder::NotApplicable), "");
        model.add_field(t, "quantity", field(FieldKind::Payload, 16, ByteOrder::NotApplicable), "");
        FieldInfo crc = field(FieldKind::Checksum, 16, ByteOrder::Little);
        crc.covers_first = 0;
        crc.covers_last  = 3;
        model.add_field(t, "crc", crc, "CRC-16/MODBUS");
        return model;
    }

    Dataset generate(const GenerateOptions& options) const override {
        check_generate_options(options);

        Rng                 rng(options.seed);
        Capture             capture;
        const std::uint32_t channel   = capture.add_channel("rs485");
        const std::uint64_t max_delay = kCharNs * options.jitter_permille / 1000;

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              start = 0;           // when the frame's first byte is due
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            if (i > 0) {
                start += kFrameSize * kCharNs + kCharNs * (5 + rng.below(16));
            }

            std::uint8_t frame[kFrameSize];
            frame[0] = static_cast<std::uint8_t>(1 + rng.below(3));
            frame[1] = static_cast<std::uint8_t>(3 + rng.below(2));
            const std::uint64_t first    = rng.below(65536);
            const std::uint64_t quantity = 1 + rng.below(125);
            frame[2] = static_cast<std::uint8_t>(first >> 8);
            frame[3] = static_cast<std::uint8_t>(first & 0xFF);
            frame[4] = static_cast<std::uint8_t>(quantity >> 8);
            frame[5] = static_cast<std::uint8_t>(quantity & 0xFF);
            const std::uint16_t crc = crc16_modbus(frame, 6);
            frame[6] = static_cast<std::uint8_t>(crc & 0xFF);
            frame[7] = static_cast<std::uint8_t>(crc >> 8);

            for (std::size_t k = 0; k < kFrameSize; ++k) {
                const std::uint64_t draw  = rng.next();
                const std::uint64_t delay = (max_delay == 0) ? 0 : draw % max_delay;
                EventInfo info;
                info.has_time = true;
                info.time_ns  = static_cast<std::int64_t>(start + k * kCharNs + delay);
                info.channel  = channel;
                capture.add_event(info, std::vector<std::uint8_t>(1, frame[k]));
            }

            FrameSpan span;
            span.first_event = static_cast<std::uint64_t>(i) * kFrameSize;
            span.event_count = kFrameSize;
            spans.push_back(span);
            types.push_back(0);
        }
        return Dataset(capture, model(), spans, types);
    }

    bool conforms(const std::vector<std::uint8_t>& frame) const override {
        if (frame.size() != kFrameSize) {
            return false;
        }
        const unsigned address  = frame[0];
        const unsigned function = frame[1];
        const unsigned quantity = (static_cast<unsigned>(frame[4]) << 8) | frame[5];
        if (address < 1 || address > 247 || (function != 3 && function != 4) ||
            quantity < 1 || quantity > 125) {
            return false;
        }
        const std::uint16_t crc = crc16_modbus(&frame[0], 6);
        return frame[6] == (crc & 0xFF) && frame[7] == (crc >> 8);
    }
};

} // namespace

const Protocol& modbus_rtu_protocol() {
    static const ModbusRtu protocol;
    return protocol;
}

} // namespace bw
