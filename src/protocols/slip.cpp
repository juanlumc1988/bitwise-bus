// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// SLIP, the serial line IP framing of RFC 1055, on a 115200 baud 8N1 line, one
// event per byte. It has no checksum and no length: a frame is the bytes between
// two END bytes (0xC0), and an END or an ESC (0xDB) inside it is sent as ESC
// followed by a code, so that the flag can never be mistaken for data:
//
//   END (0xC0) inside a frame is sent as ESC ESC_END    = 0xDB 0xDC
//   ESC (0xDB) inside a frame is sent as ESC ESC_ESC    = 0xDB 0xDD
//
// Each frame is sent with an END before it and one after it, as the drivers do
// (the first flushes whatever line noise came before), so that between two frames
// there are two ENDs, and an empty frame that a receiver ignores.
//
// SLIP carries any packet; here two records of a telemetry stream, which are what
// the truth model describes, as the frame is once the stuffing is taken out:
//
//   sample  type 0x10 | sequence (2, big-endian) | time in ms (4, big-endian) | six readings (2 each, big-endian)
//   status  type 0x20 | sequence (2) | time in ms (4) | state (1) | battery in mV (2)
//
// The sequence is the number of the frame, whatever it is, and the time goes up by
// 100 ms for each frame. Frames follow one another with nothing between them. The
// random draws, in order, so that anyone can regenerate a capture from its seed:
//   - once, before the first frame: the time of the first frame in ms, below(1000000);
//   - for each frame, its record: below(2), 0 for a sample and 1 for a status;
//   - then its fields, always every draw of the record:
//       sample: the six readings, below(65536) each;
//       status: the state, below(4), and the battery, 11000 + below(1600);
//   - then one draw per byte for its timing delay, always, so that the same seed
//     gives the same frames whatever the jitter.

#include "slip.h"

#include "common.h"

namespace bw {

namespace {

const std::uint64_t kCharNs = 10ULL * 1000000000ULL / 115200ULL;     // 86805: 10 bits at 115200 baud

const std::uint8_t kEnd = 0xC0, kEsc = 0xDB, kEscEnd = 0xDC, kEscEsc = 0xDD;

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

class Slip : public Protocol {
public:
    std::string name() const override { return "slip"; }

    std::string summary() const override {
        return "SLIP (RFC 1055): sample and status records between ENDs with byte stuffing, 115200 baud 8N1, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind           = FramingKind::Flagged;
        framing.delimiter      = kEnd;
        framing.escaped        = true;
        framing.escape         = kEsc;
        framing.delimiter_code = kEscEnd;
        framing.escape_code    = kEscEsc;
        model.set_framing(framing);

        const ByteOrder big  = ByteOrder::Big;
        const ByteOrder none = ByteOrder::NotApplicable;
        const std::size_t sample = model.add_message_type("sample");
        model.add_field(sample, "type", constant(0x10), "");
        model.add_field(sample, "sequence", field(FieldKind::Counter, 16, big), "step 1");
        model.add_field(sample, "time", field(FieldKind::Timestamp, 32, big), "step 100");
        for (int r = 0; r < 6; ++r) {
            model.add_field(sample, "reading" + std::to_string(r), field(FieldKind::Payload, 16, none), "");
        }
        const std::size_t status = model.add_message_type("status");
        model.add_field(status, "type", constant(0x20), "");
        model.add_field(status, "sequence", field(FieldKind::Counter, 16, big), "step 1");
        model.add_field(status, "time", field(FieldKind::Timestamp, 32, big), "step 100");
        model.add_field(status, "state", field(FieldKind::Enum, 8, none), "");
        model.add_field(status, "battery", field(FieldKind::Payload, 16, none), "");
        return model;
    }

    Dataset generate(const GenerateOptions& options) const override {
        check_generate_options(options);

        Rng                 rng(options.seed);
        Capture             capture;
        const std::uint32_t channel   = capture.add_channel("uart");
        const std::uint64_t max_delay = kCharNs * options.jitter_permille / 1000;

        const std::uint64_t time0 = rng.below(1000000);

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              start  = 0;
        std::uint64_t              events = 0;
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            const std::uint64_t kind = rng.below(2);

            // The frame as it is once the stuffing is taken out: big-endian numbers.
            std::vector<std::uint8_t> content;
            content.push_back(kind == 0 ? 0x10 : 0x20);
            for (int shift = 8; shift >= 0; shift -= 8) {
                content.push_back(static_cast<std::uint8_t>((i >> shift) & 0xFF));
            }
            // Below 1000000 + 100 * 100000: it never reaches the 32 bits, so there is no turn-over to write.
            const std::uint64_t time = time0 + 100 * static_cast<std::uint64_t>(i);
            for (int shift = 24; shift >= 0; shift -= 8) {
                content.push_back(static_cast<std::uint8_t>((time >> shift) & 0xFF));
            }
            if (kind == 0) {
                for (int r = 0; r < 6; ++r) {
                    const std::uint64_t reading = rng.below(65536);
                    content.push_back(static_cast<std::uint8_t>(reading >> 8));
                    content.push_back(static_cast<std::uint8_t>(reading & 0xFF));
                }
            } else {
                content.push_back(static_cast<std::uint8_t>(rng.below(4)));
                const std::uint64_t battery = 11000 + rng.below(1600);
                content.push_back(static_cast<std::uint8_t>(battery >> 8));
                content.push_back(static_cast<std::uint8_t>(battery & 0xFF));
            }

            std::vector<std::uint8_t> frame(1, kEnd);
            const std::vector<std::uint8_t> sent = stuff(content, kEnd, kEsc, kEscEnd, kEscEsc);
            frame.insert(frame.end(), sent.begin(), sent.end());
            frame.push_back(kEnd);

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

    // A frame as it is on the line, with its ENDs. SLIP has no checksum, so what makes a frame is its shape: the
    // stuffing, and a record of the size its type says. What an escape stands for does not change either, so the
    // record is its first byte and its size, and an escape and its code count as the one byte they are.
    bool conforms(const std::vector<std::uint8_t>& frame) const override {
        if (frame.empty() || frame.front() != kEnd || frame.back() != kEnd) {
            return false;
        }
        std::size_t  size = 0;
        std::uint8_t type = 0;
        for (std::size_t i = 1; i + 1 < frame.size(); ++i) {
            if (frame[i] == kEnd) {
                return false;                                  // an END inside is not data
            }
            if (frame[i] == kEsc) {
                ++i;                                           // the byte after it is there: at most the last END
                if (frame[i] != kEscEnd && frame[i] != kEscEsc) {
                    return false;                              // and an END is not a code, so an escape at the end ends here
                }
            }
            if (size == 0) {
                type = frame[i];                               // a stuffed first byte is a code: not a type
            }
            ++size;
        }
        return (type == 0x10 && size == 19) || (type == 0x20 && size == 10);
    }
};

} // namespace

const Protocol& slip_protocol() {
    static const Slip protocol;
    return protocol;
}

} // namespace bw
