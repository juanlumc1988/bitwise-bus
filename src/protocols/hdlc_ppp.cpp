// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// PPP in HDLC-like framing, the asynchronous framing of RFC 1662, on a 115200 baud
// 8N1 line, one event per byte. A frame is the bytes between two flags (0x7E), and a
// flag or an escape (0x7D) inside it is sent as the escape and the byte with its bit
// 5 flipped, so that the flag can never be mistaken for data:
//
//   0x7E inside a frame is sent as 0x7D 0x5E
//   0x7D inside a frame is sent as 0x7D 0x5D
//
// (The control characters, below 0x20, are not escaped: that is the async control
// character map of 0 that a link negotiates once it is up.) Each frame is
//
//   flag | 0xFF | 0x03 | protocol (2, big-endian) | information | FCS (2, little-endian) | flag
//
// where the FCS is the 16-bit frame check sequence of RFC 1662, CRC-16/X-25
// (polynomial 0x1021 reflected, initial value 0xFFFF, final xor 0xFFFF), over the
// address, the control, the protocol and the information, sent low byte first. It
// is written here with code of its own. Between the flags of one frame and the
// next there may be more flags, as idle fill, which belong to no frame.
//
// Three kinds of frame, whose layout the truth model gives as the frame is once the
// stuffing is taken out:
//
//   LCP Echo-Request   protocol 0xC021: code 9, identifier, length 8 (2, big-endian), magic number 0x0B7E9A31
//   IPCP Configure-Request  protocol 0x8021: code 1, identifier, length 10, option 3 of length 6: an address
//   IP datagram        protocol 0x0021: 24 bytes of data
//
// The identifier of each of the first two goes up by one for each frame of its kind.
// The random draws, in order, so that anyone can regenerate a capture from its seed:
//   - for each frame, first the idle flags before it, below(3); then its kind, below(3):
//     0 for an LCP echo, 1 for an IPCP request and 2 for an IP datagram;
//   - then its fields, always every draw of the kind: an LCP echo has none; an IPCP
//     request, which of four addresses, below(4): 192.0.2.1, 192.0.2.2, 10.0.0.1, 10.0.0.2;
//     an IP datagram, its 24 bytes, below(256) each;
//   - then one draw per byte for its timing delay, the idle flags included, always, so
//     that the same seed gives the same frames whatever the jitter.

#include "hdlc_ppp.h"

#include "common.h"

namespace bw {

namespace {

const std::uint64_t kCharNs = 10ULL * 1000000000ULL / 115200ULL;     // 86805: 10 bits at 115200 baud

const std::uint8_t kFlag = 0x7E, kEsc = 0x7D, kFlagCode = 0x5E, kEscCode = 0x5D;

// CRC-16/X-25, a bit at a time, without the final xor.
std::uint16_t crc16_register(const std::vector<std::uint8_t>& bytes) {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        crc = static_cast<std::uint16_t>(crc ^ bytes[i]);
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

FieldInfo constant(std::uint64_t value, std::uint32_t bits) {
    FieldInfo info = field(FieldKind::Constant, bits, bits > 8 ? ByteOrder::Big : ByteOrder::NotApplicable);
    info.constant  = value;
    return info;
}

const std::uint32_t kAddresses[4] = { 0xC0000201, 0xC0000202, 0x0A000001, 0x0A000002 };
const std::uint32_t kMagic        = 0x0B7E9A31;

class HdlcPpp : public Protocol {
public:
    std::string name() const override { return "hdlc-ppp"; }

    std::string summary() const override {
        return "PPP in HDLC-like framing (RFC 1662): LCP echo, IPCP request and IP datagram, FCS-16, 115200 baud 8N1, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind           = FramingKind::Flagged;
        framing.delimiter      = kFlag;
        framing.escaped        = true;
        framing.escape         = kEsc;
        framing.delimiter_code = kFlagCode;
        framing.escape_code    = kEscCode;
        model.set_framing(framing);

        const ByteOrder big  = ByteOrder::Big;
        const ByteOrder none = ByteOrder::NotApplicable;
        const char*     names[3]     = { "lcp_echo", "ipcp_request", "ip_datagram" };
        const std::uint32_t protocols[3] = { 0xC021, 0x8021, 0x0021 };
        for (std::size_t k = 0; k < 3; ++k) {
            const std::size_t t = model.add_message_type(names[k]);
            model.add_field(t, "address", constant(0xFF, 8), "");
            model.add_field(t, "control", constant(0x03, 8), "");
            model.add_field(t, "protocol", constant(protocols[k], 16), "");
            std::size_t last = 2;
            if (k == 0) {
                model.add_field(t, "code", constant(9, 8), "");
                model.add_field(t, "identifier", field(FieldKind::Counter, 8, none), "step 1");
                model.add_field(t, "length", field(FieldKind::Length, 16, big), "");
                last = model.add_field(t, "magic_number", constant(kMagic, 32), "");
            } else if (k == 1) {
                model.add_field(t, "code", constant(1, 8), "");
                model.add_field(t, "identifier", field(FieldKind::Counter, 8, none), "step 1");
                model.add_field(t, "length", field(FieldKind::Length, 16, big), "");
                model.add_field(t, "option_type", constant(3, 8), "");
                model.add_field(t, "option_length", constant(6, 8), "");
                last = model.add_field(t, "ip_address", field(FieldKind::Enum, 32, big), "");
            } else {
                last = model.add_field(t, "datagram", field(FieldKind::Payload, 192, none), "");
            }
            FieldInfo fcs = field(FieldKind::Checksum, 16, ByteOrder::Little);
            fcs.covers_first = 0;                                           // from the address
            fcs.covers_last  = static_cast<std::uint32_t>(last);
            model.add_field(t, "fcs", fcs, "CRC-16/X-25 (the FCS-16 of RFC 1662)");
        }
        return model;
    }

    Dataset generate(const GenerateOptions& options) const override {
        check_generate_options(options);

        Rng                 rng(options.seed);
        Capture             capture;
        const std::uint32_t channel   = capture.add_channel("uart");
        const std::uint64_t max_delay = kCharNs * options.jitter_permille / 1000;

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              start  = 0;
        std::uint64_t              events = 0;
        std::uint8_t               lcp_id = 0, ipcp_id = 0;
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            const std::uint64_t idle = rng.below(3);
            const std::uint64_t kind = rng.below(3);

            // The frame as it is once the stuffing is taken out.
            std::vector<std::uint8_t> content;
            content.push_back(0xFF);
            content.push_back(0x03);
            if (kind == 0) {
                content.push_back(0xC0);
                content.push_back(0x21);
                content.push_back(9);
                content.push_back(lcp_id++);
                content.push_back(0);
                content.push_back(8);
                for (int shift = 24; shift >= 0; shift -= 8) {
                    content.push_back(static_cast<std::uint8_t>((kMagic >> shift) & 0xFF));
                }
            } else if (kind == 1) {
                content.push_back(0x80);
                content.push_back(0x21);
                content.push_back(1);
                content.push_back(ipcp_id++);
                content.push_back(0);
                content.push_back(10);
                content.push_back(3);
                content.push_back(6);
                const std::uint32_t address = kAddresses[rng.below(4)];
                for (int shift = 24; shift >= 0; shift -= 8) {
                    content.push_back(static_cast<std::uint8_t>((address >> shift) & 0xFF));
                }
            } else {
                content.push_back(0x00);
                content.push_back(0x21);
                for (int k = 0; k < 24; ++k) {
                    content.push_back(static_cast<std::uint8_t>(rng.below(256)));
                }
            }
            const std::uint16_t fcs = static_cast<std::uint16_t>(crc16_register(content) ^ 0xFFFF);
            content.push_back(static_cast<std::uint8_t>(fcs & 0xFF));
            content.push_back(static_cast<std::uint8_t>(fcs >> 8));

            const std::vector<std::uint8_t> fill(static_cast<std::size_t>(idle), kFlag);
            start = emit_bytes(&capture, channel, start, kCharNs, max_delay, &rng, fill);
            events += fill.size();

            std::vector<std::uint8_t> frame(1, kFlag);
            const std::vector<std::uint8_t> sent = stuff(content, kFlag, kEsc, kFlagCode, kEscCode);
            frame.insert(frame.end(), sent.begin(), sent.end());
            frame.push_back(kFlag);
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

    // A frame as it is on the line, with its flags.
    bool conforms(const std::vector<std::uint8_t>& frame) const override {
        if (frame.empty() || frame.front() != kFlag || frame.back() != kFlag) {
            return false;
        }
        std::vector<std::uint8_t> content;
        for (std::size_t i = 1; i + 1 < frame.size(); ++i) {
            if (frame[i] == kFlag) {
                return false;                                  // a flag inside is not data
            }
            if (frame[i] == kEsc) {
                // frame[i + 1] is there, and the last byte, a flag, is not a code: an escape at the end is refused here too.
                if (frame[i + 1] != kFlagCode && frame[i + 1] != kEscCode) {
                    return false;
                }
                content.push_back(frame[i + 1] == kFlagCode ? kFlag : kEsc);
                ++i;
            } else {
                content.push_back(frame[i]);
            }
        }
        // Address, control, protocol, the information of that protocol, and the FCS.
        if (content.size() < 4 || content[0] != 0xFF || content[1] != 0x03) {
            return false;
        }
        const unsigned protocol = (static_cast<unsigned>(content[2]) << 8) | content[3];
        const std::size_t sizes[3] = { 14, 16, 30 };
        const unsigned    known[3] = { 0xC021, 0x8021, 0x0021 };
        bool ok = false;
        for (int k = 0; k < 3; ++k) {
            ok = ok || (protocol == known[k] && content.size() == sizes[k]);
        }
        // The register over the whole frame, FCS included, is a constant when the FCS is right.
        return ok && crc16_register(content) == 0xF0B8;
    }
};

} // namespace

const Protocol& hdlc_ppp_protocol() {
    static const HdlcPpp protocol;
    return protocol;
}

} // namespace bw
