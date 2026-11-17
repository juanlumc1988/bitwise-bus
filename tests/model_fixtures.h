// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Models the tests share. This one is shaped like a Modbus RTU request: two
// small enumerations, two 16-bit values with no structure to find, and a CRC.

#ifndef BW_TESTS_MODEL_FIXTURES_H
#define BW_TESTS_MODEL_FIXTURES_H

#include <cstdint>
#include <string>

#include "bw/model.h"

namespace fixtures {

inline bw::FieldInfo fixed(bw::FieldKind kind, std::uint32_t bits,
                           bw::ByteOrder order = bw::ByteOrder::NotApplicable) {
    bw::FieldInfo info;
    info.kind       = kind;
    info.bit_size   = bits;
    info.byte_order = order;
    return info;
}

inline bw::FieldInfo checksum(std::uint32_t bits, bw::ByteOrder order,
                              std::uint32_t first, std::uint32_t last) {
    bw::FieldInfo info = fixed(bw::FieldKind::Checksum, bits, order);
    info.covers_first = first;
    info.covers_last  = last;
    return info;
}

// address | function | register | quantity | crc, at bits 0, 8, 16, 32 and 48.
// The checksum's byte order, coverage and algorithm and the kind of the second
// field can be changed, so that a test can alter one thing at a time.
inline bw::Model request_model(bw::ByteOrder crc_order = bw::ByteOrder::Little,
                               std::uint32_t covers_last = 3,
                               const std::string& algorithm = "CRC-16/MODBUS",
                               bw::FieldKind function_kind = bw::FieldKind::Enum) {
    bw::Model model;
    bw::FramingInfo framing;
    framing.kind        = bw::FramingKind::IdleGap;
    framing.idle_gap_ns = 4000000;
    model.set_framing(framing);

    const std::size_t t = model.add_message_type("request");
    model.add_field(t, "address",  fixed(bw::FieldKind::Enum, 8), "");
    model.add_field(t, "function", fixed(function_kind, 8), "");
    model.add_field(t, "register", fixed(bw::FieldKind::Payload, 16), "");
    model.add_field(t, "quantity", fixed(bw::FieldKind::Payload, 16), "");
    model.add_field(t, "crc", checksum(16, crc_order, 0, covers_last), algorithm);
    return model;
}

} // namespace fixtures

#endif // BW_TESTS_MODEL_FIXTURES_H
