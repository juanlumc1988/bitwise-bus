// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// A model with every kind of field the Kaitai exporter writes, one after the
// other. Its definition is checked in as tests/roundtrip/mapping.ksy: the unit
// tests compare the exporter's output with that file, and the round-trip script
// compiles the file with the real Kaitai compiler and reads a frame with it.

#ifndef BW_TESTS_KAITAI_FIXTURES_H
#define BW_TESTS_KAITAI_FIXTURES_H

#include "bw/model.h"
#include "model_fixtures.h"

namespace fixtures {

inline bw::FieldInfo constant_field(std::uint32_t bits, bw::ByteOrder order, std::uint64_t value) {
    bw::FieldInfo info = fixed(bw::FieldKind::Constant, bits, order);
    info.constant      = value;
    return info;
}

inline bw::Model every_field() {
    bw::Model model;
    bw::FramingInfo framing;
    framing.kind        = bw::FramingKind::IdleGap;
    framing.idle_gap_ns = 4000000;
    model.set_framing(framing);

    const std::size_t t = model.add_message_type("mapping");
    model.add_field(t, "sync",     constant_field(8, bw::ByteOrder::NotApplicable, 0x7E), "");
    model.add_field(t, "id",       fixed(bw::FieldKind::Enum, 8), "");
    model.add_field(t, "count",    fixed(bw::FieldKind::Counter, 16, bw::ByteOrder::Big), "step 1");
    model.add_field(t, "stamp",    fixed(bw::FieldKind::Timestamp, 32, bw::ByteOrder::Little), "");
    model.add_field(t, "total",    fixed(bw::FieldKind::Length, 64, bw::ByteOrder::Big), "");
    model.add_field(t, "ratio",    fixed(bw::FieldKind::Float, 32, bw::ByteOrder::Little), "");
    model.add_field(t, "wide",     fixed(bw::FieldKind::Float, 64, bw::ByteOrder::Big), "");
    model.add_field(t, "name",     fixed(bw::FieldKind::Text, 32), "");
    model.add_field(t, "stuff",    fixed(bw::FieldKind::Payload, 24), "");
    model.add_field(t, "odd",      fixed(bw::FieldKind::Counter, 24, bw::ByteOrder::Big), "");
    model.add_field(t, "magic",    constant_field(16, bw::ByteOrder::Little, 0x1234), "");
    model.add_field(t, "tail",     constant_field(32, bw::ByteOrder::Big, 0xDEADBEEF), "");
    model.add_field(t, "checksum", checksum(16, bw::ByteOrder::Big, 0, 11), "CRC-16/CCITT-FALSE");
    return model;
}

} // namespace fixtures

#endif // BW_TESTS_KAITAI_FIXTURES_H
