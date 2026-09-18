// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// A CRC defined by its parameters rather than by its name.
//
// Every CRC in use is the same algorithm under six numbers: width,
// polynomial, initial value, whether input bits are reflected, whether the
// output is, and a final XOR. Name a protocol and you are naming a point in
// that space -- MODBUS is width 16, poly 0x8005, init 0xFFFF, reflected both
// ways, no final XOR.
//
// This matters here because the job is the inverse one. Given captured
// frames and no documentation, the question is not "compute a CRC" but
// "which point in this space explains these bytes?" -- and that is a search,
// which needs the parameters to be data rather than code.
//
// The implementation is bit-at-a-time. A table-driven CRC is roughly eight
// times faster, but a table has to be built per parameter set, and a search
// evaluates thousands of them against a handful of short frames. Building a
// 256-entry table to checksum twelve bytes loses badly. Where the same
// parameters are applied to a lot of data, build a table then.

#ifndef BW_CRC_H
#define BW_CRC_H

#include "bw/types.h"

namespace bw {

// The six parameters, plus a name and the algorithm's published check value
// -- the CRC of the ASCII string "123456789", which is how the catalogue in
// the literature identifies an algorithm unambiguously.
struct CrcSpec {
    const char* name;
    u8          width;     // 1..64, and not necessarily a multiple of 8:
                           // CAN is 15 bits, CAN-FD is 17 and 21
    u64         poly;
    u64         init;
    bool        refin;
    bool        refout;
    u64         xorout;
    u64         check;     // CRC of "123456789"; 0 when unknown
};

// Reverses the low `width` bits of `v`.
u64 reflect(u64 v, u8 width);

// All-ones for a given width, handling width == 64 without shifting by 64,
// which is undefined.
u64 width_mask(u8 width);

u64 crc_compute(const CrcSpec& spec, const u8* data, std::size_t len);

// Confirms a spec against its own published check value. A catalogue entry
// that fails this is mistyped, and a mistyped entry in a search space is
// worse than a missing one: it will never match anything, and nobody will
// notice why.
bool crc_spec_self_test(const CrcSpec& spec);

} // namespace bw

#endif // BW_CRC_H
