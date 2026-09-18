// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/crc.h"

namespace bw {

u64 width_mask(u8 width) {
    if (width == 0) {
        return 0;
    }
    if (width >= 64) {
        return ~0ULL;   // 1ULL << 64 is undefined
    }
    return (1ULL << width) - 1ULL;
}

u64 reflect(u64 v, u8 width) {
    u64 out = 0;
    for (u8 i = 0; i < width; ++i) {
        if ((v >> i) & 1ULL) {
            out |= 1ULL << (width - 1u - i);
        }
    }
    return out;
}

u64 crc_compute(const CrcSpec& spec, const u8* data, std::size_t len) {
    if (spec.width == 0 || spec.width > 64) {
        return 0;
    }

    const u64 mask   = width_mask(spec.width);
    const u64 topbit = 1ULL << (spec.width - 1u);

    u64 crc = spec.init & mask;

    // Bit at a time, most significant first. The usual byte-wise formulation
    // shifts the message byte into the top of the register, which only works
    // when the width is at least 8 -- and CAN's 15-bit CRC is exactly the
    // case this project cares about. Feeding one bit at a time sidesteps
    // that entirely and is correct for any width from 1 to 64.
    for (std::size_t i = 0; i < len; ++i) {
        const u8 byte = spec.refin ? static_cast<u8>(reflect(data[i], 8))
                                   : data[i];
        for (int bit = 7; bit >= 0; --bit) {
            const bool in  = ((byte >> bit) & 1u) != 0;
            const bool top = (crc & topbit) != 0;
            // Masking here keeps the register bounded. Strictly it changes
            // no result -- bits pushed above the width only ever move
            // further up and can never return to influence the top-bit test
            // -- but an unbounded register would eventually shift off the
            // end of u64, and reasoning about that is not worth the cycle
            // saved.
            crc = (crc << 1) & mask;
            if (in != top) {
                crc ^= spec.poly;
            }
        }
    }

    if (spec.refout) {
        crc = reflect(crc, spec.width);
    }
    return (crc ^ spec.xorout) & mask;
}

bool crc_spec_self_test(const CrcSpec& spec) {
    if (spec.check == 0) {
        return true;   // no published value to check against
    }
    static const u8 kCheckInput[9] = { '1', '2', '3', '4', '5', '6', '7', '8', '9' };
    return crc_compute(spec, kCheckInput, sizeof(kCheckInput)) == spec.check;
}

} // namespace bw
