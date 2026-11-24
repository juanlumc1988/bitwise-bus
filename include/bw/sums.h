// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The checksums that are not CRCs: an exclusive or, a sum, a sum negated (the
// longitudinal redundancy check), and Fletcher's two sums. They are cheap, and
// a good half of the buses a person meets have one of them (UBX, NMEA 0183, the
// LRC of Modbus ASCII), so they are searched next to the CRCs of the catalogue.
//
// The list is closed and each entry is defined here, since there is no
// parameter to search: unlike a CRC, a sum has nothing to vary but how many
// bits it keeps and how it is mixed.
//
// A result is a number of `width` bits, 8 or 16. For the Fletcher checksums it
// is the two sums, the first of them in the low byte: written little-endian, it
// is the sum of the bytes first and the sum of the sums second, which is how UBX
// sends them.

#ifndef BW_SUMS_H
#define BW_SUMS_H

#include <cstddef>

#include "bw/types.h"

namespace bw {

struct SumSpec {
    const char* name;      // XOR-8, SUM-8, SUM-8/NEGATED, FLETCHER-8, FLETCHER-16
    u8          width;     // 8 or 16
};

const SumSpec* sums();
std::size_t    sum_count();

// nullptr when there is no such sum, and for a null name.
const SumSpec* sum_find(const char* name);

// The sum of `len` bytes. Zero bytes give 0, and so does a spec that is not one of the list.
//   XOR-8          the exclusive or of the bytes
//   SUM-8          their sum, modulo 256
//   SUM-8/NEGATED  that, negated: the byte that makes the sum of all of them 0
//   FLETCHER-8     two 8-bit sums: a is the sum of the bytes and b the sum of the
//                  values a has had, both modulo 256; the result is b << 8 | a
//   FLETCHER-16    the same, modulo 255
u64 sum_compute(const SumSpec& spec, const u8* data, std::size_t len);

} // namespace bw

#endif // BW_SUMS_H
