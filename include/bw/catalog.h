// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The CRC algorithms actually encountered on embedded buses.
//
// This is not every catalogued CRC -- there are over a hundred, and most are
// confined to one file format or one vendor. These are the ones worth trying
// first against an unknown bus, which is the whole point: a search that
// starts with the plausible candidates usually ends there.
//
// Every entry carries its published check value (the CRC of "123456789"),
// and the test suite verifies all of them. An entry with a mistyped
// parameter is worse than a missing one -- it silently never matches, and
// the search reports "nothing found" for a protocol that is in the list.

#ifndef BW_CATALOG_H
#define BW_CATALOG_H

#include <cstddef>

#include "bw/crc.h"

namespace bw {

// Ordered roughly by how often they turn up on a bus, narrowest first.
const CrcSpec* catalog();
std::size_t    catalog_size();

// Entries of a given width, or null/0 if none.
const CrcSpec* catalog_find(const char* name);

} // namespace bw

#endif // BW_CATALOG_H
