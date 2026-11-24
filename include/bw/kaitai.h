// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 6: a model, written as a Kaitai Struct definition (a .ksy file), the
// format that a Kaitai compiler turns into a parser for many languages and that
// Wireshark and a number of hex editors can read.
//
// One message type becomes one definition: its fields are the `seq` of the
// top-level type, in order. What Kaitai can say is said in its terms, and the
// rest goes in `doc`, where a person reads it:
//
//   - a constant is `contents`, which the parser checks;
//   - a number of 8, 16, 32 or 64 bits is `u1`, `u2be`, `u2le`, and so on
//     (`f4be`, `f8le`... for a float), by its byte order; a whole number of
//     bytes of any other size is read as that many bytes;
//   - a field sized by an earlier length field (SizeKind::FromField) is `size:`
//     and the name of that field, which has to be written as a number of 8, 16,
//     32 or 64 bits: MAVLink's payload after its length;
//   - payload, enumerations, counters and checksums are the plain numbers or
//     bytes they are in memory, and `doc` says what the model found about them
//     and how much evidence there is. Kaitai has no checksum type and cannot
//     compute a CRC, so the algorithm and what it covers are `doc` as well;
//   - framing is `doc` too: Kaitai describes the inside of a frame.
//
// The output is deterministic: no timestamp, no path, the same model gives the
// same bytes.
//
// Fields that Kaitai could describe but this exporter does not write yet are
// refused, not approximated: a field that is not a whole number of bytes, or
// that is sized by a length that Kaitai has no integer for, or is delimited, or
// runs to the end. The stages produce none of them but a length of 24 bits.

#ifndef BW_KAITAI_H
#define BW_KAITAI_H

#include <cstddef>
#include <string>

#include "bw/model.h"

namespace bw {

// Writes the definition of one message type. `id` names the type in Kaitai: it
// must be a lower-case identifier ([a-z][a-z0-9_]*), as must every field name of
// the message type, and the field names must differ.
//
// Throws std::out_of_range for a message type that the model does not have, and
// std::invalid_argument for an id or a field name that is not valid, a field
// that is not a whole number of bytes, and a field whose size is not fixed.
std::string export_kaitai(const Model& model, std::size_t message_type, const std::string& id);

} // namespace bw

#endif // BW_KAITAI_H
