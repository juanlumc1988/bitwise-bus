// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 2: does a checksum close these frames, and which one?
//
// The search of the CRCs is bw/crc_search.h: every CRC of the catalogue, at every
// plausible place in the frame, against every frame given. The sums that are not
// CRCs (bw/sums.h: an exclusive or, a sum, Fletcher's) are searched the same way,
// and also written as hexadecimal text, two characters, with a byte between what
// they cover and them (the star of NMEA 0183). This is those searches run over
// the frames of a capture that segmentation found, behind types that follow the
// API rule of docs/roadmap.md, so that the pipeline and a binding need not handle
// a Layout or a pointer into a catalogue.
//
// The answer is a checksum only when it is the single candidate, among the CRCs
// and the sums together, and the evidence is enough for chance not to be a
// likelier explanation (SearchReport::confident). Otherwise found is false, and
// the count of candidates says whether there were none or several that could not
// be told apart. The evidence of a checksum written as text is the 8 bits it
// holds, not the 16 it takes.
//
// Only frames of one size are searched at a time. A checksum sits at a place
// that depends on the frame's length, and a message type is, for now, a size.

#ifndef BW_CHECKSUM_H
#define BW_CHECKSUM_H

#include <cstdint>
#include <string>

#include "bw/capture.h"
#include "bw/model.h"
#include "bw/segmentation.h"

namespace bw {

struct ChecksumFinding {
    bool          found          = false;   // one candidate, on enough evidence
    std::uint32_t frames         = 0;       // frames of this size that were searched
    std::uint32_t distinct_frames = 0;      // ...and how many of them were different
    std::uint32_t candidates     = 0;       // how many explanations matched every frame
    bool          truncated      = false;   // more matched than the search keeps
    std::uint32_t evidence_bits  = 0;       // as in the CRC stage: distinct frames times
                                            //   the width of the narrowest candidate

    // The rest is meaningful only when found.
    std::uint32_t header_skip    = 0;       // bytes at the start that the checksum does not cover
    std::uint32_t trailer_skip   = 0;       // bytes after the checksum
    std::uint32_t gap_bytes      = 0;       // bytes between what it covers and it, which it does not
                                            //   cover either (the star before NMEA's)
    std::uint32_t width_bits     = 0;       // on the wire: 16 for one written as two characters
    ByteOrder     byte_order     = ByteOrder::NotApplicable;
    bool          ascii_hex      = false;   // written as hexadecimal text, big-endian
    std::uint32_t algorithm      = 0;       // index: the catalogue of CRCs first, then the sums
};

// Searches the frames of `size_bytes` bytes among those of the segmentation.
ChecksumFinding find_checksum(const Capture& capture, const Segmentation& segmentation,
                              std::uint32_t size_bytes);

// The name of an algorithm: an entry of the catalogue, e.g. "CRC-16/MODBUS", or a
// sum, e.g. "FLETCHER-8", which come after the catalogue. Throws std::out_of_range
// for an index that is not one.
std::string checksum_algorithm_name(std::uint32_t index);

} // namespace bw

#endif // BW_CHECKSUM_H
