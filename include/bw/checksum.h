// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 2: does a checksum close these frames, and which one?
//
// The search itself is bw/crc_search.h: every CRC of the catalogue, at every
// plausible place in the frame, against every frame given. This is that search
// run over the frames of a capture that segmentation found, behind types that
// follow the API rule of docs/roadmap.md, so that the pipeline and a binding
// need not handle a Layout or a pointer into the catalogue.
//
// The answer is a checksum only when it is the single candidate and the
// evidence is enough for chance not to be a likelier explanation
// (SearchReport::confident). Otherwise found is false, and the count of
// candidates says whether there were none or several that could not be told
// apart.
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
    std::uint32_t width_bits     = 0;
    ByteOrder     byte_order     = ByteOrder::NotApplicable;
    std::uint32_t algorithm      = 0;       // index into the catalogue
};

// Searches the frames of `size_bytes` bytes among those of the segmentation.
ChecksumFinding find_checksum(const Capture& capture, const Segmentation& segmentation,
                              std::uint32_t size_bytes);

// The name of an entry of the catalogue, e.g. "CRC-16/MODBUS". Throws
// std::out_of_range for an index that is not one.
std::string checksum_algorithm_name(std::uint32_t index);

} // namespace bw

#endif // BW_CHECKSUM_H
