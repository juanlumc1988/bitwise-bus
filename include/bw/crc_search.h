// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Given frames off an undocumented bus, work out which CRC the device uses,
// where the checksum sits, and what it covers.
//
// The search space is small enough to walk exhaustively: a couple of dozen
// plausible algorithms, times a few candidate positions for the checksum
// field, times a few candidate starts for the covered range. A few thousand
// evaluations against a handful of short frames is microseconds, so there is
// no cleverness here and none is needed.
//
// The interesting problem is not finding a match. It is knowing whether the
// match means anything.
//
// A wrong candidate validates N frames of W-bit checksum by chance with
// probability 2^-(N*W). With a search space of roughly 2^10 candidates, the
// expected number of false positives is 2^(10 - N*W), so it takes about 17
// bits of evidence before a single match is more likely right than lucky,
// and 32 bits before it is not worth worrying about. One 8-bit checksum on
// one frame proves nothing whatsoever, and a tool that reported it as an
// answer would be worse than useless. Hence evidence_bits, and hence
// confident().

#ifndef BW_CRC_SEARCH_H
#define BW_CRC_SEARCH_H

#include <cstddef>
#include <vector>

#include "bw/catalog.h"
#include "bw/crc.h"

namespace bw {

struct Frame {
    std::vector<u8> bytes;
};

// Where the checksum lives, expressed relative to the ends of the frame
// rather than absolutely, so a corpus of varying frame lengths works
// without special-casing.
//
//   [0 .. header_skip)                        ignored (address, type, len)
//   [header_skip .. checksum_offset)          covered by the CRC
//   [checksum_offset .. +width/8)             the checksum itself
//   [.. end)                                  trailer_skip bytes, ignored
struct Layout {
    std::size_t header_skip   = 0;
    std::size_t trailer_skip  = 0;
    u8          width         = 16;
    bool        big_endian    = true;

    std::size_t field_bytes() const { return width / 8u; }

    // False when the frame is too short for this layout to make sense.
    bool fits(std::size_t frame_len) const;
    std::size_t checksum_offset(std::size_t frame_len) const;
    std::size_t covered_begin() const { return header_skip; }
    std::size_t covered_end(std::size_t frame_len) const;
};

struct Candidate {
    const CrcSpec* spec = nullptr;
    Layout         layout;
};

struct SearchOptions {
    // How many leading bytes may sit outside the covered range. Protocols
    // that exclude a sync byte or an address are common; excluding more than
    // a few is not.
    std::size_t max_header_skip = 4;
    // How many trailing bytes may follow the checksum.
    std::size_t max_trailer_skip = 2;

    bool try_big_endian    = true;
    bool try_little_endian = true;

    std::size_t max_candidates = 64;
};

struct SearchReport {
    std::vector<Candidate> candidates;

    std::size_t frames         = 0;
    // Identical frames are one observation repeated. Only distinct ones
    // count towards evidence; see the note in search().
    std::size_t distinct_frames = 0;
    std::size_t specs_tried    = 0;
    std::size_t layouts_tried = 0;

    // distinct_frames * checksum width, for the narrowest candidate found.
    // The measure of how much the answer is worth.
    u32 evidence_bits = 0;

    bool unique() const { return candidates.size() == 1; }

    // One candidate, and enough evidence that it being chance is not worth
    // considering. Anything less and the caller should be shown the
    // alternatives rather than an answer.
    bool confident() const;
};

// Reads the checksum field out of a frame.
u64 extract_checksum(const Frame& frame, const Layout& layout);

// True when `spec` and `layout` explain every frame in the corpus.
bool verify(const std::vector<Frame>& frames, const Layout& layout,
            const CrcSpec& spec);

SearchReport search(const std::vector<Frame>& frames,
                    const SearchOptions& options = SearchOptions());

} // namespace bw

#endif // BW_CRC_SEARCH_H
