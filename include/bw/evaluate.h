// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// How well did a stage do? Each function here compares what a stage found with
// what a generator knows to be true, and returns counts.
//
// Counts, never ratios. Precision is boundary_hits / found_boundaries and
// recall is boundary_hits / truth_boundaries, and whoever prints them divides.
// Nothing in the library then depends on how a floating-point number is
// rounded or formatted, so the same run scores the same on every platform.
//
// A boundary is a position where something starts or ends, because that is what
// can be right or wrong independently: a stage that finds every frame but
// puts one cut a byte late gets all but one boundary and no more.

#ifndef BW_EVALUATE_H
#define BW_EVALUATE_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bw/model.h"

namespace bw {

// A frame, as a run of events in a capture.
struct FrameSpan {
    std::uint64_t first_event = 0;
    std::uint64_t event_count = 0;
};

struct SegmentationScore {
    std::uint64_t truth_frames     = 0;
    std::uint64_t found_frames     = 0;
    std::uint64_t exact_frames     = 0;   // found frames identical to a true frame
    std::uint64_t truth_boundaries = 0;   // distinct event indexes where a true frame starts or ends
    std::uint64_t found_boundaries = 0;
    std::uint64_t boundary_hits    = 0;   // indexes that are a boundary in both
};

SegmentationScore score_segmentation(const std::vector<FrameSpan>& truth,
                                     const std::vector<FrameSpan>& found);

// The fields of one message type against the fields of another. Only a field
// with a fixed size at a fixed position can be placed, so only those count
// towards boundaries and exact fields; the others are counted in
// truth_fields and found_fields and no further.
//
// Message types are named by index on both sides. Pairing the types of an
// inferred model with those of the truth is a decision for the stage that finds
// more than one.
struct FieldScore {
    std::uint32_t truth_fields     = 0;
    std::uint32_t found_fields     = 0;
    std::uint32_t truth_boundaries = 0;   // distinct bit offsets where a placed field starts or ends
    std::uint32_t found_boundaries = 0;
    std::uint32_t boundary_hits    = 0;
    std::uint32_t exact_fields     = 0;   // found fields with the offset and size of a true one
    std::uint32_t kind_hits        = 0;   // ...and the same kind

    bool truth_has_checksum = false;
    bool found_has_checksum = false;
    // True when both sides agree about the checksum: neither has one, or both
    // do and it has the same position, size, byte order, coverage and algorithm.
    bool checksum_match     = false;
};

// Throws std::out_of_range for a message type that is not in its model.
FieldScore score_fields(const Model& truth, std::size_t truth_type,
                        const Model& found, std::size_t found_type);

} // namespace bw

#endif // BW_EVALUATE_H
