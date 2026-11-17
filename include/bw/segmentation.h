// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 3: where do the frames begin and end?
//
// The skeleton version looks only at time. A byte on a serial bus follows the
// previous byte of its frame closely and a new frame follows a silence, so the
// gaps between consecutive events fall in two groups: short ones inside a
// frame and long ones between frames. The stage finds the widest hole between
// the two groups, in ratio, and cuts at every gap on the long side of it.
//
// It says so when there is no such hole instead of guessing: a capture
// without timestamps, with the same gap everywhere, or with gaps that spread
// evenly from short to long has no framing this stage can see. Delimiters,
// length fields, stuffing and captures without timing are for later versions
// (docs/roadmap.md).
//
// Everything is integer arithmetic, so the same capture is cut in the same
// places on every platform.
//
// The shape of this API follows the rule in docs/roadmap.md: plain structs,
// the collection behind a class.

#ifndef BW_SEGMENTATION_H
#define BW_SEGMENTATION_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bw/capture.h"
#include "bw/evaluate.h"

namespace bw {

struct SegmentationOptions {
    // The shortest gap between frames must be at least this many times the
    // longest gap inside a frame. Below that the two groups are not told apart.
    std::uint32_t min_gap_ratio = 3;
};

struct SegmentationInfo {
    // False when the capture shows no division into frames. Everything else
    // here is zero then.
    bool          found                = false;
    // A gap of at least this many nanoseconds, between two consecutive events,
    // ends a frame: the shortest gap that was classed as between frames.
    std::uint64_t idle_gap_ns          = 0;
    std::uint64_t longest_inner_gap_ns = 0;     // the longest gap inside a frame
    std::uint64_t inner_gaps           = 0;     // how many gaps were classed as inside a frame
    std::uint64_t outer_gaps           = 0;     // ...and as between frames
};

class Segmentation {
public:
    // Nothing found, no frames.
    Segmentation();
    Segmentation(const SegmentationInfo& info, const std::vector<FrameSpan>& frames);

    SegmentationInfo info() const;

    std::size_t            frame_count() const;
    FrameSpan              frame(std::size_t index) const;      // throws std::out_of_range
    std::vector<FrameSpan> frames() const;

private:
    SegmentationInfo       info_;
    std::vector<FrameSpan> frames_;
};

// Cuts a capture at its long gaps. Every frame is a run of events; together
// they cover the capture. Nothing found (found false) when the capture has
// fewer than two events, an event without a time, or no hole of the ratio the
// options ask for between its short gaps and its long ones.
Segmentation segment_by_gaps(const Capture& capture, const SegmentationOptions& options);

// The bytes of a frame, in order, as one run. Throws std::out_of_range for a
// frame that is not inside the capture.
std::vector<std::uint8_t> frame_bytes(const Capture& capture, const FrameSpan& frame);

// How many bytes a frame holds, and the frames of a segmentation that hold
// exactly `size_bytes` of them, in capture order.
std::uint64_t          frame_size(const Capture& capture, const FrameSpan& frame);
std::vector<FrameSpan> frames_of_size(const Capture& capture, const Segmentation& segmentation,
                                      std::uint64_t size_bytes);

} // namespace bw

#endif // BW_SEGMENTATION_H
