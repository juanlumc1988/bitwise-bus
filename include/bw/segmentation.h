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
// evenly from short to long has no framing this stage can see.
//
// The second way to cut is by flags, for a capture that has no timing to cut
// by (a UART capture with no timestamps, or a byte every character time with
// nothing between the frames): a byte that bounds a frame on both sides, as the
// END of SLIP and the flag of HDLC do, with more flags between one frame and the
// next as often as not. What shows it is that two of them follow each other: the
// close of a frame and the open of the next. It is only that, so far: a frame that
// ends with a terminator, a flag that two frames share, and a frame that starts
// with a sync pattern and says its length are different framings that look alike
// in the bytes (a byte that occurs once per frame cuts it somewhere, and the
// terminator, the start and the middle of a frame are all such places), and
// telling them apart takes the length (docs/roadmap.md).
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
#include "bw/model.h"

namespace bw {

struct SegmentationOptions {
    // The shortest gap between frames must be at least this many times the
    // longest gap inside a frame. Below that the two groups are not told apart.
    std::uint32_t min_gap_ratio = 3;
    // A byte is taken as a flag only if it bounds at least this many frames.
    std::uint32_t min_flag_frames = 8;
};

struct SegmentationInfo {
    // False when the capture shows no division into frames. Everything else
    // here is zero then.
    bool          found                = false;
    // What cut the frames: IdleGap or Flagged, and Unknown for frames that were
    // given (a segmentation built by hand, a generator's truth).
    FramingKind   kind                 = FramingKind::Unknown;
    // Flagged: the flag, and how many bytes of the capture are that byte.
    std::uint8_t  delimiter            = 0;
    std::uint64_t flags                = 0;
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

// Cuts a capture of single-byte events at its flags: the byte that, with the
// frames it makes, is the best explained as one. Each frame is a run of bytes
// from a flag to the next flag, both included, with something between them. Two
// flags in a row bound nothing: of the three or more that may lie between two
// frames, the first closes one, the last opens the next, and the others, and the
// bytes before the first flag and after the last one, are in no frame, so the
// frames do not cover the capture. (A flag that two frames share belongs to the
// first.) A byte counts as the flag when
//   - at least a quarter of its occurrences are followed by another one;
//   - it bounds at least min_flag_frames frames;
//   - at most 4 distinct bytes start the frames (the byte after the flag), and
//     at least 95% of the frames start with one of them;
//   - at least 95% of the frames are within a factor of 4 of the median size.
// The flag with the most frames wins, and the lower byte if they tie. Nothing
// found (found false) when an event holds more or fewer than one byte, or no byte
// qualifies. Timing plays no part.
Segmentation segment_by_flags(const Capture& capture, const SegmentationOptions& options);

// The way the pipeline cuts: by flags if the capture has them, and otherwise by
// gaps.
Segmentation segment_frames(const Capture& capture, const SegmentationOptions& options);

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
