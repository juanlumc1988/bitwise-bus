// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/segmentation.h"

#include <algorithm>
#include <stdexcept>

namespace bw {

namespace {

// a/b < c/d for b, d > 0, without the overflow that a*d and c*b can have: the
// integer parts decide, and when they are equal the remainders are compared the
// other way up, since r1/b < r2/d is d/r2 < b/r1 (Euclid's algorithm).
bool fraction_less(std::uint64_t a, std::uint64_t b, std::uint64_t c, std::uint64_t d) {
    for (;;) {
        const std::uint64_t q1 = a / b;
        const std::uint64_t q2 = c / d;
        if (q1 != q2) {
            return q1 < q2;
        }
        const std::uint64_t r1 = a % b;
        const std::uint64_t r2 = c % d;
        if (r1 == 0 || r2 == 0) {
            return r1 == 0 && r2 != 0;
        }
        const std::uint64_t next_a = d;
        const std::uint64_t next_b = r2;
        const std::uint64_t next_c = b;
        const std::uint64_t next_d = r1;
        a = next_a;
        b = next_b;
        c = next_c;
        d = next_d;
    }
}

FrameSpan span(std::uint64_t first, std::uint64_t count) {
    FrameSpan s;
    s.first_event = first;
    s.event_count = count;
    return s;
}

} // namespace

Segmentation::Segmentation() {}

Segmentation::Segmentation(const SegmentationInfo& info, const std::vector<FrameSpan>& frames)
    : info_(info), frames_(frames) {}

SegmentationInfo Segmentation::info() const {
    return info_;
}

std::size_t Segmentation::frame_count() const {
    return frames_.size();
}

FrameSpan Segmentation::frame(std::size_t index) const {
    if (index >= frames_.size()) {
        throw std::out_of_range("frame index out of range");
    }
    return frames_[index];
}

std::vector<FrameSpan> Segmentation::frames() const {
    return frames_;
}

Segmentation segment_by_gaps(const Capture& capture, const SegmentationOptions& options) {
    const std::size_t events = capture.event_count();
    if (events < 2 || !capture.fully_timed()) {
        return Segmentation();
    }

    // Time never goes backwards in a capture, so the difference is not
    // negative, and unsigned arithmetic cannot overflow where signed could.
    std::vector<std::uint64_t> gaps(events - 1);
    for (std::size_t i = 0; i + 1 < events; ++i) {
        gaps[i] = static_cast<std::uint64_t>(capture.event(i + 1).time_ns) -
                  static_cast<std::uint64_t>(capture.event(i).time_ns);
    }
    std::vector<std::uint64_t> sorted(gaps);
    std::sort(sorted.begin(), sorted.end());

    // The widest hole between two consecutive gap values, in ratio. A gap of 0
    // (two events at the same instant) counts as 1 ns, so that the ratio of a
    // burst to everything else is finite. The first widest hole wins a tie.
    bool          found  = false;
    std::uint64_t best_lo = 1;
    std::uint64_t best_hi = 1;
    for (std::size_t k = 0; k + 1 < sorted.size(); ++k) {
        if (sorted[k] == sorted[k + 1]) {
            continue;
        }
        const std::uint64_t lo = std::max<std::uint64_t>(sorted[k], 1);
        const std::uint64_t hi = sorted[k + 1];
        if (!found || fraction_less(best_hi, best_lo, hi, lo)) {
            found   = true;
            best_lo = lo;
            best_hi = hi;
        }
    }
    if (!found || best_hi / best_lo < options.min_gap_ratio) {
        return Segmentation();
    }

    SegmentationInfo info;
    info.found       = true;
    info.kind        = FramingKind::IdleGap;
    info.idle_gap_ns = best_hi;
    for (std::size_t i = 0; i < gaps.size(); ++i) {
        if (gaps[i] >= best_hi) {
            ++info.outer_gaps;
        } else {
            ++info.inner_gaps;
            info.longest_inner_gap_ns = std::max(info.longest_inner_gap_ns, gaps[i]);
        }
    }

    std::vector<FrameSpan> frames;
    std::size_t            start = 0;
    for (std::size_t i = 0; i < gaps.size(); ++i) {
        if (gaps[i] >= best_hi) {
            frames.push_back(span(start, i + 1 - start));
            start = i + 1;
        }
    }
    frames.push_back(span(start, events - start));
    return Segmentation(info, frames);
}

namespace {

// The frames that the byte `flag` bounds, in the order they are in the stream, from a flag to the
// next one that has something between them and the one before it.
std::vector<FrameSpan> frames_between_flags(const std::vector<std::uint8_t>& bytes, std::uint8_t flag) {
    std::vector<std::uint64_t> at;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] == flag) {
            at.push_back(i);
        }
    }
    std::vector<FrameSpan> frames;
    std::uint64_t          free_from = 0;               // a shared flag is the first frame's
    for (std::size_t k = 0; k + 1 < at.size(); ++k) {
        if (at[k + 1] - at[k] > 1) {
            const std::uint64_t first = std::max(at[k], free_from);
            frames.push_back(span(first, at[k + 1] + 1 - first));
            free_from = at[k + 1] + 1;
        }
    }
    return frames;
}

// Does `flag` bound frames as a flag does? Fills `frames` with them when it does.
bool bounds_frames(const std::vector<std::uint8_t>& bytes, std::uint8_t flag, std::uint32_t min_frames,
                   std::vector<FrameSpan>* frames) {
    *frames = frames_between_flags(bytes, flag);
    if (frames->empty() || frames->size() < min_frames) {
        return false;
    }

    // The byte after the opening flag: a few values, nearly always.
    std::vector<std::uint64_t> starts(256, 0);
    std::vector<std::uint64_t> sizes;
    for (std::size_t i = 0; i < frames->size(); ++i) {
        const FrameSpan&    f     = (*frames)[i];
        const std::uint64_t first = f.first_event + (bytes[f.first_event] == flag ? 1 : 0);
        ++starts[bytes[first]];
        sizes.push_back(f.event_count);
    }
    std::sort(starts.begin(), starts.end());
    std::uint64_t top = 0;
    for (std::size_t k = 0; k < 4; ++k) {
        top += starts[255 - k];
    }
    if (top * 100 < 95 * frames->size()) {
        return false;
    }

    // And about the same size, nearly always.
    std::sort(sizes.begin(), sizes.end());
    const std::uint64_t median = sizes[sizes.size() / 2];
    std::uint64_t       alike  = 0;
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        alike += (sizes[i] * 4 >= median && sizes[i] <= 4 * median) ? 1 : 0;
    }
    return alike * 100 >= 95 * sizes.size();
}

} // namespace

Segmentation segment_by_flags(const Capture& capture, const SegmentationOptions& options) {
    std::vector<std::uint8_t> bytes;
    bytes.reserve(capture.event_count());
    for (std::size_t i = 0; i < capture.event_count(); ++i) {
        if (capture.event_size(i) != 1) {
            return Segmentation();
        }
        bytes.push_back(capture.event_bytes(i)[0]);
    }

    // Only a byte that is followed by itself often enough is worth cutting at.
    std::vector<std::uint64_t> count(256, 0), twice(256, 0);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        ++count[bytes[i]];
        if (i + 1 < bytes.size() && bytes[i + 1] == bytes[i]) {
            ++twice[bytes[i]];
        }
    }
    bool                   found = false;
    std::uint8_t           flag  = 0;
    std::vector<FrameSpan> best;
    for (unsigned b = 0; b < 256; ++b) {
        if (count[b] == 0 || 4 * twice[b] < count[b]) {
            continue;
        }
        std::vector<FrameSpan> frames;
        if (bounds_frames(bytes, static_cast<std::uint8_t>(b), options.min_flag_frames, &frames) &&
            (!found || frames.size() > best.size())) {
            found = true;
            flag  = static_cast<std::uint8_t>(b);
            best.swap(frames);
        }
    }
    if (!found) {
        return Segmentation();
    }
    SegmentationInfo info;
    info.found     = true;
    info.kind      = FramingKind::Flagged;
    info.delimiter = flag;
    info.flags     = count[flag];
    return Segmentation(info, best);
}

Segmentation segment_frames(const Capture& capture, const SegmentationOptions& options) {
    const Segmentation flagged = segment_by_flags(capture, options);
    return flagged.info().found ? flagged : segment_by_gaps(capture, options);
}

std::vector<std::uint8_t> frame_bytes(const Capture& capture, const FrameSpan& frame) {
    std::vector<std::uint8_t> out;
    for (std::uint64_t i = 0; i < frame.event_count; ++i) {
        const std::vector<std::uint8_t> bytes =
            capture.event_bytes(static_cast<std::size_t>(frame.first_event + i));
        out.insert(out.end(), bytes.begin(), bytes.end());
    }
    return out;
}

std::uint64_t frame_size(const Capture& capture, const FrameSpan& frame) {
    std::uint64_t size = 0;
    for (std::uint64_t i = 0; i < frame.event_count; ++i) {
        size += capture.event_size(static_cast<std::size_t>(frame.first_event + i));
    }
    return size;
}

std::vector<FrameSpan> frames_of_size(const Capture& capture, const Segmentation& segmentation,
                                      std::uint64_t size_bytes) {
    std::vector<FrameSpan> out;
    for (std::size_t i = 0; i < segmentation.frame_count(); ++i) {
        const FrameSpan frame = segmentation.frame(i);
        if (frame_size(capture, frame) == size_bytes) {
            out.push_back(frame);
        }
    }
    return out;
}

} // namespace bw
