// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/segmentation.h"

#include <algorithm>
#include <bitset>
#include <functional>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>

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

// The bytes of a capture whose events are one byte each, in order; false if one is not.
bool single_bytes(const Capture& capture, std::vector<std::uint8_t>* bytes) {
    bytes->clear();
    bytes->reserve(capture.event_count());
    for (std::size_t i = 0; i < capture.event_count(); ++i) {
        if (capture.event_size(i) != 1) {
            return false;
        }
        bytes->push_back(capture.event_bytes(i)[0]);
    }
    return true;
}

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

// Do these frames look like the frames of a protocol? They start with one of a few bytes, nearly always
// (after the flag, for the frames of a flag: `flag` is the byte to skip, or more than 255 for none), and
// are about the same size, nearly always.
bool regular_frames(const std::vector<std::uint8_t>& bytes, const std::vector<FrameSpan>& frames, unsigned flag) {
    std::vector<std::uint64_t> starts(256, 0);
    std::vector<std::uint64_t> sizes;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const FrameSpan&    f     = frames[i];
        const std::uint64_t first = f.first_event + (bytes[f.first_event] == flag ? 1 : 0);
        ++starts[bytes[first]];
        sizes.push_back(f.event_count);
    }
    std::sort(starts.begin(), starts.end());
    std::uint64_t top = 0;
    for (std::size_t k = 0; k < 4; ++k) {
        top += starts[255 - k];
    }
    if (top * 100 < 95 * frames.size()) {
        return false;
    }

    std::sort(sizes.begin(), sizes.end());
    const std::uint64_t median = sizes[sizes.size() / 2];
    std::uint64_t       alike  = 0;
    for (std::size_t i = 0; i < sizes.size(); ++i) {
        alike += (sizes[i] * 4 >= median && sizes[i] <= 4 * median) ? 1 : 0;
    }
    return alike * 100 >= 95 * sizes.size();
}

// How many of the frames are of the size that most of them are.
std::uint64_t most_alike(const std::vector<FrameSpan>& frames) {
    std::map<std::uint64_t, std::uint64_t> by_size;
    std::uint64_t                          most = 0;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        most = std::max(most, ++by_size[frames[i].event_count]);
    }
    return most;
}

// Does `flag` bound frames as a flag does? Fills `frames` with them when it does.
bool bounds_frames(const std::vector<std::uint8_t>& bytes, std::uint8_t flag, std::uint32_t min_frames,
                   std::vector<FrameSpan>* frames) {
    *frames = frames_between_flags(bytes, flag);
    if (frames->empty() || frames->size() < min_frames) {
        return false;
    }
    return regular_frames(bytes, *frames, flag);
}

// How the stuffing of a flag is written, if the capture shows it: an escape byte that is followed, every
// time, by one of two codes, both of which the capture has. There are two ways known: the codes are the flag and the escape with bit 5
// flipped (RFC 1662, HDLC), or the flag is C0 and the escape DB and the codes DC and DD (RFC 1055, SLIP).
// `after` counts the pairs of bytes in a row and `followed` the bytes that have one after them.
struct Stuffing {
    bool         found       = false;
    std::uint8_t escape      = 0;
    std::uint8_t flag_code   = 0;
    std::uint8_t escape_code = 0;
};

Stuffing find_stuffing(const std::vector<std::uint32_t>& after, const std::vector<std::uint64_t>& followed,
                       std::uint8_t flag) {
    Stuffing      best;
    std::uint64_t best_seen = 0;
    for (unsigned e = 0; e < 256; ++e) {
        for (unsigned family = 0; family < 2; ++family) {
            if (family == 1 && (flag != 0xC0 || e != 0xDB)) {
                continue;
            }
            const std::uint8_t  flag_code   = family == 0 ? static_cast<std::uint8_t>(flag ^ 0x20) : 0xDC;
            const std::uint8_t  escape_code = family == 0 ? static_cast<std::uint8_t>(e ^ 0x20) : 0xDD;
            // Both codes have to be there: one that always follows another byte is common (a line feed after a
            // carriage return is the flag 0x2A with its bit 5 flipped, and a constant field of two bytes can be
            // any pair), and two are not.
            const std::uint64_t seen        = static_cast<std::uint64_t>(after[e * 256 + flag_code]) + after[e * 256 + escape_code];
            if (after[e * 256 + flag_code] > 0 && after[e * 256 + escape_code] > 0 && seen >= 3 && seen == followed[e] &&
                seen > best_seen) {
                best.found       = true;
                best.escape      = static_cast<std::uint8_t>(e);
                best.flag_code   = flag_code;
                best.escape_code = escape_code;
                best_seen        = seen;
            }
        }
    }
    return best;
}

} // namespace

Segmentation segment_by_flags(const Capture& capture, const SegmentationOptions& options) {
    std::vector<std::uint8_t> bytes;
    if (!single_bytes(capture, &bytes)) {
        return Segmentation();
    }

    // How often each byte occurs, followed by itself, and followed by each other byte.
    std::vector<std::uint64_t> count(256, 0), twice(256, 0), followed(256, 0);
    std::vector<std::uint32_t> after(256 * 256, 0);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        ++count[bytes[i]];
        if (i + 1 < bytes.size()) {
            ++after[bytes[i] * 256u + bytes[i + 1]];
            ++followed[bytes[i]];
            if (bytes[i + 1] == bytes[i]) {
                ++twice[bytes[i]];
            }
        }
    }
    bool                   found = false;
    std::uint8_t           flag  = 0;
    Stuffing               stuffing;
    std::vector<FrameSpan> best;
    std::uint64_t          best_alike = 0;
    for (unsigned b = 0; b < 256; ++b) {
        if (count[b] == 0) {
            continue;
        }
        // Only a byte that is followed by itself often enough, or that has stuffing, is worth cutting at.
        const Stuffing candidate = find_stuffing(after, followed, static_cast<std::uint8_t>(b));
        if (4 * twice[b] < count[b] && !candidate.found) {
            continue;
        }
        std::vector<FrameSpan> frames;
        if (!bounds_frames(bytes, static_cast<std::uint8_t>(b), options.min_flag_frames, &frames)) {
            continue;
        }
        // The byte that cuts the most frames of one size (the lower byte, in a tie): a byte that comes in pairs inside
        // frames (the zeros on top of a number) cuts them at places that depend on what is in them, and not at the
        // same places in every frame.
        const std::uint64_t alike = most_alike(frames);
        if (!found || alike > best_alike) {
            found      = true;
            flag       = static_cast<std::uint8_t>(b);
            stuffing   = candidate;
            best_alike = alike;
            best.swap(frames);
        }
    }
    if (!found) {
        return Segmentation();
    }
    SegmentationInfo info;
    info.found          = true;
    info.kind           = FramingKind::Flagged;
    info.delimiter      = flag;
    info.flags          = count[flag];
    info.escaped        = stuffing.found;
    info.escape         = stuffing.escape;
    info.delimiter_code = stuffing.flag_code;
    info.escape_code    = stuffing.escape_code;
    return Segmentation(info, best);
}

namespace {

const std::uint32_t kMaxLengthOffset = 8;        // the length is looked for in the 8 bytes after the sync byte

// One reading of the stream as sync byte + length: where the length is, how wide, in which order, and
// what is added to it.
struct SyncCandidate {
    std::uint8_t  sync       = 0;
    std::uint32_t offset     = 0;
    std::uint32_t width      = 0;
    bool          big_endian = false;
    std::int64_t  adjust     = 0;
};

std::uint64_t read_length(const std::vector<std::uint8_t>& bytes, std::uint64_t at, const SyncCandidate& c) {
    std::uint64_t value = 0;
    for (std::uint32_t i = 0; i < c.width; ++i) {
        const std::uint32_t index = c.big_endian ? i : c.width - 1 - i;
        value = (value << 8) | bytes[at + index];
    }
    return value;
}

// What following a candidate through the stream gave.
struct Chain {
    std::vector<FrameSpan> frames;
    std::uint64_t          breaks  = 0;
    std::uint64_t          covered = 0;
    bool                   varies  = false;     // the lengths are not all the same
    std::size_t            before  = 0;         // how many different bytes come right before a frame
};

// From the first sync byte: a frame is where the length says, and counts when the byte after it is the
// sync byte again or the stream ends. When it is not (a sync byte inside a payload, garbage, a length that
// runs past the end), the chain starts again at the next sync byte, and that is a break once the chain has
// begun: before the first frame it is only looking for the start, and after the last sync byte there is
// nothing to start again at, which is the end of the capture.
Chain follow(const std::vector<std::uint8_t>& bytes, const std::vector<std::uint64_t>& at, const SyncCandidate& c) {
    Chain               chain;
    const std::uint64_t size = bytes.size();
    std::uint64_t       pos  = at.front();
    std::uint64_t       first_length = 0;
    std::bitset<256>    before;
    for (;;) {
        if (pos + c.offset + c.width > size) {
            break;                                           // not even the length is there: the end
        }
        const std::uint64_t length = read_length(bytes, pos + c.offset, c);
        const std::int64_t  total  = static_cast<std::int64_t>(length) + c.adjust;
        if (total >= static_cast<std::int64_t>(c.offset + c.width)) {         // it holds its own length
            const std::uint64_t next = pos + static_cast<std::uint64_t>(total);
            if (next == size || (next < size && bytes[next] == c.sync)) {
                if (chain.frames.empty()) {
                    first_length = length;
                } else if (length != first_length) {
                    chain.varies = true;
                }
                if (!chain.frames.empty()) {
                    before.set(bytes[pos - 1]);              // not the first frame's: what is before it is not known
                }
                chain.frames.push_back(span(pos, static_cast<std::uint64_t>(total)));
                chain.covered += static_cast<std::uint64_t>(total);
                pos = next;              // at the end, there is not even a length there, and the chain stops
                continue;
            }
        }
        const std::vector<std::uint64_t>::const_iterator again = std::upper_bound(at.begin(), at.end(), pos);
        if (again == at.end()) {
            break;
        }
        chain.breaks += chain.frames.empty() ? 0 : 1;
        pos = *again;
    }
    chain.before = before.count();
    return chain;
}

bool is_framing(const Chain& chain, std::uint64_t stream_size, std::uint32_t min_frames) {
    // A tenth of the frames may be broken: a line is not perfect, and a byte that arrives wrong in a length or a sync
    // byte is a break. (More than that, and what the chain says is not what the stream is.)
    return chain.frames.size() >= min_frames && chain.breaks * 10 <= chain.frames.size() &&
           chain.covered * 100 >= 90 * stream_size;
}

// Is `a` the better of two readings that make the same kind of framing? The bytes cannot tell which of
// two such readings is the frame, so a rule does, and the first of the candidates wins a tie, which is the
// lower sync byte.
bool better(const SyncCandidate& a, const Chain& chain_a, const SyncCandidate& b, const Chain& chain_b) {
    if (chain_a.varies != chain_b.varies) {
        return chain_a.varies;                               // a length that varies over a fixed size
    }
    if (chain_a.before != chain_b.before) {
        // The byte before the sync byte is not always the same: a frame starts where the bytes stop being the
        // same, and a reading that starts after a constant byte starts it too late.
        return chain_a.before > chain_b.before;
    }
    if (!chain_a.varies) {
        // Frames of one size say nothing of a length, so where and how wide it is means nothing: the one that
        // follows the most frames, which is the one that did not run out of capture reading it.
        return chain_a.frames.size() > chain_b.frames.size();
    }
    if (a.offset != b.offset) {
        return a.offset > b.offset;                          // the sync that comes first in the frame
    }
    return a.width < b.width;                                // the narrower length
}

} // namespace

Segmentation segment_by_sync(const Capture& capture, const SegmentationOptions& options) {
    std::vector<std::uint8_t> bytes;
    if (!single_bytes(capture, &bytes)) {
        return Segmentation();
    }
    // Where each byte occurs, a run of the same byte counted once, at its first: a sync byte that is twice in
    // a frame (FF FF, as Dynamixel has it) is one place, and a stream of one byte, an idle line, is none, where
    // it would be periodic with any period and taken for frames of any size.
    std::vector<std::vector<std::uint64_t> > at(256);
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        if (i == 0 || bytes[i - 1] != bytes[i]) {
            at[bytes[i]].push_back(i);
        }
    }

    bool          found = false;
    SyncCandidate best;
    Chain         best_chain;
    for (unsigned sync = 0; sync < 256; ++sync) {
        if (at[sync].size() < options.min_sync_frames) {
            continue;
        }
        for (std::uint32_t width = 1; width <= 2; ++width) {
            for (unsigned order = 0; order < (width == 1 ? 1u : 2u); ++order) {
                for (std::uint32_t offset = 1; offset <= kMaxLengthOffset; ++offset) {
                    SyncCandidate c;
                    c.sync       = static_cast<std::uint8_t>(sync);
                    c.offset     = offset;
                    c.width      = width;
                    c.big_endian = order == 1;

                    // The overhead that each pair of sync bytes in a row would give: the distance between
                    // them, less the length read at the first. The most frequent three are tried.
                    std::map<std::int64_t, std::uint64_t> votes;
                    for (std::size_t i = 0; i + 1 < at[sync].size(); ++i) {
                        const std::uint64_t p = at[sync][i];
                        if (p + offset + width > bytes.size()) {
                            break;
                        }
                        ++votes[static_cast<std::int64_t>(at[sync][i + 1] - p) -
                                static_cast<std::int64_t>(read_length(bytes, p + offset, c))];
                    }
                    std::vector<std::pair<std::uint64_t, std::int64_t> > top;
                    for (std::map<std::int64_t, std::uint64_t>::const_iterator it = votes.begin(); it != votes.end(); ++it) {
                        const bool fits = it->first >= std::numeric_limits<std::int32_t>::min() &&
                                          it->first <= std::numeric_limits<std::int32_t>::max();    // for the info
                        if (fits && it->second >= 3) {
                            top.push_back(std::make_pair(it->second, it->first));
                        }
                    }
                    std::sort(top.begin(), top.end(), std::greater<std::pair<std::uint64_t, std::int64_t> >());
                    for (std::size_t t = 0; t < top.size() && t < 3; ++t) {
                        c.adjust = top[t].second;
                        const Chain chain = follow(bytes, at[sync], c);
                        if (is_framing(chain, bytes.size(), options.min_sync_frames) &&
                            (!found || better(c, chain, best, best_chain))) {
                            found      = true;
                            best       = c;
                            best_chain = chain;
                        }
                    }
                }
            }
        }
    }
    if (!found) {
        return Segmentation();
    }

    SegmentationInfo info;
    info.found  = true;
    info.kind   = FramingKind::Contiguous;
    info.sync   = best.sync;
    info.breaks = best_chain.breaks;
    if (best_chain.varies) {
        info.length_offset     = best.offset;
        info.length_bytes      = best.width;
        info.length_big_endian = best.big_endian;
        info.length_adjust     = static_cast<std::int32_t>(best.adjust);
    } else {
        info.frame_size = static_cast<std::uint32_t>(best_chain.frames.front().event_count);
    }
    return Segmentation(info, best_chain.frames);
}

Segmentation segment_by_lines(const Capture& capture, const SegmentationOptions& options) {
    std::vector<std::uint8_t> bytes;
    if (!single_bytes(capture, &bytes)) {
        return Segmentation();
    }
    std::uint64_t text = 0, feeds = 0;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const std::uint8_t b = bytes[i];
        text += ((b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0D || b == 0x0A) ? 1 : 0;
        feeds += b == 0x0A ? 1 : 0;
    }
    if (text * 100 < 95 * bytes.size()) {
        return Segmentation();
    }

    std::vector<FrameSpan> frames;
    std::uint64_t          start = 0;
    for (std::uint64_t i = 0; i < bytes.size(); ++i) {
        if (bytes[i] == 0x0A) {
            const bool empty = i == start || (i == start + 1 && bytes[start] == 0x0D);
            if (!empty) {
                frames.push_back(span(start, i + 1 - start));
            }
            start = i + 1;
        }
    }
    if (frames.empty() || frames.size() < options.min_line_frames || !regular_frames(bytes, frames, 256)) {
        return Segmentation();
    }
    SegmentationInfo info;
    info.found     = true;
    info.kind      = FramingKind::Terminated;
    info.delimiter = 0x0A;
    info.flags     = feeds;
    return Segmentation(info, frames);
}

namespace {

// Does `fine` cut at every place inside the capture where `coarse` does, and in more places? The frames of
// `fine` need not cover the capture, so a boundary is where one starts or ends. A tenth of the places of `coarse`
// may be missed: a line feed that arrives wrong joins two lines, and a flag or a sync byte that does, two frames,
// and none of them is a reason for the silences to be the better evidence.
bool refines(const Segmentation& fine, const Segmentation& coarse, std::uint64_t events) {
    if (fine.frame_count() <= coarse.frame_count()) {
        return false;
    }
    std::vector<std::uint64_t> edges;
    for (std::size_t i = 0; i < fine.frame_count(); ++i) {
        edges.push_back(fine.frame(i).first_event);
        edges.push_back(fine.frame(i).first_event + fine.frame(i).event_count);
    }
    std::sort(edges.begin(), edges.end());
    std::uint64_t places = 0;
    std::uint64_t missed = 0;
    for (std::size_t i = 0; i < coarse.frame_count(); ++i) {
        const std::uint64_t cuts[2] = { coarse.frame(i).first_event,
                                        coarse.frame(i).first_event + coarse.frame(i).event_count };
        for (int k = 0; k < 2; ++k) {
            if (cuts[k] > 0 && cuts[k] < events) {
                ++places;
                missed += std::binary_search(edges.begin(), edges.end(), cuts[k]) ? 0 : 1;
            }
        }
    }
    return missed * 10 <= places;
}

// How many sizes a tenth of the frames or more have. A length that says a size means something when frames
// are of several sizes; where one frame in a hundred has a byte more (a byte stuffed), any byte that is constant
// in each of the two sizes is a length that fits.
std::size_t sizes_of_a_tenth(const Segmentation& segmentation) {
    std::map<std::uint64_t, std::uint64_t> by_size;
    for (std::size_t i = 0; i < segmentation.frame_count(); ++i) {
        ++by_size[segmentation.frame(i).event_count];
    }
    std::size_t n = 0;
    for (std::map<std::uint64_t, std::uint64_t>::const_iterator it = by_size.begin(); it != by_size.end(); ++it) {
        n += it->second * 10 >= segmentation.frame_count() ? 1 : 0;
    }
    return n;
}

} // namespace

Segmentation segment_frames(const Capture& capture, const SegmentationOptions& options) {
    const Segmentation flagged = segment_by_flags(capture, options);
    const Segmentation gaps    = segment_by_gaps(capture, options);
    const Segmentation sync    = segment_by_sync(capture, options);
    // A flag that the stuffing shows is a flag. One that it does not is a byte that comes in pairs, and is the
    // framing unless something else says more: gaps that its frames do not cut at (the zeros on top of a number
    // are not where frames end), or a length that sizes every frame of a chain of them, with none broken (a byte
    // that is stuffed makes a frame longer than its type, and a length that is not one is wrong by it).
    if (flagged.info().found) {
        const bool gapped = gaps.info().found && !refines(flagged, gaps, capture.event_count());
        const bool sized  = sync.info().breaks == 0 && sizes_of_a_tenth(sync) >= 2;
        if (flagged.info().escaped || (!gapped && !sized)) {
            return flagged;
        }
    }
    // Text in lines is what it is whatever else the bytes of its sentences can be made to say: a separator after an
    // address that is in the same place in each, and a letter after it that takes a few values, read as a sync byte
    // and a length, make a chain that is self-consistent, with no break at all, in text that is regular enough, and
    // nothing in the bytes tells that chain from the real one of printable frames with a line feed inside. Text that
    // has lines is lines; a capture that is not text has none, and the sync byte and the length are all there is.
    const Segmentation lines = segment_by_lines(capture, options);
    const Segmentation& fine = lines.info().found ? lines : sync;
    if (!fine.info().found) {
        return gaps;
    }
    // Where there are gaps they are the better evidence, unless the sync bytes and lengths, or the lines, cut the
    // same frames and more (a burst of frames with silence only after the last): then the finer cut is the frames.
    if (!gaps.info().found || refines(fine, gaps, capture.event_count())) {
        return fine;
    }
    return gaps;
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

Capture frame_contents(const Capture& capture, const Segmentation& segmentation) {
    const SegmentationInfo info = segmentation.info();
    Capture                out;
    for (std::uint32_t c = 1; c < capture.channel_count(); ++c) {
        out.add_channel(capture.channel_name(c));
    }
    for (std::size_t i = 0; i < segmentation.frame_count(); ++i) {
        const FrameSpan                 frame = segmentation.frame(i);
        const std::vector<std::uint8_t> wire  = frame_bytes(capture, frame);
        std::vector<std::uint8_t>       content;
        if (info.kind != FramingKind::Flagged) {
            content = wire;
        } else {
            std::size_t first = 0;
            std::size_t end   = wire.size();
            if (first < end && wire[first] == info.delimiter) {
                ++first;
            }
            if (first < end && wire[end - 1] == info.delimiter) {
                --end;
            }
            for (std::size_t k = first; k < end; ++k) {
                if (info.escaped && wire[k] == info.escape && k + 1 < end &&
                    (wire[k + 1] == info.delimiter_code || wire[k + 1] == info.escape_code)) {
                    content.push_back(wire[k + 1] == info.delimiter_code ? info.delimiter : info.escape);
                    ++k;
                } else {
                    content.push_back(wire[k]);
                }
            }
        }
        EventInfo event;
        if (frame.event_count > 0) {
            event = capture.event(static_cast<std::size_t>(frame.first_event));
        }
        out.add_event(event, content);
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
