// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/fields.h"

#include <algorithm>
#include <bitset>
#include <limits>
#include <stdexcept>

namespace bw {

namespace {

typedef std::vector<std::uint8_t> Bytes;

std::uint32_t saturate(std::uint64_t value) {
    const std::uint64_t max = std::numeric_limits<std::uint32_t>::max();
    return static_cast<std::uint32_t>(value > max ? max : value);
}

// The smallest number of bits that can tell `values` values apart.
std::uint32_t ceil_log2(std::size_t values) {
    std::uint32_t bits = 0;
    while ((static_cast<std::uint64_t>(1) << bits) < values) {
        ++bits;
    }
    return bits;
}

FieldStructure classify(std::size_t distinct, std::size_t frames, const FieldOptions& options) {
    if (distinct == 1) {
        return FieldStructure::Constant;
    }
    if (distinct <= options.max_enum_values &&
        static_cast<std::uint64_t>(frames) >= 4 * static_cast<std::uint64_t>(distinct)) {
        return FieldStructure::Few;
    }
    return FieldStructure::Many;
}

std::vector<Bytes> frames_in(const Capture& capture, const std::vector<FrameSpan>& spans) {
    std::vector<Bytes> out;
    out.reserve(spans.size());
    for (std::size_t i = 0; i < spans.size(); ++i) {
        out.push_back(frame_bytes(capture, spans[i]));
    }
    return out;
}

FieldRegion region_of(std::uint32_t offset, std::uint32_t size, FieldStructure structure) {
    FieldRegion r;
    r.byte_offset = offset;
    r.byte_size   = size;
    r.structure   = structure;
    return r;
}

// The bytes of a region of a frame as a number. size is at most 8.
std::uint64_t value_of(const Bytes& frame, const FieldRegion& region, ByteOrder order) {
    std::uint64_t value = 0;
    for (std::uint32_t i = 0; i < region.byte_size; ++i) {
        const std::uint32_t at = (order == ByteOrder::Little) ? region.byte_size - 1 - i : i;
        value = (value << 8) | frame[region.byte_offset + at];
    }
    return value;
}

// Successive frames differ by the same non-zero step, in this byte order.
bool is_counter(const std::vector<Bytes>& frames, const FieldRegion& region, ByteOrder order,
                std::uint64_t* step) {
    const std::uint64_t mask = region.byte_size >= 8
        ? std::numeric_limits<std::uint64_t>::max()
        : (static_cast<std::uint64_t>(1) << (8 * region.byte_size)) - 1;
    std::uint64_t previous = value_of(frames[0], region, order);
    std::uint64_t first    = 0;
    for (std::size_t i = 1; i < frames.size(); ++i) {
        const std::uint64_t value = value_of(frames[i], region, order);
        const std::uint64_t delta = (value - previous) & mask;
        if (i == 1) {
            if (delta == 0) {
                return false;
            }
            first = delta;
        } else if (delta != first) {
            return false;
        }
        previous = value;
    }
    *step = first;
    return true;
}

void type_region(FieldRegion* region, const std::vector<Bytes>& frames) {
    const std::uint64_t n = frames.size();

    // Constants and enums are claimed for single bytes only: that is all stage
    // 4 makes of them, and a wider one would need a byte order that nothing
    // here could decide.
    if (region->structure == FieldStructure::Constant && region->byte_size == 1) {
        region->kind          = FieldKind::Constant;
        region->constant      = frames[0][region->byte_offset];
        region->evidence_bits = saturate(8 * (n - 1));
        return;
    }
    if (region->structure == FieldStructure::Few && region->byte_size == 1) {
        std::bitset<256> seen;
        for (std::size_t i = 0; i < frames.size(); ++i) {
            seen.set(frames[i][region->byte_offset]);
        }
        region->kind          = FieldKind::Enum;
        region->evidence_bits = saturate(n * (8 - ceil_log2(seen.count())));
        return;
    }
    if (region->structure == FieldStructure::Many && region->byte_size <= 8 && frames.size() >= 3) {
        const ByteOrder orders[2] = { ByteOrder::Big, ByteOrder::Little };
        const int       tries     = region->byte_size == 1 ? 1 : 2;
        for (int t = 0; t < tries; ++t) {
            std::uint64_t step = 0;
            if (is_counter(frames, *region, orders[t], &step)) {
                region->kind          = FieldKind::Counter;
                region->byte_order    = region->byte_size == 1 ? ByteOrder::NotApplicable : orders[t];
                region->step          = step;
                region->evidence_bits = saturate(8 * static_cast<std::uint64_t>(region->byte_size) * (n - 2));
                return;
            }
        }
    }
    region->kind          = FieldKind::Payload;     // no structure found, and no claim
    region->evidence_bits = 0;
}

// ---- Numbers of several bytes ----------------------------------------------------------------------------
//
// Stage 4 sees bytes, so a number of several bytes comes out in pieces: a counter of four bytes has a low half
// that changes all the time, a third byte that changes once in a while and a fourth that has not changed yet;
// a float has bytes of mantissa that change and a byte of exponent that takes a few values. What follows puts the
// pieces together when the bytes, taken as a number, show it, and only then. (A byte that varies next to bytes that
// are always zero is not put together with them: it may be a small number in two bytes or a byte and some flags,
// and nothing tells which.) It works on the regions that typing has made, never on a checksum.

bool varies(const FieldRegion& region) {
    return region.structure != FieldStructure::Constant && region.kind != FieldKind::Checksum;
}

// The two regions, which are next to each other, as one.
FieldRegion span_of(const FieldRegion& first, const FieldRegion& last) {
    FieldRegion out;
    out.byte_offset = first.byte_offset;
    out.byte_size   = last.byte_offset + last.byte_size - first.byte_offset;
    out.structure   = FieldStructure::Many;
    return out;
}

// The regions first to last, as one.
FieldRegion join(const std::vector<FieldRegion>& regions, std::size_t first, std::size_t last) {
    return span_of(regions[first], regions[last]);
}

// The widest window of regions from `first` that is a counter in a byte order: the same non-zero step from each
// frame to the next. Its first and last regions vary, since a window that ends in a byte that never changes says
// nothing about it (a counter of one byte next to a zero is also a counter of two, if it never wraps).
bool counter_window(const std::vector<FieldRegion>& regions, std::size_t first, const std::vector<Bytes>& frames,
                    FieldRegion* out, std::size_t* last) {
    if (frames.size() < 3 || !varies(regions[first])) {
        return false;
    }
    bool found = false;
    for (std::size_t j = first + 1; j < regions.size() && regions[j].kind != FieldKind::Checksum; ++j) {
        FieldRegion window = join(regions, first, j);
        if (window.byte_size > 8) {
            break;
        }
        if (!varies(regions[j])) {
            continue;
        }
        const ByteOrder orders[2] = { ByteOrder::Big, ByteOrder::Little };
        for (int t = 0; t < 2; ++t) {
            std::uint64_t step = 0;
            if (is_counter(frames, window, orders[t], &step)) {
                window.kind          = FieldKind::Counter;
                window.byte_order    = orders[t];
                window.step          = step;
                window.evidence_bits = saturate(8 * static_cast<std::uint64_t>(window.byte_size) *
                                                (frames.size() - 2));
                *out   = window;
                *last  = j;
                found  = true;
                break;
            }
        }
    }
    return found;
}

// Four bytes that, as an IEEE 754 float in this byte order, are in a plausible range in nearly all of the frames
// where they are not zero, and whose two lowest bytes of mantissa are as random as the digits of a measurement
// are: at least 8 values each, and a half of the frames' worth if there are fewer than 16 frames (so a value that
// never changes is no float). Random bytes are not in the range (the exponent is one of 49 values in 256), nor are
// small integers (their exponent is 0), nor counters (taken before); and flags, which can have a byte on top that
// makes them look like a float, have few values in the bytes below it. The byte on top, which has the sign and
// most of the exponent, is often constant, and so a window may start at a constant region. Four bytes that are
// printable characters in every frame are text, where digits stand in the places of an exponent and a mantissa.
bool plausible_float(const std::vector<Bytes>& frames, const FieldRegion& window, ByteOrder order) {
    std::size_t nonzero  = 0;
    std::size_t in_range = 0;
    const std::size_t needed = std::min<std::size_t>(8, frames.size() / 2);
    for (std::uint32_t k = 0; k < 2; ++k) {
        const std::uint32_t at = window.byte_offset + (order == ByteOrder::Little ? k : 3 - k);
        std::bitset<256>    seen;
        for (std::size_t i = 0; i < frames.size(); ++i) {
            seen.set(frames[i][at]);
        }
        if (seen.count() < needed) {
            return false;
        }
    }
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const std::uint64_t bits = value_of(frames[i], window, order);
        if ((bits & 0x7FFFFFFFULL) == 0) {
            continue;                                   // zero, either sign
        }
        ++nonzero;
        const std::uint64_t exponent = (bits >> 23) & 0xFF;
        if (exponent >= 0x68 && exponent <= 0x98) {     // about 1e-7 to 4e7
            ++in_range;
        }
    }
    return nonzero * 2 >= frames.size() && in_range * 100 >= nonzero * 95;
}

bool printable_text(const std::vector<Bytes>& frames, const FieldRegion& window) {
    for (std::size_t i = 0; i < frames.size(); ++i) {
        for (std::uint32_t k = 0; k < window.byte_size; ++k) {
            const std::uint8_t byte = frames[i][window.byte_offset + k];
            if (byte < 0x20 || byte > 0x7E) {
                return false;
            }
        }
    }
    return true;
}

bool float_window(const std::vector<FieldRegion>& regions, std::size_t first, const std::vector<Bytes>& frames,
                  FieldRegion* out, std::size_t* last) {
    if (frames.size() < 8) {
        return false;
    }
    std::uint32_t size = 0;
    std::size_t   j    = first;
    for (; j < regions.size() && regions[j].kind != FieldKind::Checksum && size < 4; ++j) {
        size += regions[j].byte_size;
    }
    if (size != 4) {
        return false;
    }
    FieldRegion window = join(regions, first, j - 1);
    if (printable_text(frames, window)) {
        return false;
    }
    const ByteOrder orders[2] = { ByteOrder::Little, ByteOrder::Big };
    for (int t = 0; t < 2; ++t) {
        if (plausible_float(frames, window, orders[t])) {
            window.kind          = FieldKind::Float;
            window.byte_order    = orders[t];
            window.evidence_bits = saturate(frames.size());
            *out  = window;
            *last = j - 1;
            return true;
        }
    }
    return false;
}

bool natural_size(std::uint32_t size) {
    return size == 1 || size == 2 || size == 4 || size == 8;
}

// A counter of 3, 5, 6 or 7 bytes is a counter of 4 or 8 that has not yet changed in its top bytes. They are the
// constant regions next to it (after it if it is little-endian, before it if it is big-endian; `nearest_first`),
// if those are exactly what is missing. How many of them there are, or none.
std::size_t padding_for(const std::vector<FieldRegion>& nearest_first, std::uint32_t size) {
    const std::uint32_t natural = size <= 4 ? 4 : 8;
    std::uint32_t       have    = size;
    for (std::size_t k = 0; k < nearest_first.size(); ++k) {
        if (nearest_first[k].structure != FieldStructure::Constant) {
            return 0;
        }
        have += nearest_first[k].byte_size;
        if (have >= natural) {
            return have == natural ? k + 1 : 0;
        }
    }
    return 0;
}

// The counter with the constant bytes that bring it to the size of a number, if it is still a counter with them.
// `out` is what has been put out so far, and `last` the region of the input where the counter ends; they are
// changed when it takes regions of either.
void pad_counter(const std::vector<FieldRegion>& regions, const std::vector<Bytes>& frames,
                 std::vector<FieldRegion>* out, FieldRegion* counter, std::size_t* last) {
    if (natural_size(counter->byte_size)) {
        return;
    }
    const bool little = counter->byte_order == ByteOrder::Little;
    std::vector<FieldRegion> nearest;
    for (std::size_t k = 0; k < 8; ++k) {
        if (little && *last + 1 + k < regions.size()) {
            nearest.push_back(regions[*last + 1 + k]);
        } else if (!little && k < out->size()) {
            nearest.push_back((*out)[out->size() - 1 - k]);
        }
    }
    const std::size_t take = padding_for(nearest, counter->byte_size);
    if (take == 0) {
        return;
    }
    FieldRegion padded = little ? span_of(*counter, nearest[take - 1]) : span_of(nearest[take - 1], *counter);
    std::uint64_t step = 0;
    if (!is_counter(frames, padded, counter->byte_order, &step)) {
        return;
    }
    padded.kind          = FieldKind::Counter;
    padded.byte_order    = counter->byte_order;
    padded.step          = step;
    padded.evidence_bits = counter->evidence_bits;
    *counter             = padded;
    if (little) {
        *last += take;
    } else {
        out->resize(out->size() - take);
    }
}

std::vector<FieldRegion> merge_numbers(const std::vector<FieldRegion>& regions, const std::vector<Bytes>& frames) {
    std::vector<FieldRegion> out;
    std::size_t i = 0;
    while (i < regions.size()) {
        FieldRegion merged;
        std::size_t last = i;
        // A counter that is several regions together, or one that typing found in a region of its own.
        const bool window = counter_window(regions, i, frames, &merged, &last);
        if (window || regions[i].kind == FieldKind::Counter) {
            if (!window) {
                merged = regions[i];
            }
            pad_counter(regions, frames, &out, &merged, &last);
            out.push_back(merged);
            i = last + 1;
        } else if (float_window(regions, i, frames, &merged, &last)) {
            out.push_back(merged);
            i = last + 1;
        } else {
            out.push_back(regions[i]);
            ++i;
        }
    }
    return out;
}

} // namespace

FieldMap::FieldMap() {}

FieldMap::FieldMap(std::uint32_t frame_bytes, std::uint32_t frames)
    : frame_bytes_(frame_bytes), frames_(frames) {}

void FieldMap::add_region(const FieldRegion& region) {
    const std::uint32_t expected = regions_.empty()
        ? 0 : regions_.back().byte_offset + regions_.back().byte_size;
    if (region.byte_size == 0 || region.byte_offset != expected ||
        static_cast<std::uint64_t>(region.byte_offset) + region.byte_size > frame_bytes_) {
        throw std::invalid_argument("a region must be non-empty, start where the previous one ended "
                                    "and end inside the frame");
    }
    regions_.push_back(region);
}

std::uint32_t FieldMap::frame_bytes() const {
    return frame_bytes_;
}

std::uint32_t FieldMap::frames() const {
    return frames_;
}

std::size_t FieldMap::region_count() const {
    return regions_.size();
}

FieldRegion FieldMap::region(std::size_t index) const {
    if (index >= regions_.size()) {
        throw std::out_of_range("region index out of range");
    }
    return regions_[index];
}

FieldMap discover_fields(const Capture& capture, const Segmentation& segmentation,
                         const ChecksumFinding& checksum, std::uint32_t size_bytes,
                         const FieldOptions& options) {
    const std::uint32_t size           = size_bytes;
    const std::uint32_t checksum_bytes = checksum.width_bits / 8;
    std::uint32_t       checksum_start = 0;
    std::uint32_t       covered_end    = 0;     // where what it covers ends: before the gap, if any
    if (checksum.found) {
        // The covered range is not empty, or the search would not have said so.
        if (checksum.width_bits == 0 || checksum.width_bits % 8 != 0 ||
            static_cast<std::uint64_t>(checksum.header_skip) + checksum.trailer_skip +
                checksum.gap_bytes + checksum_bytes >= size) {
            throw std::invalid_argument("the checksum does not fit frames of this size");
        }
        checksum_start = size - checksum.trailer_skip - checksum_bytes;
        covered_end    = checksum_start - checksum.gap_bytes;
    }

    const std::vector<FrameSpan> spans = frames_of_size(capture, segmentation, size);
    FieldMap map(size, saturate(spans.size()));
    if (size == 0 || spans.empty() || spans.size() < options.min_frames) {
        return map;
    }

    std::vector<std::bitset<256> > seen(size);
    const std::vector<Bytes>       frames = frames_in(capture, spans);
    for (std::size_t i = 0; i < frames.size(); ++i) {
        for (std::uint32_t k = 0; k < size; ++k) {
            seen[k].set(frames[i][k]);
        }
    }
    std::vector<FieldStructure> structure(size);
    for (std::uint32_t k = 0; k < size; ++k) {
        structure[k] = classify(seen[k].count(), frames.size(), options);
    }

    std::uint32_t k = 0;
    while (k < size) {
        if (checksum.found && k == checksum_start) {
            FieldRegion region = region_of(k, checksum_bytes, FieldStructure::Checksum);
            region.kind          = FieldKind::Checksum;
            region.byte_order    = checksum.byte_order;
            region.ascii_hex     = checksum.ascii_hex;
            region.evidence_bits = checksum.evidence_bits;
            map.add_region(region);
            k += checksum_bytes;
            continue;
        }
        std::uint32_t end = k + 1;
        if (structure[k] == FieldStructure::Many) {
            // A run of bytes with nothing to tell them apart is one field, but
            // not across a place where the checksum's coverage begins or ends,
            // or where the checksum itself does.
            while (end < size && structure[end] == FieldStructure::Many &&
                   !(checksum.found && (end == checksum.header_skip || end == covered_end ||
                                        end == checksum_start))) {
                ++end;
            }
        }
        map.add_region(region_of(k, end - k, structure[k]));
        k = end;
    }
    return map;
}

FieldMap type_fields(const FieldMap& layout, const Capture& capture,
                     const Segmentation& segmentation) {
    FieldMap out(layout.frame_bytes(), layout.frames());
    if (layout.region_count() == 0) {
        return out;
    }
    const std::vector<FrameSpan> spans = frames_of_size(capture, segmentation, layout.frame_bytes());
    if (spans.empty() || spans.size() != layout.frames()) {
        throw std::invalid_argument("the layout is of other frames than these");
    }
    const std::vector<Bytes> frames = frames_in(capture, spans);
    std::vector<FieldRegion> typed;
    for (std::size_t i = 0; i < layout.region_count(); ++i) {
        FieldRegion region = layout.region(i);
        if (region.kind == FieldKind::Unknown) {
            type_region(&region, frames);
        }
        typed.push_back(region);
    }
    const std::vector<FieldRegion> merged = merge_numbers(typed, frames);
    for (std::size_t i = 0; i < merged.size(); ++i) {
        out.add_region(merged[i]);
    }
    return out;
}

} // namespace bw
