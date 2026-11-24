// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/fields.h"

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
    for (std::size_t i = 0; i < layout.region_count(); ++i) {
        FieldRegion region = layout.region(i);
        if (region.kind == FieldKind::Unknown) {
            type_region(&region, frames);
        }
        out.add_region(region);
    }
    return out;
}

} // namespace bw
