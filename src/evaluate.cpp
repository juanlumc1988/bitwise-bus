// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/evaluate.h"

#include <limits>
#include <map>
#include <set>
#include <utility>

namespace bw {

namespace {

std::uint64_t span_end(const FrameSpan& span) {
    const std::uint64_t max = std::numeric_limits<std::uint64_t>::max();
    return span.event_count > max - span.first_event ? max : span.first_event + span.event_count;
}

std::set<std::uint64_t> span_boundaries(const std::vector<FrameSpan>& spans) {
    std::set<std::uint64_t> out;
    for (std::size_t i = 0; i < spans.size(); ++i) {
        out.insert(spans[i].first_event);
        out.insert(span_end(spans[i]));
    }
    return out;
}

typedef std::pair<std::uint64_t, std::uint32_t> Placement;   // bit offset, bit size

// The fields that have a fixed size at a fixed position, by where they are.
std::map<Placement, FieldKind> placed_fields(const Model& model, std::size_t type) {
    std::map<Placement, FieldKind> out;
    for (std::size_t f = 0; f < model.field_count(type); ++f) {
        const FieldInfo     info     = model.field(type, f);
        const FieldPosition position = model.field_position(type, f);
        if (position.fixed && info.size_kind == SizeKind::Fixed) {
            out[Placement(position.bit_offset, info.bit_size)] = info.kind;
        }
    }
    return out;
}

std::set<std::uint64_t> field_boundaries(const std::map<Placement, FieldKind>& placed) {
    std::set<std::uint64_t> out;
    for (std::map<Placement, FieldKind>::const_iterator it = placed.begin(); it != placed.end(); ++it) {
        out.insert(it->first.first);
        out.insert(it->first.first + it->first.second);
    }
    return out;
}

template <typename T>
std::uint64_t common(const std::set<T>& a, const std::set<T>& b) {
    std::uint64_t n = 0;
    for (typename std::set<T>::const_iterator it = a.begin(); it != a.end(); ++it) {
        if (b.count(*it) != 0) {
            ++n;
        }
    }
    return n;
}

bool find_checksum(const Model& model, std::size_t type, std::size_t* index) {
    for (std::size_t f = 0; f < model.field_count(type); ++f) {
        if (model.field(type, f).kind == FieldKind::Checksum) {
            *index = f;
            return true;
        }
    }
    return false;
}

// What a checksum covers, in bits. A field that is split in two, or two that
// are merged, change the indexes of the fields a checksum covers and not what
// it covers, so a model that cuts the bytes differently from the truth can
// still have found the same checksum. When the covered fields are not all of a
// fixed size at a fixed position there are no bits to compare, and the indexes
// stand in for them.
struct Coverage {
    bool          in_bits = false;
    std::uint64_t first   = 0;       // bit offset when in_bits, else a field index
    std::uint64_t last    = 0;       // end bit offset when in_bits, else a field index
};

Coverage coverage_of(const Model& model, std::size_t type, const FieldInfo& checksum) {
    Coverage out;
    out.first = checksum.covers_first;
    out.last  = checksum.covers_last;
    const FieldInfo     last_info = model.field(type, checksum.covers_last);
    const FieldPosition begin     = model.field_position(type, checksum.covers_first);
    const FieldPosition end       = model.field_position(type, checksum.covers_last);
    if (begin.fixed && end.fixed && last_info.size_kind == SizeKind::Fixed) {
        out.in_bits = true;
        out.first   = begin.bit_offset;
        out.last    = end.bit_offset + last_info.bit_size;
    }
    return out;
}

bool same_checksum(const Model& truth, std::size_t truth_type, std::size_t truth_index,
                   const Model& found, std::size_t found_type, std::size_t found_index) {
    const FieldInfo     a  = truth.field(truth_type, truth_index);
    const FieldInfo     b  = found.field(found_type, found_index);
    const FieldPosition pa = truth.field_position(truth_type, truth_index);
    const FieldPosition pb = found.field_position(found_type, found_index);
    const Coverage      ca = coverage_of(truth, truth_type, a);
    const Coverage      cb = coverage_of(found, found_type, b);
    return pa.fixed == pb.fixed && (!pa.fixed || pa.bit_offset == pb.bit_offset) &&
           a.size_kind == b.size_kind && a.bit_size == b.bit_size &&
           a.byte_order == b.byte_order &&
           ca.in_bits == cb.in_bits && ca.first == cb.first && ca.last == cb.last &&
           truth.field_detail(truth_type, truth_index) == found.field_detail(found_type, found_index);
}

} // namespace

SegmentationScore score_segmentation(const std::vector<FrameSpan>& truth,
                                     const std::vector<FrameSpan>& found) {
    SegmentationScore score;
    score.truth_frames = truth.size();
    score.found_frames = found.size();

    std::set<std::pair<std::uint64_t, std::uint64_t> > true_frames;
    for (std::size_t i = 0; i < truth.size(); ++i) {
        true_frames.insert(std::make_pair(truth[i].first_event, truth[i].event_count));
    }
    for (std::size_t i = 0; i < found.size(); ++i) {
        if (true_frames.count(std::make_pair(found[i].first_event, found[i].event_count)) != 0) {
            ++score.exact_frames;
        }
    }

    const std::set<std::uint64_t> true_cuts  = span_boundaries(truth);
    const std::set<std::uint64_t> found_cuts = span_boundaries(found);
    score.truth_boundaries = true_cuts.size();
    score.found_boundaries = found_cuts.size();
    score.boundary_hits    = common(true_cuts, found_cuts);
    return score;
}

FieldScore score_fields(const Model& truth, std::size_t truth_type,
                        const Model& found, std::size_t found_type) {
    FieldScore score;
    score.truth_fields = static_cast<std::uint32_t>(truth.field_count(truth_type));
    score.found_fields = static_cast<std::uint32_t>(found.field_count(found_type));

    const std::map<Placement, FieldKind> true_placed  = placed_fields(truth, truth_type);
    const std::map<Placement, FieldKind> found_placed = placed_fields(found, found_type);

    const std::set<std::uint64_t> true_cuts  = field_boundaries(true_placed);
    const std::set<std::uint64_t> found_cuts = field_boundaries(found_placed);
    score.truth_boundaries = static_cast<std::uint32_t>(true_cuts.size());
    score.found_boundaries = static_cast<std::uint32_t>(found_cuts.size());
    score.boundary_hits    = static_cast<std::uint32_t>(common(true_cuts, found_cuts));

    for (std::map<Placement, FieldKind>::const_iterator it = found_placed.begin();
         it != found_placed.end(); ++it) {
        const std::map<Placement, FieldKind>::const_iterator match = true_placed.find(it->first);
        if (match != true_placed.end()) {
            ++score.exact_fields;
            if (match->second == it->second) {
                ++score.kind_hits;
            }
        }
    }

    std::size_t truth_index = 0;
    std::size_t found_index = 0;
    score.truth_has_checksum = find_checksum(truth, truth_type, &truth_index);
    score.found_has_checksum = find_checksum(found, found_type, &found_index);
    if (score.truth_has_checksum && score.found_has_checksum) {
        score.checksum_match = same_checksum(truth, truth_type, truth_index,
                                             found, found_type, found_index);
    } else {
        score.checksum_match = !score.truth_has_checksum && !score.found_has_checksum;
    }
    return score;
}

} // namespace bw
