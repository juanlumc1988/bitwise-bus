// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/analyze.h"

#include <algorithm>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>

namespace bw {

namespace {

std::string number(std::uint64_t value) {
    return std::to_string(static_cast<unsigned long long>(value));
}

// Most frames first, then the smaller size.
bool more_frequent(const std::pair<std::uint64_t, std::uint64_t>& a,
                   const std::pair<std::uint64_t, std::uint64_t>& b) {
    return a.first != b.first ? a.first > b.first : a.second < b.second;
}

FieldInfo info_of(const FieldRegion& region) {
    FieldInfo info;
    info.kind          = region.kind;
    info.size_kind     = SizeKind::Fixed;
    info.bit_size      = 8 * region.byte_size;
    info.byte_order    = region.byte_order;
    info.evidence_bits = region.evidence_bits;
    if (region.kind == FieldKind::Constant) {
        info.constant = region.constant;
    }
    return info;
}

// Adds the fields of a typed map to a message type of the model.
void add_fields(Model* model, std::size_t type, const FieldMap& fields,
                const ChecksumFinding& checksum) {
    for (std::size_t i = 0; i < fields.region_count(); ++i) {
        const FieldRegion region = fields.region(i);
        FieldInfo         info   = info_of(region);
        std::string       name   = "field_" + number(region.byte_offset);
        std::string       detail;
        if (region.kind == FieldKind::Checksum) {
            // The bytes before it end where it starts, and the first of the
            // fields it covers starts where the search said coverage begins.
            std::uint32_t first = 0;
            for (std::size_t j = 0; j < i; ++j) {
                if (fields.region(j).byte_offset == checksum.header_skip) {
                    first = static_cast<std::uint32_t>(j);
                    break;
                }
            }
            info.covers_first = first;
            info.covers_last  = static_cast<std::uint32_t>(i - 1);
            name              = "checksum";
            detail            = checksum_algorithm_name(checksum.algorithm);
        } else if (region.kind == FieldKind::Counter) {
            detail = "step " + number(region.step);
        }
        model->add_field(type, name, info, detail);
    }
}

std::string checksum_line(const ChecksumFinding& c) {
    if (c.found) {
        return "checksum " + checksum_algorithm_name(c.algorithm) + ", " + number(c.width_bits) +
               " bits" + (c.byte_order == ByteOrder::Big ? " big-endian"
                          : c.byte_order == ByteOrder::Little ? " little-endian" : "") +
               ", evidence " + number(c.evidence_bits) + " bits";
    }
    if (c.candidates == 0) {
        return "no checksum found";
    }
    if (c.candidates == 1 && !c.truncated) {
        return "no checksum found: one candidate, but on thin evidence (" +
               number(c.evidence_bits) + " bits)";
    }
    return "no checksum found: " + number(c.candidates) + (c.truncated ? " or more" : "") +
           " candidates that cannot be told apart";
}

} // namespace

Analysis::Analysis() {}

Analysis::Analysis(const AnalysisInfo& info, const Segmentation& segmentation, const Model& model,
                   const std::vector<MessageTypeReport>& reports)
    : info_(info), segmentation_(segmentation), model_(model), reports_(reports) {
    if (reports.size() != model.message_type_count()) {
        throw std::invalid_argument("an analysis needs one report for each message type");
    }
}

AnalysisInfo Analysis::info() const {
    return info_;
}

Segmentation Analysis::segmentation() const {
    return segmentation_;
}

Model Analysis::model() const {
    return model_;
}

std::size_t Analysis::type_count() const {
    return reports_.size();
}

MessageTypeReport Analysis::type_report(std::size_t message_type) const {
    if (message_type >= reports_.size()) {
        throw std::out_of_range("message type out of range");
    }
    return reports_[message_type];
}

Analysis analyze(const Capture& capture, const AnalyzeOptions& options) {
    return analyze_frames(capture, segment_by_gaps(capture, options.segmentation), options);
}

Analysis analyze_frames(const Capture& capture, const Segmentation& segmentation,
                        const AnalyzeOptions& options) {
    AnalysisInfo info;
    info.events = capture.event_count();
    info.bytes  = capture.total_bytes();

    info.segmentation = segmentation.info();
    if (!info.segmentation.found) {
        return Analysis(info, segmentation, Model(), std::vector<MessageTypeReport>());
    }
    info.frames = segmentation.frame_count();

    std::map<std::uint64_t, std::uint64_t> by_size;      // frame size -> how many frames
    for (std::size_t i = 0; i < segmentation.frame_count(); ++i) {
        ++by_size[frame_size(capture, segmentation.frame(i))];
    }
    std::vector<std::pair<std::uint64_t, std::uint64_t> > types;   // (frames, size)
    for (std::map<std::uint64_t, std::uint64_t>::const_iterator it = by_size.begin();
         it != by_size.end(); ++it) {
        if (it->second >= options.fields.min_frames && it->first > 0 &&
            it->first <= std::numeric_limits<std::uint32_t>::max()) {
            types.push_back(std::make_pair(it->second, it->first));
        } else {
            info.ignored_frames += it->second;
        }
    }
    std::sort(types.begin(), types.end(), more_frequent);

    // What cut the frames is known only when it was the gaps.
    Model model;
    FramingInfo framing;
    if (info.segmentation.idle_gap_ns != 0) {
        framing.kind        = FramingKind::IdleGap;
        framing.idle_gap_ns = info.segmentation.idle_gap_ns;
    }
    model.set_framing(framing);

    std::vector<MessageTypeReport> reports;
    for (std::size_t t = 0; t < types.size(); ++t) {
        const std::uint32_t size = static_cast<std::uint32_t>(types[t].second);

        MessageTypeReport report;
        report.frame_bytes = size;
        report.frames      = static_cast<std::uint32_t>(types[t].first);
        report.checksum    = find_checksum(capture, segmentation, size);

        const FieldMap layout = discover_fields(capture, segmentation, report.checksum, size,
                                                options.fields);
        const FieldMap typed  = type_fields(layout, capture, segmentation);

        const std::size_t type = model.add_message_type("type" + number(t));
        add_fields(&model, type, typed, report.checksum);
        reports.push_back(report);
    }
    return Analysis(info, segmentation, model, reports);
}

std::string describe_analysis(const Analysis& analysis) {
    const AnalysisInfo info = analysis.info();
    std::string        out  = "events     " + number(info.events) + " (" + number(info.bytes) + " bytes)\n";

    const SegmentationInfo& seg = info.segmentation;
    if (!seg.found) {
        out += "framing    none found: the gaps between events do not split into short and long ones\n";
        return out + describe_model(analysis.model());
    }
    if (seg.idle_gap_ns == 0) {
        out += "framing    not looked for: the frames were given\n";
    } else {
        out += "framing    idle gap: a gap of at least " + number(seg.idle_gap_ns) + " ns ends a frame (" +
               number(seg.outer_gaps) + " gaps between frames, " + number(seg.inner_gaps) +
               " inside them, the longest " + number(seg.longest_inner_gap_ns) + " ns)\n";
    }
    out += "frames     " + number(info.frames);
    if (info.ignored_frames != 0) {
        out += " (" + number(info.ignored_frames) + " of a size too rare to say anything about)";
    }
    out += "\n";
    for (std::size_t t = 0; t < analysis.type_count(); ++t) {
        const MessageTypeReport r = analysis.type_report(t);
        out += "type" + number(t) + "      " + number(r.frame_bytes) + " bytes, " + number(r.frames) +
               " frames; " + checksum_line(r.checksum) + "\n";
    }
    return out + describe_model(analysis.model());
}

} // namespace bw
