// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/analyze.h"

#include <algorithm>
#include <limits>
#include <map>
#include <stdexcept>
#include <utility>

#include "bw/messages.h"

namespace bw {

namespace {

std::string number(std::uint64_t value) {
    return std::to_string(static_cast<unsigned long long>(value));
}

// Most frames first, then the smaller size.
typedef std::pair<std::pair<std::uint64_t, std::uint64_t>, std::int64_t> TypeKey;
bool more_frequent_type(const TypeKey& a, const TypeKey& b) {
    return a.first.first != b.first.first ? a.first.first > b.first.first : a.first.second < b.first.second;
}

FieldInfo info_of(const FieldRegion& region) {
    FieldInfo info;
    info.kind          = region.kind;
    info.size_kind     = SizeKind::Fixed;
    info.bit_size      = 8 * region.byte_size;
    info.byte_order    = region.byte_order;
    info.ascii_hex     = region.ascii_hex;
    info.evidence_bits = region.evidence_bits;
    if (region.kind == FieldKind::Constant) {
        info.constant = region.constant;
    }
    return info;
}

// The algorithm, and the hidden byte if there is one: "CRC-16/MCRF4XX seeded with 50".
std::string checksum_name(const ChecksumFinding& c) {
    std::string name = checksum_algorithm_name(c.algorithm);
    if (c.seeded) {
        name += " seeded with " + number(c.seed);
    }
    return name;
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
            // The first of the fields it covers starts where the search said
            // coverage begins, and the last ends where it says it ends: at the
            // checksum, or before the separator that comes between them.
            const std::uint32_t covered_end = region.byte_offset - checksum.gap_bytes;
            std::uint32_t       first       = 0;
            std::uint32_t       last        = static_cast<std::uint32_t>(i - 1);
            for (std::size_t j = 0; j < i; ++j) {
                const FieldRegion other = fields.region(j);
                if (other.byte_offset == checksum.header_skip) {
                    first = static_cast<std::uint32_t>(j);
                }
                if (other.byte_offset + other.byte_size == covered_end) {
                    last = static_cast<std::uint32_t>(j);
                }
            }
            info.covers_first = first;
            info.covers_last  = last;
            name              = "checksum";
            detail            = checksum_name(checksum);
        } else if (region.kind == FieldKind::Counter) {
            detail = "step " + number(region.step);
        }
        model->add_field(type, name, info, detail);
    }
}

// A kind of message that has frames of several sizes, as the model has it: the fields of its header
// (up to where the payload starts), the length that says how long the payload is, the payload, and the
// checksum after it.
struct KindType {
    std::vector<FieldRegion> header;
    std::size_t              length_field  = 0;        // the region that holds the length
    std::size_t              first_covered = 0;        // the region where what the checksum covers starts
    ChecksumFinding          checksum;
    LengthField              length;
    std::uint32_t            smallest = 0;
    std::uint32_t            largest  = 0;
    std::uint32_t            frames   = 0;
};

// Tries to make one message type of a kind. It needs a checksum that explains the frames of all of its
// sizes (the same, with the same hidden byte: evidence that they are one kind and not several that
// share a discriminator), because where the payload starts is the length constant less what comes after
// the payload: size = length + adjust, and adjust is the header and what follows. Without it, the sizes
// stay types of their own.
bool build_kind(const Capture& read, const Segmentation& frames, const MessageKinds& kinds, std::size_t kind,
                const FieldOptions& options, KindType* out) {
    std::vector<std::vector<std::uint8_t> > bytes;
    for (std::size_t i = 0; i < frames.frame_count(); ++i) {
        if (kinds.frame_kind[i] == static_cast<std::int32_t>(kind)) {
            bytes.push_back(frame_bytes(read, frames.frame(i)));
        }
    }
    if (bytes.empty()) {
        return false;
    }
    std::size_t smallest = bytes[0].size();
    std::size_t largest  = bytes[0].size();
    for (std::size_t i = 1; i < bytes.size(); ++i) {
        smallest = std::min(smallest, bytes[i].size());
        largest  = std::max(largest, bytes[i].size());
    }

    // A checksum written as text (which has a separator, as in NMEA, or not) or with bytes after it is not put into
    // the model of a kind: the type has the checksum last, as bytes.
    const ChecksumFinding checksum = find_checksum_of_frames(bytes);
    if (!checksum.found || checksum.ascii_hex || checksum.trailer_skip != 0) {
        return false;
    }
    // The length counts the payload, so what follows it is the checksum and the rest is the header; a
    // length that counts the checksum too leaves no room for it.
    const std::uint64_t after  = checksum.width_bits / 8;
    const LengthField&  length = kinds.length;
    if (static_cast<std::uint64_t>(length.adjust) < after) {
        return false;
    }
    // adjust is at most the size of the smallest frame (the length is never negative), so the header, which
    // is the first payload_start bytes, is in all of them.
    const std::uint64_t payload_start = static_cast<std::uint64_t>(length.adjust) - after;

    // The header, as frames of their own, which stage 4 and 5 read like any others.
    Capture                header;
    std::vector<FrameSpan> spans;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        header.add_event(EventInfo(), std::vector<std::uint8_t>(bytes[i].begin(),
                         bytes[i].begin() + static_cast<std::ptrdiff_t>(payload_start)));
        FrameSpan span;
        span.first_event = i;
        span.event_count = 1;
        spans.push_back(span);
    }
    SegmentationInfo info;
    info.found = true;
    const Segmentation whole(info, spans);
    const FieldMap     layout = discover_fields(header, whole, ChecksumFinding(),
                                                static_cast<std::uint32_t>(payload_start), options);
    if (layout.region_count() == 0) {
        return false;
    }
    const FieldMap typed = type_fields(layout, header, whole);

    // The length is a field of its own, of all of its bytes: stage 4 sees bytes, and a length of two comes out
    // as two, which are put together when they are the length and nothing else. A run of bytes with no structure
    // that goes across an end of the length (a length with many values, next to a counter) leaves some of its bytes
    // uncounted, and then the type has no length to be sized by. What the checksum covers has to start at a field.
    bool          first_found = checksum.header_skip == payload_start;
    std::uint32_t absorbed    = 0;
    bool          length_made = false;
    out->first_covered        = typed.region_count();      // the payload, if that is where it starts
    for (std::size_t i = 0; i < typed.region_count(); ++i) {
        FieldRegion         region = typed.region(i);
        const std::uint32_t end    = region.byte_offset + region.byte_size;
        const bool          inside = region.byte_offset >= length.offset && end <= length.offset + length.bytes;
        if (inside) {
            absorbed += region.byte_size;
            if (length_made) {
                continue;
            }
            region.byte_offset = length.offset;
            region.byte_size   = length.bytes;
            out->length_field  = out->header.size();
            length_made        = true;
        }
        if (region.byte_offset == checksum.header_skip) {
            out->first_covered = out->header.size();
            first_found        = true;
        }
        out->header.push_back(region);
    }
    if (absorbed != length.bytes || !first_found) {
        return false;
    }
    out->checksum = checksum;
    out->length   = length;
    out->smallest = static_cast<std::uint32_t>(smallest);
    out->largest  = static_cast<std::uint32_t>(largest);
    out->frames   = static_cast<std::uint32_t>(bytes.size());
    return true;
}

void add_kind_fields(Model* model, std::size_t type, const KindType& kind) {
    for (std::size_t i = 0; i < kind.header.size(); ++i) {
        const FieldRegion region = kind.header[i];
        FieldInfo         info   = info_of(region);
        std::string       name   = "field_" + number(region.byte_offset);
        if (i == kind.length_field) {
            info.kind          = FieldKind::Length;
            info.constant      = 0;
            info.byte_order    = kind.length.bytes == 1 ? ByteOrder::NotApplicable
                               : kind.length.big_endian ? ByteOrder::Big : ByteOrder::Little;
            info.evidence_bits = kind.length.evidence_bits;
            name               = "length";
        }
        model->add_field(type, name, info, "");
    }
    FieldInfo payload;
    payload.kind       = FieldKind::Payload;
    payload.size_kind  = SizeKind::FromField;
    payload.size_field = static_cast<std::uint32_t>(kind.length_field);
    const std::size_t payload_index = model->add_field(type, "payload", payload, "");

    FieldInfo checksum;
    checksum.kind          = FieldKind::Checksum;
    checksum.bit_size      = kind.checksum.width_bits;
    checksum.byte_order    = kind.checksum.byte_order;
    checksum.covers_first  = static_cast<std::uint32_t>(kind.first_covered);
    checksum.covers_last   = static_cast<std::uint32_t>(payload_index);
    checksum.evidence_bits = kind.checksum.evidence_bits;
    model->add_field(type, "checksum", checksum, checksum_name(kind.checksum));
}

std::string hex_byte(unsigned value) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       out      = "0x";
    out += digits[(value >> 4) & 15];
    out += digits[value & 15];
    return out;
}

std::string checksum_line(const ChecksumFinding& c) {
    if (c.found) {
        const std::string form =
            c.ascii_hex ? "written as two hexadecimal characters"
                        : number(c.width_bits) + " bits" +
                              (c.byte_order == ByteOrder::Big ? " big-endian"
                               : c.byte_order == ByteOrder::Little ? " little-endian" : "");
        return "checksum " + checksum_name(c) + ", " + form +
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
    return analyze_frames(capture, segment_frames(capture, options.segmentation), options);
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

    // The later stages read the frames as the bytes of the protocol: for flagged frames, without the flags
    // and with the stuffing undone, which is what a checksum is over and what the model describes.
    Capture      contents;
    Segmentation whole;
    if (info.segmentation.kind == FramingKind::Flagged) {
        contents = frame_contents(capture, segmentation);
        std::vector<FrameSpan> spans;
        for (std::size_t i = 0; i < contents.event_count(); ++i) {
            FrameSpan span;
            span.first_event = i;
            span.event_count = 1;
            spans.push_back(span);
        }
        whole = Segmentation(info.segmentation, spans);
    }
    const bool           stripped = info.segmentation.kind == FramingKind::Flagged;
    const Capture&       read     = stripped ? contents : capture;
    const Segmentation&  frames   = stripped ? whole : segmentation;

    // Kinds of message that come in several sizes are one type each, when a checksum explains all of
    // their frames; the sizes that are then taken are not types of their own.
    const MessageKinds         kinds = find_message_kinds(read, frames, options.fields.min_frames);
    std::vector<KindType>      built;
    std::map<std::uint64_t, bool> taken;                 // sizes that are in a kind of several
    for (std::size_t k = 0; k < kinds.kinds.size(); ++k) {
        KindType kind;
        if (build_kind(read, frames, kinds, k, options.fields, &kind)) {
            built.push_back(kind);
            for (std::size_t s = 0; s < kinds.kinds[k].sizes.size(); ++s) {
                taken[kinds.kinds[k].sizes[s]] = true;
            }
        }
    }

    std::map<std::uint64_t, std::uint64_t> by_size;      // frame size -> how many frames
    for (std::size_t i = 0; i < frames.frame_count(); ++i) {
        ++by_size[frame_size(read, frames.frame(i))];
    }
    // Each type is (frames, smallest size, index in `built` or -1 for a size of its own).
    std::vector<std::pair<std::pair<std::uint64_t, std::uint64_t>, std::int64_t> > types;
    for (std::map<std::uint64_t, std::uint64_t>::const_iterator it = by_size.begin();
         it != by_size.end(); ++it) {
        if (taken.count(it->first) == 0 && it->second >= options.fields.min_frames && it->first > 0 &&
            it->first <= std::numeric_limits<std::uint32_t>::max()) {
            types.push_back(std::make_pair(std::make_pair(it->second, it->first), std::int64_t(-1)));
        }
    }
    for (std::size_t b = 0; b < built.size(); ++b) {
        types.push_back(std::make_pair(std::make_pair(std::uint64_t(built[b].frames),
                                                      std::uint64_t(built[b].smallest)),
                                       static_cast<std::int64_t>(b)));
    }
    std::sort(types.begin(), types.end(), more_frequent_type);
    std::uint64_t typed_frames = 0;
    for (std::size_t t = 0; t < types.size(); ++t) {
        typed_frames += types[t].first.first;
    }
    info.ignored_frames = frames.frame_count() - typed_frames;

    // What cut the frames is known when it was the flags or the gaps. A gap is
    // never 0 (the segmentation takes the shortest long one), so idle_gap_ns says
    // it was the gaps, also for a segmentation that has no kind.
    Model model;
    FramingInfo framing;
    if (info.segmentation.kind == FramingKind::Flagged) {
        framing.kind      = FramingKind::Flagged;
        framing.delimiter = info.segmentation.delimiter;
        if (info.segmentation.escaped) {
            framing.escaped        = true;
            framing.escape         = info.segmentation.escape;
            framing.delimiter_code = info.segmentation.delimiter_code;
            framing.escape_code    = info.segmentation.escape_code;
        }
    } else if (info.segmentation.kind == FramingKind::Terminated) {
        framing.kind      = FramingKind::Terminated;
        framing.delimiter = info.segmentation.delimiter;
    } else if (info.segmentation.kind == FramingKind::Contiguous) {
        framing.kind = FramingKind::Contiguous;
    } else if (info.segmentation.idle_gap_ns != 0) {
        framing.kind        = FramingKind::IdleGap;
        framing.idle_gap_ns = info.segmentation.idle_gap_ns;
    }
    model.set_framing(framing);

    std::vector<MessageTypeReport> reports;
    for (std::size_t t = 0; t < types.size(); ++t) {
        if (types[t].second >= 0) {
            const KindType& kind = built[static_cast<std::size_t>(types[t].second)];
            MessageTypeReport report;
            report.frame_bytes         = kind.smallest;
            report.largest_frame_bytes = kind.largest;
            report.frames              = kind.frames;
            report.checksum            = kind.checksum;
            add_kind_fields(&model, model.add_message_type("type" + number(t)), kind);
            reports.push_back(report);
            continue;
        }
        const std::uint32_t size = static_cast<std::uint32_t>(types[t].first.second);

        MessageTypeReport report;
        report.frame_bytes         = size;
        report.largest_frame_bytes = size;
        report.frames              = static_cast<std::uint32_t>(types[t].first.first);
        report.checksum            = find_checksum(read, frames, size);

        const FieldMap layout = discover_fields(read, frames, report.checksum, size, options.fields);
        const FieldMap typed  = type_fields(layout, read, frames);

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
        out += "framing    none found: the gaps between events do not split into short and long ones, "
               "no byte bounds the frames as a flag, none starts them and says how long they are, and it is not text in lines\n";
        return out + describe_model(analysis.model());
    }
    if (seg.kind == FramingKind::Contiguous) {
        out += "framing    sync byte " + hex_byte(seg.sync) + ", ";
        if (seg.length_bytes == 0) {
            out += "frames of " + number(seg.frame_size) + " bytes";
        } else {
            out += "frame size = the ";
            out += seg.length_bytes == 1 ? "1-byte" : seg.length_big_endian ? "big-endian 2-byte" : "little-endian 2-byte";
            out += " length at offset " + number(seg.length_offset);
            out += seg.length_adjust >= 0 ? " plus " + number(static_cast<std::uint64_t>(seg.length_adjust))
                                          : " minus " + number(static_cast<std::uint64_t>(-static_cast<std::int64_t>(seg.length_adjust)));
        }
        out += " (" + number(seg.breaks) + (seg.breaks == 1 ? " break" : " breaks") + " in the chain)\n";
    } else if (seg.kind == FramingKind::Terminated) {
        out += "framing    lines: each frame ends with the byte " + hex_byte(seg.delimiter) + " (" + number(seg.flags) +
               " of them in the capture)\n";
    } else if (seg.kind == FramingKind::Flagged) {
        out += "framing    flags: the byte " + hex_byte(seg.delimiter) + " bounds each frame (" + number(seg.flags) +
               " of them in the capture)";
        if (seg.escaped) {
            out += ", stuffed: " + hex_byte(seg.delimiter) + " as " + hex_byte(seg.escape) + " " + hex_byte(seg.delimiter_code) +
                   " and " + hex_byte(seg.escape) + " as " + hex_byte(seg.escape) + " " + hex_byte(seg.escape_code);
        }
        out += "\n";
    } else if (seg.idle_gap_ns == 0) {
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
        out += "type" + number(t) + "      " + number(r.frame_bytes);
        if (r.largest_frame_bytes > r.frame_bytes) {
            out += " to " + number(r.largest_frame_bytes);
        }
        out += " bytes, " + number(r.frames) + " frames; " + checksum_line(r.checksum) + "\n";
    }
    return out + describe_model(analysis.model());
}

} // namespace bw
