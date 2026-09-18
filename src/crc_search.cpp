// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/crc_search.h"

#include <set>

namespace bw {
namespace {

// Below this, a single match is as likely to be coincidence as fact. See the
// header for where the number comes from.
const u32 kConfidentEvidenceBits = 32;

} // namespace

bool Layout::fits(std::size_t frame_len) const {
    // The covered range must be non-empty: a CRC over zero bytes is the same
    // constant for every frame, which matches trivially and means nothing.
    const std::size_t overhead = header_skip + trailer_skip + field_bytes();
    return field_bytes() > 0 && frame_len > overhead;
}

std::size_t Layout::checksum_offset(std::size_t frame_len) const {
    return frame_len - trailer_skip - field_bytes();
}

std::size_t Layout::covered_end(std::size_t frame_len) const {
    return checksum_offset(frame_len);
}

u64 extract_checksum(const Frame& frame, const Layout& layout) {
    const std::size_t len = frame.bytes.size();
    if (!layout.fits(len)) {
        return 0;
    }

    const std::size_t at = layout.checksum_offset(len);
    const std::size_t n  = layout.field_bytes();

    u64 value = 0;
    if (layout.big_endian) {
        for (std::size_t i = 0; i < n; ++i) {
            value = (value << 8) | frame.bytes[at + i];
        }
    } else {
        for (std::size_t i = n; i > 0; --i) {
            value = (value << 8) | frame.bytes[at + i - 1];
        }
    }
    return value;
}

bool verify(const std::vector<Frame>& frames, const Layout& layout,
            const CrcSpec& spec) {
    if (frames.empty() || spec.width != layout.width) {
        return false;
    }

    for (std::size_t i = 0; i < frames.size(); ++i) {
        const Frame&      frame = frames[i];
        const std::size_t len   = frame.bytes.size();
        if (!layout.fits(len)) {
            return false;
        }

        const std::size_t begin = layout.covered_begin();
        const std::size_t end   = layout.covered_end(len);
        if (begin >= end) {
            return false;
        }

        const u64 computed = crc_compute(spec, frame.bytes.data() + begin,
                                         end - begin);
        if (computed != extract_checksum(frame, layout)) {
            return false;
        }
    }
    return true;
}

bool SearchReport::confident() const {
    return unique() && evidence_bits >= kConfidentEvidenceBits;
}

SearchReport search(const std::vector<Frame>& frames,
                    const SearchOptions& options) {
    SearchReport report;
    report.frames = frames.size();
    if (frames.empty()) {
        return report;
    }

    std::set<std::vector<u8> > seen;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        seen.insert(frames[i].bytes);
    }
    report.distinct_frames = seen.size();

    std::size_t shortest = frames[0].bytes.size();
    for (std::size_t i = 1; i < frames.size(); ++i) {
        if (frames[i].bytes.size() < shortest) {
            shortest = frames[i].bytes.size();
        }
    }

    bool endians[2] = { options.try_big_endian, options.try_little_endian };

    for (std::size_t s = 0; s < catalog_size(); ++s) {
        const CrcSpec& spec = catalog()[s];

        // A checksum whose width is not a whole number of bytes cannot be
        // pulled out of a byte-aligned frame by this code. crc_compute
        // handles such widths -- CAN's 15-bit CRC among them -- but reading
        // the field needs bit-level framing, which a decoded capture has
        // usually already stripped. Left out rather than guessed at.
        if (spec.width % 8u != 0) {
            continue;
        }
        ++report.specs_tried;

        // A one-byte field has no byte order, so trying both would report
        // the same finding twice and make every 8-bit search look ambiguous.
        const int endian_count = (spec.width <= 8u) ? 1 : 2;

        for (int e = 0; e < endian_count; ++e) {
            if (!endians[e]) {
                continue;
            }
            for (std::size_t trailer = 0; trailer <= options.max_trailer_skip; ++trailer) {
                for (std::size_t header = 0; header <= options.max_header_skip; ++header) {
                    Layout layout;
                    layout.header_skip  = header;
                    layout.trailer_skip = trailer;
                    layout.width        = spec.width;
                    layout.big_endian   = (e == 0);

                    if (!layout.fits(shortest)) {
                        continue;
                    }
                    ++report.layouts_tried;

                    if (!verify(frames, layout, spec)) {
                        continue;
                    }
                    if (report.candidates.size() < options.max_candidates) {
                        Candidate found;
                        found.spec   = &spec;
                        found.layout = layout;
                        report.candidates.push_back(found);
                    }
                }
            }
        }
    }

    // Evidence is measured against the narrowest checksum that matched --
    // the weakest claim among the candidates -- and counts DISTINCT frames.
    //
    // Identical frames are one observation repeated, not several. A capture
    // of a device sending the same heartbeat forty times carries exactly as
    // much evidence as one heartbeat, and counting it forty times would
    // manufacture confidence out of nothing. Captures like that are the
    // normal case on a quiet bus, not an edge case.
    if (!report.candidates.empty()) {
        u8 narrowest = 64;
        for (std::size_t i = 0; i < report.candidates.size(); ++i) {
            if (report.candidates[i].layout.width < narrowest) {
                narrowest = report.candidates[i].layout.width;
            }
        }
        report.evidence_bits = static_cast<u32>(report.distinct_frames) * narrowest;
    }
    return report;
}

} // namespace bw
