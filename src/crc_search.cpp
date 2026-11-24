// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/crc_search.h"

#include <map>
#include <set>
#include <utility>

namespace bw {
namespace {

// Below this, a single match is as likely to be coincidence as fact. See the
// header for where the number comes from.
const u32 kConfidentEvidenceBits = 32;

// The bits a hidden byte is worth to a search that may choose it: the value it was free to take.
const u64 kHiddenByteBits = 8;

// A CRC whose polynomial is a multiple of a narrower one's, with neither init nor final xor, leaves the
// narrower one's CRC in its own bytes: over the frame less its last byte, CRC-16/LJ1200 (0x6F63) is explained
// by CRC-8/GSM-A (0x1D) as well, and CRC-64/ECMA-182 by CRC-16/UMTS. The narrower CRC says nothing the
// wider does not, so it is not another answer: one whose field is inside the field of another, and which
// starts covering at the same place, is a part of it.
bool is_part_of(const Candidate& part, const Candidate& whole) {
    const Layout& p = part.layout;
    const Layout& w = whole.layout;
    // The hidden byte, if there is one, is in both or it is not the same finding.
    if (part.seeded != whole.seeded || (part.seeded && part.seed != whole.seed)) {
        return false;
    }
    return p.header_skip == w.header_skip && p.width < w.width &&
           p.trailer_skip >= w.trailer_skip &&
           p.trailer_skip + p.field_bytes() <= w.trailer_skip + w.field_bytes();
}

// Is `later` the same checksum as `earlier`, only starting to cover after bytes that are zero in every frame?
bool is_shifted(const Candidate& later, const Candidate& earlier, const std::vector<Frame>& frames) {
    const Layout& l = later.layout;
    const Layout& e = earlier.layout;
    return later.spec == earlier.spec && later.seeded == earlier.seeded && (!later.seeded || later.seed == earlier.seed) &&
           l.width == e.width && l.big_endian == e.big_endian && l.trailer_skip == e.trailer_skip &&
           e.header_skip < l.header_skip && zero_bytes(frames, e.header_skip, l.header_skip);
}

} // namespace

bool zero_bytes(const std::vector<Frame>& frames, std::size_t from, std::size_t to) {
    for (std::size_t i = 0; i < frames.size(); ++i) {
        for (std::size_t k = from; k < to; ++k) {
            if (k >= frames[i].bytes.size() || frames[i].bytes[k] != 0) {
                return false;
            }
        }
    }
    return true;
}

std::size_t distinct_covered(const std::vector<Frame>& frames, std::size_t first, std::size_t after) {
    std::set<std::vector<u8> > seen;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const std::vector<u8>& b = frames[i].bytes;
        if (first + after <= b.size()) {
            seen.insert(std::vector<u8>(b.begin() + static_cast<std::ptrdiff_t>(first),
                                        b.end() - static_cast<std::ptrdiff_t>(after)));
        }
    }
    return seen.size();
}

bool Layout::fits(std::size_t frame_len) const {
    // Byte-aligned widths only; see the header for why a 15-bit field cannot
    // be read by this code even though the CRC itself is fine with it.
    if (width == 0 || width % 8u != 0) {
        return false;
    }
    // The covered range must be non-empty: a CRC over zero bytes is the same
    // constant for every frame, which matches trivially and means nothing.
    const std::size_t overhead = header_skip + trailer_skip + field_bytes();
    return frame_len > overhead;
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

std::vector<u8> hidden_bytes(const std::vector<Frame>& frames, const Layout& layout,
                             const CrcSpec& spec) {
    std::vector<u8> fitting;
    if (frames.empty() || spec.width != layout.width) {
        return fitting;
    }
    for (std::size_t f = 0; f < frames.size(); ++f) {
        const std::size_t len = frames[f].bytes.size();
        if (!layout.fits(len)) {
            return std::vector<u8>();
        }
    }

    // For the first frame, every byte; for the others, only those left. The covered bytes are fed
    // once for each frame, and the one more byte is all that is done for each value.
    for (int value = 0; value < 256; ++value) {
        fitting.push_back(static_cast<u8>(value));
    }
    for (std::size_t f = 0; f < frames.size() && !fitting.empty(); ++f) {
        const Frame&      frame = frames[f];
        const std::size_t begin = layout.covered_begin();
        const std::size_t end   = layout.covered_end(frame.bytes.size());
        const u64         state = crc_feed(spec, crc_begin(spec), frame.bytes.data() + begin, end - begin);
        const u64         field = extract_checksum(frame, layout);

        std::vector<u8> left;
        for (std::size_t i = 0; i < fitting.size(); ++i) {
            if (crc_end(spec, crc_feed(spec, state, &fitting[i], 1)) == field) {
                left.push_back(fitting[i]);
            }
        }
        fitting = left;
    }
    return fitting;
}

u32 candidate_evidence(const Candidate& candidate, std::size_t distinct_frames) {
    const u64 bits = static_cast<u64>(distinct_frames) * candidate.layout.width;
    const u64 free = candidate.seeded ? kHiddenByteBits : 0;
    return static_cast<u32>(bits > free ? bits - free : 0);
}

bool SearchReport::confident() const {
    return unique() && evidence_bits >= kConfidentEvidenceBits;
}

SearchReport search(const std::vector<Frame>& frames,
                    const SearchOptions& options) {
    SearchReport report;
    std::map<std::pair<std::size_t, std::size_t>, std::size_t> covered;      // distinct things covered, by place
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
        // Collapsing them must not land on an option the caller switched
        // off, though: asking for little-endian only and getting no search
        // at all would be a silent no-answer.
        const bool single_byte  = (spec.width <= 8u);
        const int  endian_count = single_byte ? 1 : 2;

        for (int e = 0; e < endian_count; ++e) {
            const bool enabled = single_byte ? (endians[0] || endians[1])
                                             : endians[e];
            if (!enabled) {
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
                    if (options.min_evidence_bits != 0) {
                        const std::pair<std::size_t, std::size_t> key(header, trailer + layout.field_bytes());
                        std::map<std::pair<std::size_t, std::size_t>, std::size_t>::iterator hit = covered.find(key);
                        if (hit == covered.end()) {
                            hit = covered.insert(std::make_pair(key, distinct_covered(frames, key.first, key.second))).first;
                        }
                        Candidate worth;
                        worth.layout = layout;
                        worth.seeded = options.hidden_byte;
                        if (candidate_evidence(worth, hit->second) < options.min_evidence_bits) {
                            continue;
                        }
                    }
                    ++report.layouts_tried;

                    // The CRC as it is, and then with a hidden byte, if asked for.
                    std::vector<Candidate> matches;
                    Candidate              found;
                    found.spec   = &spec;
                    found.layout = layout;
                    if (verify(frames, layout, spec)) {
                        matches.push_back(found);
                    }
                    if (options.hidden_byte) {
                        const std::vector<u8> seeds = hidden_bytes(frames, layout, spec);
                        for (std::size_t k = 0; k < seeds.size(); ++k) {
                            found.seeded = true;
                            found.seed   = seeds[k];
                            matches.push_back(found);
                        }
                    }
                    for (std::size_t k = 0; k < matches.size(); ++k) {
                        // The same checksum as one already found, starting later over bytes that are always zero:
                        // not another answer, and not one more to keep. (The header is the innermost loop, so
                        // the one that starts earlier has been found first.)
                        bool shifted = false;
                        for (std::size_t j = 0; j < report.candidates.size() && !shifted; ++j) {
                            shifted = is_shifted(matches[k], report.candidates[j], frames);
                        }
                        if (shifted) {
                            continue;
                        }
                        if (report.candidates.size() < options.max_candidates) {
                            report.candidates.push_back(matches[k]);
                        } else {
                            report.truncated = true;
                        }
                    }
                }
            }
        }
    }

    std::vector<Candidate> whole;
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        bool part = false;
        for (std::size_t j = 0; j < report.candidates.size() && !part; ++j) {
            part = is_part_of(report.candidates[i], report.candidates[j]);
        }
        if (!part) {
            whole.push_back(report.candidates[i]);
        }
    }
    report.candidates = whole;

    // Evidence is measured against the weakest claim among the candidates
    // (the narrowest checksum, or one with a byte it was free to choose), and
    // counts DISTINCT frames.
    //
    // Identical frames are one observation repeated, not several. A capture
    // of a device sending the same heartbeat forty times carries exactly as
    // much evidence as one heartbeat, and counting it forty times would
    // manufacture confidence out of nothing. Captures like that are the
    // normal case on a quiet bus, not an edge case.
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        const u32 bits = candidate_evidence(report.candidates[i], report.distinct_frames);
        report.evidence_bits = (i == 0 || bits < report.evidence_bits) ? bits : report.evidence_bits;
    }
    return report;
}

} // namespace bw
