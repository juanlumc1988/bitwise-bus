// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/checksum.h"

#include <algorithm>
#include <limits>
#include <stdexcept>

#include "bw/catalog.h"
#include "bw/crc_search.h"
#include "bw/messages.h"
#include "bw/sums.h"

namespace bw {

namespace {

std::uint32_t saturate(std::uint64_t value) {
    const std::uint64_t max = std::numeric_limits<std::uint32_t>::max();
    return static_cast<std::uint32_t>(value > max ? max : value);
}

// As in the CRC search (bw/crc_search.cpp): below this, a single match is as likely to be chance as fact.
const std::uint32_t kConfidentEvidenceBits = 32;

// A hidden byte is looked for in at least this many different frames. With one, every checksum of a byte
// has some value of it that explains the frame, and with two a few by chance: the search would answer
// with candidates for bytes that are not a checksum at all.
const std::size_t kMinFramesForHiddenByte = 3;

// Where a sum sits in a frame and how it is written.
struct SumLayout {
    std::size_t header_skip  = 0;
    std::size_t trailer_skip = 0;
    std::size_t gap          = 0;      // bytes between what it covers and it (the star of NMEA)
    bool        hex          = false;  // two characters, hexadecimal, the high digit first
    bool        big_endian   = true;   // of the bytes of a number that is not text

    std::size_t field_bytes(const SumSpec& spec) const { return hex ? 2u : spec.width / 8u; }
};

struct SumHit {
    const SumSpec* spec = nullptr;
    SumLayout      layout;
};

int hex_digit(std::uint8_t c) {
    if (c >= '0' && c <= '9') {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    }
    return -1;
}

// Does the sum, at this place and written this way, explain every frame?
bool verify_sum(const std::vector<Frame>& frames, const SumSpec& spec, const SumLayout& layout) {
    const std::size_t field    = layout.field_bytes(spec);
    const std::size_t overhead = layout.header_skip + layout.trailer_skip + layout.gap + field;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const std::vector<std::uint8_t>& bytes = frames[i].bytes;
        if (bytes.size() <= overhead) {
            return false;                  // nothing is covered, and a sum of nothing is a constant
        }
        const std::size_t at  = bytes.size() - layout.trailer_skip - field;
        const std::size_t end = at - layout.gap;

        std::uint64_t written = 0;
        if (layout.hex) {
            const int high = hex_digit(bytes[at]);
            const int low  = hex_digit(bytes[at + 1]);
            if (high < 0 || low < 0) {
                return false;
            }
            written = static_cast<std::uint64_t>(high * 16 + low);
        } else if (layout.big_endian) {
            for (std::size_t k = 0; k < field; ++k) {
                written = (written << 8) | bytes[at + k];
            }
        } else {
            for (std::size_t k = field; k > 0; --k) {
                written = (written << 8) | bytes[at + k - 1];
            }
        }
        if (sum_compute(spec, bytes.data() + layout.header_skip, end - layout.header_skip) != written) {
            return false;
        }
    }
    return true;
}

// The ways a sum can be written: as bytes (a single one has no order; two have both, as with the CRCs)
// or, for one of 8 bits, as text with or without a byte between it and what it covers.
std::vector<SumLayout> forms_of(const SumSpec& spec) {
    std::vector<SumLayout> forms;
    SumLayout form;
    forms.push_back(form);
    if (spec.width > 8) {
        form.big_endian = false;
        forms.push_back(form);
    } else {
        form.hex = true;
        for (form.gap = 0; form.gap <= 1; ++form.gap) {
            forms.push_back(form);
        }
    }
    return forms;
}

// Is `part` a piece of `whole`? A sum written as a byte inside the field of a wider one, over bytes that
// start at the same place, is that one seen through a narrower window: Fletcher's first sum is the plain
// sum of the bytes, so wherever it explains a frame in two bytes it also explains it in one. That is one
// finding, not two, and the wider is the one that says what the frame holds. (The same rule is applied to
// the CRCs, in bw/crc_search.cpp.) A text one has no part: its characters are not the sum's bytes.
bool is_part_of(const SumHit& part, const SumHit& whole) {
    const SumLayout& p = part.layout;
    const SumLayout& w = whole.layout;
    if (p.hex || w.hex || p.header_skip != w.header_skip) {
        return false;
    }
    const std::size_t p_field = p.field_bytes(*part.spec);
    const std::size_t w_field = w.field_bytes(*whole.spec);
    return w_field > p_field && p.trailer_skip >= w.trailer_skip &&
           p.trailer_skip + p_field <= w.trailer_skip + w_field;
}

// Every sum, in every form, at every place the CRCs are looked for.
// `room` is how many it may keep: the CRCs and the sums share the candidates the options allow.
std::vector<SumHit> search_sums(const std::vector<Frame>& frames, const SearchOptions& options,
                                std::size_t room, bool* truncated) {
    std::vector<SumHit> hits;
    for (std::size_t s = 0; s < sum_count(); ++s) {
        const SumSpec&               spec  = sums()[s];
        const std::vector<SumLayout> forms = forms_of(spec);
        for (std::size_t f = 0; f < forms.size(); ++f) {
            for (std::size_t trailer = 0; trailer <= options.max_trailer_skip; ++trailer) {
                for (std::size_t header = 0; header <= options.max_header_skip; ++header) {
                    SumHit hit;
                    hit.spec                = &spec;
                    hit.layout              = forms[f];
                    hit.layout.trailer_skip = trailer;
                    hit.layout.header_skip  = header;
                    if (!verify_sum(frames, spec, hit.layout)) {
                        continue;
                    }
                    if (hits.size() < room) {
                        hits.push_back(hit);
                    } else {
                        *truncated = true;
                    }
                }
            }
        }
    }

    // What is left is what explains something that no other explanation holds.
    std::vector<SumHit> kept;
    for (std::size_t i = 0; i < hits.size(); ++i) {
        bool part = false;
        for (std::size_t j = 0; j < hits.size() && !part; ++j) {
            part = is_part_of(hits[i], hits[j]);
        }
        if (!part) {
            kept.push_back(hits[i]);
        }
    }
    return kept;
}

} // namespace

ChecksumFinding find_checksum(const Capture& capture, const Segmentation& segmentation,
                              std::uint32_t size_bytes) {
    std::vector<std::vector<std::uint8_t> > bytes;
    const std::vector<FrameSpan> spans = frames_of_size(capture, segmentation, size_bytes);
    for (std::size_t i = 0; i < spans.size(); ++i) {
        bytes.push_back(frame_bytes(capture, spans[i]));
    }
    return find_checksum_of_frames(bytes);
}

ChecksumFinding find_checksum_of_frames(const std::vector<std::vector<std::uint8_t> >& given) {
    std::vector<Frame> frames;
    for (std::size_t i = 0; i < given.size(); ++i) {
        Frame frame;
        frame.bytes = given[i];
        frames.push_back(frame);
    }

    ChecksumFinding finding;
    finding.frames = saturate(frames.size());
    if (frames.empty()) {
        return finding;
    }

    SearchOptions options;
    SearchReport  report = search(frames, options);
    // The CRCs and the sums share the candidates the options allow.
    bool                sums_truncated = false;
    const std::size_t   room = options.max_candidates - report.candidates.size();
    std::vector<SumHit> hits = search_sums(frames, options, room, &sums_truncated);

    // Only if nothing explains the frames as they are: a hidden byte would explain too much.
    if (report.candidates.empty() && hits.empty() && !report.truncated && !sums_truncated &&
        report.distinct_frames >= kMinFramesForHiddenByte) {
        options.hidden_byte = true;
        report              = search(frames, options);
    }

    finding.distinct_frames = saturate(report.distinct_frames);
    finding.candidates      = saturate(report.candidates.size() + hits.size());
    finding.truncated       = report.truncated || sums_truncated;

    // As in the CRC search: what the weakest of the candidates is worth, once for each different frame.
    // A sum written as text holds 8 bits, the same as one written as a byte.
    std::vector<std::uint32_t> bits;
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        bits.push_back(candidate_evidence(report.candidates[i], report.distinct_frames));
    }
    for (std::size_t i = 0; i < hits.size(); ++i) {
        bits.push_back(saturate(static_cast<std::uint64_t>(report.distinct_frames) * hits[i].spec->width));
    }
    if (!bits.empty()) {
        finding.evidence_bits = *std::min_element(bits.begin(), bits.end());
    }

    if (finding.truncated || finding.candidates != 1 || finding.evidence_bits < kConfidentEvidenceBits) {
        return finding;
    }
    finding.found = true;
    if (!report.candidates.empty()) {
        const Candidate& only = report.candidates[0];
        finding.header_skip  = saturate(only.layout.header_skip);
        finding.trailer_skip = saturate(only.layout.trailer_skip);
        finding.width_bits   = only.layout.width;
        finding.byte_order   = only.layout.width <= 8 ? ByteOrder::NotApplicable
                             : only.layout.big_endian ? ByteOrder::Big : ByteOrder::Little;
        finding.seeded       = only.seeded;
        finding.seed         = only.seed;                  // 0 unless seeded
        finding.algorithm    = saturate(static_cast<std::uint64_t>(only.spec - catalog()));
    } else {
        const SumHit& only = hits[0];
        finding.header_skip  = saturate(only.layout.header_skip);
        finding.trailer_skip = saturate(only.layout.trailer_skip);
        finding.gap_bytes    = saturate(only.layout.gap);
        finding.ascii_hex    = only.layout.hex;
        finding.width_bits   = only.layout.hex ? 16u : only.spec->width;
        finding.byte_order   = only.layout.hex ? ByteOrder::Big
                             : only.spec->width <= 8 ? ByteOrder::NotApplicable
                             : only.layout.big_endian ? ByteOrder::Big : ByteOrder::Little;
        finding.algorithm    = saturate(catalog_size() + static_cast<std::uint64_t>(only.spec - sums()));
    }
    return finding;
}

std::string checksum_algorithm_name(std::uint32_t index) {
    if (index < catalog_size()) {
        return catalog()[index].name;
    }
    if (index - catalog_size() < sum_count()) {
        return sums()[index - catalog_size()].name;
    }
    throw std::out_of_range("checksum algorithm index out of range");
}

} // namespace bw
