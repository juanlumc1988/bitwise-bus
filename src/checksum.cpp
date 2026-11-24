// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/checksum.h"

#include <algorithm>
#include <limits>
#include <set>
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

// Does the sum, at this place and written this way, explain this frame?
bool explains_sum(const std::vector<std::uint8_t>& bytes, const SumSpec& spec, const SumLayout& layout) {
    const std::size_t field    = layout.field_bytes(spec);
    const std::size_t overhead = layout.header_skip + layout.trailer_skip + layout.gap + field;
    if (bytes.size() <= overhead) {
        return false;                      // nothing is covered, and a sum of nothing is a constant
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
    return sum_compute(spec, bytes.data() + layout.header_skip, end - layout.header_skip) == written;
}

// ...and every frame?
bool verify_sum(const std::vector<Frame>& frames, const SumSpec& spec, const SumLayout& layout) {
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (!explains_sum(frames[i].bytes, spec, layout)) {
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

// Is `later` the same sum as `earlier`, only starting to cover after bytes that are zero in every frame? A zero
// changes no sum, so the frames cannot say whether it is covered (the same rule as for the CRCs, bw/crc_search.h).
bool is_shifted(const SumHit& later, const SumHit& earlier, const std::vector<Frame>& frames) {
    const SumLayout& l = later.layout;
    const SumLayout& e = earlier.layout;
    return later.spec == earlier.spec && l.hex == e.hex && l.gap == e.gap && l.big_endian == e.big_endian &&
           l.trailer_skip == e.trailer_skip && e.header_skip < l.header_skip &&
           zero_bytes(frames, e.header_skip, l.header_skip);
}

// Does the CRC, at this place and with the hidden byte it was found with, explain this frame?
bool explains_crc(const Frame& frame, const Candidate& candidate) {
    const Layout&     layout = candidate.layout;
    const std::size_t length = frame.bytes.size();
    if (!layout.fits(length)) {
        return false;
    }
    const std::size_t begin = layout.covered_begin();
    u64               state = crc_feed(*candidate.spec, crc_begin(*candidate.spec), frame.bytes.data() + begin,
                                       layout.covered_end(length) - begin);
    if (candidate.seeded) {
        const u8 seed = candidate.seed;
        state         = crc_feed(*candidate.spec, state, &seed, 1);
    }
    return crc_end(*candidate.spec, state) == extract_checksum(frame, layout);
}

// The frames that a candidate explains.
std::vector<Frame> explained_by(const std::vector<Frame>& frames, const Candidate& candidate) {
    std::vector<Frame> out;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (explains_crc(frames[i], candidate)) {
            out.push_back(frames[i]);
        }
    }
    return out;
}

std::vector<Frame> explained_by(const std::vector<Frame>& frames, const SumHit& hit) {
    std::vector<Frame> out;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (explains_sum(frames[i].bytes, *hit.spec, hit.layout)) {
            out.push_back(frames[i]);
        }
    }
    return out;
}

// As in the CRC search: what each of the candidates is worth, once for each different thing it covers in the
// frames that it explains; those of the CRCs first and then those of the sums. A sum written as text holds 8
// bits, the same as one written as a byte.
std::vector<std::uint32_t> evidence_of(const std::vector<Frame>& frames, const SearchReport& report,
                                       const std::vector<SumHit>& hits) {
    std::vector<std::uint32_t> bits;
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        const Layout&            layout    = report.candidates[i].layout;
        const std::vector<Frame> explained = explained_by(frames, report.candidates[i]);
        bits.push_back(candidate_evidence(report.candidates[i],
                                          distinct_covered(explained, layout.header_skip,
                                                           layout.trailer_skip + layout.field_bytes())));
    }
    for (std::size_t i = 0; i < hits.size(); ++i) {
        const SumLayout&         layout    = hits[i].layout;
        const std::vector<Frame> explained = explained_by(frames, hits[i]);
        bits.push_back(saturate(static_cast<std::uint64_t>(
                                    distinct_covered(explained, layout.header_skip,
                                                     layout.trailer_skip + layout.field_bytes(*hits[i].spec) + layout.gap)) *
                                hits[i].spec->width));
    }
    return bits;
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
                    bool shifted = false;                  // the header is the innermost loop: the earlier one is in already
                    for (std::size_t j = 0; j < hits.size() && !shifted; ++j) {
                        shifted = is_shifted(hit, hits[j], frames);
                    }
                    if (shifted) {
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

// With this many different frames a tenth of them may be wrong and the rest still say what the checksum is.
const std::size_t kMinDistinctForTolerance = 12;
// The groups of different frames that are searched, and how many frames each has. Looking for a hidden byte costs
// two hundred times what looking for a CRC does, so there are fewer groups for it: with one frame in twenty wrong
// a group of eight is free of them two times in three, and one of two groups is, almost nine times in ten.
const std::size_t kGroupFrames       = 8;
const std::size_t kGroups            = 8;
const std::size_t kGroupsHiddenByte  = 2;

bool same_candidate(const Candidate& a, const Candidate& b) {
    return a.spec == b.spec && a.seeded == b.seeded && (!a.seeded || a.seed == b.seed) &&
           a.layout.header_skip == b.layout.header_skip && a.layout.trailer_skip == b.layout.trailer_skip &&
           a.layout.width == b.layout.width && a.layout.big_endian == b.layout.big_endian;
}

bool same_sum(const SumHit& a, const SumHit& b) {
    return a.spec == b.spec && a.layout.header_skip == b.layout.header_skip &&
           a.layout.trailer_skip == b.layout.trailer_skip && a.layout.gap == b.layout.gap &&
           a.layout.hex == b.layout.hex && a.layout.big_endian == b.layout.big_endian;
}

// The checksums that explain nine in ten of the frames or more. The search is not tried on all the frames, which
// a frame that arrived wrong would stop from explaining anything, but on groups of different frames, each of
// which may be free of the wrong ones; what a group finds is then tried on all the frames. Replaces `report` and
// `hits` with them, and says whether there were enough frames for it.
bool tolerant_search(const std::vector<Frame>& frames, const SearchOptions& options, SearchReport* report,
                     std::vector<SumHit>* hits) {
    std::vector<Frame> distinct;
    std::set<std::vector<std::uint8_t> > seen;
    for (std::size_t i = 0; i < frames.size(); ++i) {
        if (seen.insert(frames[i].bytes).second) {
            distinct.push_back(frames[i]);
        }
    }
    const std::size_t allowed = frames.size() / 10;
    if (distinct.size() < kMinDistinctForTolerance || allowed == 0) {
        return false;
    }

    std::vector<Candidate> found;
    std::vector<SumHit>    found_sums;
    const std::size_t      groups = options.hidden_byte ? kGroupsHiddenByte : kGroups;
    const std::size_t      stride = std::max<std::size_t>(1, (distinct.size() - kGroupFrames) / (groups - 1));
    std::size_t            last   = distinct.size();                // no group yet
    for (std::size_t g = 0; g < groups; ++g) {
        const std::size_t first = std::min(g * stride, distinct.size() - kGroupFrames);
        if (first == last) {
            break;                                                  // the groups have reached the end
        }
        last = first;
        const std::vector<Frame> group(distinct.begin() + static_cast<std::ptrdiff_t>(first),
                                       distinct.begin() + static_cast<std::ptrdiff_t>(first + kGroupFrames));
        const SearchReport       r = search(group, options);
        for (std::size_t i = 0; i < r.candidates.size(); ++i) {
            bool known = false;
            for (std::size_t j = 0; j < found.size() && !known; ++j) {
                known = same_candidate(r.candidates[i], found[j]);
            }
            if (!known && found.size() < options.max_candidates) {
                found.push_back(r.candidates[i]);
            }
        }
        bool                      truncated = false;           // of a group of eight: not asked about
        const std::vector<SumHit> sums      = search_sums(group, options, options.max_candidates, &truncated);
        for (std::size_t i = 0; i < sums.size(); ++i) {
            bool known = false;
            for (std::size_t j = 0; j < found_sums.size() && !known; ++j) {
                known = same_sum(sums[i], found_sums[j]);
            }
            if (!known && found_sums.size() < options.max_candidates) {
                found_sums.push_back(sums[i]);
            }
        }
    }

    SearchReport kept;
    kept.frames          = frames.size();
    kept.distinct_frames = distinct.size();
    for (std::size_t i = 0; i < found.size(); ++i) {
        if (explained_by(frames, found[i]).size() + allowed >= frames.size()) {
            kept.candidates.push_back(found[i]);
        }
    }
    std::vector<SumHit> kept_sums;
    for (std::size_t i = 0; i < found_sums.size(); ++i) {
        if (explained_by(frames, found_sums[i]).size() + allowed >= frames.size()) {
            kept_sums.push_back(found_sums[i]);
        }
    }
    *report = kept;
    *hits   = kept_sums;
    return true;
}

std::size_t count_strong(const std::vector<std::uint32_t>& bits) {
    std::size_t strong = 0;
    for (std::size_t i = 0; i < bits.size(); ++i) {
        strong += bits[i] >= kConfidentEvidenceBits ? 1 : 0;
    }
    return strong;
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
    std::vector<std::uint32_t> bits = evidence_of(frames, report, hits);

    // Only if nothing explains the frames as they are, with evidence of its own: a hidden byte would explain too
    // much, and what little a plain candidate has (what it covers hardly changes) does not stop it.
    if (count_strong(bits) == 0 && !report.truncated && !sums_truncated &&
        report.distinct_frames >= kMinFramesForHiddenByte) {
        options.hidden_byte = true;
        report              = search(frames, options);
        bits                = evidence_of(frames, report, hits);
        if (report.truncated) {
            // So many that could never be the answer explain the frames that the list is full, and what is not in it
            // cannot be told from nothing: look only where an answer could be.
            SearchOptions focused     = options;
            focused.min_evidence_bits = kConfidentEvidenceBits;
            report                    = search(frames, focused);
            bits                      = evidence_of(frames, report, hits);
        }
    }
    // Still nothing: perhaps some of the frames are wrong. The same, over groups of frames, and then all of them.
    if (count_strong(bits) == 0 && !report.truncated && !sums_truncated) {
        for (int hidden = 0; hidden < 2 && count_strong(bits) == 0; ++hidden) {
            options.hidden_byte       = hidden != 0;
            options.min_evidence_bits = kConfidentEvidenceBits;
            SearchReport        tolerant;
            std::vector<SumHit> tolerant_hits;
            if (!tolerant_search(frames, options, &tolerant, &tolerant_hits)) {
                break;
            }
            const std::vector<std::uint32_t> tolerant_bits = evidence_of(frames, tolerant, tolerant_hits);
            if (count_strong(tolerant_bits) != 0) {
                report = tolerant;
                hits   = tolerant_hits;
                bits   = tolerant_bits;
            }
        }
    }

    finding.distinct_frames = saturate(report.distinct_frames);
    finding.candidates      = saturate(report.candidates.size() + hits.size());
    finding.truncated       = report.truncated || sums_truncated;

    // One that has enough evidence by itself and no other that has is the answer: the rest explain what any
    // algorithm would, because what they cover hardly changes. Without it, the weakest says how sure to be.
    const std::size_t strong    = count_strong(bits);
    std::size_t       strong_at = 0;
    for (std::size_t i = 0; i < bits.size(); ++i) {
        if (bits[i] >= kConfidentEvidenceBits) {
            strong_at = i;
        }
    }
    if (!bits.empty()) {
        finding.evidence_bits = strong == 1 ? bits[strong_at] : *std::min_element(bits.begin(), bits.end());
    }

    if (finding.truncated || strong != 1) {
        return finding;
    }
    finding.found = true;
    finding.unexplained_frames = saturate(frames.size() - (strong_at < report.candidates.size()
                                              ? explained_by(frames, report.candidates[strong_at]).size()
                                              : explained_by(frames, hits[strong_at - report.candidates.size()]).size()));
    if (strong_at < report.candidates.size()) {
        const Candidate& only = report.candidates[strong_at];
        finding.header_skip  = saturate(only.layout.header_skip);
        finding.trailer_skip = saturate(only.layout.trailer_skip);
        finding.width_bits   = only.layout.width;
        finding.byte_order   = only.layout.width <= 8 ? ByteOrder::NotApplicable
                             : only.layout.big_endian ? ByteOrder::Big : ByteOrder::Little;
        finding.seeded       = only.seeded;
        finding.seed         = only.seed;                  // 0 unless seeded
        finding.algorithm    = saturate(static_cast<std::uint64_t>(only.spec - catalog()));
    } else {
        const SumHit& only = hits[strong_at - report.candidates.size()];
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
