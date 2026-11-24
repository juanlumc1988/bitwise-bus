// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Lines of text made up from a seed (generate_synthetic_text): that each line is what its model says, written
// again here, that the protocols are of all sorts, and what the pipeline finds in them, with the line as it is and with
// noise: the kinds of sentence, their fields (as many as the truth's) and the checksum.

#include "doctest.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <set>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/evaluate.h"
#include "bw/segmentation.h"
#include "bw/synthetic.h"

using bw::Dataset;
using bw::FieldKind;
using bw::SizeKind;

namespace {

typedef std::vector<std::uint8_t> Bytes;

Dataset text_of(std::uint64_t seed, std::uint32_t frames = 100, std::uint32_t jitter = 0) {
    bw::SyntheticOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_synthetic_text(o);
}

Bytes line_of(const Dataset& d, std::size_t index) {
    return bw::frame_bytes(d.capture(), d.frame(index));
}

std::string hex2(unsigned value) {
    const char digits[] = "0123456789ABCDEF";
    std::string out;
    out += digits[(value >> 4) & 15];
    out += digits[value & 15];
    return out;
}

// Does the line have the fields of its type, one after the other, to the last byte? Constants are what they say, text goes
// up to its delimiter (the first one), and the checksum is the exclusive or of the bytes from where its first field starts
// to where its last ends less the byte that ends it, as two characters.
bool is_line_of(const bw::Model& m, std::uint32_t type, const Bytes& line) {
    std::vector<std::size_t> from, to;
    std::size_t              at = 0;
    for (std::size_t f = 0; f < m.field_count(type); ++f) {
        const bw::FieldInfo info = m.field(type, f);
        from.push_back(at);
        if (info.kind == FieldKind::Constant) {
            const std::size_t bytes = info.bit_size / 8;
            if (at + bytes > line.size()) {
                return false;
            }
            for (std::size_t i = 0; i < bytes; ++i) {
                if (line[at + i] != ((info.constant >> (8 * (bytes - 1 - i))) & 0xFF)) {
                    return false;
                }
            }
            at += bytes;
        } else if (info.kind == FieldKind::Text && info.size_kind == SizeKind::Delimited) {
            while (at < line.size() && line[at] != info.delimiter) {
                ++at;
            }
            if (at == line.size()) {
                return false;
            }
            ++at;
        } else if (info.kind == FieldKind::Checksum && info.ascii_hex && info.bit_size == 16) {
            if (at + 2 > line.size() || f == 0 || info.covers_last >= f || info.covers_first > info.covers_last) {
                return false;
            }
            unsigned x = 0;
            for (std::size_t i = from[info.covers_first]; i + 1 < to[info.covers_last]; ++i) {
                x ^= line[i];
            }
            const std::string want = hex2(x);
            if (line[at] != static_cast<std::uint8_t>(want[0]) || line[at + 1] != static_cast<std::uint8_t>(want[1])) {
                return false;
            }
            at += 2;
        } else {
            return false;
        }
        to.push_back(at);
    }
    return at == line.size();
}

} // namespace

TEST_CASE("synthetic text: the same seed is the same protocol and the same capture, and others are not") {
    CHECK(text_of(7, 50, 300).capture().equals(text_of(7, 50, 300).capture()));
    CHECK(bw::describe_model(text_of(7).model()) == bw::describe_model(text_of(7, 10).model()));
    std::set<std::string> models;
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        models.insert(bw::describe_model(text_of(seed).model()));
    }
    CHECK(models.size() == 20);
    CHECK_FALSE(text_of(7).capture().equals(text_of(8).capture()));
    // It is not the binary protocol of the same seed.
    bw::SyntheticOptions o;
    o.seed = 7;
    CHECK_FALSE(bw::generate_synthetic(o).capture().equals(text_of(7, 200).capture()));
}

TEST_CASE("synthetic text: options out of range are refused, and no frames is an empty capture") {
    bw::SyntheticOptions o;
    o.frames = 100001;
    CHECK_THROWS_AS(bw::generate_synthetic_text(o), std::invalid_argument);
    o.frames          = 10;
    o.jitter_permille = 501;
    CHECK_THROWS_AS(bw::generate_synthetic_text(o), std::invalid_argument);
    CHECK_NOTHROW(text_of(1, 100000));
    const Dataset none = text_of(1, 0);
    CHECK(none.frame_count() == 0);
    CHECK(none.capture().event_count() == 0);
    CHECK(none.model().message_type_count() >= 1);
}

TEST_CASE("synthetic text: every line of every protocol is what its model says, checksum included") {
    std::uint64_t checks = 0, lines = 0;
    for (std::uint64_t seed = 1; seed <= 300; ++seed) {
        const Dataset d = text_of(seed, 60, seed % 2 ? 0 : 300);
        CAPTURE(seed);
        REQUIRE(d.frame_count() == 60);
        CHECK(d.model().framing().kind == bw::FramingKind::Terminated);
        CHECK(d.model().framing().delimiter == 0x0A);
        for (std::size_t i = 0; i < d.frame_count(); ++i) {
            const Bytes line = line_of(d, i);
            ++lines;
            if (!is_line_of(d.model(), d.frame_message_type(i), line)) {
                CAPTURE(i);
                FAIL_CHECK("a line is not what its model says");
                break;
            }
            ++checks;
            CHECK(line.back() == 0x0A);
        }
    }
    CHECK(checks == lines);
}

TEST_CASE("synthetic text: the protocols are of all sorts") {
    std::set<char>        separators;
    std::set<bool>        starts;
    std::set<std::size_t> kinds, words;
    std::set<std::string> endings;
    bool                  same = false, varying = false;
    for (std::uint64_t seed = 1; seed <= 200; ++seed) {
        const bw::Model m = text_of(seed).model();
        kinds.insert(m.message_type_count());
        for (std::size_t t = 0; t < m.message_type_count(); ++t) {
            const bool start = m.field_name(t, 0) == "start";
            starts.insert(start);
            // The address ends with the separator.
            separators.insert(static_cast<char>(m.field(t, start ? 1 : 0).constant & 0xFF));
            std::size_t n     = 0;
            bool        check = false;
            for (std::size_t f = 0; f < m.field_count(t); ++f) {
                const bw::FieldInfo info = m.field(t, f);
                if (m.field_name(t, f).compare(0, 6, "field_") == 0) {
                    ++n;
                    same    = same || info.kind == FieldKind::Constant;
                    varying = varying || info.kind == FieldKind::Text;
                }
                check = check || info.kind == FieldKind::Checksum;
            }
            words.insert(n);
            const std::size_t last = m.field_count(t) - 1;
            const bool        end  = m.field_name(t, last) == "end";
            endings.insert(std::string(check ? "check " : "none ") +
                           (check ? (m.field(t, last).constant == 0x0D0A ? "crlf" : "lf") : (end ? "crlf" : "lf")));
        }
    }
    CHECK(separators == std::set<char>({ ',', ';', '|', ' ' }));
    CHECK(starts == std::set<bool>({ false, true }));
    CHECK(kinds == std::set<std::size_t>({ 1, 2, 3 }));
    CHECK(*words.begin() == 2);
    CHECK(*words.rbegin() == 7);
    CHECK(endings == std::set<std::string>({ "check crlf", "check lf", "none crlf", "none lf" }));
    CHECK(same);
    CHECK(varying);
}

TEST_CASE("synthetic text: a separator and a letter that takes two values are not a sync byte and a length") {
    // Seed 8 has one kind of sentence of 18 bytes, a field of the letters D and T and a pause after one in three. The
    // separator after the address and the letter read as a sync byte and a length, a chain of 67 frames that has two breaks:
    // lines are text, and what a chain with a break says does not cut them.
    const Dataset d = text_of(8, 200, 300);
    const bw::Segmentation sync = bw::segment_by_sync(d.capture(), bw::SegmentationOptions());
    REQUIRE(sync.info().found);
    CHECK(sync.info().breaks > 0);
    const bw::Segmentation chosen = bw::segment_frames(d.capture(), bw::SegmentationOptions());
    CHECK(chosen.info().kind == bw::FramingKind::Terminated);
    const bw::SegmentationScore score = bw::score_segmentation(d.frames(), chosen.frames());
    CHECK(score.exact_frames == 200);
    CHECK(score.found_frames == 200);
}

// ---- The pipeline, over many protocols of text -----------------------------------------------------------------------

namespace {

struct Counts {
    std::uint64_t protocols     = 0;
    std::uint64_t truth_frames  = 0;
    std::uint64_t exact_frames  = 0;
    std::uint64_t truth_types   = 0;     // of at least 12 lines
    std::uint64_t paired        = 0;     // ...found, by how its lines start
    std::uint64_t shaped        = 0;     // ...that have no checksum, or one that their lines can show, and so all their fields
    std::uint64_t same_fields   = 0;     // ...of which has as many fields as the truth's
    std::uint64_t eligible      = 0;     // ...with a checksum that its lines can show: at least 12 different
    std::uint64_t right         = 0;     // ...of which has the very one (position, coverage, algorithm)
    std::uint64_t spurious      = 0;     // a checksum found in a type that has none
    std::uint64_t strays        = 0;     // found types that are of no true one
};

// What a type starts with, as text: its constants, up to the first field that is not one.
std::string lead_of(const bw::Model& m, std::size_t type) {
    std::string out;
    for (std::size_t f = 0; f < m.field_count(type); ++f) {
        const bw::FieldInfo info = m.field(type, f);
        if (info.kind != FieldKind::Constant) {
            break;
        }
        for (std::size_t i = 0; i < info.bit_size / 8; ++i) {
            out += static_cast<char>((info.constant >> (8 * (info.bit_size / 8 - 1 - i))) & 0xFF);
        }
    }
    return out;
}

// The start of a true type that must be in the lead of the found one: everything before its first field of text or its
// first constant that is a word, which is the address and the separator: the field named "address".
std::string head_of(const bw::Model& m, std::size_t type) {
    std::string out;
    for (std::size_t f = 0; f < m.field_count(type); ++f) {
        const bw::FieldInfo info = m.field(type, f);
        for (std::size_t i = 0; i < info.bit_size / 8; ++i) {
            out += static_cast<char>((info.constant >> (8 * (info.bit_size / 8 - 1 - i))) & 0xFF);
        }
        if (m.field_name(type, f) == "address") {
            break;
        }
    }
    return out;
}

bool has_checksum(const bw::Model& m, std::size_t type) {
    for (std::size_t f = 0; f < m.field_count(type); ++f) {
        if (m.field(type, f).kind == FieldKind::Checksum) {
            return true;
        }
    }
    return false;
}

void measure_text(std::uint64_t first, std::uint64_t count, std::uint32_t frames, const bw::NoiseOptions& noise, Counts* c) {
    for (std::uint64_t seed = first; seed < first + count; ++seed) {
        Dataset d = text_of(seed, frames, seed % 2 ? 0 : 300);
        if (noise.corrupt_permille != 0 || noise.lose_permille != 0) {
            bw::NoiseOptions n = noise;
            n.seed             = seed;
            d                  = bw::add_noise(d, n);
        }
        const bw::Analysis a = bw::analyze(d.capture(), bw::AnalyzeOptions());
        ++c->protocols;
        const bw::SegmentationScore s = bw::score_segmentation(d.frames(), a.segmentation().frames());
        c->truth_frames += s.truth_frames;
        c->exact_frames += s.exact_frames;

        const bw::Model truth = d.model();
        std::vector<std::size_t>      lines(truth.message_type_count(), 0);
        std::vector<std::set<Bytes> > distinct(truth.message_type_count());
        for (std::size_t i = 0; i < d.frame_count(); ++i) {
            ++lines[d.frame_message_type(i)];
            distinct[d.frame_message_type(i)].insert(line_of(d, i));
        }
        std::vector<bool> seen(truth.message_type_count(), false);
        for (std::size_t t = 0; t < a.type_count(); ++t) {
            const std::string lead = lead_of(a.model(), t);
            int               at   = -1;
            for (std::size_t k = 0; k < truth.message_type_count(); ++k) {
                const std::string head = head_of(truth, k);
                if (lead.compare(0, head.size(), head) == 0 && lead.size() >= head.size()) {
                    at = static_cast<int>(k);
                }
            }
            if (at < 0 || seen[static_cast<std::size_t>(at)]) {
                ++c->strays;
                continue;
            }
            seen[static_cast<std::size_t>(at)] = true;
            const std::size_t k = static_cast<std::size_t>(at);
            const bool eligible = has_checksum(truth, k) && distinct[k].size() >= 12;
            ++c->paired;
            c->shaped += eligible || !has_checksum(truth, k) ? 1 : 0;
            if (eligible) {
                ++c->eligible;
                const bw::FieldScore score = bw::score_fields(truth, k, a.model(), t);
                c->right += score.checksum_match ? 1 : 0;
                c->same_fields += a.model().field_count(t) == truth.field_count(k) ? 1 : 0;
            } else if (!has_checksum(truth, k)) {
                // With no checksum nothing says where the start ends: it is the first bytes of the head, which is one constant.
                const std::size_t merged = truth.field_name(k, 0) == "start" ? 1 : 0;
                c->same_fields += a.model().field_count(t) + merged == truth.field_count(k) ? 1 : 0;
                c->spurious += bw::score_fields(truth, k, a.model(), t).found_has_checksum ? 1 : 0;
            }
        }
        for (std::size_t k = 0; k < truth.message_type_count(); ++k) {
            c->truth_types += lines[k] >= 12 ? 1 : 0;
        }
    }
}

double ratio(std::uint64_t a, std::uint64_t b) {
    return b == 0 ? 1.0 : static_cast<double>(a) / static_cast<double>(b);
}

void print(const char* label, const Counts& c) {
    std::printf("text %-22s protocols %llu: frames %.4f, types %llu of %llu, checksum %llu of %llu, fields %llu of %llu, spurious %llu, strays %llu\n",
                label, static_cast<unsigned long long>(c.protocols), ratio(c.exact_frames, c.truth_frames),
                static_cast<unsigned long long>(c.paired), static_cast<unsigned long long>(c.truth_types),
                static_cast<unsigned long long>(c.right), static_cast<unsigned long long>(c.eligible),
                static_cast<unsigned long long>(c.same_fields), static_cast<unsigned long long>(c.shaped),
                static_cast<unsigned long long>(c.spurious),
                static_cast<unsigned long long>(c.strays));
}

} // namespace

TEST_CASE("text pipeline: with no noise the lines, the kinds, the fields and the checksum are found") {
    Counts c;
    measure_text(1, 60, 200, bw::NoiseOptions(), &c);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("clean", c);
    }
    CHECK(c.exact_frames == c.truth_frames);
    CHECK(c.paired == c.truth_types);
    CHECK(c.strays == 0);
    CHECK(c.spurious == 0);
    CHECK(c.right == c.eligible);
    CHECK(c.same_fields == c.shaped);
}

TEST_CASE("text pipeline: a byte wrong in one line in fifty, or lines lost, leave the kinds, the fields and the checksum") {
    bw::NoiseOptions corrupt;
    corrupt.corrupt_permille = 20;
    Counts c;
    measure_text(1, 40, 200, corrupt, &c);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("corrupt 2%", c);
    }
    CHECK(ratio(c.exact_frames, c.truth_frames) >= 0.98);
    CHECK(ratio(c.paired, c.truth_types) >= 0.97);
    CHECK(c.spurious == 0);
    CHECK(ratio(c.right, c.eligible) >= 0.95);
    CHECK(ratio(c.same_fields, c.shaped) >= 0.95);

    bw::NoiseOptions lose;
    lose.lose_permille = 50;
    Counts l;
    measure_text(1, 40, 200, lose, &l);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("lose 5%", l);
    }
    CHECK(l.exact_frames == l.truth_frames);
    CHECK(l.paired == l.truth_types);
    CHECK(l.strays == 0);
    CHECK(l.spurious == 0);
    CHECK(l.right == l.eligible);
    CHECK(l.same_fields == l.shaped);
}

TEST_CASE("text sweep: thousands of protocols of text, with the line as it is and with noise") {
    // Not run unless asked for: BW_SWEEP_SEEDS=1000 bw_tests -tc="text sweep*". It says what it measured.
    const char* env = std::getenv("BW_SWEEP_SEEDS");
    if (env == nullptr || std::atoi(env) <= 0) {
        return;
    }
    const std::uint64_t count      = static_cast<std::uint64_t>(std::atoi(env));
    const std::uint32_t corrupt[4] = { 0, 20, 0, 50 };
    const std::uint32_t lose[4]    = { 0, 0, 50, 50 };
    for (int k = 0; k < 4; ++k) {
        bw::NoiseOptions n;
        n.corrupt_permille = corrupt[k];
        n.lose_permille    = lose[k];
        Counts c;
        measure_text(1, count, 200, n, &c);
        char label[64];
        std::snprintf(label, sizeof(label), "corrupt %u, lose %u", corrupt[k], lose[k]);
        print(label, c);
        // The baseline, over 1000 protocols (docs/roadmap.md), and the threshold that is pinned, a few points below it
        // so that a sweep of 300 protocols, or of 3000, passes by the same margin:
        //
        //                     frames          types            checksum right   fields           strays / types
        //   line as it is     0.999 >= 0.998  1.000 >= 0.998   0.994 >= 0.985   0.995 >= 0.985   0     == 0
        //   1 in 50 wrong     0.997 >= 0.995  1.000 >= 0.998   0.988 >= 0.97    0.991 >= 0.975   0.003 <= 0.01
        //   1 in 20 lost      0.999 >= 0.998  1.000 >= 0.998   0.994 >= 0.985   0.995 >= 0.985   0     == 0
        //   both              0.993 >= 0.985  0.998 >= 0.995   0.965 >= 0.94    0.975 >= 0.95    0.031 <= 0.05
        //
        // and no checksum where there is none, whatever the line.
        const double frames_at[4]  = { 0.998, 0.995, 0.998, 0.985 };
        const double types_at[4]   = { 0.998, 0.998, 0.998, 0.995 };
        const double right_at[4]   = { 0.985, 0.97, 0.985, 0.94 };
        const double fields_at[4]  = { 0.985, 0.975, 0.985, 0.95 };
        const double strays_at[4]  = { 0.0, 0.01, 0.0, 0.05 };
        CHECK(c.spurious == 0);
        CHECK(ratio(c.exact_frames, c.truth_frames) >= frames_at[k]);
        CHECK(ratio(c.paired, c.truth_types) >= types_at[k]);
        CHECK(ratio(c.right, c.eligible) >= right_at[k]);
        CHECK(ratio(c.same_fields, c.shaped) >= fields_at[k]);
        CHECK(ratio(c.strays, c.paired) <= strays_at[k]);
    }
}
