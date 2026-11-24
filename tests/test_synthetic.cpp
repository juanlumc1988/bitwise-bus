// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Protocols made up from a seed, and noise on a capture (bw/synthetic.h), and what the pipeline
// does with them: a property tried over many protocols instead of the six that have a name.
//
//   - The generator is checked against the stages' own code: the checksum of every frame of every
//     protocol is recomputed with the catalogue of CRCs and the sums of bw/crc.h and bw/sums.h, which
//     the generator does not use, and what the model says of a frame is checked against its bytes.
//   - Noise leaves the answer true: the frames that are left are the model's frames.
//   - Over many seeds, the pipeline finds the frames of a protocol that has no noise, the checksum in
//     nearly every type that has evidence enough for one, never one that is not there, and most of the
//     boundaries of the fields; and with a line that is not perfect it loses a little of that, not
//     all of it. The numbers that the properties ask for are the least of what was measured, with a
//     margin, so that a change that makes any of them worse is seen.
//
// A sweep of thousands of protocols is `BW_SWEEP_SEEDS=3000 bw_tests -tc="synthetic sweep*"`, and
// prints what it measured.

#include "doctest.h"

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <set>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/catalog.h"
#include "bw/crc.h"
#include "bw/segmentation.h"
#include "bw/sums.h"
#include "bw/synthetic.h"

using bw::Dataset;

namespace {

typedef std::vector<std::uint8_t> Bytes;

// ---- What a truth frame is, from its events, without the pipeline -----------------------------------------------

Bytes wire_bytes(const Dataset& d, std::size_t index) {
    const bw::Capture capture = d.capture();
    const bw::FrameSpan span  = d.frame(index);
    Bytes out;
    for (std::uint64_t e = span.first_event; e < span.first_event + span.event_count; ++e) {
        const Bytes b = capture.event_bytes(static_cast<std::size_t>(e));
        out.insert(out.end(), b.begin(), b.end());
    }
    return out;
}

// The frame as the protocol has it: between flags, with what was stuffed taken out, as the model says.
Bytes content_bytes(const Dataset& d, std::size_t index) {
    const Bytes               wire    = wire_bytes(d, index);
    const bw::FramingInfo     framing = d.model().framing();
    if (framing.kind != bw::FramingKind::Flagged) {
        return wire;
    }
    Bytes out;
    for (std::size_t i = 1; i + 1 < wire.size(); ++i) {
        if (wire[i] == framing.escape && i + 2 < wire.size()) {
            ++i;
            out.push_back(wire[i] == framing.delimiter_code ? framing.delimiter : framing.escape);
        } else {
            out.push_back(wire[i]);
        }
    }
    return out;
}

std::uint64_t number_at(const Bytes& frame, std::size_t at, unsigned bytes, bw::ByteOrder order) {
    std::uint64_t value = 0;
    for (unsigned i = 0; i < bytes; ++i) {
        const unsigned k = order == bw::ByteOrder::Big ? i : bytes - 1 - i;
        value            = (value << 8) | frame[at + k];
    }
    return value;
}

// ---- The generator against the stages' own checksums --------------------------------------------------------------

// Does the checksum field of the frame hold what the catalogue's CRC, or the sum, gives for the bytes it covers?
bool checksum_holds(const Dataset& d, std::uint32_t type, const Bytes& frame) {
    const bw::Model model = d.model();
    const std::size_t last = model.field_count(type) - 1;
    const bw::FieldInfo cs = model.field(type, last);
    if (cs.kind != bw::FieldKind::Checksum) {
        return true;                                       // none to hold
    }
    std::string name = model.field_detail(type, last);
    int         seed = -1;
    const std::string marker = " seeded with ";
    const std::size_t at     = name.find(marker);
    if (at != std::string::npos) {
        seed = std::atoi(name.c_str() + at + marker.size());
        name = name.substr(0, at);
    }
    const unsigned     width = cs.bit_size / 8;
    const std::size_t  first = static_cast<std::size_t>(model.field_position(type, cs.covers_first).bit_offset / 8);
    const std::size_t  end   = frame.size() - width;
    if (end <= first) {
        return false;
    }
    std::uint64_t computed = 0;
    if (const bw::CrcSpec* spec = bw::catalog_find(name.c_str())) {
        bw::u64 state = bw::crc_feed(*spec, bw::crc_begin(*spec), frame.data() + first, end - first);
        if (seed >= 0) {
            const bw::u8 extra = static_cast<bw::u8>(seed);
            state              = bw::crc_feed(*spec, state, &extra, 1);
        }
        computed = bw::crc_end(*spec, state);
    } else if (const bw::SumSpec* sum = bw::sum_find(name.c_str())) {
        computed = bw::sum_compute(*sum, frame.data() + first, end - first);
    } else {
        return false;                                      // an algorithm that is in neither
    }
    return computed == number_at(frame, end, width, cs.byte_order);
}

} // namespace

TEST_CASE("synthetic: the same seed is the same protocol and the same capture, and others are not") {
    bw::SyntheticOptions o;
    o.seed   = 77;
    o.frames = 50;
    const Dataset a = bw::generate_synthetic(o);
    const Dataset b = bw::generate_synthetic(o);
    CHECK(a.capture().equals(b.capture()));
    CHECK(bw::describe_model(a.model()) == bw::describe_model(b.model()));
    CHECK(a.frame_count() == 50);

    std::set<std::string> models;
    for (std::uint64_t seed = 1; seed <= 40; ++seed) {
        o.seed = seed;
        models.insert(bw::describe_model(bw::generate_synthetic(o).model()));
    }
    CHECK(models.size() >= 38);                            // a few may be the same by chance, hardly more

    // The timing noise changes when bytes are, not which.
    o.seed = 77;
    bw::SyntheticOptions jittered = o;
    jittered.jitter_permille      = 400;
    const Dataset c               = bw::generate_synthetic(jittered);
    REQUIRE(c.frame_count() == a.frame_count());
    for (std::size_t i = 0; i < a.frame_count(); ++i) {
        CHECK(wire_bytes(a, i) == wire_bytes(c, i));
    }
}

TEST_CASE("synthetic: options out of range are refused, and no frames is an empty capture") {
    bw::SyntheticOptions o;
    o.frames = 100001;
    CHECK_THROWS_AS(bw::generate_synthetic(o), std::invalid_argument);
    o.frames          = 10;
    o.jitter_permille = 501;
    CHECK_THROWS_AS(bw::generate_synthetic(o), std::invalid_argument);
    o.jitter_permille = 500;
    CHECK(bw::generate_synthetic(o).frame_count() == 10);
    o.frames = 0;
    const Dataset none = bw::generate_synthetic(o);
    CHECK(none.frame_count() == 0);
    CHECK(none.capture().event_count() == 0);
    CHECK(none.model().message_type_count() >= 1);         // the protocol is there, and nothing was sent
}

TEST_CASE("synthetic: every frame of every protocol is what its model says, checksum included") {
    bw::SyntheticOptions o;
    o.frames = 60;
    for (std::uint64_t seed = 1; seed <= 150; ++seed) {
        o.seed = seed;
        const Dataset d     = bw::generate_synthetic(o);
        const bw::Model m   = d.model();
        CAPTURE(seed);
        REQUIRE(d.frame_count() == 60);
        // Of the frames of a protocol with a length that counts the payload, size less length is the same.
        std::set<std::int64_t>               adjusts;
        std::map<std::uint32_t, std::set<std::size_t> > sizes;
        for (std::size_t i = 0; i < d.frame_count(); ++i) {
            const std::uint32_t type  = d.frame_message_type(i);
            const Bytes         frame = content_bytes(d, i);
            sizes[type].insert(frame.size());
            CHECK(checksum_holds(d, type, frame));
            for (std::size_t f = 0; f < m.field_count(type); ++f) {
                const bw::FieldInfo     info = m.field(type, f);
                const bw::FieldPosition pos  = m.field_position(type, f);
                if (!pos.fixed || info.size_kind != bw::SizeKind::Fixed) {
                    continue;
                }
                REQUIRE(pos.bit_offset / 8 + info.bit_size / 8 <= frame.size());
                const std::size_t at = static_cast<std::size_t>(pos.bit_offset / 8);
                if (info.kind == bw::FieldKind::Constant) {
                    CHECK(number_at(frame, at, info.bit_size / 8, info.byte_order) == info.constant);
                } else if (info.kind == bw::FieldKind::Length) {
                    adjusts.insert(static_cast<std::int64_t>(frame.size()) -
                                   static_cast<std::int64_t>(number_at(frame, at, info.bit_size / 8, info.byte_order)));
                }
            }
        }
        CHECK(adjusts.size() <= 1);
        // No two kinds of message share a size.
        std::set<std::size_t> all;
        std::size_t           total = 0;
        for (std::map<std::uint32_t, std::set<std::size_t> >::const_iterator it = sizes.begin(); it != sizes.end(); ++it) {
            all.insert(it->second.begin(), it->second.end());
            total += it->second.size();
        }
        CHECK(all.size() == total);
    }
}

TEST_CASE("synthetic: the protocols are of all sorts") {
    // Over 300 seeds, each of the things that a protocol can be is there, so that the property below is tried on them.
    std::map<std::string, int> seen;
    bw::SyntheticOptions       o;
    o.frames = 10;
    for (std::uint64_t seed = 1; seed <= 300; ++seed) {
        o.seed          = seed;
        const bw::Model m = bw::generate_synthetic(o).model();
        switch (m.framing().kind) {
            case bw::FramingKind::IdleGap:    ++seen["gap"]; break;
            case bw::FramingKind::Contiguous: ++seen["sync"]; break;
            case bw::FramingKind::Flagged:    ++seen["flags"]; break;
            default:                          ++seen["other"]; break;
        }
        seen["types" + std::to_string(m.message_type_count())] += 1;
        bool none = true;
        for (std::size_t t = 0; t < m.message_type_count(); ++t) {
            for (std::size_t f = 0; f < m.field_count(t); ++f) {
                const bw::FieldInfo info = m.field(t, f);
                seen["field " + bw::field_kind_name(info.kind)] += 1;
                if (info.size_kind == bw::SizeKind::FromField) {
                    ++seen["sized payload"];
                }
                if (info.kind == bw::FieldKind::Checksum) {
                    none = false;
                    const std::string detail = m.field_detail(t, f);
                    seen["checksum " + detail.substr(0, detail.find(" seeded"))] += 1;
                    seen[detail.find("seeded") != std::string::npos ? "seeded" : "not seeded"] += 1;
                    seen["checksum bits " + std::to_string(info.bit_size)] += 1;
                }
            }
        }
        seen[none ? "no checksum" : "a checksum"] += 1;
    }
    CHECK(seen["other"] == 0);
    CHECK(seen["gap"] >= 60);
    CHECK(seen["sync"] >= 60);
    CHECK(seen["flags"] >= 40);
    for (int types = 1; types <= 4; ++types) {
        CHECK(seen["types" + std::to_string(types)] >= 10);
    }
    CHECK(seen["sized payload"] >= 20);
    CHECK(seen["seeded"] >= 20);
    CHECK(seen["no checksum"] >= 15);
    CHECK(seen["checksum bits 8"] >= 50);
    CHECK(seen["checksum bits 16"] >= 100);
    CHECK(seen["checksum bits 32"] >= 30);
    const char* kinds[] = { "constant", "enum", "counter", "float", "flags", "payload", "length", "checksum" };
    for (std::size_t k = 0; k < sizeof(kinds) / sizeof(kinds[0]); ++k) {
        CHECK(seen[std::string("field ") + kinds[k]] >= 100);
    }
    for (std::size_t a = 0; a < 12; ++a) {
        static const char* algorithms[] = { "CRC-8", "CRC-8/MAXIM-DOW", "CRC-16/MODBUS", "CRC-16/ARC", "CRC-16/XMODEM",
                                            "CRC-16/IBM-3740", "CRC-16/IBM-SDLC", "CRC-16/MCRF4XX", "CRC-32/ISO-HDLC",
                                            "CRC-32/MPEG-2", "XOR-8", "SUM-8" };
        CHECK(seen[std::string("checksum ") + algorithms[a]] >= 10);
    }
}

// ---- Noise -----------------------------------------------------------------------------------------------------------

namespace {

Dataset protocol_of(std::uint64_t seed, std::uint32_t frames = 100) {
    bw::SyntheticOptions o;
    o.seed   = seed;
    o.frames = frames;
    return bw::generate_synthetic(o);
}

// How many bytes of the frame differ from the clean one, whose size is the same.
std::size_t differences(const Bytes& a, const Bytes& b) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < a.size(); ++i) {
        n += a[i] != b[i] ? 1 : 0;
    }
    return n;
}

} // namespace

TEST_CASE("noise: no rates is the same capture, and the same seed is the same noise") {
    const Dataset clean = protocol_of(5);
    bw::NoiseOptions n;
    n.seed = 9;
    const Dataset same = bw::add_noise(clean, n);
    CHECK(same.capture().equals(clean.capture()));
    CHECK(same.frame_count() == clean.frame_count());
    CHECK(bw::describe_model(same.model()) == bw::describe_model(clean.model()));

    n.corrupt_permille = 300;
    n.lose_permille    = 100;
    const Dataset a    = bw::add_noise(clean, n);
    const Dataset b    = bw::add_noise(clean, n);
    CHECK(a.capture().equals(b.capture()));
    n.seed = 10;
    CHECK_FALSE(a.capture().equals(bw::add_noise(clean, n).capture()));
}

TEST_CASE("noise: a rate over a thousand is refused") {
    const Dataset clean = protocol_of(5, 10);
    bw::NoiseOptions n;
    n.corrupt_permille = 1001;
    CHECK_THROWS_AS(bw::add_noise(clean, n), std::invalid_argument);
    n.corrupt_permille = 1000;
    n.lose_permille    = 1001;
    CHECK_THROWS_AS(bw::add_noise(clean, n), std::invalid_argument);
    n.lose_permille = 1000;
    const Dataset none = bw::add_noise(clean, n);
    CHECK(none.frame_count() == 0);                        // all of them lost
    CHECK(none.capture().event_count() == 0);
}

TEST_CASE("noise: every frame of a thousand is changed in one byte, and the others in none") {
    const Dataset clean = protocol_of(8);
    bw::NoiseOptions n;
    n.corrupt_permille = 1000;
    const Dataset all  = bw::add_noise(clean, n);
    REQUIRE(all.frame_count() == clean.frame_count());
    for (std::size_t i = 0; i < clean.frame_count(); ++i) {
        const Bytes a = wire_bytes(clean, i);
        const Bytes b = wire_bytes(all, i);
        REQUIRE(a.size() == b.size());
        CHECK(differences(a, b) == 1);
        CHECK(all.frame_message_type(i) == clean.frame_message_type(i));
        CHECK(all.frame(i).event_count == clean.frame(i).event_count);
    }
    // Of 300 in a thousand, about a third of them, and the rest as they were.
    n.corrupt_permille = 300;
    const Dataset some = bw::add_noise(protocol_of(8, 1000), n);
    std::size_t   changed = 0;
    const Dataset big     = protocol_of(8, 1000);
    for (std::size_t i = 0; i < big.frame_count(); ++i) {
        const std::size_t d = differences(wire_bytes(big, i), wire_bytes(some, i));
        CHECK(d <= 1);
        changed += d;
    }
    CHECK(changed > 240);
    CHECK(changed < 360);
}

TEST_CASE("noise: the frames that are lost are not in the capture or the truth, and the others are as they were") {
    const Dataset big = protocol_of(21, 500);
    bw::NoiseOptions n;
    n.lose_permille = 200;
    const Dataset lost = bw::add_noise(big, n);
    CHECK(lost.frame_count() > 350);
    CHECK(lost.frame_count() < 450);
    // What is left is a subsequence of the frames, with their types, and the events are those of the frames.
    std::size_t at = 0;
    for (std::size_t i = 0; i < lost.frame_count(); ++i) {
        const Bytes b = wire_bytes(lost, i);
        while (at < big.frame_count() && !(wire_bytes(big, at) == b && big.frame_message_type(at) == lost.frame_message_type(i))) {
            ++at;
        }
        REQUIRE(at < big.frame_count());
        ++at;
    }
    CHECK(lost.capture().event_count() < big.capture().event_count());
    std::uint64_t events = 0;
    for (std::size_t i = 0; i < lost.frame_count(); ++i) {
        CHECK(lost.frame(i).first_event == events);        // back to back: nothing is in no frame
        events += lost.frame(i).event_count;
    }
    CHECK(events == lost.capture().event_count());
}

TEST_CASE("noise: events that are in no frame are kept, and the time of the others does not move") {
    // A frame, an event of no frame, a frame, another event of no frame.
    bw::Capture capture;
    for (int i = 0; i < 8; ++i) {
        bw::EventInfo info;
        info.has_time = true;
        info.time_ns  = 1000 * i;
        capture.add_event(info, Bytes(1, static_cast<std::uint8_t>(0x10 + i)));
    }
    bw::Model model;
    const std::size_t t = model.add_message_type("a");
    bw::FieldInfo     f;
    f.kind     = bw::FieldKind::Payload;
    f.bit_size = 16;
    model.add_field(t, "x", f, "");
    std::vector<bw::FrameSpan> spans(2);
    spans[0].first_event = 1;
    spans[0].event_count = 2;
    spans[1].first_event = 5;
    spans[1].event_count = 2;
    const std::vector<std::uint32_t> types(2, 0);
    const Dataset                    d(capture, model, spans, types);

    bw::NoiseOptions n;
    n.lose_permille = 1000;
    const Dataset lost = bw::add_noise(d, n);
    CHECK(lost.frame_count() == 0);
    CHECK(lost.capture().event_count() == 4);              // the events of no frame
    CHECK(lost.capture().event_bytes(0) == Bytes(1, 0x10));
    CHECK(lost.capture().event_bytes(1) == Bytes(1, 0x13));
    CHECK(lost.capture().event_bytes(2) == Bytes(1, 0x14));
    CHECK(lost.capture().event_bytes(3) == Bytes(1, 0x17));
    CHECK(lost.capture().event(1).time_ns == 3000);

    n.lose_permille    = 0;
    n.corrupt_permille = 1000;
    const Dataset damaged = bw::add_noise(d, n);
    REQUIRE(damaged.frame_count() == 2);
    CHECK(damaged.frame(0).first_event == 1);
    CHECK(damaged.frame(1).first_event == 5);
    // Of the two events of a frame, one byte is another; the events of no frame are as they were.
    const std::size_t outside[4] = { 0, 3, 4, 7 };
    for (std::size_t k = 0; k < 4; ++k) {
        CHECK(damaged.capture().event_bytes(outside[k]) == capture.event_bytes(outside[k]));
    }
    for (std::size_t first = 1; first <= 5; first += 4) {
        std::size_t changed = 0;
        for (std::size_t e = first; e < first + 2; ++e) {
            changed += damaged.capture().event_bytes(e) == capture.event_bytes(e) ? 0 : 1;
        }
        CHECK(changed == 1);
    }
}

// ---- The pipeline, over many protocols -------------------------------------------------------------------------

namespace {

struct Measured {
    std::uint64_t protocols       = 0;
    std::uint64_t truth_frames    = 0;
    std::uint64_t exact_frames    = 0;
    std::uint64_t found_frames    = 0;
    std::uint64_t exact_protocols = 0;     // every frame, and no more
    std::uint64_t eligible        = 0;     // types with a checksum that the frames can show
    std::uint64_t right           = 0;     // ...of which it was found, the very one
    std::uint64_t wrong           = 0;     // a checksum found that is not the one (the same, shifted over zeros, is not one)
    std::uint64_t spurious        = 0;     // a checksum found in a type that has none
    std::uint64_t truth_bounds    = 0;
    std::uint64_t hit_bounds      = 0;
    std::uint64_t truth_fields    = 0;
    std::uint64_t exact_fields    = 0;
    std::uint64_t unpaired        = 0;     // found types that are of no frame of the truth
};

// The truth type that each found type is, by the frames they have in common: the votes of the frames that start at
// the same event, for the smallest size of the found type (which is a size of it; the others, up to the largest, may
// be those of another type). -1 for one that has none.
std::vector<int> pair_types(const Dataset& truth, const bw::Analysis& a) {
    const bw::Capture contents = bw::frame_contents(truth.capture(), a.segmentation());
    const std::vector<bw::FrameSpan> found = a.segmentation().frames();
    std::map<std::uint64_t, std::size_t> truth_at;
    for (std::size_t i = 0; i < truth.frame_count(); ++i) {
        truth_at[truth.frame(i).first_event] = i;
    }
    std::map<std::size_t, std::map<int, std::uint64_t> > votes;          // size -> truth type -> frames
    for (std::size_t j = 0; j < found.size() && j < contents.event_count(); ++j) {
        const std::map<std::uint64_t, std::size_t>::const_iterator it = truth_at.find(found[j].first_event);
        if (it != truth_at.end()) {
            ++votes[contents.event_size(j)][static_cast<int>(truth.frame_message_type(it->second))];
        }
    }
    std::vector<int> out;
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        const bw::MessageTypeReport r = a.type_report(t);
        const std::map<std::size_t, std::map<int, std::uint64_t> >::const_iterator v = votes.find(r.frame_bytes);
        int           best = -1;
        std::uint64_t most = 0;
        if (v != votes.end()) {
            for (std::map<int, std::uint64_t>::const_iterator k = v->second.begin(); k != v->second.end(); ++k) {
                if (k->second > most) {
                    most = k->second;
                    best = k->first;
                }
            }
        }
        out.push_back(best);
    }
    return out;
}

// How many different frames of a type the truth has, and in how many sizes.
void truth_type_facts(const Dataset& d, std::uint32_t type, std::size_t* distinct, std::size_t* sizes) {
    std::set<Bytes>       frames;
    std::set<std::size_t> lengths;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        if (d.frame_message_type(i) == type) {
            const Bytes b = content_bytes(d, i);
            frames.insert(b);
            lengths.insert(b.size());
        }
    }
    *distinct = frames.size();
    *sizes    = lengths.size();
}

// The checksum that the pipeline found, against the one the truth has. Where it starts may be a byte or two off,
// over bytes that are zero in the frames (a checksum cannot tell if they are covered): that is the same.
bool is_the_checksum(const Dataset& d, std::uint32_t type, const bw::ChecksumFinding& f) {
    const bw::Model   m  = d.model();
    const std::size_t at = m.field_count(type) - 1;
    const bw::FieldInfo cs = m.field(type, at);
    if (!f.found || cs.kind != bw::FieldKind::Checksum) {
        return false;
    }
    std::string name = m.field_detail(type, at);
    const std::size_t seeded = name.find(" seeded with ");
    const bool        truth_seeded = seeded != std::string::npos;
    if (truth_seeded) {
        if (!f.seeded || f.seed != static_cast<std::uint32_t>(std::atoi(name.c_str() + seeded + 13))) {
            return false;
        }
        name = name.substr(0, seeded);
    } else if (f.seeded) {
        return false;
    }
    if (bw::checksum_algorithm_name(f.algorithm) != name || f.width_bits != cs.bit_size || f.trailer_skip != 0 ||
        (cs.bit_size > 8 && f.byte_order != cs.byte_order)) {
        return false;
    }
    const std::uint32_t truth_skip = static_cast<std::uint32_t>(m.field_position(type, cs.covers_first).bit_offset / 8);
    if (f.header_skip == truth_skip) {
        return true;
    }
    // Different by bytes that never hold anything but zero, in the frames of this type.
    const std::uint32_t lo = std::min(f.header_skip, truth_skip);
    const std::uint32_t hi = std::max(f.header_skip, truth_skip);
    std::uint64_t       frames = 0;
    std::uint64_t       zeros  = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        if (d.frame_message_type(i) == type) {
            const Bytes b = content_bytes(d, i);
            ++frames;
            bool zero = b.size() > hi;
            for (std::uint32_t k = lo; zero && k < hi; ++k) {
                zero = b[k] == 0;
            }
            zeros += zero ? 1 : 0;
        }
    }
    return frames > 0 && zeros * 10 >= 9 * frames;
}

void measure(std::uint64_t first, std::uint64_t count, std::uint32_t frames, const bw::NoiseOptions& noise, Measured* m) {
    for (std::uint64_t seed = first; seed < first + count; ++seed) {
        bw::SyntheticOptions o;
        o.seed   = seed;
        o.frames = frames;
        Dataset d = bw::generate_synthetic(o);
        if (noise.corrupt_permille != 0 || noise.lose_permille != 0) {
            bw::NoiseOptions n = noise;
            n.seed             = seed;
            d                  = bw::add_noise(d, n);
        }
        const bw::Analysis a = bw::analyze(d.capture(), bw::AnalyzeOptions());
        const bw::SegmentationScore s = bw::score_segmentation(d.frames(), a.segmentation().frames());
        ++m->protocols;
        m->truth_frames += s.truth_frames;
        m->exact_frames += s.exact_frames;
        m->found_frames += s.found_frames;
        m->exact_protocols += (s.exact_frames == s.truth_frames && s.found_frames == s.truth_frames) ? 1 : 0;

        const std::vector<int> paired = pair_types(d, a);
        for (std::size_t t = 0; t < a.type_count(); ++t) {
            if (paired[t] < 0) {
                ++m->unpaired;
                continue;
            }
            const std::uint32_t truth_type = static_cast<std::uint32_t>(paired[t]);
            const bw::FieldScore f = bw::score_fields(d.model(), truth_type, a.model(), t);
            m->truth_bounds += f.truth_boundaries;
            m->hit_bounds   += f.boundary_hits;
            m->truth_fields += f.truth_fields;
            m->exact_fields += f.exact_fields;

            const bw::ChecksumFinding& found = a.type_report(t).checksum;
            if (!f.truth_has_checksum) {
                m->spurious += found.found ? 1 : 0;
                continue;
            }
            std::size_t distinct = 0;
            std::size_t sizes    = 0;
            truth_type_facts(d, truth_type, &distinct, &sizes);
            const std::string detail = d.model().field_detail(truth_type, d.model().field_count(truth_type) - 1);
            // What the frames can show: a checksum with a byte of its own, in frames of one size, is any of several
            // (what a different start value does to every frame is the same, and the byte takes it up); and
            // frames that are nearly all the same say nothing of any.
            const bool shown = distinct >= 8 && !(detail.find("seeded") != std::string::npos && sizes == 1);
            if (found.found && !is_the_checksum(d, truth_type, found)) {
                ++m->wrong;
                if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
                    std::printf("seed %llu type %u: found %s%s %u (%u bits, skip %u/%u, %u candidates) and the truth has %s\n",
                                static_cast<unsigned long long>(seed), truth_type,
                                bw::checksum_algorithm_name(found.algorithm).c_str(), found.seeded ? " seeded with" : "",
                                found.seed, found.width_bits, found.header_skip, found.trailer_skip, found.candidates,
                                detail.c_str());
                }
            }
            if (shown) {
                ++m->eligible;
                m->right += is_the_checksum(d, truth_type, found) ? 1 : 0;
            }
        }
    }
}

double ratio(std::uint64_t a, std::uint64_t b) {
    return b == 0 ? 1.0 : static_cast<double>(a) / static_cast<double>(b);
}

void print(const char* label, const Measured& m) {
    std::printf("%-22s %4llu protocols: frames %.4f exact (%llu of %llu protocols whole); checksum %llu of %llu, "
                "wrong %llu, spurious %llu; boundaries %.3f, exact fields %.3f\n",
                label, static_cast<unsigned long long>(m.protocols), ratio(m.exact_frames, m.truth_frames),
                static_cast<unsigned long long>(m.exact_protocols), static_cast<unsigned long long>(m.protocols),
                static_cast<unsigned long long>(m.right), static_cast<unsigned long long>(m.eligible),
                static_cast<unsigned long long>(m.wrong), static_cast<unsigned long long>(m.spurious),
                ratio(m.hit_bounds, m.truth_bounds), ratio(m.exact_fields, m.truth_fields));
}

} // namespace

TEST_CASE("pipeline: with no noise the frames are found, the checksum is the right one or none, and the boundaries are most") {
    Measured m;
    measure(1, 50, 200, bw::NoiseOptions(), &m);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("clean", m);
    }
    CHECK(m.exact_protocols == m.protocols);                // every frame of every protocol, and no more
    CHECK(m.spurious == 0);
    CHECK(m.wrong == 0);
    CHECK(ratio(m.right, m.eligible) >= 0.97);
    CHECK(ratio(m.hit_bounds, m.truth_bounds) >= 0.85);
    CHECK(ratio(m.exact_fields, m.truth_fields) >= 0.60);
    CHECK(m.unpaired == 0);
}

TEST_CASE("pipeline: a byte wrong in one frame in fifty costs a few frames, and the checksum is still found") {
    bw::NoiseOptions n;
    n.corrupt_permille = 20;
    Measured m;
    measure(1, 30, 200, n, &m);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("corrupt 2%", m);
    }
    CHECK(ratio(m.exact_frames, m.truth_frames) >= 0.99);
    CHECK(m.spurious == 0);
    CHECK(ratio(m.wrong, m.eligible) <= 0.02);
    CHECK(ratio(m.right, m.eligible) >= 0.93);
    CHECK(ratio(m.hit_bounds, m.truth_bounds) >= 0.85);
}

TEST_CASE("pipeline: frames that are lost change nothing that they do not take with them") {
    bw::NoiseOptions n;
    n.lose_permille = 50;
    Measured m;
    measure(1, 25, 200, n, &m);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("lose 5%", m);
    }
    CHECK(m.exact_protocols == m.protocols);
    CHECK(m.spurious == 0);
    CHECK(m.wrong == 0);
    CHECK(ratio(m.right, m.eligible) >= 0.97);
    CHECK(ratio(m.hit_bounds, m.truth_bounds) >= 0.85);
}

TEST_CASE("pipeline: a line of one frame in twenty wrong and one in twenty lost is still read") {
    bw::NoiseOptions n;
    n.corrupt_permille = 50;
    n.lose_permille    = 50;
    Measured m;
    measure(1, 25, 200, n, &m);
    if (std::getenv("BW_SYNTHETIC_VERBOSE") != nullptr) {
        print("corrupt 5%, lose 5%", m);
    }
    CHECK(ratio(m.exact_frames, m.truth_frames) >= 0.93);
    CHECK(m.spurious == 0);
    CHECK(ratio(m.wrong, m.eligible) <= 0.03);
    CHECK(ratio(m.right, m.eligible) >= 0.82);
    CHECK(ratio(m.hit_bounds, m.truth_bounds) >= 0.82);
}

TEST_CASE("pipeline: whatever the line, it does not throw, and it says the same twice") {
    // Few frames, a lot of noise, all of it lost: nothing to find, and nothing wrong with saying so.
    const std::uint32_t frames[4]  = { 0, 1, 5, 40 };
    const std::uint32_t corrupt[4] = { 0, 1000, 500, 100 };
    const std::uint32_t lose[4]    = { 0, 0, 500, 900 };
    for (std::uint64_t seed = 1; seed <= 20; ++seed) {
        for (int k = 0; k < 4; ++k) {
            bw::SyntheticOptions o;
            o.seed   = seed;
            o.frames = frames[k];
            bw::NoiseOptions n;
            n.seed             = seed;
            n.corrupt_permille = corrupt[(k + seed) % 4];
            n.lose_permille    = lose[k];
            const Dataset d    = bw::add_noise(bw::generate_synthetic(o), n);
            CAPTURE(seed);
            CAPTURE(k);
            const std::string first  = bw::describe_analysis(bw::analyze(d.capture(), bw::AnalyzeOptions()));
            const std::string second = bw::describe_analysis(bw::analyze(d.capture(), bw::AnalyzeOptions()));
            CHECK(first == second);
        }
    }
}

TEST_CASE("synthetic sweep: thousands of protocols, with the line as it is and with noise") {
    // Not run unless asked for: BW_SWEEP_SEEDS=3000 bw_tests -tc="synthetic sweep*". It says what it measured.
    const char* env = std::getenv("BW_SWEEP_SEEDS");
    if (env == nullptr || std::atoi(env) <= 0) {
        return;
    }
    const std::uint64_t count = static_cast<std::uint64_t>(std::atoi(env));
    const std::uint32_t corrupt[4] = { 0, 20, 0, 50 };
    const std::uint32_t lose[4]    = { 0, 0, 50, 50 };
    // BW_SWEEP_CONFIGS=1 is the line as it is only, and 4 (the default) all of them.
    const char*         configs    = std::getenv("BW_SWEEP_CONFIGS");
    const int           how_many   = configs != nullptr && std::atoi(configs) > 0 ? std::min(4, std::atoi(configs)) : 4;
    for (int k = 0; k < how_many; ++k) {
        bw::NoiseOptions n;
        n.corrupt_permille = corrupt[k];
        n.lose_permille    = lose[k];
        Measured m;
        measure(1, count, 200, n, &m);
        char label[64];
        std::snprintf(label, sizeof(label), "corrupt %u, lose %u", corrupt[k], lose[k]);
        print(label, m);
        // Measured over 1500 protocols: frames 1.0000, 0.9949, 1.0000 and 0.9748; the checksum 0.9976, 0.9782, 0.9971 and
        // 0.9124 of those that the frames can show, none wrong but 2 in 3710 in the last, none where there is none;
        // boundaries 0.90, 0.90, 0.91, 0.89.
        CHECK(m.spurious == 0);
        CHECK(ratio(m.wrong, m.eligible) <= (k == 3 ? 0.005 : 0.001));
        CHECK(ratio(m.right, m.eligible) >= (k == 0 || k == 2 ? 0.99 : k == 1 ? 0.96 : 0.88));
        CHECK(ratio(m.hit_bounds, m.truth_bounds) >= 0.85);
        CHECK(ratio(m.exact_frames, m.truth_frames) >= (k == 0 || k == 2 ? 0.999 : k == 1 ? 0.99 : 0.96));
        if (k == 0 || k == 2) {
            CHECK(m.exact_protocols == m.protocols);
        }
    }
}
