// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The registry and the generators are what every later test stands on, so what
// is checked here is not only that a generator runs but that it can be trusted.
//
//   - It is deterministic: a seed is a capture, on every platform. Two captures
//     are checked in, and were produced by a second implementation written in
//     another language from the documented algorithm, not by this one.
//   - Its checksum agrees with the inference stage's, though neither was written
//     with the other's code; and the stage's has the published check values.
//   - What it claims about itself is true: the model it declares describes the
//     frames it emits, the frames are where the dataset says, and a stage that
//     found them perfectly would score perfectly.

#include "doctest.h"

#include <algorithm>
#include <fstream>
#include <iterator>
#include <set>
#include <stdexcept>
#include <string>
#include <vector>

#include "bw/capture.h"
#include "bw/catalog.h"
#include "bw/crc.h"
#include "bw/evaluate.h"
#include "bw/protocol.h"

using bw::Capture;
using bw::Dataset;
using bw::FrameSpan;
using bw::GenerateOptions;

namespace {

typedef std::vector<std::uint8_t> Bytes;

std::string read_file(const std::string& name) {
    const std::string path = std::string(BW_CORPUS_DIR) + "/" + name;
    std::ifstream in(path.c_str(), std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

GenerateOptions options(std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return o;
}

std::string csv(const Dataset& d) {
    return bw::format_capture_csv(d.capture());
}

// The bytes of every event of a frame, in order.
Bytes frame_bytes(const Capture& c, const FrameSpan& f) {
    Bytes out;
    for (std::uint64_t i = 0; i < f.event_count; ++i) {
        const Bytes b = c.event_bytes(static_cast<std::size_t>(f.first_event + i));
        out.insert(out.end(), b.begin(), b.end());
    }
    return out;
}

Bytes all_bytes(const Capture& c) {
    FrameSpan whole;
    whole.event_count = c.event_count();
    return frame_bytes(c, whole);
}

// CRC-16/MODBUS from the inference stage's catalogue: the other implementation
// the generator's is checked against.
std::uint16_t catalogue_crc(const Bytes& body) {
    const bw::CrcSpec* spec = bw::catalog_find("CRC-16/MODBUS");
    REQUIRE(spec != nullptr);
    return static_cast<std::uint16_t>(bw::crc_compute(*spec, body.empty() ? nullptr : &body[0], body.size()));
}

// A frame of six bytes with a correct CRC after it, little-endian.
Bytes with_crc(Bytes body) {
    const std::uint16_t crc = catalogue_crc(body);
    body.push_back(static_cast<std::uint8_t>(crc & 0xFF));
    body.push_back(static_cast<std::uint8_t>(crc >> 8));
    return body;
}

Bytes request(std::uint8_t address, std::uint8_t function, std::uint16_t first, std::uint16_t quantity) {
    Bytes body;
    body.push_back(address);
    body.push_back(function);
    body.push_back(static_cast<std::uint8_t>(first >> 8));
    body.push_back(static_cast<std::uint8_t>(first & 0xFF));
    body.push_back(static_cast<std::uint8_t>(quantity >> 8));
    body.push_back(static_cast<std::uint8_t>(quantity & 0xFF));
    return with_crc(body);
}

// The pauses between consecutive events, split by what the model says a frame
// boundary is: segmentation in miniature, with the gap the model declares.
std::vector<FrameSpan> split_by_gap(const Capture& c, std::uint64_t idle_gap_ns) {
    std::vector<FrameSpan> found;
    for (std::size_t i = 0; i < c.event_count(); ++i) {
        const bool starts = (i == 0) ||
            static_cast<std::uint64_t>(c.event(i).time_ns - c.event(i - 1).time_ns) >= idle_gap_ns;
        if (starts) {
            FrameSpan f;
            f.first_event = i;
            found.push_back(f);
        }
        found.back().event_count += 1;
    }
    return found;
}

const std::uint64_t kChar = 11ULL * 1000000000ULL / 9600ULL;      // 1145833 ns

} // namespace

// ---- The registry ----------------------------------------------------------

TEST_CASE("the registry lists the protocols by name, in order") {
    const std::vector<std::string> names = bw::protocol_names();
    REQUIRE(!names.empty());
    CHECK(std::find(names.begin(), names.end(), "modbus-rtu") != names.end());
    CHECK(std::is_sorted(names.begin(), names.end()));
    for (std::size_t i = 0; i < names.size(); ++i) {
        const bw::Protocol* p = bw::find_protocol(names[i]);
        REQUIRE(p != nullptr);
        CHECK(p->name() == names[i]);
    }
    CHECK(bw::find_protocol("no-such-protocol") == nullptr);
    CHECK(bw::find_protocol("") == nullptr);
    CHECK(bw::find_protocol("MODBUS-RTU") == nullptr);                // names are exact
}

TEST_CASE("asking for a protocol that does not exist says which do") {
    const std::vector<std::string> names = bw::protocol_names();
    std::string known;
    for (std::size_t i = 0; i < names.size(); ++i) {
        known += (i == 0 ? "" : ", ") + names[i];
    }
    const std::string expected = "unknown protocol 'nope'; known: " + known;
    try { bw::protocol_summary("nope"); FAIL("no exception"); }
    catch (const std::invalid_argument& e) { CHECK(std::string(e.what()) == expected); }
    CHECK_THROWS_AS(bw::protocol_model("nope"), std::invalid_argument);
    CHECK_THROWS_AS(bw::generate_protocol("nope", GenerateOptions()), std::invalid_argument);
    CHECK_THROWS_AS(bw::protocol_conforms("nope", Bytes()), std::invalid_argument);
}

TEST_CASE("every registered protocol keeps the promises of a protocol") {
    const std::vector<std::string> names = bw::protocol_names();
    for (std::size_t n = 0; n < names.size(); ++n) {
        const std::string& name = names[n];
        INFO("protocol " << name);

        const std::string summary = bw::protocol_summary(name);
        CHECK(!summary.empty());
        CHECK(summary.find('\n') == std::string::npos);

        const bw::Model model = bw::protocol_model(name);
        CHECK(model.message_type_count() >= 1);

        const Dataset data = bw::generate_protocol(name, options(5, 12));
        CHECK(bw::describe_model(data.model()) == bw::describe_model(model));
        REQUIRE(data.frame_count() == 12);
        CHECK(data.capture().event_count() > 0);
        CHECK(data.capture().fully_timed());

        // Every frame the dataset says is there belongs to the protocol.
        for (std::size_t i = 0; i < data.frame_count(); ++i) {
            CHECK(bw::protocol_conforms(name, frame_bytes(data.capture(), data.frame(i))));
        }

        // Writing the capture to a file and reading it back changes nothing.
        CHECK(bw::parse_capture_csv(csv(data)).equals(data.capture()));

        // The same options are the same capture; another seed is another one.
        CHECK(csv(bw::generate_protocol(name, options(5, 12))) == csv(data));
        CHECK(csv(bw::generate_protocol(name, options(6, 12))) != csv(data));

        // Timing noise moves timestamps and nothing else.
        const Dataset noisy = bw::generate_protocol(name, options(5, 12, 300));
        CHECK(all_bytes(noisy.capture()) == all_bytes(data.capture()));
        CHECK(csv(noisy) != csv(data));
        CHECK(noisy.frames().size() == data.frames().size());

        // Options out of range are refused, and no frames is a valid request.
        CHECK_THROWS_AS(bw::generate_protocol(name, options(1, 100001)), std::invalid_argument);
        CHECK_THROWS_AS(bw::generate_protocol(name, options(1, 1, 501)), std::invalid_argument);
        CHECK(bw::generate_protocol(name, options(1, 0)).frame_count() == 0);
        CHECK(bw::generate_protocol(name, options(1, 1, 500)).frame_count() == 1);
    }
}

TEST_CASE("the most frames that can be asked for can be generated") {
    const Dataset d = bw::generate_protocol("modbus-rtu", options(1, 100000));
    CHECK(d.frame_count() == 100000);
    CHECK(d.capture().event_count() == 800000);
}

// ---- Modbus RTU ------------------------------------------------------------

TEST_CASE("modbus-rtu: its model is exactly the documented one") {
    CHECK(bw::describe_model(bw::protocol_model("modbus-rtu")) ==
          "framing: idle gap, at least 4010415 ns\n"
          "message type 0 \"request\"\n"
          "  0 \"address\"  enum      8 bits @0\n"
          "  1 \"function\" enum      8 bits @8\n"
          "  2 \"register\" payload   16 bits @16\n"
          "  3 \"quantity\" payload   16 bits @32\n"
          "  4 \"crc\"      checksum  16 bits @48 little-endian covers 0..3 CRC-16/MODBUS\n");
    CHECK(bw::protocol_summary("modbus-rtu") ==
          "Modbus RTU requests for functions 3 and 4, 9600 baud 8N1, one event per byte");
}

TEST_CASE("modbus-rtu: a seed is a capture, the same on every platform") {
    // Produced by an independent implementation in Python, from the algorithm
    // documented in src/protocols/modbus_rtu.cpp.
    CHECK(csv(bw::generate_protocol("modbus-rtu", options(1, 3))) ==
          read_file("synth_modbus_rtu_seed1.csv"));
    CHECK(csv(bw::generate_protocol("modbus-rtu", options(7, 3, 300))) ==
          read_file("synth_modbus_rtu_seed7_jitter300.csv"));
}

TEST_CASE("modbus-rtu: the frames are eight bytes, in the ranges they claim, with the right CRC") {
    const Dataset d = bw::generate_protocol("modbus-rtu", options(3, 50));
    const Capture c = d.capture();
    REQUIRE(d.frame_count() == 50);
    CHECK(c.event_count() == 400);
    CHECK(c.channel_count() == 2);
    CHECK(c.channel_name(1) == "rs485");

    std::set<unsigned> addresses, functions;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        CHECK(d.frame(i).first_event == i * 8);
        CHECK(d.frame(i).event_count == 8);
        CHECK(d.frame_message_type(i) == 0);

        const Bytes f = frame_bytes(c, d.frame(i));
        REQUIRE(f.size() == 8);
        CHECK(f[0] >= 1);
        CHECK(f[0] <= 3);
        CHECK((f[1] == 3 || f[1] == 4));
        const unsigned quantity = (static_cast<unsigned>(f[4]) << 8) | f[5];
        CHECK(quantity >= 1);
        CHECK(quantity <= 125);
        addresses.insert(f[0]);
        functions.insert(f[1]);

        // The generator's own CRC against the inference stage's, which has the
        // published check values: two implementations, one answer.
        const Bytes body(f.begin(), f.begin() + 6);
        const std::uint16_t crc = catalogue_crc(body);
        CHECK(f[6] == (crc & 0xFF));
        CHECK(f[7] == (crc >> 8));
    }
    CHECK(addresses.size() == 3);               // all of them turn up in fifty frames
    CHECK(functions.size() == 2);

    for (std::size_t i = 0; i < c.event_count(); ++i) {
        CHECK(c.event(i).has_time);
        CHECK(c.event(i).channel == 1);
        CHECK(c.event(i).direction == bw::Direction::Unknown);
        CHECK_FALSE(c.event(i).has_id);
        CHECK(c.event_size(i) == 1);
    }
}

TEST_CASE("modbus-rtu: without jitter, bytes are one character apart and frames a whole number of characters") {
    const Dataset d = bw::generate_protocol("modbus-rtu", options(4, 50, 0));
    const Capture c = d.capture();
    std::set<std::uint64_t> pauses;
    for (std::size_t i = 1; i < c.event_count(); ++i) {
        const std::uint64_t interval = static_cast<std::uint64_t>(c.event(i).time_ns - c.event(i - 1).time_ns);
        if (i % 8 != 0) {
            CHECK(interval == kChar);                              // inside a frame
        } else {
            CHECK(interval % kChar == 0);                          // between frames: 6 to 21 characters
            CHECK(interval >= 6 * kChar);
            CHECK(interval <= 21 * kChar);
            pauses.insert(interval);
        }
    }
    CHECK(pauses.size() >= 2);                                     // the pause is not constant
}

TEST_CASE("modbus-rtu: with the most jitter, a frame still holds together and its neighbours stay apart") {
    const Dataset d = bw::generate_protocol("modbus-rtu", options(4, 50, 500));
    const Capture c = d.capture();
    const std::uint64_t max_delay = kChar * 500 / 1000;
    const std::uint64_t idle      = d.model().framing().idle_gap_ns;
    bool moved = false;
    for (std::size_t i = 1; i < c.event_count(); ++i) {
        const std::int64_t interval = c.event(i).time_ns - c.event(i - 1).time_ns;
        REQUIRE(interval > 0);                                     // time moves forward, strictly
        if (i % 8 != 0) {
            CHECK(static_cast<std::uint64_t>(interval) + max_delay > kChar);       // at least a character less the delay
            CHECK(static_cast<std::uint64_t>(interval) < kChar + max_delay);
            CHECK(static_cast<std::uint64_t>(interval) < idle);
            moved = moved || static_cast<std::uint64_t>(interval) != kChar;
        } else {
            CHECK(static_cast<std::uint64_t>(interval) > idle);
        }
    }
    CHECK(moved);
}

TEST_CASE("modbus-rtu: cutting the capture where the model says a gap is finds exactly the true frames") {
    for (std::uint32_t jitter = 0; jitter <= 500; jitter += 250) {
        for (std::uint64_t seed = 1; seed <= 20; ++seed) {
            const Dataset d = bw::generate_protocol("modbus-rtu", options(seed, 30, jitter));
            const std::vector<FrameSpan> found = split_by_gap(d.capture(), d.model().framing().idle_gap_ns);
            const bw::SegmentationScore s = bw::score_segmentation(d.frames(), found);
            INFO("seed " << seed << ", jitter " << jitter);
            CHECK(s.truth_frames == 30);
            CHECK(s.found_frames == 30);
            CHECK(s.exact_frames == 30);
            CHECK(s.boundary_hits == s.truth_boundaries);
            CHECK(s.boundary_hits == s.found_boundaries);
        }
    }
}

TEST_CASE("modbus-rtu: the same seed gives the same frames whatever the jitter, and fewer frames are a prefix") {
    const Dataset quiet = bw::generate_protocol("modbus-rtu", options(9, 20, 0));
    const Dataset loud  = bw::generate_protocol("modbus-rtu", options(9, 20, 500));
    CHECK(all_bytes(quiet.capture()) == all_bytes(loud.capture()));
    // Asking for fewer frames does not change what comes first.
    const Dataset fewer = bw::generate_protocol("modbus-rtu", options(9, 5, 0));
    const Bytes five = all_bytes(fewer.capture());
    const Bytes twenty = all_bytes(quiet.capture());
    CHECK(Bytes(twenty.begin(), twenty.begin() + static_cast<std::ptrdiff_t>(five.size())) == five);
}

TEST_CASE("modbus-rtu: no frames is an empty capture with just a header") {
    const Dataset d = bw::generate_protocol("modbus-rtu", options(1, 0));
    CHECK(d.capture().event_count() == 0);
    CHECK(d.frame_count() == 0);
    CHECK(csv(d) == "# bitwise-capture 1\ntime_ns,channel,direction,id,data\n");
}

TEST_CASE("modbus-rtu: the reference decoder accepts what is valid and refuses each way of not being") {
    CHECK(bw::protocol_conforms("modbus-rtu", request(1, 3, 0, 1)));
    CHECK(bw::protocol_conforms("modbus-rtu", request(247, 4, 65535, 125)));
    CHECK(bw::protocol_conforms("modbus-rtu", request(17, 3, 40001, 10)));     // not only what the generator makes

    // The address, the function and the quantity have limits of their own.
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(0, 3, 0, 1)));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(248, 3, 0, 1)));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(1, 2, 0, 1)));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(1, 5, 0, 1)));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(1, 3, 0, 0)));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(1, 3, 0, 126)));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", request(1, 3, 0, 0x0101)));   // the high byte counts

    // Length.
    const Bytes good = request(1, 3, 10, 5);
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", Bytes(good.begin(), good.end() - 1)));
    Bytes longer = good;
    longer.push_back(0);
    CHECK_FALSE(bw::protocol_conforms("modbus-rtu", longer));
}

TEST_CASE("modbus-rtu: flipping any one bit of a valid frame makes it fail, so the CRC is really checked") {
    const Bytes good = request(2, 4, 1234, 7);
    REQUIRE(bw::protocol_conforms("modbus-rtu", good));
    for (std::size_t byte = 0; byte < good.size(); ++byte) {
        for (int bit = 0; bit < 8; ++bit) {
            Bytes bad = good;
            bad[byte] = static_cast<std::uint8_t>(bad[byte] ^ (1u << bit));
            INFO("byte " << byte << ", bit " << bit);
            CHECK_FALSE(bw::protocol_conforms("modbus-rtu", bad));
        }
    }
}
