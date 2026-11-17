// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The capture reader is the front door of every later stage, so these tests
// are about what it refuses as much as what it accepts. A malformed file has
// to be rejected with the line it is on, whole, and never half-read: the
// stages downstream assume that a capture that loaded is a capture that was
// read in full.

#include "doctest.h"

#include <chrono>
#include <cstdint>
#include <fstream>
#include <initializer_list>
#include <iterator>
#include <limits>
#include <string>
#include <vector>

#include "bw/capture.h"
#include "bw/crc_search.h"

using bw::Capture;
using bw::Direction;
using bw::EventInfo;

namespace {

typedef std::vector<std::uint8_t> Bytes;

struct Failure {
    bool        threw = false;
    std::size_t line  = 0;
    std::string what;
};

Failure parse_failure(const std::string& text) {
    Failure f;
    try {
        bw::parse_capture_csv(text);
    } catch (const bw::CaptureError& e) {
        f.threw = true;
        f.line  = e.line();
        f.what  = e.what();
    }
    return f;
}

bool mentions(const std::string& what, const std::string& part) {
    return what.find(part) != std::string::npos;
}

Bytes bytes_of(std::initializer_list<int> values) {
    Bytes out;
    for (std::initializer_list<int>::const_iterator it = values.begin(); it != values.end(); ++it) {
        out.push_back(static_cast<std::uint8_t>(*it));
    }
    return out;
}

std::uint64_t g_rng = 0x9E3779B97F4A7C15ULL;

std::uint64_t next_random() {
    g_rng ^= g_rng << 13;
    g_rng ^= g_rng >> 7;
    g_rng ^= g_rng << 17;
    return g_rng;
}

// Events of every kind: timed or not, with and without an identifier, on a few
// channels, with zero to twelve bytes. Time only ever goes forward.
Capture random_capture() {
    Capture capture;
    const char* const names[] = {"uart1", "can0", "spi 2"};
    const std::size_t channels = next_random() % 4;
    for (std::size_t c = 0; c < channels; ++c) {
        capture.add_channel(names[c]);
    }
    std::int64_t time = static_cast<std::int64_t>(next_random() % 1000000) - 500000;
    const std::size_t events = next_random() % 24;
    for (std::size_t i = 0; i < events; ++i) {
        EventInfo info;
        info.has_time = (next_random() % 4) != 0;
        if (info.has_time) {
            time += static_cast<std::int64_t>(next_random() % 2000);
            info.time_ns = time;
        }
        info.channel   = static_cast<std::uint32_t>(next_random() % capture.channel_count());
        info.direction = static_cast<Direction>(next_random() % 3);
        info.has_id    = (next_random() % 3) == 0;
        if (info.has_id) {
            info.id = static_cast<std::uint32_t>(next_random());
        }
        Bytes bytes(next_random() % 13);
        for (std::size_t b = 0; b < bytes.size(); ++b) {
            bytes[b] = static_cast<std::uint8_t>(next_random());
        }
        capture.add_event(info, bytes);
    }
    return capture;
}

} // namespace

// ---- What is accepted ------------------------------------------------------

TEST_CASE("a file with only a data column is a capture of unnamed, untimed events") {
    const Capture c = bw::parse_capture_csv("data\n01 02\nff\n");
    REQUIRE(c.event_count() == 2);
    CHECK(c.event_bytes(0) == bytes_of({0x01, 0x02}));
    CHECK(c.event_bytes(1) == bytes_of({0xff}));
    CHECK(c.event_size(0) == 2);
    CHECK(c.total_bytes() == 3);
    CHECK(c.channel_count() == 1);
    CHECK(c.channel_name(0) == "");
    const EventInfo e = c.event(0);
    CHECK_FALSE(e.has_time);
    CHECK(e.channel == 0);
    CHECK(e.direction == Direction::Unknown);
    CHECK_FALSE(e.has_id);
    CHECK_FALSE(c.fully_timed());
}

TEST_CASE("columns come in any order and any case") {
    const Capture c = bw::parse_capture_csv(
        "ID, Data ,TIME_NS,Direction,CHANNEL\n"
        "0x123, de ad,  42 ,RX, can0\n");
    REQUIRE(c.event_count() == 1);
    const EventInfo e = c.event(0);
    CHECK(e.has_time);
    CHECK(e.time_ns == 42);
    CHECK(e.direction == Direction::Rx);
    CHECK(e.has_id);
    CHECK(e.id == 0x123u);
    CHECK(c.channel_name(e.channel) == "can0");
    CHECK(c.event_bytes(0) == bytes_of({0xde, 0xad}));
    CHECK(c.fully_timed());
}

TEST_CASE("columns from a later version are ignored") {
    const Capture c = bw::parse_capture_csv("data,voltage_mv,time_ns\n01,3300,5\n");
    REQUIRE(c.event_count() == 1);
    CHECK(c.event(0).time_ns == 5);
    CHECK(c.event_bytes(0) == bytes_of({0x01}));
}

TEST_CASE("comments, blank lines, CRLF and a byte-order mark are all fine") {
    const std::string text = std::string("\xEF\xBB\xBF") +
        "# a comment\r\n\r\n   # indented comment\r\ndata\r\n\r\n01\r\n02";   // no final newline
    const Capture c = bw::parse_capture_csv(text);
    REQUIRE(c.event_count() == 2);
    CHECK(c.event_bytes(1) == bytes_of({0x02}));
}

TEST_CASE("a header alone is an empty capture, and a blank line is not an event") {
    CHECK(bw::parse_capture_csv("data\n").event_count() == 0);
    CHECK(bw::parse_capture_csv("data\n\n01\n\n").event_count() == 1);
    // On a one-column header a row of just a comma has two fields: refused, not read as empty.
    CHECK(parse_failure("data\n,\n").line == 2);
}

TEST_CASE("an event with no bytes, such as a break, is allowed") {
    const Capture c = bw::parse_capture_csv("time_ns,data\n10,\n20,01\n");
    REQUIRE(c.event_count() == 2);
    CHECK(c.event_size(0) == 0);
    CHECK(c.event_bytes(0).empty());
    CHECK(c.event_size(1) == 1);
    CHECK(c.total_bytes() == 1);
}

TEST_CASE("hex data: pairs, optionally separated by blanks, either case") {
    CHECK(bw::parse_capture_csv("data\n0102\n").event_bytes(0) == bytes_of({0x01, 0x02}));
    CHECK(bw::parse_capture_csv("data\n01  02\n").event_bytes(0) == bytes_of({0x01, 0x02}));
    CHECK(bw::parse_capture_csv("data\n 01\t02 \n").event_bytes(0) == bytes_of({0x01, 0x02}));
    CHECK(bw::parse_capture_csv("data\nAbCd\n").event_bytes(0) == bytes_of({0xab, 0xcd}));
    CHECK(bw::parse_capture_csv("data\n00 ff 7f 80\n").event_bytes(0) == bytes_of({0x00, 0xff, 0x7f, 0x80}));
}

TEST_CASE("time: signed integers, with the whole 64-bit range") {
    CHECK(bw::parse_capture_csv("time_ns,data\n0,01\n").event(0).time_ns == 0);
    CHECK(bw::parse_capture_csv("time_ns,data\n+5,01\n").event(0).time_ns == 5);
    CHECK(bw::parse_capture_csv("time_ns,data\n-7,01\n").event(0).time_ns == -7);
    const Capture c = bw::parse_capture_csv(
        "time_ns,data\n-9223372036854775808,01\n9223372036854775807,02\n");
    CHECK(c.event(0).time_ns == std::numeric_limits<std::int64_t>::min());
    CHECK(c.event(1).time_ns == std::numeric_limits<std::int64_t>::max());
}

TEST_CASE("an empty time is an untimed event, and may sit among timed ones") {
    const Capture c = bw::parse_capture_csv("time_ns,data\n10,01\n,02\n10,03\n");
    CHECK(c.event(0).has_time);
    CHECK_FALSE(c.event(1).has_time);
    CHECK(c.event(2).has_time);
    CHECK_FALSE(c.fully_timed());
}

TEST_CASE("identifiers: hex, with or without a prefix, up to 32 bits") {
    CHECK(bw::parse_capture_csv("id,data\n7e8,01\n").event(0).id == 0x7e8u);
    CHECK(bw::parse_capture_csv("id,data\n0X7E8,01\n").event(0).id == 0x7e8u);
    CHECK(bw::parse_capture_csv("id,data\n0,01\n").event(0).has_id);
    CHECK(bw::parse_capture_csv("id,data\nFFFFFFFF,01\n").event(0).id == 0xFFFFFFFFu);
    CHECK(bw::parse_capture_csv("id,data\n0x00000001,01\n").event(0).id == 1u);
    CHECK_FALSE(bw::parse_capture_csv("id,data\n,01\n").event(0).has_id);
}

TEST_CASE("channels are numbered by first appearance, and the unnamed one is 0") {
    const Capture c = bw::parse_capture_csv(
        "channel,data\nb,01\na,02\nb,03\n,04\n");
    REQUIRE(c.channel_count() == 3);
    CHECK(c.channel_name(0) == "");
    CHECK(c.channel_name(1) == "b");
    CHECK(c.channel_name(2) == "a");
    CHECK(c.event(0).channel == 1);
    CHECK(c.event(1).channel == 2);
    CHECK(c.event(2).channel == 1);
    CHECK(c.event(3).channel == 0);
}

// ---- What is refused -------------------------------------------------------

TEST_CASE("a file without a header is refused") {
    CHECK(parse_failure("").threw);
    CHECK(parse_failure("# only a comment\n\n").threw);
    CHECK(parse_failure("").line == 0);
}

TEST_CASE("a header must have a data column, once") {
    const Failure none = parse_failure("# c\ntime_ns,channel\n1,a\n");
    CHECK(none.threw);
    CHECK(none.line == 2);
    CHECK(mentions(none.what, "'data'"));

    const Failure twice = parse_failure("data,time_ns,Data\n01,1,02\n");
    CHECK(twice.threw);
    CHECK(twice.line == 1);
    CHECK(mentions(twice.what, "two 'data' columns"));
}

TEST_CASE("a row with the wrong number of fields is refused, with its line") {
    const Failure few = parse_failure("time_ns,data\n1,01\n2\n");
    CHECK(few.line == 3);
    CHECK(mentions(few.what, "expected 2 fields, found 1"));
    const Failure many = parse_failure("data\n01,02\n");
    CHECK(many.line == 2);
    CHECK(mentions(many.what, "expected 1 fields, found 2"));
}

TEST_CASE("quotes are refused instead of being half-understood") {
    const Failure f = parse_failure("data,channel\n01,\"a,b\"\n");
    CHECK(f.threw);
    CHECK(f.line == 2);
    CHECK(mentions(f.what, "quot"));
    CHECK(parse_failure("\"data\"\n01\n").line == 1);
}

TEST_CASE("bad hex data: odd digits, a bad character, a split byte") {
    const Failure odd = parse_failure("data\n01\n0a1\n");
    CHECK(odd.line == 3);
    CHECK(mentions(odd.what, "odd number of hex digits in '0a1'"));
    const Failure bad = parse_failure("data\n0g\n");
    CHECK(mentions(bad.what, "'g' is not a hex digit"));
    const Failure split = parse_failure("data\n0 1\n");
    CHECK(split.threw);
    CHECK(mentions(split.what, "odd number"));
    CHECK(mentions(parse_failure("data\n0x01\n").what, "'x' is not a hex digit"));
}

TEST_CASE("bad time: not an integer, or out of range") {
    const char* const bad[] = {"1.5", "1e3", "abc", "12ab", "+", "-", "0x10", "9223372036854775808",
                               "-9223372036854775809", "99999999999999999999999"};
    for (std::size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        const Failure f = parse_failure(std::string("time_ns,data\n") + bad[i] + ",01\n");
        INFO("time_ns = " << bad[i]);
        CHECK(f.threw);
        CHECK(f.line == 2);
        CHECK(mentions(f.what, "time_ns"));
    }
}

TEST_CASE("time that goes backwards is refused, even across untimed events") {
    const Failure f = parse_failure("time_ns,data\n100,01\n50,02\n");
    CHECK(f.line == 3);
    CHECK(mentions(f.what, "time goes backwards"));
    CHECK(parse_failure("time_ns,data\n100,01\n,02\n99,03\n").line == 4);
    CHECK_FALSE(parse_failure("time_ns,data\n100,01\n100,02\n").threw);   // equal is fine
}

TEST_CASE("bad direction and bad identifier are refused") {
    const Failure d = parse_failure("direction,data\nrx,01\nsideways,02\n");
    CHECK(d.line == 3);
    CHECK(mentions(d.what, "direction"));
    const char* const bad[] = {"123456789", "0x", "xyz", "0x1g", "-1"};
    for (std::size_t i = 0; i < sizeof(bad) / sizeof(bad[0]); ++i) {
        const Failure f = parse_failure(std::string("id,data\n") + bad[i] + ",01\n");
        INFO("id = " << bad[i]);
        CHECK(f.threw);
        CHECK(mentions(f.what, "id"));
    }
}

TEST_CASE("the line number counts every physical line, comments and blanks included") {
    const Failure f = parse_failure("# one\n\n  \ndata\n# five\n01\nzz\n");
    CHECK(f.line == 7);
}

// ---- The capture itself ----------------------------------------------------

TEST_CASE("reading past the end, or on a missing channel, is an error") {
    Capture c;
    EventInfo e;
    c.add_event(e, bytes_of({1}));
    CHECK_THROWS_AS(c.event(1), std::out_of_range);
    CHECK_THROWS_AS(c.event_bytes(1), std::out_of_range);
    CHECK_THROWS_AS(c.event_size(1), std::out_of_range);
    CHECK_THROWS_AS(c.channel_name(1), std::out_of_range);
    e.channel = 5;
    CHECK_THROWS_AS(c.add_event(e, Bytes()), std::invalid_argument);
    CHECK(c.event_count() == 1);                 // a refused event leaves nothing behind
    CHECK(c.total_bytes() == 1);
}

TEST_CASE("a capture refuses an event that goes back in time, and stays usable") {
    Capture c;
    EventInfo e;
    e.has_time = true;
    e.time_ns  = 100;
    c.add_event(e, bytes_of({1}));
    e.time_ns = 99;
    CHECK_THROWS_AS(c.add_event(e, bytes_of({2, 3})), std::invalid_argument);
    CHECK(c.event_count() == 1);
    CHECK(c.total_bytes() == 1);
    e.time_ns = 100;
    c.add_event(e, bytes_of({4}));
    CHECK(c.event_count() == 2);
    CHECK(c.fully_timed());
}

TEST_CASE("unused fields do not make two equal captures differ") {
    EventInfo plain;
    EventInfo dirty;
    dirty.time_ns = 12345;              // has_time is false, so this means nothing
    dirty.id      = 0xDEADu;            // has_id is false
    Capture a, b;
    a.add_event(plain, bytes_of({1}));
    b.add_event(dirty, bytes_of({1}));
    CHECK(a.equals(b));
    CHECK(bw::format_capture_csv(a) == bw::format_capture_csv(b));
    EventInfo other = plain;
    other.direction = Direction::Tx;
    Capture c;
    c.add_event(other, bytes_of({1}));
    CHECK_FALSE(a.equals(c));
}

TEST_CASE("equals tells bytes, event boundaries and channels apart") {
    Capture a, b, c, d;
    EventInfo e;
    a.add_event(e, bytes_of({1, 2}));
    b.add_event(e, bytes_of({1}));
    b.add_event(e, bytes_of({2}));          // same bytes, split into two events
    CHECK_FALSE(a.equals(b));
    c.add_event(e, bytes_of({1, 3}));
    CHECK_FALSE(a.equals(c));
    Capture split_a, split_b;               // the same three bytes in two events, cut differently
    split_a.add_event(e, bytes_of({1}));
    split_a.add_event(e, bytes_of({2, 3}));
    split_b.add_event(e, bytes_of({1, 2}));
    split_b.add_event(e, bytes_of({3}));
    CHECK_FALSE(split_a.equals(split_b));
    EventInfo on_x = e;
    on_x.channel = d.add_channel("x");      // the same event, on a named channel
    d.add_event(on_x, bytes_of({1, 2}));
    CHECK_FALSE(a.equals(d));
}

TEST_CASE("equals compares channels by name, not by number, and ignores unused ones") {
    Capture a, b;
    const std::uint32_t ax = a.add_channel("x");
    const std::uint32_t ay = a.add_channel("y");
    a.add_channel("nobody uses this");
    const std::uint32_t by = b.add_channel("y");      // the other way round
    const std::uint32_t bx = b.add_channel("x");
    EventInfo e;
    e.channel = ay; a.add_event(e, bytes_of({1}));
    e.channel = ax; a.add_event(e, bytes_of({2}));
    e.channel = by; b.add_event(e, bytes_of({1}));
    e.channel = bx; b.add_event(e, bytes_of({2}));
    CHECK(a.channel_count() != b.channel_count());
    CHECK(a.equals(b));
    CHECK(b.equals(a));

    Capture swapped;                                   // same names, but on the wrong events
    const std::uint32_t sx = swapped.add_channel("x");
    const std::uint32_t sy = swapped.add_channel("y");
    e.channel = sx; swapped.add_event(e, bytes_of({1}));
    e.channel = sy; swapped.add_event(e, bytes_of({2}));
    CHECK_FALSE(a.equals(swapped));
}

TEST_CASE("an empty capture is not fully timed") {
    CHECK_FALSE(Capture().fully_timed());
}

// ---- Writing and the round trip --------------------------------------------

TEST_CASE("the writer's output is exactly the documented form") {
    Capture c;
    const std::uint32_t uart = c.add_channel("uart0");
    EventInfo a;
    a.has_time = true; a.time_ns = 0; a.channel = uart; a.direction = Direction::Rx;
    c.add_event(a, bytes_of({0x01, 0x0a}));
    EventInfo b;
    b.has_id = true; b.id = 0x7e8;
    c.add_event(b, Bytes());
    EventInfo d;
    d.has_time = true; d.time_ns = 100; d.channel = uart; d.direction = Direction::Tx;
    d.has_id = true; d.id = 0;
    c.add_event(d, bytes_of({0xff}));
    CHECK(bw::format_capture_csv(c) ==
          "# bitwise-capture 1\n"
          "time_ns,channel,direction,id,data\n"
          "0,uart0,rx,,01 0a\n"
          ",,,0x7e8,\n"
          "100,uart0,tx,0x0,ff\n");
}

TEST_CASE("a channel name that cannot be written is refused") {
    const char* const names[] = {"a,b", "a\"b", "a\nb", "a\rb", " lead", "trail "};
    for (std::size_t i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        Capture c;
        c.add_channel(names[i]);
        INFO("channel name #" << i);
        CHECK_THROWS_AS(bw::format_capture_csv(c), std::invalid_argument);
    }
}

TEST_CASE("the extremes survive a round trip") {
    Capture c;
    EventInfo first;
    first.has_time = true;
    first.time_ns  = std::numeric_limits<std::int64_t>::min();
    first.has_id   = true;
    first.id       = 0xFFFFFFFFu;
    c.add_event(first, bytes_of({0x00, 0xff}));
    EventInfo last;
    last.has_time = true;
    last.time_ns  = std::numeric_limits<std::int64_t>::max();
    c.add_event(last, Bytes());
    const Capture back = bw::parse_capture_csv(bw::format_capture_csv(c));
    CHECK(back.equals(c));
}

TEST_CASE("any capture survives a round trip, and writing it again changes nothing") {
    for (int i = 0; i < 300; ++i) {
        const Capture original = random_capture();
        const std::string text = bw::format_capture_csv(original);
        const Capture back     = bw::parse_capture_csv(text);
        INFO("random capture #" << i);
        CHECK(back.equals(original));
        CHECK(bw::format_capture_csv(back) == text);
    }
}

// ---- Size ------------------------------------------------------------------

TEST_CASE("a large capture is built, written and read in time proportional to its size") {
    // Building a capture once took time proportional to the square of its size:
    // 100000 events took thirty-five seconds. A bound this loose is not about
    // speed; linear code is far inside it and quadratic code is far outside.
    const std::chrono::steady_clock::time_point start = std::chrono::steady_clock::now();

    Capture capture;
    EventInfo info;
    info.has_time = true;
    for (int i = 0; i < 50000; ++i) {
        info.time_ns = i;
        capture.add_event(info, bytes_of({i & 0xFF}));
    }
    const std::string text = bw::format_capture_csv(capture);
    const Capture back     = bw::parse_capture_csv(text);

    const long long elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - start).count();
    CHECK(back.event_count() == 50000);
    CHECK(back.equals(capture));
    CHECK_MESSAGE(elapsed_ms < 5000, "took " << elapsed_ms << " ms");
}

// ---- Statistics ------------------------------------------------------------

TEST_CASE("statistics: intervals between consecutive timed events") {
    const Capture c = bw::parse_capture_csv("time_ns,data\n0,01\n10,02\n10,03\n40,04\n");
    const bw::CaptureStats s = bw::capture_stats(c);
    CHECK(s.events == 4);
    CHECK(s.bytes == 4);
    CHECK(s.timed_events == 4);
    CHECK(s.first_time_ns == 0);
    CHECK(s.last_time_ns == 40);
    CHECK(s.interval_count == 3);            // 10, 0, 30
    CHECK(s.min_interval_ns == 0);
    CHECK(s.median_interval_ns == 10);
    CHECK(s.max_interval_ns == 30);
}

TEST_CASE("statistics: the median of an even count is the lower middle value") {
    const Capture c = bw::parse_capture_csv("time_ns,data\n0,01\n1,01\n3,01\n6,01\n10,01\n");
    const bw::CaptureStats s = bw::capture_stats(c);
    CHECK(s.interval_count == 4);            // 1, 2, 3, 4
    CHECK(s.median_interval_ns == 2);
}

TEST_CASE("statistics: untimed events are skipped, not treated as time zero") {
    const Capture c = bw::parse_capture_csv("time_ns,data\n100,01\n,02\n250,03\n");
    const bw::CaptureStats s = bw::capture_stats(c);
    CHECK(s.events == 3);
    CHECK(s.timed_events == 2);
    CHECK(s.first_time_ns == 100);
    CHECK(s.last_time_ns == 250);
    CHECK(s.interval_count == 1);
    CHECK(s.min_interval_ns == 150);
    CHECK(s.max_interval_ns == 150);
}

TEST_CASE("statistics: no timing, one timed event, and an empty capture") {
    const bw::CaptureStats none = bw::capture_stats(bw::parse_capture_csv("data\n01\n02\n"));
    CHECK(none.events == 2);
    CHECK(none.timed_events == 0);
    CHECK(none.interval_count == 0);
    const bw::CaptureStats one = bw::capture_stats(bw::parse_capture_csv("time_ns,data\n7,01\n"));
    CHECK(one.timed_events == 1);
    CHECK(one.first_time_ns == 7);
    CHECK(one.last_time_ns == 7);
    CHECK(one.interval_count == 0);
    const bw::CaptureStats empty = bw::capture_stats(Capture());
    CHECK(empty.events == 0);
    CHECK(empty.bytes == 0);
}

TEST_CASE("statistics: an interval wider than the signed range does not overflow") {
    const Capture c = bw::parse_capture_csv(
        "time_ns,data\n-9223372036854775808,01\n9223372036854775807,02\n");
    const bw::CaptureStats s = bw::capture_stats(c);
    CHECK(s.interval_count == 1);
    CHECK(s.max_interval_ns == std::numeric_limits<std::uint64_t>::max());
}

// ---- A real capture, through the stage that already exists ------------------

TEST_CASE("the checked-in Modbus capture holds two frames whose CRC the search finds") {
    const std::string path = std::string(BW_CORPUS_DIR) + "/modbus_rtu_two_requests.csv";
    std::ifstream in(path.c_str(), std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    const std::string text((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    const Capture capture = bw::parse_capture_csv(text);
    REQUIRE(capture.event_count() == 16);
    CHECK(capture.fully_timed());
    CHECK(capture.channel_name(capture.event(0).channel) == "rs485");

    // Segmentation in miniature: a pause longer than 3.5 characters (about 4 ms
    // at 9600 baud) ends a frame. The real stage is a later pull request.
    std::vector<bw::Frame> frames;
    for (std::size_t i = 0; i < capture.event_count(); ++i) {
        const bool starts = (i == 0) ||
            (capture.event(i).time_ns - capture.event(i - 1).time_ns) > 4000000;
        if (starts) {
            frames.push_back(bw::Frame());
        }
        const Bytes b = capture.event_bytes(i);
        frames.back().bytes.insert(frames.back().bytes.end(), b.begin(), b.end());
    }
    REQUIRE(frames.size() == 2);
    CHECK(frames[0].bytes == bytes_of({0x01, 0x03, 0x00, 0x00, 0x00, 0x0a, 0xc5, 0xcd}));
    CHECK(frames[1].bytes == bytes_of({0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x31, 0xca}));

    const bw::SearchReport report = bw::search(frames);
    REQUIRE(report.unique());
    CHECK(std::string(report.candidates[0].spec->name) == "CRC-16/MODBUS");
    CHECK_FALSE(report.candidates[0].layout.big_endian);
}
