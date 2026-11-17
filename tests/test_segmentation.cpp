// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 3, segmentation by gaps. The cases are written so that each rule of the
// stage has one that fails if the rule is broken: the ratio at its exact
// boundary, which of two holes is the widest, a tie, gaps of zero, and gaps so
// large that comparing ratios by multiplying them would overflow.

#include "doctest.h"

#include <cstdint>
#include <stdexcept>
#include <vector>

#include "bw/segmentation.h"

using bw::Capture;
using bw::EventInfo;
using bw::FrameSpan;
using bw::Segmentation;
using bw::SegmentationOptions;

namespace {

// One byte per event, at the given times.
Capture at_times(const std::vector<std::int64_t>& times) {
    Capture c;
    for (std::size_t i = 0; i < times.size(); ++i) {
        EventInfo info;
        info.has_time = true;
        info.time_ns  = times[i];
        c.add_event(info, std::vector<std::uint8_t>(1, static_cast<std::uint8_t>(i)));
    }
    return c;
}

// Times from a list of gaps, starting at 0.
std::vector<std::int64_t> times_of(const std::vector<std::int64_t>& gaps) {
    std::vector<std::int64_t> t(1, 0);
    for (std::size_t i = 0; i < gaps.size(); ++i) {
        t.push_back(t.back() + gaps[i]);
    }
    return t;
}

Segmentation cut(const std::vector<std::int64_t>& gaps, std::uint32_t ratio = 3) {
    SegmentationOptions options;
    options.min_gap_ratio = ratio;
    return bw::segment_by_gaps(at_times(times_of(gaps)), options);
}

std::vector<std::uint64_t> sizes(const Segmentation& s) {
    std::vector<std::uint64_t> out;
    for (std::size_t i = 0; i < s.frame_count(); ++i) {
        out.push_back(s.frame(i).event_count);
    }
    return out;
}

} // namespace

TEST_CASE("segmentation: short gaps inside frames, long ones between them") {
    // Three frames of four events: 1000 ns inside, 20000 ns between.
    const Segmentation s = cut({1000, 1000, 1000, 20000, 1000, 1000, 1000, 20000, 1000, 1000, 1000});
    const bw::SegmentationInfo info = s.info();
    CHECK(info.found);
    CHECK(info.idle_gap_ns == 20000);
    CHECK(info.longest_inner_gap_ns == 1000);
    CHECK(info.inner_gaps == 9);
    CHECK(info.outer_gaps == 2);
    REQUIRE(s.frame_count() == 3);
    CHECK(s.frame(0).first_event == 0);
    CHECK(s.frame(0).event_count == 4);
    CHECK(s.frame(1).first_event == 4);
    CHECK(s.frame(1).event_count == 4);
    CHECK(s.frame(2).first_event == 8);
    CHECK(s.frame(2).event_count == 4);
}

TEST_CASE("segmentation: the frames cover the capture, in order, with no gaps between them") {
    const Segmentation s = cut({10, 10, 500, 10, 500, 500, 10, 10, 10});
    REQUIRE(s.info().found);
    std::uint64_t next = 0;
    for (std::size_t i = 0; i < s.frame_count(); ++i) {
        CHECK(s.frame(i).first_event == next);
        CHECK(s.frame(i).event_count > 0);
        next += s.frame(i).event_count;
    }
    CHECK(next == 10);
    CHECK(sizes(s) == std::vector<std::uint64_t>({3, 2, 1, 4}));
    CHECK(s.frames().size() == s.frame_count());
    CHECK_THROWS_AS(s.frame(s.frame_count()), std::out_of_range);
}

TEST_CASE("segmentation: the ratio between the groups has to reach the option, exactly") {
    // 1000 inside; 2999 between is a ratio of 2.999, and 3000 is 3.
    CHECK_FALSE(cut({1000, 1000, 2999, 1000, 1000}, 3).info().found);
    CHECK(cut({1000, 1000, 3000, 1000, 1000}, 3).info().found);
    // The option moves the line.
    CHECK(cut({1000, 1000, 2999, 1000, 1000}, 2).info().found);
    CHECK_FALSE(cut({1000, 1000, 3000, 1000, 1000}, 4).info().found);
    CHECK(cut({1000, 1000, 4000, 1000, 1000}, 4).info().found);
    // A frame boundary is a gap of at least the idle gap, not more than it.
    const Segmentation s = cut({1000, 1000, 3000, 1000, 3000, 1000}, 3);
    CHECK(s.info().idle_gap_ns == 3000);
    CHECK(sizes(s) == std::vector<std::uint64_t>({3, 2, 2}));
}

TEST_CASE("segmentation: it says nothing was found instead of cutting at noise") {
    const SegmentationOptions options;
    CHECK_FALSE(bw::segment_by_gaps(Capture(), options).info().found);
    CHECK_FALSE(bw::segment_by_gaps(at_times(std::vector<std::int64_t>(1, 5)), options).info().found);
    CHECK_FALSE(cut({1000, 1000, 1000, 1000}).info().found);            // the same gap everywhere
    CHECK_FALSE(cut({0, 0, 0, 0}).info().found);                        // everything at one instant
    CHECK_FALSE(cut({1000, 1000, 1000}, 1).info().found);               // not even when any hole would do
    CHECK_FALSE(cut({1000, 1000, 1000}, 0).info().found);
    CHECK_FALSE(cut({1000, 1100, 1200, 1300, 1400, 1500}).info().found);   // an even spread
    CHECK(cut({1000, 1000, 1000, 1000}).frame_count() == 0);

    // An event without a time makes the whole capture unsegmentable by time, and
    // its (meaningless) time is not read as a gap: after events at 1000 to 1300 an
    // untimed one would otherwise look like a jump backwards of 1300 ns.
    Capture c;
    EventInfo timed;
    timed.has_time = true;
    for (int i = 0; i < 4; ++i) {
        timed.time_ns = 1000 + 100 * i;
        c.add_event(timed, std::vector<std::uint8_t>(1, static_cast<std::uint8_t>(i)));
    }
    c.add_event(EventInfo(), std::vector<std::uint8_t>(1, 9));
    CHECK_FALSE(bw::segment_by_gaps(c, options).info().found);
}

TEST_CASE("segmentation: with two holes the wider one, in ratio, is the cut") {
    // Gaps 10, 40, 400: the hole from 10 to 40 is 4 times, from 40 to 400 is 10 times.
    const Segmentation s = cut({10, 10, 40, 10, 400, 40, 10});
    CHECK(s.info().found);
    CHECK(s.info().idle_gap_ns == 400);
    CHECK(s.info().longest_inner_gap_ns == 40);
    CHECK(sizes(s) == std::vector<std::uint64_t>({5, 3}));
    // Wider in ratio, not in difference: 10 to 50 is 5 times and 40 apart, 50 to
    // 200 is 4 times and 150 apart.
    const Segmentation t = cut({10, 50, 10, 200, 10});
    CHECK(t.info().idle_gap_ns == 50);
    CHECK(sizes(t) == std::vector<std::uint64_t>({2, 2, 2}));
}

TEST_CASE("segmentation: equal holes go to the first, so the answer is the same every time") {
    // 10 -> 100 and 100 -> 1000 are both ten times: the first wins.
    const Segmentation s = cut({10, 100, 1000, 10});
    CHECK(s.info().idle_gap_ns == 100);
    CHECK(sizes(s) == std::vector<std::uint64_t>({2, 1, 2}));
}

TEST_CASE("segmentation: events at the same instant are one frame") {
    // Bursts: gaps of 0 inside and 5000 between. A gap of 0 counts as 1 ns for
    // the ratio, so the burst against the rest is a ratio of 5000, not infinite.
    const Segmentation s = cut({0, 0, 5000, 0, 5000, 0, 0, 0});
    CHECK(s.info().found);
    CHECK(s.info().idle_gap_ns == 5000);
    CHECK(s.info().longest_inner_gap_ns == 0);
    CHECK(sizes(s) == std::vector<std::uint64_t>({3, 2, 4}));
}

TEST_CASE("segmentation: holes are compared exactly, also when multiplying them would overflow") {
    // Gaps near 2^60, so a product of two of them does not fit in 64 bits.
    // Sorted 2e17, 7e17, 2.1007e18: 3.5 times then 3.001 times, and the first is wider.
    const std::int64_t a = 200000000000000000LL;
    const std::int64_t b = 700000000000000000LL;
    const Segmentation first = cut({a, b, 2100700000000000000LL}, 3);
    CHECK(first.info().idle_gap_ns == static_cast<std::uint64_t>(b));
    CHECK(sizes(first) == std::vector<std::uint64_t>({2, 1, 1}));

    // 3.5 times then 3.6 times: the second is wider, though both have the same integer part.
    const Segmentation second = cut({a, b, 2520000000000000000LL}, 3);
    CHECK(second.info().idle_gap_ns == 2520000000000000000ULL);
    CHECK(sizes(second) == std::vector<std::uint64_t>({3, 1}));

    // The same ratio twice, exactly: a tie, so the first.
    const Segmentation tie = cut({a, 3 * a, 9 * a}, 3);
    CHECK(tie.info().idle_gap_ns == static_cast<std::uint64_t>(3 * a));

    // Whole numbers apart but with a remainder in only one of them.
    const Segmentation remainder = cut({a, 3 * a, 9 * a + 1}, 3);
    CHECK(remainder.info().idle_gap_ns == static_cast<std::uint64_t>(9 * a + 1));
}

TEST_CASE("segmentation: the cuts are where the long gaps are, with the short ones around them") {
    // 7 7 90 8 7 7 95 7: the hole from 8 to 90 is the widest, so 90 and 95 cut.
    CHECK(sizes(cut({7, 7, 90, 8, 7, 7, 95, 7})) == std::vector<std::uint64_t>({3, 4, 2}));
}

TEST_CASE("segmentation: frame bytes and sizes join the bytes of every event of a frame") {
    Capture c;
    EventInfo e;
    e.has_time = true;
    e.time_ns  = 0;
    c.add_event(e, std::vector<std::uint8_t>({1, 2}));
    e.time_ns = 10;
    c.add_event(e, std::vector<std::uint8_t>({3}));
    e.time_ns = 5000;
    c.add_event(e, std::vector<std::uint8_t>({4, 5, 6}));

    FrameSpan whole;
    whole.event_count = 3;
    FrameSpan tail;
    tail.first_event = 2;
    tail.event_count = 1;
    CHECK(bw::frame_bytes(c, whole) == std::vector<std::uint8_t>({1, 2, 3, 4, 5, 6}));
    CHECK(bw::frame_bytes(c, tail) == std::vector<std::uint8_t>({4, 5, 6}));
    CHECK(bw::frame_size(c, whole) == 6);
    CHECK(bw::frame_size(c, tail) == 3);

    FrameSpan past;
    past.first_event = 2;
    past.event_count = 2;
    CHECK_THROWS_AS(bw::frame_bytes(c, past), std::out_of_range);
    CHECK_THROWS_AS(bw::frame_size(c, past), std::out_of_range);

    // The frames of one size, in capture order: [1 2 3] is 3 bytes and [4 5 6] is 3 bytes.
    const Segmentation s = bw::segment_by_gaps(c, SegmentationOptions());
    REQUIRE(s.info().found);
    REQUIRE(s.frame_count() == 2);
    CHECK(bw::frames_of_size(c, s, 3).size() == 2);
    CHECK(bw::frames_of_size(c, s, 3)[1].first_event == 2);
    CHECK(bw::frames_of_size(c, s, 4).empty());
}
