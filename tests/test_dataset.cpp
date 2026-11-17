// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// A Dataset is the truth that stages are scored against, so it must not be
// able to hold a truth that contradicts itself: frames that overlap, that
// leave the capture, or that name a message type the model does not have.

#include "doctest.h"

#include <limits>
#include <stdexcept>
#include <string>
#include <vector>

#include "bw/dataset.h"
#include "model_fixtures.h"

using bw::Capture;
using bw::Dataset;
using bw::FrameSpan;

namespace {

Capture capture_of(std::size_t events) {
    Capture c;
    bw::EventInfo e;
    for (std::size_t i = 0; i < events; ++i) {
        c.add_event(e, std::vector<std::uint8_t>(1, static_cast<std::uint8_t>(i)));
    }
    return c;
}

FrameSpan span(std::uint64_t first, std::uint64_t count) {
    FrameSpan s;
    s.first_event = first;
    s.event_count = count;
    return s;
}

std::vector<std::uint32_t> types(std::size_t n, std::uint32_t type = 0) {
    return std::vector<std::uint32_t>(n, type);
}

std::string refusal(const Capture& c, const std::vector<FrameSpan>& frames,
                    const std::vector<std::uint32_t>& message_types) {
    try {
        Dataset d(c, fixtures::request_model(), frames, message_types);
    } catch (const std::invalid_argument& e) {
        return e.what();
    }
    return "";
}

bool mentions(const std::string& what, const std::string& part) {
    return what.find(part) != std::string::npos;
}

} // namespace

TEST_CASE("an empty dataset has nothing in it") {
    const Dataset d;
    CHECK(d.capture().event_count() == 0);
    CHECK(d.model().message_type_count() == 0);
    CHECK(d.frame_count() == 0);
    CHECK(d.frames().empty());
    CHECK_THROWS_AS(d.frame(0), std::out_of_range);
}

TEST_CASE("a dataset hands back what it was built from") {
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 3));
    frames.push_back(span(3, 5));
    const Dataset d(capture_of(8), fixtures::request_model(), frames, types(2));

    CHECK(d.capture().event_count() == 8);
    CHECK(bw::describe_model(d.model()) == bw::describe_model(fixtures::request_model()));
    REQUIRE(d.frame_count() == 2);
    CHECK(d.frame(1).first_event == 3);
    CHECK(d.frame(1).event_count == 5);
    CHECK(d.frame_message_type(0) == 0);
    REQUIRE(d.frames().size() == 2);
    CHECK(d.frames()[0].event_count == 3);
    CHECK_THROWS_AS(d.frame(2), std::out_of_range);
    CHECK_THROWS_AS(d.frame_message_type(2), std::out_of_range);
}

TEST_CASE("frames may touch, and may leave events between them") {
    std::vector<FrameSpan> touching;
    touching.push_back(span(0, 4));
    touching.push_back(span(4, 4));
    CHECK(refusal(capture_of(8), touching, types(2)).empty());

    std::vector<FrameSpan> apart;
    apart.push_back(span(0, 2));
    apart.push_back(span(6, 2));
    CHECK(refusal(capture_of(8), apart, types(2)).empty());
}

TEST_CASE("a frame must have events, and fit inside the capture") {
    std::vector<FrameSpan> empty;
    empty.push_back(span(2, 0));
    CHECK(mentions(refusal(capture_of(8), empty, types(1)), "no events"));

    std::vector<FrameSpan> past_the_end;
    past_the_end.push_back(span(6, 3));                    // events 6, 7, 8 of 8
    CHECK(mentions(refusal(capture_of(8), past_the_end, types(1)), "outside the capture"));

    std::vector<FrameSpan> starts_outside;
    starts_outside.push_back(span(9, 1));
    CHECK(mentions(refusal(capture_of(8), starts_outside, types(1)), "outside the capture"));

    std::vector<FrameSpan> exact;                          // the last event of the capture is allowed
    exact.push_back(span(7, 1));
    CHECK(refusal(capture_of(8), exact, types(1)).empty());

    std::vector<FrameSpan> wraps;                          // first + count overflows 64 bits
    wraps.push_back(span(1, std::numeric_limits<std::uint64_t>::max()));
    CHECK(mentions(refusal(capture_of(8), wraps, types(1)), "outside the capture"));
}

TEST_CASE("frames must be in order and must not overlap") {
    std::vector<FrameSpan> overlap;
    overlap.push_back(span(0, 5));
    overlap.push_back(span(4, 2));
    const std::string a = refusal(capture_of(8), overlap, types(2));
    CHECK(mentions(a, "frame 1"));
    CHECK(mentions(a, "overlaps"));

    std::vector<FrameSpan> backwards;
    backwards.push_back(span(4, 2));
    backwards.push_back(span(0, 2));
    CHECK(mentions(refusal(capture_of(8), backwards, types(2)), "out of order"));

    std::vector<FrameSpan> same;
    same.push_back(span(0, 2));
    same.push_back(span(0, 2));
    CHECK(mentions(refusal(capture_of(8), same, types(2)), "overlaps"));
}

TEST_CASE("every frame names a message type the model has, and every frame has one") {
    std::vector<FrameSpan> frames;
    frames.push_back(span(0, 2));
    frames.push_back(span(2, 2));
    std::vector<std::uint32_t> bad = types(2);
    bad[1] = 1;                                            // the model has only type 0
    const std::string what = refusal(capture_of(8), frames, bad);
    CHECK(mentions(what, "frame 1"));
    CHECK(mentions(what, "message type 1"));

    CHECK(mentions(refusal(capture_of(8), frames, types(1)), "2 frames and 1 message types"));
    CHECK(mentions(refusal(capture_of(8), frames, types(3)), "2 frames and 3 message types"));
}
