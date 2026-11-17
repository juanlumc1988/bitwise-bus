// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// What a capture is, and how it is read from and written to a file.
//
// A capture is a sequence of events. An event is whatever the capturing tool
// delivered in one piece with one timestamp: a UART byte, a burst of bytes, a
// CAN frame. Nothing here decides where a frame begins or ends; that is the
// job of segmentation, which needs the events exactly as they were captured.
// The file format is specified in docs/capture-format.md.
//
// The shape of this API follows the rule in docs/roadmap.md, which aims at
// binding it to other languages without a facade: <cstdint> types, no aliases;
// plain structs for what crosses the boundary; the collection owned by a class
// and reached through accessors. That aim has not been checked against a
// binding generator yet. CaptureError, which derives from std::runtime_error,
// is the part most likely to need care.

#ifndef BW_CAPTURE_H
#define BW_CAPTURE_H

#include <cstddef>
#include <cstdint>
#include <stdexcept>
#include <string>
#include <vector>

namespace bw {

enum class Direction : std::uint8_t {
    Unknown = 0,
    Rx      = 1,
    Tx      = 2
};

// Everything about an event except its bytes.
struct EventInfo {
    std::int64_t  time_ns  = 0;        // meaningful only when has_time
    bool          has_time = false;
    std::uint32_t channel  = 0;        // index into the capture's channel table
    Direction     direction = Direction::Unknown;
    bool          has_id   = false;
    std::uint32_t id       = 0;        // meaningful only when has_id: the CAN ID
};

class Capture {
public:
    // Channel 0 always exists and is the unnamed one.
    Capture();

    // The index of the channel with this name, adding it if it is new.
    std::uint32_t add_channel(const std::string& name);

    // Throws std::invalid_argument if the channel does not exist or if the
    // event is timed and earlier than the latest timed event so far. Time never
    // goes backwards in a capture; the file format has the same rule.
    void add_event(const EventInfo& info, const std::vector<std::uint8_t>& bytes);

    std::size_t               event_count() const;
    EventInfo                 event(std::size_t index) const;         // throws std::out_of_range
    std::size_t               event_size(std::size_t index) const;    // throws std::out_of_range
    std::vector<std::uint8_t> event_bytes(std::size_t index) const;   // throws std::out_of_range

    std::size_t channel_count() const;
    std::string channel_name(std::uint32_t channel) const;            // throws std::out_of_range

    std::size_t total_bytes() const;
    bool        fully_timed() const;     // every event has a time (false when empty)

    // Same events, in the same order, with the same bytes. A channel is compared
    // by name: one that no event uses, and the order channels were added in, are
    // not part of what a capture says, and a capture file cannot carry them.
    bool        equals(const Capture& other) const;

private:
    struct Record {
        EventInfo   info;
        std::size_t end;                 // end of this event's bytes in bytes_
    };

    std::vector<Record>        records_;
    std::vector<std::uint8_t>  bytes_;
    std::vector<std::string>   channels_;
    std::int64_t               last_time_     = 0;
    bool                       has_last_time_ = false;
    std::size_t                timed_events_  = 0;
};

// A malformed capture file. what() starts with "line N: " when the problem is
// on a line.
class CaptureError : public std::runtime_error {
public:
    CaptureError(std::size_t line, const std::string& message);
    std::size_t line() const;            // 1-based; 0 when not tied to a line

private:
    std::size_t line_;
};

// Reads a capture file whole or not at all; throws CaptureError.
Capture parse_capture_csv(const std::string& text);

// Throws std::invalid_argument if a channel name cannot be written without
// quoting. Reading the result gives back an equal capture.
std::string format_capture_csv(const Capture& capture);

// The shape of a capture's timing, for a first look at it. An interval is the
// time between two consecutive timed events; the median of an even number of
// them is the lower of the middle two.
struct CaptureStats {
    std::uint64_t events           = 0;
    std::uint64_t bytes            = 0;
    std::uint64_t timed_events     = 0;
    std::int64_t  first_time_ns    = 0;       // meaningful only when timed_events > 0
    std::int64_t  last_time_ns     = 0;
    std::uint64_t interval_count   = 0;
    std::uint64_t min_interval_ns  = 0;       // meaningful only when interval_count > 0
    std::uint64_t median_interval_ns = 0;
    std::uint64_t max_interval_ns  = 0;
};

CaptureStats capture_stats(const Capture& capture);

} // namespace bw

#endif // BW_CAPTURE_H
