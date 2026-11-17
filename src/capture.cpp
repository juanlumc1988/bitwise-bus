// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/capture.h"

#include <algorithm>
#include <cstdio>

namespace bw {

// ---- Capture ---------------------------------------------------------------

Capture::Capture() {
    channels_.push_back(std::string());
}

std::uint32_t Capture::add_channel(const std::string& name) {
    for (std::size_t i = 0; i < channels_.size(); ++i) {
        if (channels_[i] == name) {
            return static_cast<std::uint32_t>(i);
        }
    }
    channels_.push_back(name);
    return static_cast<std::uint32_t>(channels_.size() - 1);
}

void Capture::add_event(const EventInfo& info,
                        const std::vector<std::uint8_t>& bytes) {
    if (info.channel >= channels_.size()) {
        throw std::invalid_argument(
            "event is on channel " + std::to_string(info.channel) +
            " but the capture has " + std::to_string(channels_.size()));
    }

    // Stored canonically, so that two captures of the same events are equal
    // whatever the unused fields held when they were built.
    EventInfo stored = info;
    if (stored.has_time) {
        if (has_last_time_ && stored.time_ns < last_time_) {
            throw std::invalid_argument(
                "time goes backwards: " + std::to_string(stored.time_ns) +
                " ns after " + std::to_string(last_time_) + " ns");
        }
    } else {
        stored.time_ns = 0;
    }
    if (!stored.has_id) {
        stored.id = 0;
    }

    // The only steps that can run out of memory come first. If either throws,
    // nothing has changed; the push_back below needs no new storage, so it
    // cannot throw, and no bytes are ever left that no event owns.
    records_.reserve(records_.size() + 1);
    bytes_.insert(bytes_.end(), bytes.begin(), bytes.end());
    Record record;
    record.info = stored;
    record.end  = bytes_.size();
    records_.push_back(record);

    if (stored.has_time) {
        last_time_     = stored.time_ns;
        has_last_time_ = true;
        ++timed_events_;
    }
}

std::size_t Capture::event_count() const {
    return records_.size();
}

EventInfo Capture::event(std::size_t index) const {
    return records_.at(index).info;
}

std::size_t Capture::event_size(std::size_t index) const {
    const std::size_t end   = records_.at(index).end;
    const std::size_t begin = (index == 0) ? 0 : records_[index - 1].end;
    return end - begin;
}

std::vector<std::uint8_t> Capture::event_bytes(std::size_t index) const {
    const std::size_t end   = records_.at(index).end;
    const std::size_t begin = (index == 0) ? 0 : records_[index - 1].end;
    return std::vector<std::uint8_t>(bytes_.begin() + static_cast<std::ptrdiff_t>(begin),
                                     bytes_.begin() + static_cast<std::ptrdiff_t>(end));
}

std::size_t Capture::channel_count() const {
    return channels_.size();
}

std::string Capture::channel_name(std::uint32_t channel) const {
    return channels_.at(channel);
}

std::size_t Capture::total_bytes() const {
    return records_.empty() ? 0 : records_.back().end;
}

bool Capture::fully_timed() const {
    return !records_.empty() && timed_events_ == records_.size();
}

bool Capture::equals(const Capture& other) const {
    if (records_.size() != other.records_.size() || bytes_ != other.bytes_) {
        return false;
    }
    for (std::size_t i = 0; i < records_.size(); ++i) {
        const Record& a = records_[i];
        const Record& b = other.records_[i];
        // Channels by name: the numbering is an accident of the order they were
        // added in, and a file cannot say it.
        if (a.end != b.end || a.info.time_ns != b.info.time_ns ||
            a.info.has_time != b.info.has_time ||
            channels_[a.info.channel] != other.channels_[b.info.channel] ||
            a.info.direction != b.info.direction || a.info.has_id != b.info.has_id ||
            a.info.id != b.info.id) {
            return false;
        }
    }
    return true;
}

// ---- CaptureError ----------------------------------------------------------

CaptureError::CaptureError(std::size_t line, const std::string& message)
    : std::runtime_error(line == 0 ? message
                                   : "line " + std::to_string(line) + ": " + message),
      line_(line) {}

std::size_t CaptureError::line() const {
    return line_;
}

// ---- Reading ---------------------------------------------------------------

namespace {

bool is_blank(char c) {
    return c == ' ' || c == '\t';
}

std::string trim(const std::string& s) {
    std::size_t begin = 0;
    std::size_t end   = s.size();
    while (begin < end && is_blank(s[begin])) {
        ++begin;
    }
    while (end > begin && is_blank(s[end - 1])) {
        --end;
    }
    return s.substr(begin, end - begin);
}

std::string lower(std::string s) {
    for (std::size_t i = 0; i < s.size(); ++i) {
        if (s[i] >= 'A' && s[i] <= 'Z') {
            s[i] = static_cast<char>(s[i] - 'A' + 'a');
        }
    }
    return s;
}

int hex_value(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

std::vector<std::string> split_commas(const std::string& line) {
    std::vector<std::string> fields;
    std::size_t begin = 0;
    for (;;) {
        const std::size_t comma = line.find(',', begin);
        if (comma == std::string::npos) {
            fields.push_back(trim(line.substr(begin)));
            return fields;
        }
        fields.push_back(trim(line.substr(begin, comma - begin)));
        begin = comma + 1;
    }
}

// A signed decimal integer that fits in 64 bits, and nothing else.
bool parse_int64(const std::string& s, std::int64_t* out) {
    std::size_t i        = 0;
    bool        negative = false;
    if (i < s.size() && (s[i] == '+' || s[i] == '-')) {
        negative = (s[i] == '-');
        ++i;
    }
    if (i == s.size()) {
        return false;
    }
    const std::uint64_t one   = 1;
    const std::uint64_t limit = negative ? (one << 63) : ((one << 63) - 1);
    std::uint64_t       magnitude = 0;
    for (; i < s.size(); ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(s[i] - '0');
        if (magnitude > (limit - digit) / 10) {      // magnitude * 10 + digit > limit
            return false;
        }
        magnitude = magnitude * 10 + digit;
    }
    *out = negative ? static_cast<std::int64_t>(std::uint64_t(0) - magnitude)
                    : static_cast<std::int64_t>(magnitude);
    return true;
}

// At most 8 hex digits, with or without a 0x prefix.
bool parse_hex_u32(const std::string& s, std::uint32_t* out) {
    std::size_t i = 0;
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        i = 2;
    }
    if (i == s.size() || s.size() - i > 8) {
        return false;
    }
    std::uint32_t value = 0;
    for (; i < s.size(); ++i) {
        const int h = hex_value(s[i]);
        if (h < 0) {
            return false;
        }
        value = (value << 4) | static_cast<std::uint32_t>(h);
    }
    *out = value;
    return true;
}

// Two hex digits per byte. Blanks separate bytes and may not split one.
bool parse_hex_bytes(const std::string& s, std::vector<std::uint8_t>* out,
                     std::string* why) {
    out->clear();
    std::size_t i = 0;
    while (i < s.size()) {
        if (is_blank(s[i])) {
            ++i;
            continue;
        }
        const std::size_t begin = i;
        while (i < s.size() && !is_blank(s[i])) {
            ++i;
        }
        if ((i - begin) % 2 != 0) {
            *why = "odd number of hex digits in '" + s.substr(begin, i - begin) + "'";
            return false;
        }
        for (std::size_t k = begin; k < i; k += 2) {
            const int hi = hex_value(s[k]);
            const int lo = hex_value(s[k + 1]);
            if (hi < 0 || lo < 0) {
                *why = std::string("'") + (hi < 0 ? s[k] : s[k + 1]) +
                       "' is not a hex digit";
                return false;
            }
            out->push_back(static_cast<std::uint8_t>(hi * 16 + lo));
        }
    }
    return true;
}

struct Columns {
    int time      = -1;
    int channel   = -1;
    int direction = -1;
    int id        = -1;
    int data      = -1;
};

void read_header(const std::string& line, std::size_t line_no, Columns* columns,
                 std::size_t* width) {
    const std::vector<std::string> names = split_commas(line);
    *width = names.size();
    for (std::size_t i = 0; i < names.size(); ++i) {
        const std::string name = lower(names[i]);
        int*              slot = nullptr;
        if (name == "time_ns")        slot = &columns->time;
        else if (name == "channel")   slot = &columns->channel;
        else if (name == "direction") slot = &columns->direction;
        else if (name == "id")        slot = &columns->id;
        else if (name == "data")      slot = &columns->data;
        if (slot == nullptr) {
            continue;                 // a column from a later version: ignored
        }
        if (*slot >= 0) {
            throw CaptureError(line_no, "the header has two '" + name + "' columns");
        }
        *slot = static_cast<int>(i);
    }
    if (columns->data < 0) {
        throw CaptureError(line_no, "the header has no 'data' column");
    }
}

const char kByteOrderMark[] = "\xEF\xBB\xBF";

} // namespace

Capture parse_capture_csv(const std::string& text) {
    Capture     capture;
    Columns     columns;
    std::size_t width     = 0;
    bool        in_header = true;
    std::size_t line_no   = 0;
    std::size_t pos       = (text.compare(0, 3, kByteOrderMark) == 0) ? 3 : 0;

    while (pos < text.size()) {
        const std::size_t newline = text.find('\n', pos);
        std::string       line    = text.substr(pos, newline == std::string::npos
                                                         ? std::string::npos
                                                         : newline - pos);
        pos = (newline == std::string::npos) ? text.size() : newline + 1;
        ++line_no;
        if (!line.empty() && line[line.size() - 1] == '\r') {
            line.erase(line.size() - 1);
        }

        const std::string body = trim(line);
        if (body.empty() || body[0] == '#') {
            continue;
        }
        if (line.find('"') != std::string::npos) {
            throw CaptureError(line_no, "double quotes are not supported: the format has no quoting");
        }

        if (in_header) {
            read_header(line, line_no, &columns, &width);
            in_header = false;
            continue;
        }

        const std::vector<std::string> fields = split_commas(line);
        if (fields.size() != width) {
            throw CaptureError(line_no, "expected " + std::to_string(width) +
                                        " fields, found " + std::to_string(fields.size()));
        }

        EventInfo info;
        if (columns.time >= 0 && !fields[columns.time].empty()) {
            if (!parse_int64(fields[columns.time], &info.time_ns)) {
                throw CaptureError(line_no, "time_ns: '" + fields[columns.time] +
                                            "' is not an integer number of nanoseconds");
            }
            info.has_time = true;
        }
        if (columns.channel >= 0) {
            info.channel = capture.add_channel(fields[columns.channel]);
        }
        if (columns.direction >= 0) {
            const std::string d = lower(fields[columns.direction]);
            if (d == "rx")          info.direction = Direction::Rx;
            else if (d == "tx")     info.direction = Direction::Tx;
            else if (!d.empty()) {
                throw CaptureError(line_no, "direction: '" + fields[columns.direction] +
                                            "' is not rx, tx or empty");
            }
        }
        if (columns.id >= 0 && !fields[columns.id].empty()) {
            if (!parse_hex_u32(fields[columns.id], &info.id)) {
                throw CaptureError(line_no, "id: '" + fields[columns.id] +
                                            "' is not a hexadecimal identifier of up to 8 digits");
            }
            info.has_id = true;
        }

        std::vector<std::uint8_t> bytes;
        std::string               why;
        if (!parse_hex_bytes(fields[columns.data], &bytes, &why)) {
            throw CaptureError(line_no, "data: " + why);
        }

        try {
            capture.add_event(info, bytes);
        } catch (const std::invalid_argument& e) {
            throw CaptureError(line_no, e.what());
        }
    }

    if (in_header) {
        throw CaptureError(0, "the file has no header row");
    }
    return capture;
}

// ---- Writing ---------------------------------------------------------------

std::string format_capture_csv(const Capture& capture) {
    for (std::size_t c = 0; c < capture.channel_count(); ++c) {
        const std::string name = capture.channel_name(static_cast<std::uint32_t>(c));
        if (name != trim(name) ||
            name.find_first_of(",\"\r\n") != std::string::npos) {
            throw std::invalid_argument("channel name '" + name +
                                        "' cannot be written to a capture file");
        }
    }

    static const char kDigits[] = "0123456789abcdef";
    std::string out = "# bitwise-capture 1\ntime_ns,channel,direction,id,data\n";
    for (std::size_t i = 0; i < capture.event_count(); ++i) {
        const EventInfo info = capture.event(i);
        if (info.has_time) {
            out += std::to_string(static_cast<long long>(info.time_ns));
        }
        out += ',';
        out += capture.channel_name(info.channel);
        out += ',';
        out += (info.direction == Direction::Rx) ? "rx"
             : (info.direction == Direction::Tx) ? "tx" : "";
        out += ',';
        if (info.has_id) {
            char id[16];
            std::snprintf(id, sizeof(id), "0x%x", static_cast<unsigned>(info.id));
            out += id;
        }
        out += ',';
        const std::vector<std::uint8_t> bytes = capture.event_bytes(i);
        for (std::size_t b = 0; b < bytes.size(); ++b) {
            if (b != 0) {
                out += ' ';
            }
            out += kDigits[bytes[b] >> 4];
            out += kDigits[bytes[b] & 0xFu];
        }
        out += '\n';
    }
    return out;
}

// ---- Statistics ------------------------------------------------------------

CaptureStats capture_stats(const Capture& capture) {
    CaptureStats stats;
    stats.events = capture.event_count();
    stats.bytes  = capture.total_bytes();

    std::vector<std::uint64_t> intervals;
    bool         have_previous = false;
    std::int64_t previous      = 0;
    for (std::size_t i = 0; i < capture.event_count(); ++i) {
        const EventInfo info = capture.event(i);
        if (!info.has_time) {
            continue;
        }
        if (stats.timed_events == 0) {
            stats.first_time_ns = info.time_ns;
        }
        stats.last_time_ns = info.time_ns;
        ++stats.timed_events;
        if (have_previous) {
            // Time does not go backwards, so this difference is not negative;
            // unsigned arithmetic gives it without overflowing the signed range.
            intervals.push_back(static_cast<std::uint64_t>(info.time_ns) -
                                static_cast<std::uint64_t>(previous));
        }
        previous      = info.time_ns;
        have_previous = true;
    }

    stats.interval_count = intervals.size();
    if (!intervals.empty()) {
        std::sort(intervals.begin(), intervals.end());
        stats.min_interval_ns    = intervals.front();
        stats.median_interval_ns = intervals[(intervals.size() - 1) / 2];
        stats.max_interval_ns    = intervals.back();
    }
    return stats;
}

} // namespace bw
