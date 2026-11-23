// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// NMEA 0183, the text protocol of marine instruments and GPS receivers, on a
// 4800 baud 8N1 line, one event per byte. Three sentences, in the order a
// receiver sends them each second: GGA (fix data), RMC (recommended minimum)
// and VTG (course and speed). A sentence is
//
//   $ talker-and-type , field , field ... * hh CR LF
//
// text, with fields of varying length, some of them empty, ending in the two
// hexadecimal digits (upper case) of the exclusive or of the characters between
// the $ and the *. It is written here with code of its own, not with the
// inference stages. The talker is always GP.
//
//   GGA  time, latitude, N or S, longitude, E or W, quality, satellites, HDOP,
//        altitude, M, geoid separation, M, age of the differential data (empty),
//        differential station (empty)
//   RMC  time, status, latitude, N or S, longitude, E or W, speed in knots,
//        course, date, magnetic variation (empty), its direction (empty), mode
//   VTG  true course, T, magnetic course (empty), M, speed in knots, N, speed in
//        km/h, K, mode
//
// The time is hhmmss.00; a latitude is ddmm.mmmmm and a longitude dddmm.mmmmm;
// an altitude, a speed, a course and a dilution of precision are written with
// one decimal and the digits they need, so that the sentences differ in length.
//
// A receiver sends its three sentences back to back and then is silent until
// the next second: the sentences of epoch e begin at e seconds, one after the
// other, and a sentence is not set apart from the one before it by anything but
// its $. The random draws, in order, so that anyone can regenerate a capture
// from its seed:
//   - once, before the first epoch: the time of day in seconds, below(86400); the
//     hemispheres, N (0) or S (1) then E (0) or W (1), below(2) each; the first
//     latitude in 1e-5 minutes of arc, below(540000000), and longitude,
//     below(1080000000); the day 1 + below(28), month 1 + below(12) and year
//     20 + below(10); and the geoid separation in tenths of a metre, below(800) - 400;
//   - at the start of each epoch, the latitude and longitude each move by
//     below(2001) - 1000 (modulo the whole range), then the altitude is drawn,
//     below(20000) tenths of a metre; from the second epoch on the time goes up
//     by a second;
//   - then, as the sentence is written:
//       GGA: the quality, [1, 1, 1, 2, 4][below(5)]; the satellites, 4 + below(9);
//            the HDOP in tenths, 5 + below(30);
//       RMC: the status, A for [0, 1, 2], V for 3, of below(4); the speed in
//            tenths of a knot, below(1500); the course in tenths of a degree,
//            below(3600); the mode, A or D, below(2);
//       VTG: the true course, below(3600); the speed, below(1500); the mode, A
//            or D, below(2); the speed in km/h is 1.852 times it, to the tenth;
//   - then one draw per byte for its timing delay, always, so that the same seed
//     gives the same sentences whatever the jitter.
// The last epoch has as many sentences as are asked for, so it may be short.

#include "nmea0183.h"

#include "common.h"

namespace bw {

namespace {

const std::uint64_t kCharNs   = 10ULL * 1000000000ULL / 4800ULL;     // 2083333: 10 bits at 4800 baud
const std::uint64_t kEpochNs  = 1000000000ULL;                       // one second
const std::uint64_t kLatRange = 90ULL * 6000000ULL;                  // 1e-5 minutes of arc in 90 degrees
const std::uint64_t kLonRange = 180ULL * 6000000ULL;

std::string pad(std::uint64_t value, std::size_t width) {
    std::string text = std::to_string(static_cast<unsigned long long>(value));
    return text.size() >= width ? text : std::string(width - text.size(), '0') + text;
}

// 2243 tenths is "224.3".
std::string tenths(std::uint64_t value) {
    return std::to_string(static_cast<unsigned long long>(value / 10)) + "." +
           std::to_string(static_cast<unsigned long long>(value % 10));
}

// ddmm.mmmmm for a latitude (degrees of 2 digits) and dddmm.mmmmm for a longitude (3).
std::string position(std::uint64_t units, std::size_t degree_digits) {
    const std::uint64_t degrees = units / 6000000;
    const std::uint64_t rest    = units % 6000000;
    return pad(degrees, degree_digits) + pad(rest / 100000, 2) + "." + pad(rest % 100000, 5);
}

std::uint8_t xor_of(const std::string& body) {
    std::uint8_t sum = 0;
    for (std::size_t i = 0; i < body.size(); ++i) {
        sum = static_cast<std::uint8_t>(sum ^ static_cast<std::uint8_t>(body[i]));
    }
    return sum;
}

std::string hex2(unsigned value) {
    static const char digits[] = "0123456789ABCDEF";
    std::string       out;
    out += digits[(value >> 4) & 15];
    out += digits[value & 15];
    return out;
}

std::string join(const std::vector<std::string>& fields) {
    std::string out;
    for (std::size_t i = 0; i < fields.size(); ++i) {
        out += (i == 0 ? "" : ",") + fields[i];
    }
    return out;
}

std::vector<std::uint8_t> sentence(const std::string& body) {
    const std::string text = "$" + body + "*" + hex2(xor_of(body)) + "\r\n";
    return std::vector<std::uint8_t>(text.begin(), text.end());
}

FieldInfo constant_text(const std::string& text) {
    FieldInfo info;
    info.kind       = FieldKind::Constant;
    info.bit_size   = static_cast<std::uint32_t>(8 * text.size());
    info.byte_order = text.size() > 1 ? ByteOrder::Big : ByteOrder::NotApplicable;
    for (std::size_t i = 0; i < text.size(); ++i) {
        info.constant = (info.constant << 8) | static_cast<std::uint8_t>(text[i]);
    }
    return info;
}

FieldInfo text_field(char delimiter) {
    FieldInfo info;
    info.kind      = FieldKind::Text;
    info.size_kind = SizeKind::Delimited;
    info.delimiter = static_cast<std::uint8_t>(delimiter);
    return info;
}

struct Sentence {
    const char* name;
    const char* address;           // talker, type and the comma after it
    const char* fields;            // the names of the fields, space separated
};

const Sentence kSentences[3] = {
    { "gga", "GPGGA,", "time latitude north_south longitude east_west quality satellites hdop altitude "
                       "altitude_unit geoid_separation geoid_unit differential_age differential_station" },
    { "rmc", "GPRMC,", "time status latitude north_south longitude east_west speed course date "
                       "magnetic_variation magnetic_direction mode" },
    { "vtg", "GPVTG,", "true_course true_unit magnetic_course magnetic_unit speed_knots knots_unit "
                       "speed_kmh kmh_unit mode" },
};

std::vector<std::string> split_names(const std::string& names) {
    std::vector<std::string> out;
    std::string              current;
    for (std::size_t i = 0; i <= names.size(); ++i) {
        if (i == names.size() || names[i] == ' ') {
            out.push_back(current);
            current.clear();
        } else {
            current += names[i];
        }
    }
    return out;
}

class Nmea0183 : public Protocol {
public:
    std::string name() const override { return "nmea0183"; }

    std::string summary() const override {
        return "NMEA 0183: GGA, RMC and VTG sentences, 4800 baud 8N1, three back to back each second, one event per byte";
    }

    Model model() const override {
        Model model;
        FramingInfo framing;
        framing.kind      = FramingKind::Terminated;
        framing.delimiter = '\n';
        model.set_framing(framing);

        for (std::size_t s = 0; s < 3; ++s) {
            const std::size_t t = model.add_message_type(kSentences[s].name);
            model.add_field(t, "start", constant_text("$"), "");
            model.add_field(t, "address", constant_text(kSentences[s].address), "");
            const std::vector<std::string> names = split_names(kSentences[s].fields);
            std::size_t                    last  = 1;
            for (std::size_t f = 0; f < names.size(); ++f) {
                // Each field runs to the comma after it, and the last to the star.
                last = model.add_field(t, names[f], text_field(f + 1 == names.size() ? '*' : ','), "");
            }
            FieldInfo checksum;
            checksum.kind         = FieldKind::Checksum;
            checksum.bit_size     = 16;
            checksum.byte_order   = ByteOrder::Big;
            checksum.ascii_hex    = true;
            checksum.covers_first = 1;                       // from the address
            checksum.covers_last  = static_cast<std::uint32_t>(last);
            model.add_field(t, "checksum", checksum, "XOR of the characters between $ and *");
            model.add_field(t, "end", constant_text("\r\n"), "");
        }
        return model;
    }

    Dataset generate(const GenerateOptions& options) const override {
        check_generate_options(options);

        Rng                 rng(options.seed);
        Capture             capture;
        const std::uint32_t channel   = capture.add_channel("uart");
        const std::uint64_t max_delay = kCharNs * options.jitter_permille / 1000;

        std::uint64_t seconds   = rng.below(86400);
        const bool    south     = rng.below(2) == 1;
        const bool    west      = rng.below(2) == 1;
        std::uint64_t latitude  = rng.below(kLatRange);
        std::uint64_t longitude = rng.below(kLonRange);
        // One statement for each draw: the operands of a + are evaluated in any order.
        const std::uint64_t day   = 1 + rng.below(28);
        const std::uint64_t month = 1 + rng.below(12);
        const std::uint64_t year  = 20 + rng.below(10);
        const std::string   date  = pad(day, 2) + pad(month, 2) + pad(year, 2);
        const std::int64_t geoid = static_cast<std::int64_t>(rng.below(800)) - 400;
        const std::string  separation = (geoid < 0 ? "-" : "") + tenths(static_cast<std::uint64_t>(geoid < 0 ? -geoid : geoid));

        std::vector<FrameSpan>     spans;
        std::vector<std::uint32_t> types;
        std::uint64_t              events = 0;
        std::uint64_t              at     = 0;
        std::uint64_t              altitude = 0;
        std::string                clock, lat, lon;
        for (std::uint32_t i = 0; i < options.frames; ++i) {
            const std::uint32_t kind = i % 3;
            if (kind == 0) {                                 // an epoch begins
                latitude  = (latitude + kLatRange - 1000 + rng.below(2001)) % kLatRange;
                longitude = (longitude + kLonRange - 1000 + rng.below(2001)) % kLonRange;
                altitude  = rng.below(20000);
                seconds   = (seconds + (i == 0 ? 0 : 1)) % 86400;
                clock     = pad(seconds / 3600, 2) + pad((seconds / 60) % 60, 2) + pad(seconds % 60, 2) + ".00";
                lat       = position(latitude, 2);
                lon       = position(longitude, 3);
                at        = (i / 3) * kEpochNs;
            }
            const std::string ns = south ? "S" : "N";
            const std::string ew = west ? "W" : "E";

            std::vector<std::string> fields;
            if (kind == 0) {
                static const unsigned qualities[5] = { 1, 1, 1, 2, 4 };
                const unsigned        quality      = qualities[rng.below(5)];
                const std::uint64_t   satellites   = 4 + rng.below(9);
                const std::uint64_t   hdop         = 5 + rng.below(30);
                const std::string     items[14]    = { clock, lat, ns, lon, ew, std::to_string(quality),
                                                       pad(satellites, 2), tenths(hdop), tenths(altitude), "M",
                                                       separation, "M", "", "" };
                fields.assign(items, items + 14);
            } else if (kind == 1) {
                const bool          valid  = rng.below(4) != 3;
                const std::uint64_t speed  = rng.below(1500);
                const std::uint64_t course = rng.below(3600);
                const bool          differential = rng.below(2) == 1;
                const std::string   items[12] = { clock, valid ? "A" : "V", lat, ns, lon, ew, tenths(speed),
                                                  tenths(course), date, "", "", differential ? "D" : "A" };
                fields.assign(items, items + 12);
            } else {
                const std::uint64_t course = rng.below(3600);
                const std::uint64_t speed  = rng.below(1500);
                const bool          differential = rng.below(2) == 1;
                const std::string   items[9] = { tenths(course), "T", "", "M", tenths(speed), "N",
                                                 tenths(speed * 1852 / 1000), "K", differential ? "D" : "A" };
                fields.assign(items, items + 9);
            }
            const std::vector<std::uint8_t> bytes = sentence(std::string(kSentences[kind].address) + join(fields));
            at = emit_bytes(&capture, channel, at, kCharNs, max_delay, &rng, bytes);

            FrameSpan span;
            span.first_event = events;
            span.event_count = bytes.size();
            spans.push_back(span);
            types.push_back(kind);
            events += bytes.size();
        }
        return Dataset(capture, model(), spans, types);
    }

    bool conforms(const std::vector<std::uint8_t>& frame) const override {
        const std::size_t n = frame.size();
        if (n < 12 || n > 82 || frame[0] != '$' || frame[n - 2] != '\r' || frame[n - 1] != '\n' ||
            frame[n - 5] != '*') {
            return false;
        }
        std::string body;
        for (std::size_t i = 1; i < n - 5; ++i) {
            if (frame[i] < 0x20 || frame[i] > 0x7E || frame[i] == '$' || frame[i] == '*') {
                return false;
            }
            body += static_cast<char>(frame[i]);
        }
        const std::string digits = hex2(xor_of(body));
        if (frame[n - 4] != digits[0] || frame[n - 3] != digits[1]) {
            return false;
        }
        // A sentence of the protocol: its address, and the number of fields it has.
        std::size_t commas = 0;
        for (std::size_t i = 0; i < body.size(); ++i) {
            commas += body[i] == ',' ? 1 : 0;
        }
        for (std::size_t s = 0; s < 3; ++s) {
            const std::string address = kSentences[s].address;
            if (body.compare(0, address.size(), address) == 0) {
                const std::size_t fields = split_names(kSentences[s].fields).size();
                // The sentences of version 2.3 end with a mode, those of 2.1 do not.
                return commas == fields || (s != 0 && commas + 1 == fields);
            }
        }
        return false;
    }
};

} // namespace

const Protocol& nmea0183_protocol() {
    static const Nmea0183 protocol;
    return protocol;
}

} // namespace bw
