// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// NMEA 0183, the first text protocol: sentences of varying length with empty
// fields, a checksum written as two hexadecimal characters, and a receiver that
// sends its three sentences back to back once a second. Checked against the
// sentences as they are written in the descriptions of the protocol, against an
// exclusive or written again here, and, as for the others, against the Python
// implementation (tests/mirror/mirror.py) through the captures checked in.

#include "doctest.h"

#include <cstdint>
#include <set>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/evaluate.h"
#include "bw/protocol.h"
#include "bw/segmentation.h"
#include "golden.h"

using bw::Capture;
using bw::Dataset;
using bw::FieldKind;
using bw::GenerateOptions;

namespace {

typedef std::vector<std::uint8_t> Bytes;

Dataset make(std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol("nmea0183", o);
}

std::string sentence_of(const Dataset& d, std::size_t i) {
    const Bytes b = bw::frame_bytes(d.capture(), d.frame(i));
    return std::string(b.begin(), b.end());
}

Bytes bytes_of(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

std::string csv(const Dataset& d) {
    return bw::format_capture_csv(d.capture());
}

// The two digits after the star, worked out again.
std::string checksum_of(const std::string& body) {
    unsigned value = 0;
    for (std::size_t i = 0; i < body.size(); ++i) {
        value ^= static_cast<unsigned char>(body[i]);
    }
    const char digits[] = "0123456789ABCDEF";
    std::string out;
    out += digits[value >> 4];
    out += digits[value & 15];
    return out;
}

std::string with_checksum(const std::string& body) {
    return "$" + body + "*" + checksum_of(body) + "\r\n";
}

// The fields of a sentence, split at the commas, address first and the star left out.
std::vector<std::string> fields_of(const std::string& sentence) {
    const std::string body = sentence.substr(1, sentence.size() - 6);
    std::vector<std::string> out;
    std::string current;
    for (std::size_t i = 0; i <= body.size(); ++i) {
        if (i == body.size() || body[i] == ',') {
            out.push_back(current);
            current.clear();
        } else {
            current += body[i];
        }
    }
    return out;
}

bool all_digits(const std::string& s, std::size_t from, std::size_t to) {
    for (std::size_t i = from; i < to; ++i) {
        if (s[i] < '0' || s[i] > '9') {
            return false;
        }
    }
    return true;
}

} // namespace

TEST_CASE("nmea0183: the exclusive or of the sentences as they are written in the descriptions") {
    CHECK(checksum_of("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,") == "47");
    CHECK(checksum_of("GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W") == "6A");
    CHECK(checksum_of("GPGLL,4916.45,N,12311.12,W,225444,A,") == "1D");

    // The decoder of the protocol accepts the first two (the RMC of version 2.1, with no mode)
    // and refuses the third only for being a sentence it does not know.
    CHECK(bw::protocol_conforms("nmea0183", bytes_of("$GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,*47\r\n")));
    CHECK(bw::protocol_conforms("nmea0183", bytes_of("$GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W*6A\r\n")));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of("$GPGLL,4916.45,N,12311.12,W,225444,A,*1D\r\n")));
}

TEST_CASE("nmea0183: its model is the documented one") {
    const bw::Model m = bw::protocol_model("nmea0183");
    CHECK(m.framing().kind == bw::FramingKind::Terminated);
    CHECK(m.framing().delimiter == '\n');
    REQUIRE(m.message_type_count() == 3);
    const char*       names[3]  = { "gga", "rmc", "vtg" };
    const std::size_t fields[3] = { 18, 16, 13 };        // $, address, the data fields, checksum, CR LF
    const std::uint64_t addresses[3] = { 0x47504747412CULL, 0x4750524D432CULL, 0x47505654472CULL };   // "GPGGA," ...
    for (std::size_t t = 0; t < 3; ++t) {
        CAPTURE(t);
        CHECK(m.message_type_name(t) == names[t]);
        REQUIRE(m.field_count(t) == fields[t]);
        CHECK(m.field(t, 0).constant == '$');
        CHECK(m.field(t, 1).constant == addresses[t]);
        CHECK(m.field(t, 1).bit_size == 48);
        // The data fields are text that runs to the comma after it, and the last to the star.
        for (std::size_t f = 2; f + 3 < m.field_count(t); ++f) {
            CHECK(m.field(t, f).kind == FieldKind::Text);
            CHECK(m.field(t, f).size_kind == bw::SizeKind::Delimited);
            CHECK(m.field(t, f).delimiter == ',');
        }
        const std::size_t last = m.field_count(t) - 3;
        CHECK(m.field(t, last).delimiter == '*');
        const bw::FieldInfo checksum = m.field(t, last + 1);
        CHECK(checksum.kind == FieldKind::Checksum);
        CHECK(checksum.ascii_hex);
        CHECK(checksum.bit_size == 16);
        CHECK(checksum.covers_first == 1);                 // from the address: not the $
        CHECK(checksum.covers_last == last);
        CHECK(m.field(t, last + 2).constant == 0x0D0A);
    }
    CHECK(m.field_name(0, 10) == "altitude");
    CHECK(m.field_name(1, 3) == "status");
    CHECK(m.field_name(2, 6) == "speed_knots");
    // Nothing after the first text field has a fixed place: the sentences differ in length.
    CHECK(m.field_position(0, 2).fixed);
    CHECK_FALSE(m.field_position(0, 3).fixed);
}

TEST_CASE("nmea0183: a seed is a capture, the same on every platform") {
    CHECK(golden::first_difference(csv(make(1, 6)), golden::read_file("synth_nmea0183_seed1_6frames.csv")) == "");
    CHECK(golden::first_difference(csv(make(3, 9, 300)),
                                   golden::read_file("synth_nmea0183_seed3_9frames_jitter300.csv")) == "");
}

TEST_CASE("nmea0183: every sentence is one of the three, with the right checksum, and they alternate") {
    const Dataset d = make(31, 300);
    REQUIRE(d.frame_count() == 300);
    const char* addresses[3] = { "$GPGGA,", "$GPRMC,", "$GPVTG," };
    const std::size_t counts[3] = { 14, 12, 9 };
    std::set<std::size_t> lengths;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        const std::string s = sentence_of(d, i);
        CAPTURE(s);
        CHECK(d.frame_message_type(i) == i % 3);
        CHECK(s.compare(0, 7, addresses[i % 3]) == 0);
        CHECK(s.size() <= 82);                                          // the longest a sentence may be
        CHECK(s.substr(s.size() - 2) == "\r\n");
        CHECK(s[s.size() - 5] == '*');
        CHECK(s.substr(s.size() - 4, 2) == checksum_of(s.substr(1, s.size() - 6)));
        CHECK(fields_of(s).size() == counts[i % 3] + 1);               // the address and its fields
        lengths.insert(s.size() + 1000 * (i % 3));
        for (std::size_t k = 0; k + 2 < s.size(); ++k) {
            CHECK((s[k] >= 0x20 && s[k] <= 0x7E));                      // printable, apart from the CR LF
        }
    }
    CHECK(lengths.size() > 12);                                         // the sentences differ in length
}

TEST_CASE("nmea0183: what the fields hold") {
    const Dataset d = make(32, 600);
    std::string   first_date, first_separation, first_ns, first_ew;
    std::int64_t  last_seconds = -1;
    std::size_t   empty_fields = 0;
    std::set<std::size_t> altitude_lengths;
    for (std::size_t i = 0; i < d.frame_count(); i += 3) {
        const std::vector<std::string> gga = fields_of(sentence_of(d, i));
        const std::vector<std::string> rmc = fields_of(sentence_of(d, i + 1));
        const std::vector<std::string> vtg = fields_of(sentence_of(d, i + 2));
        CAPTURE(i);

        // The time: hhmmss.00, the same in the epoch, a second later in the next.
        REQUIRE(gga[1].size() == 9);
        CHECK(all_digits(gga[1], 0, 6));
        CHECK(gga[1].substr(6) == ".00");
        CHECK(gga[1] == rmc[1]);
        const std::int64_t seconds = std::stoi(gga[1].substr(0, 2)) * 3600 + std::stoi(gga[1].substr(2, 2)) * 60 +
                                     std::stoi(gga[1].substr(4, 2));
        if (last_seconds >= 0) {
            CHECK(seconds == (last_seconds + 1) % 86400);
        }
        last_seconds = seconds;

        // The position: the same in both sentences, ddmm.mmmmm and dddmm.mmmmm, with the same hemispheres throughout.
        CHECK(gga[2] == rmc[3]);
        CHECK(gga[4] == rmc[5]);
        CHECK(gga[2].size() == 10);
        CHECK(gga[2][4] == '.');
        CHECK(gga[4].size() == 11);
        CHECK(gga[4][5] == '.');
        CHECK(std::stoi(gga[2].substr(0, 2)) < 90);
        CHECK(std::stoi(gga[2].substr(2, 2)) < 60);
        CHECK(std::stoi(gga[4].substr(0, 3)) < 180);
        CHECK(std::stoi(gga[4].substr(3, 2)) < 60);
        if (first_ns.empty()) {
            first_ns = gga[3];
            first_ew = gga[5];
            first_date = rmc[9];
            first_separation = gga[11];
        }
        CHECK((gga[3] == "N" || gga[3] == "S"));
        CHECK(gga[3] == first_ns);
        CHECK(gga[5] == first_ew);
        CHECK(rmc[4] == first_ns);
        CHECK(rmc[6] == first_ew);

        // GGA: quality, satellites, HDOP, altitude, units, separation, and two empty fields.
        const int quality = std::stoi(gga[6]);
        CHECK((quality == 1 || quality == 2 || quality == 4));
        CHECK(gga[7].size() == 2);
        CHECK((std::stoi(gga[7]) >= 4 && std::stoi(gga[7]) <= 12));
        CHECK(gga[8].size() == 3);                                       // the HDOP, 0.5 to 3.4
        CHECK(gga[10] == "M");
        CHECK(gga[12] == "M");
        CHECK(gga[11] == first_separation);                              // the same all along
        CHECK(gga[13].empty());
        CHECK(gga[14].empty());
        altitude_lengths.insert(gga[9].size());
        CHECK(gga[9].find('.') != std::string::npos);

        // RMC: status, speed, course, the date that does not change, two empty fields, and the mode.
        CHECK((rmc[2] == "A" || rmc[2] == "V"));
        CHECK(rmc[9] == first_date);
        CHECK(rmc[9].size() == 6);
        CHECK(rmc[10].empty());
        CHECK(rmc[11].empty());
        CHECK((rmc[12] == "A" || rmc[12] == "D"));

        // VTG: the units in their places, an empty magnetic course, and the speed in km/h that goes with the knots.
        CHECK(vtg[2] == "T");
        CHECK(vtg[3].empty());
        CHECK(vtg[4] == "M");
        CHECK(vtg[6] == "N");
        CHECK(vtg[8] == "K");
        const std::size_t dot = vtg[5].find('.');
        REQUIRE(dot != std::string::npos);
        const std::uint64_t knots_tenths = std::stoull(vtg[5].substr(0, dot)) * 10 + std::stoull(vtg[5].substr(dot + 1));
        const std::string   kmh = vtg[7];
        const std::size_t   dot2 = kmh.find('.');
        REQUIRE(dot2 != std::string::npos);
        CHECK(std::stoull(kmh.substr(0, dot2)) * 10 + std::stoull(kmh.substr(dot2 + 1)) == knots_tenths * 1852 / 1000);
        CHECK((vtg[9] == "A" || vtg[9] == "D"));

        for (std::size_t f = 0; f < gga.size(); ++f) { empty_fields += gga[f].empty() ? 1 : 0; }
    }
    CHECK(empty_fields == 400);                                          // two in each of 200 GGA sentences
    CHECK(altitude_lengths.size() >= 3);                                 // altitudes of different widths
}

TEST_CASE("nmea0183: the sentences of a second are back to back, and then there is silence until the next") {
    const Capture c = make(33, 30).capture();
    const Dataset d = make(33, 30);
    // Without noise: each epoch begins on the second, and its bytes follow one another a character apart.
    std::size_t event = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        for (std::uint64_t k = 0; k < d.frame(i).event_count; ++k, ++event) {
            if (k == 0 && i % 3 == 0) {
                CHECK(c.event(event).time_ns == static_cast<std::int64_t>((i / 3) * 1000000000ULL));
            } else {
                CHECK(c.event(event).time_ns - c.event(event - 1).time_ns == 2083333);       // 10 bits at 4800 baud
            }
        }
    }
    // An epoch is shorter than half a second, so the silence is the longest gap by far.
    CHECK(c.event(event - 1).time_ns < 9 * 1000000000LL + 500000000LL);
}

TEST_CASE("nmea0183: the decoder refuses each way a sentence can be wrong") {
    const std::string good = "$GPVTG,96.1,T,,M,2.7,N,5.0,K,A*33\r\n";
    REQUIRE(bw::protocol_conforms("nmea0183", bytes_of(good)));
    for (std::size_t i = 0; i < good.size(); ++i) {
        for (unsigned bit = 0; bit < 8; ++bit) {
            std::string bad = good;
            bad[i] = static_cast<char>(bad[i] ^ (1 << bit));
            // A bit of the body or of the checksum fails the checksum; a bit of the rest, the shape.
            CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(bad)));
        }
    }
    CHECK_FALSE(bw::protocol_conforms("nmea0183", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(good.substr(0, good.size() - 1))));       // no LF
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(good.substr(0, good.size() - 2) + "\n\n")));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(good + "\r\n")));                          // two sentences
    // Hexadecimal digits are upper case: the same sentence with a letter of its checksum in lower case is refused.
    bool tried = false;
    for (unsigned speed = 0; speed < 100 && !tried; ++speed) {
        const std::string body = "GPVTG,1.0,T,,M," + std::to_string(speed) + ".0,N,0.0,K,A";
        std::string       text = with_checksum(body);
        if ((text[text.size() - 4] >= 'A' && text[text.size() - 4] <= 'F') ||
            (text[text.size() - 3] >= 'A' && text[text.size() - 3] <= 'F')) {
            CHECK(bw::protocol_conforms("nmea0183", bytes_of(text)));
            for (std::size_t k = text.size() - 4; k <= text.size() - 3; ++k) {
                if (text[k] >= 'A' && text[k] <= 'F') {
                    text[k] = static_cast<char>(text[k] + ('a' - 'A'));
                }
            }
            CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(text)));
            tried = true;
        }
    }
    CHECK(tried);
    // The number of fields, the address, a character that is not printable, and the length.
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum("GPVTG,96.1,T,,M,2.7,N,5.0,K,A,B"))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum("GPVTG,96.1,T,,M,2.7,N,5.0"))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum("GPXXX,96.1,T,,M,2.7,N,5.0,K,A"))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(std::string("GPVTG,96.1,T,,M,2.7,N,5.0,K,\x7F")))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(std::string("GPVTG,96.1,T,,M,2.7,N,5.0,K,") + std::string(60, 'A')))));
    // A star or a dollar inside.
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum("GPVTG,96.1,T,,M,2.7,N,5.0,K,*"))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum("GPVTG,96.1,T,,M,2.7,N,5.0,K,$"))));
}

TEST_CASE("nmea0183 baseline: gaps find the seconds, not the sentences") {
    // Where the text protocols start: the silence between one second and the next is the only gap there is,
    // so segmentation by gaps finds bursts of three sentences. Every cut it makes is a real one, and two of
    // each three real cuts are missed; and what the stages do with the bursts, or with the true sentences
    // (which have as many sizes as the fields have widths, so that two kinds of sentence share a size and
    // one kind has several), is not yet a model of the protocol. The numbers are those of seed 3, 90 sentences.
    const Dataset d = make(3, 90);
    const bw::Segmentation seg = bw::segment_by_gaps(d.capture(), bw::SegmentationOptions());
    REQUIRE(seg.info().found);
    const bw::SegmentationScore s = bw::score_segmentation(d.frames(), seg.frames());
    CHECK(s.truth_frames == 90);
    CHECK(s.found_frames == 30);
    CHECK(s.exact_frames == 0);
    CHECK(s.truth_boundaries == 91);
    CHECK(s.found_boundaries == 31);
    CHECK(s.boundary_hits == 31);

    // Given the true sentences: seven message types where there are three, and in each of them the exclusive
    // or, written as two hexadecimal characters after the star, which is not covered, with the dollar left out
    // and the carriage return and line feed after.
    bw::SegmentationInfo info;
    info.found = true;
    const bw::Analysis a = bw::analyze_frames(d.capture(), bw::Segmentation(info, d.frames()), bw::AnalyzeOptions());
    CHECK(a.type_count() == 7);
    for (std::size_t t = 0; t < a.type_count(); ++t) {
        const bw::ChecksumFinding& c = a.type_report(t).checksum;
        CAPTURE(t);
        REQUIRE(c.found);
        CHECK(bw::checksum_algorithm_name(c.algorithm) == "XOR-8");
        CHECK(c.ascii_hex);
        CHECK(c.width_bits == 16);
        CHECK(c.byte_order == bw::ByteOrder::Big);
        CHECK(c.header_skip == 1);
        CHECK(c.gap_bytes == 1);
        CHECK(c.trailer_skip == 2);
        CHECK(c.evidence_bits == 8 * c.distinct_frames);

        // In the model: the star is a field of its own that the checksum does not cover, and the
        // checksum is text, and covers from the first character after the dollar.
        const bw::Model& m = a.model();
        REQUIRE(t < m.message_type_count());
        const std::size_t count = m.field_count(t);
        REQUIRE(count >= 6);
        const std::size_t checksum = count - 3;                      // then CR and LF
        const bw::FieldInfo info = m.field(t, checksum);
        CHECK(info.kind == bw::FieldKind::Checksum);
        CHECK(info.ascii_hex);
        CHECK(info.bit_size == 16);
        CHECK(info.covers_first == 1);
        CHECK(info.covers_last == checksum - 2);
        CHECK(m.field_detail(t, checksum) == "XOR-8");
        CHECK(m.field(t, checksum - 1).kind == bw::FieldKind::Constant);
        CHECK(m.field(t, checksum - 1).constant == '*');
    }
    CHECK(bw::describe_analysis(a).find("checksum XOR-8, written as two hexadecimal characters, evidence ") != std::string::npos);
}

TEST_CASE("nmea0183: a negative separation has its sign, small numbers their zeros, and the day turns over") {
    // Seed 0 has a geoid separation below zero, which is written with its minus.
    const std::vector<std::string> negative = fields_of(sentence_of(make(0, 3), 0));
    CHECK(negative[11] == "-30.1");
    CHECK(negative[12] == "M");

    // The degrees, minutes and fractions that are small are written with their zeros: a latitude is always
    // 10 characters and a longitude 11. The seeds are tried in order, and some have a fraction below 10000.
    bool small_fraction = false, small_minutes = false, small_degrees = false;
    for (std::uint64_t seed = 0; seed < 400; ++seed) {
        const std::vector<std::string> gga = fields_of(sentence_of(make(seed, 3), 0));
        CAPTURE(seed);
        REQUIRE(gga.size() == 15);
        CHECK(gga[2].size() == 10);
        CHECK(gga[4].size() == 11);
        CHECK(all_digits(gga[2], 0, 4));
        CHECK(all_digits(gga[2], 5, 10));
        CHECK(all_digits(gga[4], 0, 5));
        CHECK(all_digits(gga[4], 6, 11));
        small_fraction = small_fraction || gga[2].compare(5, 1, "0") == 0 || gga[4].compare(6, 1, "0") == 0;
        small_minutes  = small_minutes || gga[2].compare(2, 1, "0") == 0;
        small_degrees  = small_degrees || gga[4].compare(0, 1, "0") == 0 || gga[2].compare(0, 1, "0") == 0;
    }
    CHECK(small_fraction);
    CHECK(small_minutes);
    CHECK(small_degrees);

    // Seed 12677 begins at 23:59:50, so that fifteen epochs later the clock has turned over: it goes from 235959.00 to 000000.00.
    const Dataset day = make(12677, 45);
    std::string   before;
    bool          turned = false;
    for (std::size_t i = 0; i < day.frame_count(); i += 3) {
        const std::string time = fields_of(sentence_of(day, i))[1];
        if (i == 0) {
            REQUIRE(time == "235950.00");
        }
        if (!before.empty()) {
            turned = turned || (before == "235959.00" && time == "000000.00");
        }
        before = time;
    }
    CHECK(turned);
}

TEST_CASE("nmea0183: the limits of a sentence: 82 characters, printable, and the fields it has") {
    // A sentence of version 2.3 has all its fields, and one of 2.1 may lack the mode; GGA has no such form.
    const std::string vtg = "GPVTG,96.1,T,,M,2.7,N,5.0,K,";
    CHECK(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(vtg + "A"))));
    CHECK(bw::protocol_conforms("nmea0183", bytes_of(with_checksum("GPVTG,96.1,T,,M,2.7,N,5.0,K"))));      // 2.1: no mode
    const std::string gga = "GPGGA,123519.00,4807.03800,N,01131.00000,E,1,08,0.9,545.4,M,46.9,M,";
    CHECK(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(gga + ","))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(gga))));                              // 13 fields

    // The longest sentence is 82 characters with the $, the checksum and the CR LF.
    const std::string at_most = vtg + std::string(82 - 6 - vtg.size(), 'A');
    REQUIRE(with_checksum(at_most).size() == 82);
    CHECK(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(at_most))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(at_most + "A"))));

    // What is not printable is refused even when the checksum is right.
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(vtg + "\x01"))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(vtg + "\x1F"))));
    CHECK_FALSE(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(vtg + "\x7F"))));
    CHECK(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(vtg + "~"))));                              // 0x7E is
    CHECK(bw::protocol_conforms("nmea0183", bytes_of(with_checksum(vtg + " "))));                              // and so is a space
}
