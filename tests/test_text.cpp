// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Lines of text with a separator (bw/text.h): which byte separates, which kinds of line there are,
// and the fields of each. The lines are made here, from sentences that have the shape of NMEA 0183 and
// from others that do not, so that what is claimed is checked against what was written.

#include "doctest.h"

#include <cstdint>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/capture.h"
#include "bw/fields.h"
#include "bw/segmentation.h"
#include "bw/text.h"

using bw::FieldKind;
using bw::SizeKind;
using bw::TextField;
using bw::TextType;
using bw::TextTypes;

namespace {

typedef std::vector<std::uint8_t> Bytes;
typedef std::vector<Bytes>        Lines;

Bytes bytes_of(const std::string& text) {
    return Bytes(text.begin(), text.end());
}

std::string hex2(unsigned value) {
    const char digits[] = "0123456789ABCDEF";
    std::string out;
    out += digits[(value >> 4) & 15];
    out += digits[value & 15];
    return out;
}

// "$" + body + "*" + the exclusive or of the body, as two hexadecimal characters + CR LF.
std::string sentence(const std::string& body) {
    unsigned x = 0;
    for (std::size_t i = 0; i < body.size(); ++i) {
        x ^= static_cast<unsigned char>(body[i]);
    }
    return "$" + body + "*" + hex2(x) + "\r\n";
}

// A sentence of one kind with a time that is different in each, a hemisphere that is N or S, a number of one or two
// digits, and what does not change.
std::string abc(unsigned i) {
    return sentence("GPABC," + std::to_string(100000 + 37 * i) + "," + (i % 3 == 0 ? "N" : "S") + "," +
                    std::to_string(i * 13 % 97) + ",x");
}

// Another kind, with four fields.
std::string xyz(unsigned i) {
    return sentence("GPXYZ," + std::to_string(5 + i % 7) + "," + (i % 2 == 0 ? "A" : "V") + "," + std::to_string(i * 7 % 50) + ",");
}

Lines lines_of(const std::vector<std::string>& texts) {
    Lines out;
    for (std::size_t i = 0; i < texts.size(); ++i) {
        out.push_back(bytes_of(texts[i]));
    }
    return out;
}

std::vector<std::string> many(std::string (*make)(unsigned), unsigned from, unsigned to) {
    std::vector<std::string> out;
    for (unsigned i = from; i < to; ++i) {
        out.push_back(make(i));
    }
    return out;
}

// The bytes of a Constant, as text.
std::string value_of(const TextField& f) {
    return std::string(f.bytes.begin(), f.bytes.end());
}

TextTypes find(const Lines& lines) {
    return bw::find_text_types(lines, bw::FieldOptions());
}

} // namespace

TEST_CASE("text: sentences of one kind are its constants, its text up to a comma, the checksum and the end") {
    const TextTypes t = find(lines_of(many(abc, 0, 24)));
    REQUIRE(t.found);
    CHECK(t.separator == ',');
    CHECK(t.ignored == 0);
    REQUIRE(t.types.size() == 1);
    const TextType& type = t.types[0];
    CHECK(type.frames == 24);
    REQUIRE(type.fields.size() == 8);
    const std::vector<TextField>& f = type.fields;

    // The dollar and the address are constants, in 8 and 48 bits, and the evidence is 8 bits for each byte after the first line.
    CHECK(f[0].kind == FieldKind::Constant);
    CHECK(value_of(f[0]) == "$");
    CHECK(f[0].evidence_bits == 8 * 23);
    CHECK(f[1].kind == FieldKind::Constant);
    CHECK(value_of(f[1]) == "GPABC,");
    CHECK(f[1].evidence_bits == 8 * 6 * 23);

    // The time and the number take their width from what they hold; the hemisphere has two values.
    for (int i = 2; i <= 4; ++i) {
        CAPTURE(i);
        CHECK(f[i].kind == FieldKind::Text);
        CHECK(f[i].size_kind == SizeKind::Delimited);
        CHECK(f[i].delimiter == ',');
        CHECK(f[i].evidence_bits == 24);
    }
    CHECK(f[2].detail.empty());
    CHECK(f[3].detail == "one of \"N\", \"S\"");
    CHECK(f[4].detail.empty());

    // What is last before the checksum is constant: "x" and the star, which ends it.
    CHECK(f[5].kind == FieldKind::Constant);
    CHECK(value_of(f[5]) == "x*");

    CHECK(f[6].kind == FieldKind::Checksum);
    CHECK(f[6].covers_first == 1);                           // the address: the dollar is not covered
    CHECK(f[6].covers_last == 5);                            // up to the star, which is part of the last field
    CHECK(f[7].kind == FieldKind::Constant);
    CHECK(value_of(f[7]) == "\r\n");

    CHECK(type.checksum.found);
    CHECK(type.checksum.ascii_hex);
    CHECK(type.checksum.header_skip == 1);
    CHECK(type.checksum.gap_bytes == 1);
    CHECK(type.checksum.trailer_skip == 2);
    CHECK(type.smallest == 24);                              // the number has one digit or two
    CHECK(type.largest == 25);
}

TEST_CASE("text: the kinds are told apart by how they start, most lines first, and then by the head") {
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 20; ++i) {
        texts.push_back(xyz(i));
        if (i < 12) {
            texts.push_back(abc(i));
        }
    }
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 2);
    CHECK(t.types[0].frames == 20);
    CHECK(value_of(t.types[0].fields[1]) == "GPXYZ,");
    CHECK(t.types[1].frames == 12);
    CHECK(value_of(t.types[1].fields[1]) == "GPABC,");
    // The last field of the first is empty, and so is only its star.
    REQUIRE(t.types[0].fields.size() == 8);
    CHECK(t.types[0].fields[5].kind == FieldKind::Constant);
    CHECK(value_of(t.types[0].fields[5]) == "*");

    // With as many lines each, the head says: ABC before XYZ.
    std::vector<std::string> equal;
    for (unsigned i = 0; i < 12; ++i) {
        equal.push_back(xyz(i));
        equal.push_back(abc(i));
    }
    const TextTypes e = find(lines_of(equal));
    REQUIRE(e.types.size() == 2);
    CHECK(value_of(e.types[0].fields[1]) == "GPABC,");
    CHECK(value_of(e.types[1].fields[1]) == "GPXYZ,");
}

TEST_CASE("text: a few lines that are wrong do not change the separator, and are counted as left out") {
    // 196 sentences and four with other numbers of commas: the comma still puts 196 in a kind, and a byte that
    // every line has once (the dollar) puts all 200 in one, but has nothing to cut.
    std::vector<std::string> texts = many(abc, 0, 196);
    texts.push_back("$GPABC,1\r\n");
    texts.push_back("$GPABC,1,2\r\n");
    texts.push_back("$GPABC,1,2,3\r\n");
    texts.push_back("$GPABC,1,2,3,4,5\r\n");
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    CHECK(t.separator == ',');
    CHECK(t.ignored == 4);
    REQUIRE(t.types.size() == 1);
    CHECK(t.types[0].frames == 196);
    CHECK(t.types[0].fields.size() == 8);
    CHECK(t.types[0].checksum.found);
}

TEST_CASE("text: a line of a kind that does not end as the others is a frame of it, and not evidence for its fields") {
    std::vector<std::string> texts = many(abc, 0, 24);
    std::string              odd   = abc(24);
    odd[odd.size() - 1] = 'X';                                      // CR and then X: no line feed, no tail
    texts.push_back(odd);
    // Another is a wrong checksum: the sentence is cut like the others and the checksum search says one does not agree.
    std::string wrong = abc(25);
    wrong[wrong.size() - 3] = wrong[wrong.size() - 3] == '0' ? '1' : '0';
    texts.push_back(wrong);
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    CHECK(t.types[0].frames == 26);
    CHECK(t.types[0].fields[0].evidence_bits == 8 * 24);           // 25 lines are cut as the kind says: 24 after the first
    CHECK(t.types[0].fields[2].evidence_bits == 25);
    REQUIRE(t.types[0].checksum.found);
    CHECK(t.types[0].checksum.unexplained_frames == 1);            // the wrong one; the tail is not what a checksum covers
}

TEST_CASE("text: with no checksum the last field ends at the carriage return, and the line feed is the end") {
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 12; ++i) {
        texts.push_back("ST," + std::to_string(i + 1) + "," + std::to_string(i * 37 % 91) + "\r\n");
    }
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    const std::vector<TextField>& f = t.types[0].fields;
    CHECK_FALSE(t.types[0].checksum.found);
    REQUIRE(f.size() == 4);
    CHECK(value_of(f[0]) == "ST,");
    CHECK(f[1].kind == FieldKind::Text);
    CHECK(f[1].delimiter == ',');
    CHECK(f[2].kind == FieldKind::Text);
    CHECK(f[2].delimiter == '\r');
    CHECK(f[3].kind == FieldKind::Constant);
    CHECK(value_of(f[3]) == "\n");

    // Lines that end with a line feed alone have nothing after the last field.
    std::vector<std::string> unix_lines;
    for (unsigned i = 0; i < 12; ++i) {
        unix_lines.push_back("ST," + std::to_string(i + 1) + "," + std::to_string(i * 37 % 91) + "\n");
    }
    const TextTypes u = find(lines_of(unix_lines));
    REQUIRE(u.found);
    REQUIRE(u.types[0].fields.size() == 3);
    CHECK(u.types[0].fields[2].delimiter == '\n');
}

TEST_CASE("text: a checksum that starts at the first byte is not cut from the head, and one with no byte before it is no field") {
    // "ST,3,21*" and the checksum of all of it, from the first byte.
    std::vector<std::string> from_start;
    for (unsigned i = 0; i < 20; ++i) {
        const std::string body = "ST," + std::to_string(i + 1) + "," + std::to_string(i * 37 % 91);
        unsigned          x    = 0;
        for (std::size_t k = 0; k < body.size(); ++k) {
            x ^= static_cast<unsigned char>(body[k]);
        }
        from_start.push_back(body + "*" + hex2(x) + "\r\n");
    }
    const TextTypes t = find(lines_of(from_start));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    const std::vector<TextField>& f = t.types[0].fields;
    REQUIRE(t.types[0].checksum.found);
    CHECK(t.types[0].checksum.header_skip == 0);
    REQUIRE(f.size() == 5);
    CHECK(value_of(f[0]) == "ST,");
    CHECK(f[3].kind == FieldKind::Checksum);
    CHECK(f[3].covers_first == 0);
    CHECK(f[3].covers_last == 2);
    CHECK(f[2].delimiter == '*');

    // The characters straight after what they cover, with no byte between: there is nowhere to end the last field,
    // so the checksum is not a field of the line, and the line is read as if it had none.
    std::vector<std::string> glued;
    for (unsigned i = 0; i < 20; ++i) {
        const std::string body = "ST," + std::to_string(i + 1) + "," + std::to_string(i * 37 % 91);
        unsigned          x    = 0;
        for (std::size_t k = 0; k < body.size(); ++k) {
            x ^= static_cast<unsigned char>(body[k]);
        }
        glued.push_back(body + hex2(x) + "\r\n");
    }
    const TextTypes g = find(lines_of(glued));
    REQUIRE(g.found);
    REQUIRE(g.types.size() == 1);
    CHECK_FALSE(g.types[0].checksum.found);
    REQUIRE(g.types[0].fields.size() == 4);
    CHECK(g.types[0].fields[2].kind == FieldKind::Text);
    CHECK(g.types[0].fields[2].delimiter == '\r');
}

TEST_CASE("text: a constant of more than eight bytes is several, and a field that is always empty is its separator") {
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 12; ++i) {
        texts.push_back("ABCDEFGHIJKL," + std::to_string(i + 1) + ",,OK," + std::to_string(i * 37 % 91) + "\r\n");
    }
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    const std::vector<TextField>& f = t.types[0].fields;
    REQUIRE(f.size() == 7);
    CHECK(value_of(f[0]) == "ABCDEFGH");
    CHECK(value_of(f[1]) == "IJKL,");
    CHECK(f[0].evidence_bits == 8 * 8 * 11);
    CHECK(f[1].evidence_bits == 8 * 5 * 11);
    CHECK(f[2].kind == FieldKind::Text);                            // the counter
    CHECK(value_of(f[3]) == ",");                                   // empty
    CHECK(value_of(f[4]) == "OK,");
    CHECK(f[5].kind == FieldKind::Text);
    CHECK(f[5].delimiter == '\r');
    CHECK(value_of(f[6]) == "\n");
}

TEST_CASE("text: the values of a field are said when there are a few and each recurs, and not otherwise") {
    // `values` cycle through the lines; the second field is different in each.
    struct Case {
        std::vector<std::string> values;
        unsigned                 lines;
        const char*              detail;
    };
    std::vector<std::string> seventeen, sixteen;
    for (unsigned v = 0; v < 17; ++v) {
        seventeen.push_back(std::to_string(10 + v));
        if (v < 16) {
            sixteen.push_back(std::to_string(10 + v));
        }
    }
    std::vector<std::string> ab, abc3, quotes, empty_and_a, tabs;
    ab.push_back("A");
    ab.push_back("V");
    abc3.push_back("A");
    abc3.push_back("B");
    abc3.push_back("C");
    quotes.push_back("a\"b");
    quotes.push_back("c");
    empty_and_a.push_back("");
    empty_and_a.push_back("A");
    tabs.push_back("a\tb");
    tabs.push_back("c");
    const Case cases[] = {
        { ab,          8,  "one of \"A\", \"V\"" },                // four of each
        { ab,          7,  "" },                                      // 3.5 each
        { abc3,        12, "one of \"A\", \"B\", \"C\"" },
        { abc3,        11, "" },
        { sixteen,     64, "" },                                      // checked below: more than four each is needed
        { seventeen,   68, "" },                                      // more than sixteen
        { quotes,      8,  "" },                                      // a quote is not something to write plainly
        { empty_and_a, 8,  "one of \"\", \"A\"" },
        { tabs,        8,  "" },
    };
    for (std::size_t c = 0; c < sizeof(cases) / sizeof(cases[0]); ++c) {
        std::vector<std::string> texts;
        for (unsigned i = 0; i < cases[c].lines; ++i) {
            texts.push_back("K," + cases[c].values[i % cases[c].values.size()] + "," + std::to_string(i) + "\r\n");
        }
        CAPTURE(c);
        const TextTypes t = find(lines_of(texts));
        REQUIRE(t.found);
        REQUIRE(t.types.size() == 1);
        REQUIRE(t.types[0].fields.size() >= 3);
        CHECK(t.types[0].fields[1].kind == FieldKind::Text);
        const std::string expected = c == 4 ? "one of " : cases[c].detail;
        if (c == 4) {
            // Sixteen values of four lines each: the most that is said.
            CHECK(t.types[0].fields[1].detail.compare(0, expected.size(), expected) == 0);
            CHECK(t.types[0].fields[1].detail.find("\"25\"") != std::string::npos);
        } else {
            CHECK(t.types[0].fields[1].detail == expected);
        }
    }
}

TEST_CASE("text: a line with one separator is two fields") {
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 10; ++i) {
        texts.push_back("T=" + std::to_string(100 + 7 * i) + "\n");
    }
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    CHECK(t.separator == '=');
    REQUIRE(t.types.size() == 1);
    REQUIRE(t.types[0].fields.size() == 2);
    CHECK(value_of(t.types[0].fields[0]) == "T=");
    CHECK(t.types[0].fields[1].kind == FieldKind::Text);
    CHECK(t.types[0].fields[1].delimiter == '\n');
}

TEST_CASE("text: what is not lines of text with a separator is not found") {
    CHECK_FALSE(find(Lines()).found);

    // Bytes that are not characters.
    Lines binary;
    std::uint64_t x = 88172645463325252ULL;
    for (int i = 0; i < 30; ++i) {
        Bytes line;
        for (int k = 0; k < 40; ++k) {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            line.push_back(static_cast<std::uint8_t>(x >> 24));
        }
        line.push_back(0x0A);
        binary.push_back(line);
    }
    const TextTypes b = find(binary);
    CHECK_FALSE(b.found);
    CHECK(b.ignored == 30);

    // Lines that do not end with a line feed.
    std::vector<std::string> no_feed = many(abc, 0, 24);
    for (std::size_t i = 0; i < no_feed.size(); ++i) {
        no_feed[i].resize(no_feed[i].size() - 1);
    }
    CHECK_FALSE(find(lines_of(no_feed)).found);

    // No byte that is not a letter or a digit has the lines in kinds.
    std::vector<std::string> words;
    for (unsigned i = 0; i < 24; ++i) {
        words.push_back("alpha" + std::to_string(i) + "\n");
    }
    CHECK_FALSE(find(lines_of(words)).found);

    // Half of the lines in kinds is not enough: four in five are needed.
    std::vector<std::string> half = many(abc, 0, 24);
    for (unsigned i = 0; i < 24; ++i) {
        half.push_back("G" + std::to_string(1000 + i) + ",1,2\r\n");         // every one starts differently, with no dollar
    }
    CHECK_FALSE(find(lines_of(half)).found);

    // The same in four of five is.
    std::vector<std::string> most = many(abc, 0, 24);
    for (unsigned i = 0; i < 6; ++i) {
        most.push_back("G" + std::to_string(1000 + i) + ",1,2\r\n");
    }
    const TextTypes m = find(lines_of(most));
    CHECK(m.found);
    CHECK(m.ignored == 6);
    most.push_back("G1006,1,2\r\n");
    CHECK_FALSE(find(lines_of(most)).found);

    // The lines of a kind are at least `min_frames`.
    const Lines three = lines_of(many(abc, 0, 3));
    CHECK_FALSE(find(three).found);
    bw::FieldOptions options;
    options.min_frames = 3;
    CHECK(bw::find_text_types(three, options).found);
}

TEST_CASE("text: the pipeline makes the message types of lines of text, whatever cut them") {
    // One event for each line, which no segmentation said anything about.
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 12; ++i) {
        texts.push_back(xyz(i));
        texts.push_back(abc(i));
    }
    texts.push_back("odd one\n");
    texts.push_back("$GPQQQ,1,2\r\n");
    bw::Capture capture;
    std::vector<bw::FrameSpan> spans;
    for (std::size_t i = 0; i < texts.size(); ++i) {
        capture.add_event(bw::EventInfo(), bytes_of(texts[i]));
        bw::FrameSpan span;
        span.first_event = i;
        span.event_count = 1;
        spans.push_back(span);
    }
    bw::SegmentationInfo info;
    info.found = true;
    const bw::Analysis a = bw::analyze_frames(capture, bw::Segmentation(info, spans), bw::AnalyzeOptions());
    REQUIRE(a.type_count() == 2);
    CHECK(a.info().frames == 26);
    CHECK(a.info().ignored_frames == 2);
    CHECK(a.type_report(0).frames == 12);
    CHECK(a.type_report(0).frame_bytes == 24);
    CHECK(a.type_report(0).largest_frame_bytes == 25);
    CHECK(a.type_report(0).checksum.found);

    const bw::Model m = a.model();
    REQUIRE(m.message_type_count() == 2);
    CHECK(m.message_type_name(0) == "type0");
    REQUIRE(m.field_count(0) == 8);
    CHECK(m.field_name(0, 0) == "field_0");
    CHECK(m.field(0, 0).kind == FieldKind::Constant);
    CHECK(m.field(0, 0).constant == '$');
    CHECK(m.field(0, 0).bit_size == 8);
    CHECK(m.field(0, 0).byte_order == bw::ByteOrder::NotApplicable);
    CHECK(m.field(0, 1).bit_size == 48);
    CHECK(m.field(0, 1).byte_order == bw::ByteOrder::Big);
    CHECK(m.field(0, 1).constant == 0x47504142432CULL);                  // GPABC,
    CHECK(m.field(0, 3).kind == FieldKind::Text);
    CHECK(m.field(0, 3).size_kind == SizeKind::Delimited);
    CHECK(m.field(0, 3).delimiter == ',');
    CHECK(m.field_position(0, 2).fixed);
    CHECK_FALSE(m.field_position(0, 3).fixed);
    CHECK(m.field_name(0, 6) == "checksum");
    CHECK(m.field(0, 6).ascii_hex);
    CHECK(m.field(0, 6).covers_first == 1);
    CHECK(m.field(0, 6).covers_last == 5);
    CHECK(m.field_detail(0, 6) == "XOR-8");
    CHECK(m.field(0, 6).evidence_bits == a.type_report(0).checksum.evidence_bits);
    CHECK(m.field_detail(0, 3) == "one of \"N\", \"S\"");

    const std::string described = bw::describe_analysis(a);
    CHECK(described.find("frames     26 (2 of a size or kind too rare to say anything about)\n") != std::string::npos);
    CHECK(described.find("type0      24 to 25 bytes, 12 frames; checksum XOR-8, written as two hexadecimal characters, evidence ") !=
          std::string::npos);
}

TEST_CASE("text: 95% of the bytes are characters and 95% of the lines end with a line feed, and not a line less") {
    // Twenty lines of ten bytes: K, a letter, a comma, five digits and a line feed.
    const auto make = [](unsigned bad_bytes, unsigned no_feed, char last) {
        Lines lines;
        for (unsigned i = 0; i < 20; ++i) {
            std::string text = "K,";
            text += static_cast<char>('A' + i % 2);
            text += ",";
            text += std::to_string(10000 + i * 37);
            text += last;
            if (i < bad_bytes) {
                text[text.size() - 2] = '\x01';                          // not a character
            }
            if (i >= 20 - no_feed) {
                text[text.size() - 1] = ' ';                             // no line feed
            }
            lines.push_back(bytes_of(text));
        }
        return lines;
    };
    CHECK(find(make(0, 0, '\n')).found);
    CHECK(find(make(10, 0, '\n')).found);                                // 190 of 200: 95%
    CHECK_FALSE(find(make(11, 0, '\n')).found);
    CHECK(find(make(0, 1, '\n')).found);                                 // 19 of 20 end with a line feed
    CHECK_FALSE(find(make(0, 2, '\n')).found);
    // A tilde is a character, in a byte in ten of them.
    Lines tilde = make(0, 0, '\n');
    for (std::size_t i = 0; i < tilde.size(); ++i) {
        tilde[i][tilde[i].size() - 2] = '~';
    }
    CHECK(find(tilde).found);
    // And 0x7F is not.
    Lines del = make(0, 0, '\n');
    for (std::size_t i = 0; i < del.size(); ++i) {
        del[i][del[i].size() - 2] = 0x7F;
    }
    CHECK_FALSE(find(del).found);
}

TEST_CASE("text: of two separators with as many in the lines that they make kinds of, the one with more lines in them, then more kinds") {
    // 35 lines have four semicolons; 28 of them also have five commas after a start that is always the same: a kind of
    // 35 lines and 140 semicolons, and a kind of 28 lines (four in five of them) and 140 commas. The semicolon has more lines.
    std::vector<std::string> lines;
    for (unsigned i = 0; i < 35; ++i) {
        std::string text = "K;1;2;3;4";
        if (i < 28) {
            for (unsigned k = 0; k < 5; ++k) {
                text += "," + std::to_string(10 + (i * 7 + k * 3) % 90);
            }
        }
        lines.push_back(text + "\n");
    }
    const TextTypes more_lines = find(lines_of(lines));
    REQUIRE(more_lines.found);
    CHECK(more_lines.separator == ';');
    CHECK(more_lines.ignored == 0);

    // 36 lines with three semicolons and three commas each: the semicolons are in one kind and the commas in two (the start
    // is a or b), and the commas have more kinds.
    std::vector<std::string> kinds;
    for (unsigned i = 0; i < 36; ++i) {
        kinds.push_back(std::string("K;") + (i % 2 == 0 ? "a" : "b") + "," + std::to_string(10 + i) + ";" + std::to_string(20 + i * 3 % 70) +
                        ";" + std::to_string(30 + i * 5 % 60) + "," + std::to_string(40 + i * 7 % 50) + "," + std::to_string(50 + i) + "\n");
    }
    const TextTypes more_kinds = find(lines_of(kinds));
    REQUIRE(more_kinds.found);
    CHECK(more_kinds.separator == ',');
    CHECK(more_kinds.types.size() == 2);

    // Two kinds for the semicolon, by how many of them there are (two and four), and one for the comma, which has more of
    // the start in common: 120 of each in 40 lines, and the semicolon has more kinds.
    std::vector<std::string> counts;
    for (unsigned i = 0; i < 40; ++i) {
        std::string text = "K;x," + std::to_string(10 + i) + "," + std::to_string(20 + i * 3 % 70) + "," + std::to_string(30 + i * 5 % 60) + ";";
        if (i % 2 == 1) {
            text += std::to_string(40 + i) + ";" + std::to_string(50 + i * 7 % 40) + ";";
        }
        counts.push_back(text + "\n");
    }
    const TextTypes by_count = find(lines_of(counts));
    REQUIRE(by_count.found);
    CHECK(by_count.separator == ';');
    CHECK(by_count.types.size() == 2);
}

TEST_CASE("text: a separator that has kinds for four lines in five or more is the one looked at, and not one that has more separators in fewer") {
    // 14 of 20 lines have ten commas in a kind: 70% of the lines, and the most separators. The six others have a comma too, each
    // after something of its own, and are in no kind. The dollar is in all of them.
    std::vector<std::string> seventy;
    for (unsigned i = 0; i < 20; ++i) {
        std::string text = "$K";
        if (i < 14) {
            for (unsigned k = 0; k < 10; ++k) {
                text += "," + std::to_string(i * 3 + k);
            }
        } else {
            text = "$Q" + std::to_string(i) + ",x";
        }
        seventy.push_back(text + "\n");
    }
    const TextTypes t = find(lines_of(seventy));
    REQUIRE(t.found);
    CHECK(t.separator == '$');

    // At 16 of 20 (four in five) the commas are in: it is one that makes kinds of enough of the lines.
    std::vector<std::string> eighty;
    for (unsigned i = 0; i < 20; ++i) {
        eighty.push_back(i < 16 ? "$K," + std::to_string(i) + "," + std::to_string(i * 7) + "," + std::to_string(i * 5 + 1) + "\n"
                                : "$other" + std::to_string(i) + "\n");
    }
    const TextTypes e = find(lines_of(eighty));
    REQUIRE(e.found);
    CHECK(e.separator == ',');
    CHECK(e.ignored == 4);
}

TEST_CASE("text: letters and digits are never the separator, and the bytes next to them in the table can be") {
    // Three of a byte in every line, then two commas: where the byte may be the separator it is, with more of them.
    const char alphanumeric[] = { '0', '9', 'A', 'Z', 'a', 'z' };
    const char others[]       = { '/', ':', '@', '[', '`', '{' };
    for (int k = 0; k < 12; ++k) {
        const char ch = k < 6 ? alphanumeric[k] : others[k - 6];
        std::vector<std::string> lines;
        for (unsigned i = 0; i < 12; ++i) {
            lines.push_back(std::string(3, ch) + "K," + std::to_string(10 + i * 7) + "," + std::to_string(50 + i * 3) + "\n");
        }
        CAPTURE(ch);
        const TextTypes t = find(lines_of(lines));
        REQUIRE(t.found);
        CHECK(t.separator == (k < 6 ? ',' : ch));
    }
}

TEST_CASE("text: a kind whose lines do not end alike is not a type, and nothing is found when that is all there is") {
    // Three lines of a kind end with a carriage return and a line feed, and one with a line feed: the kind has four lines,
    // and three of them are cut as it says, which is fewer than a type needs.
    const Lines mixed = lines_of({ "K,1,2\r\n", "K,3,4\r\n", "K,5,6\r\n", "K,7,8\n" });
    CHECK_FALSE(find(mixed).found);
    CHECK(find(mixed).types.empty());
}

TEST_CASE("text: what makes a line one of the kind's is its ending, its separators, and its last field up to the first delimiter") {
    // 24 sentences, and a 25th whose star is another byte: it is a line of the kind (the same start, as many commas) that is
    // not cut as the others, so the last field is the same in all that are, and the checksum is a field of the kind.
    std::vector<std::string> texts = many(abc, 0, 24);
    std::string              no_star = abc(24);
    no_star[no_star.find('*')] = '!';
    texts.push_back(no_star);
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    CHECK(t.types[0].frames == 25);
    CHECK(t.types[0].fields[0].evidence_bits == 8 * 23);
    CHECK(t.types[0].fields[5].kind == FieldKind::Constant);
    CHECK(value_of(t.types[0].fields[5]) == "x*");

    // A line whose last field has the delimiter before its end (a carriage return inside it) is no line of the kind either.
    std::vector<std::string> inside;
    for (unsigned i = 0; i < 12; ++i) {
        inside.push_back("K," + std::to_string(i + 1) + "," + std::to_string(i * 37 % 91) + "\r\n");
    }
    inside.push_back("K,3,x\ry\r\n");
    const TextTypes in = find(lines_of(inside));
    REQUIRE(in.found);
    REQUIRE(in.types.size() == 1);
    CHECK(in.types[0].frames == 13);
    CHECK(in.types[0].fields[0].evidence_bits == 8 * 2 * 11);                 // "K,", for the twelve that are cut as the kind says

    // A separator after the checksum is a field of the end, which is constant: ",\n" there.
    std::vector<std::string> after;
    for (unsigned i = 0; i < 24; ++i) {
        std::string s = abc(i);
        s.replace(s.size() - 2, 2, ",\n");
        after.push_back(s);
    }
    const TextTypes a = find(lines_of(after));
    REQUIRE(a.found);
    REQUIRE(a.types.size() == 1);
    REQUIRE(a.types[0].fields.size() == 8);
    CHECK(a.types[0].fields[6].kind == FieldKind::Checksum);
    CHECK(value_of(a.types[0].fields[7]) == ",\n");
    CHECK(a.types[0].checksum.trailer_skip == 2);
    CHECK(a.types[0].fields[2].evidence_bits == 24);

    // A last field that is empty is a field: it is the delimiter, and the line is as long as the head and the delimiter and
    // what follows. Of these lines, with one separator, one in four has nothing after it.
    std::vector<std::string> empty;
    for (unsigned i = 0; i < 24; ++i) {
        empty.push_back(sentence("GPABC," + (i % 4 == 0 ? std::string() : std::to_string(100 + i * 7))));
    }
    const TextTypes e = find(lines_of(empty));
    REQUIRE(e.found);
    REQUIRE(e.types.size() == 1);
    REQUIRE(e.types[0].fields.size() == 5);
    CHECK(e.types[0].fields[2].kind == FieldKind::Text);
    CHECK(e.types[0].fields[2].delimiter == '*');
    CHECK(e.types[0].fields[2].evidence_bits == 24);
}

TEST_CASE("text: lines that end in two ways are the kind's with the more common, the first of them when there are as many") {
    // Two end with a carriage return and a line feed and two with a line feed: the line feed alone is the first in the
    // order of bytes, and it is what they end with; the carriage return is then in the last field of two.
    const Lines tied = lines_of({ "K,1,2\r\n", "K,3,4\n", "K,5,6\r\n", "K,7,8\n" });
    const TextTypes t = find(tied);
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    REQUIRE(t.types[0].fields.size() == 3);
    CHECK(t.types[0].fields[2].delimiter == '\n');
}

TEST_CASE("text: with as many of one separator as of another in as many kinds, the one that has more of the start in common") {
    // One comma in each line, and the dollar once: the comma has the address before it, which is the same in all of them.
    std::vector<std::string> lines;
    for (unsigned i = 0; i < 24; ++i) {
        lines.push_back(sentence("GPABC," + std::to_string(100 + i * 7)));
    }
    const TextTypes t = find(lines_of(lines));
    REQUIRE(t.found);
    CHECK(t.separator == ',');
    REQUIRE(t.types.size() == 1);
    REQUIRE(t.types[0].fields.size() == 5);
    CHECK(value_of(t.types[0].fields[1]) == "GPABC,");
}

TEST_CASE("text: lines between flags are read without them") {
    // Twelve sentences of two kinds, each between two tildes, as a segmentation by flags gives them.
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 12; ++i) {
        texts.push_back(std::string("~") + abc(i) + "~");
        texts.push_back(std::string("~") + xyz(i) + "~");
    }
    bw::Capture capture;
    std::vector<bw::FrameSpan> spans;
    for (std::size_t i = 0; i < texts.size(); ++i) {
        capture.add_event(bw::EventInfo(), bytes_of(texts[i]));
        bw::FrameSpan span;
        span.first_event = i;
        span.event_count = 1;
        spans.push_back(span);
    }
    bw::SegmentationInfo info;
    info.found     = true;
    info.kind      = bw::FramingKind::Flagged;
    info.delimiter = '~';
    const bw::Analysis a = bw::analyze_frames(capture, bw::Segmentation(info, spans), bw::AnalyzeOptions());
    REQUIRE(a.type_count() == 2);
    CHECK(a.model().framing().kind == bw::FramingKind::Flagged);
    CHECK(a.model().field(0, 0).constant == '$');
    CHECK(a.type_report(0).frame_bytes == 24);                      // without the flags
    CHECK(a.type_report(0).checksum.found);
}

TEST_CASE("text: a checksum may start to cover where the head ends, and then the head is all constant") {
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 24; ++i) {
        const std::string value = std::to_string(1000 + i * 37);
        unsigned          x     = 0;
        for (std::size_t k = 0; k < value.size(); ++k) {
            x ^= static_cast<unsigned char>(value[k]);
        }
        texts.push_back("K," + value + "*" + hex2(x) + "\r\n");
    }
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    REQUIRE(t.types[0].checksum.found);
    CHECK(t.types[0].checksum.header_skip == 2);
    const std::vector<TextField>& f = t.types[0].fields;
    REQUIRE(f.size() == 4);
    CHECK(value_of(f[0]) == "K,");
    CHECK(f[1].kind == FieldKind::Text);
    CHECK(f[1].delimiter == '*');
    CHECK(f[2].kind == FieldKind::Checksum);
    CHECK(f[2].covers_first == 1);
    CHECK(f[2].covers_last == 1);
    CHECK(value_of(f[3]) == "\r\n");
}

TEST_CASE("text: a checksum that follows a separator is not a field of its own, and no type is made of lines that are none") {
    // The byte before the two characters is the separator: the last field would be that byte alone, and where the fields
    // end would be said twice. The lines are read as if they had no checksum, and the last field has the characters.
    std::vector<std::string> texts;
    for (unsigned i = 0; i < 24; ++i) {
        const std::string body = "K," + std::to_string(10 + i * 7) + "," + std::to_string(100 + i * 13 % 89);
        unsigned          x    = 0;
        for (std::size_t k = 0; k < body.size(); ++k) {
            x ^= static_cast<unsigned char>(body[k]);
        }
        texts.push_back(body + "," + hex2(x) + "\r\n");
    }
    const TextTypes t = find(lines_of(texts));
    REQUIRE(t.found);
    REQUIRE(t.types.size() == 1);
    CHECK_FALSE(t.types[0].checksum.found);
    const std::vector<TextField>& f = t.types[0].fields;
    REQUIRE(f.size() == 5);
    CHECK(f[3].kind == FieldKind::Text);
    CHECK(f[3].delimiter == '\r');
    CHECK(value_of(f[4]) == "\n");

    // Lines whose last field has the carriage return inside are cut as none of them is, and nothing is made of them, with no
    // minimum of lines as with any.
    bw::FieldOptions none;
    none.min_frames = 0;
    CHECK_FALSE(bw::find_text_types(lines_of({ "K,a\rb\r\n", "K,c\rd\r\n" }), none).found);
}
