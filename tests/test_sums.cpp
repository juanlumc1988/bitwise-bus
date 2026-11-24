// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The checksums that are not CRCs (bw/sums.h), and stage 2 searching for them: as
// a byte, as two bytes, and as two characters of text after a separator.
//
// The values are published ones (the u-blox protocol description, the NMEA 0183
// sentence everybody quotes, the Fletcher-16 of "abcde" of the literature) and
// the frames the search is tried on are built here with a definition of the sums
// of their own, so that no test rests on the code it tests.

#include "doctest.h"

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "bw/catalog.h"
#include "bw/checksum.h"
#include "bw/crc_search.h"
#include "bw/segmentation.h"
#include "bw/sums.h"
#include "frame_fixtures.h"

using bw::ByteOrder;
using bw::ChecksumFinding;
using fixtures::Bytes;

namespace {

const bw::SumSpec& sum(const char* name) {
    const bw::SumSpec* spec = bw::sum_find(name);
    REQUIRE(spec != nullptr);
    return *spec;
}

Bytes text(const char* s) {
    return Bytes(s, s + std::strlen(s));
}

std::uint64_t compute(const char* name, const Bytes& data) {
    return bw::sum_compute(sum(name), data.empty() ? nullptr : &data[0], data.size());
}

// ---- A definition of the sums that is not the library's: the two running sums with a modulus.

std::uint32_t fletcher(const Bytes& data, std::uint32_t modulus) {
    std::uint32_t first = 0, second = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        first  = (first + data[i]) % modulus;
        second = (second + first) % modulus;
    }
    return (second << 8) | first;
}

std::uint8_t xor_of(const Bytes& data) {
    std::uint8_t out = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        out = static_cast<std::uint8_t>(out ^ data[i]);
    }
    return out;
}

std::uint8_t sum_of(const Bytes& data) {
    unsigned total = 0;
    for (std::size_t i = 0; i < data.size(); ++i) {
        total += data[i];
    }
    return static_cast<std::uint8_t>(total & 0xFF);
}

// What each frame form puts where the checksum goes, for the bytes that it covers.
typedef Bytes (*Encoder)(const Bytes& covered);

Bytes enc_xor(const Bytes& c)  { return Bytes(1, xor_of(c)); }
Bytes enc_sum(const Bytes& c)  { return Bytes(1, sum_of(c)); }
Bytes enc_neg(const Bytes& c)  { return Bytes(1, static_cast<std::uint8_t>(0x100 - sum_of(c))); }
Bytes enc_f8_le(const Bytes& c) {
    const std::uint32_t v = fletcher(c, 256);
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    return out;
}
Bytes enc_f8_be(const Bytes& c) {
    const Bytes le = enc_f8_le(c);
    Bytes       out;
    out.push_back(le[1]);
    out.push_back(le[0]);
    return out;
}
Bytes enc_f16_le(const Bytes& c) {
    const std::uint32_t v = fletcher(c, 255);
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(v & 0xFF));
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    return out;
}
Bytes hex_of(std::uint8_t value, const char* digits) {
    Bytes out;
    out.push_back(static_cast<std::uint8_t>(digits[value >> 4]));
    out.push_back(static_cast<std::uint8_t>(digits[value & 15]));
    return out;
}
Bytes enc_hex_upper(const Bytes& c) { return hex_of(xor_of(c), "0123456789ABCDEF"); }
Bytes enc_hex_lower(const Bytes& c) { return hex_of(xor_of(c), "0123456789abcdef"); }
Bytes enc_hex_sum(const Bytes& c)   { return hex_of(sum_of(c), "0123456789ABCDEF"); }
// A text checksum that is not text.
Bytes enc_not_hex(const Bytes& c)   { Bytes out = enc_hex_upper(c); out[0] = 'G'; return out; }
// The F8 sums, and then the sum of all of that: a checksum over a checksum.
Bytes enc_f8_then_sum(const Bytes& c) {
    Bytes out = enc_f8_le(c);
    Bytes all = c;
    all.insert(all.end(), out.begin(), out.end());
    out.push_back(sum_of(all));
    return out;
}

// header (random, not covered) + payload (random, covered) + the separator, if any + the checksum + trailer.
Bytes frame(fixtures::Random* rng, std::size_t header, std::size_t payload, int separator, Encoder encode,
            std::size_t trailer) {
    Bytes out;
    for (std::size_t i = 0; i < header; ++i) {
        out.push_back(rng->byte());
    }
    Bytes covered;
    for (std::size_t i = 0; i < payload; ++i) {
        covered.push_back(rng->byte());
    }
    out.insert(out.end(), covered.begin(), covered.end());
    if (separator >= 0) {
        out.push_back(static_cast<std::uint8_t>(separator));
    }
    const Bytes field = encode(covered);
    out.insert(out.end(), field.begin(), field.end());
    for (std::size_t i = 0; i < trailer; ++i) {
        out.push_back(rng->byte());
    }
    return out;
}

std::vector<Bytes> frames_of(unsigned seed, std::size_t count, std::size_t header, std::size_t payload,
                             int separator, Encoder encode, std::size_t trailer) {
    fixtures::Random   rng(seed);
    std::vector<Bytes> out;
    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(frame(&rng, header, payload, separator, encode, trailer));
    }
    return out;
}

ChecksumFinding search(const std::vector<Bytes>& frames) {
    const bw::Capture      capture = fixtures::capture_of(frames);
    const bw::Segmentation cut     = bw::segment_by_gaps(capture, bw::SegmentationOptions());
    return bw::find_checksum(capture, cut, static_cast<std::uint32_t>(frames[0].size()));
}

} // namespace

TEST_CASE("sums: the list is closed, with the names and widths the documentation gives") {
    REQUIRE(bw::sum_count() == 5);
    const char*   names[5]  = { "XOR-8", "SUM-8", "SUM-8/NEGATED", "FLETCHER-8", "FLETCHER-16" };
    const unsigned widths[5] = { 8, 8, 8, 16, 16 };
    for (std::size_t i = 0; i < 5; ++i) {
        CHECK(std::string(bw::sums()[i].name) == names[i]);
        CHECK(bw::sums()[i].width == widths[i]);
        CHECK(bw::sum_find(names[i]) == &bw::sums()[i]);
    }
    CHECK(bw::sum_find("CRC-16/MODBUS") == nullptr);
    CHECK(bw::sum_find("xor-8") == nullptr);          // names are exact
    CHECK(bw::sum_find("") == nullptr);
    CHECK(bw::sum_find(nullptr) == nullptr);
}

TEST_CASE("sums: published values") {
    // u-blox, the polls and an acknowledgement in the description of the protocol: the two sums over the
    // class, the identifier, the length and the payload, first the sum of the bytes and then the sum of the sums.
    const std::uint8_t mon_ver[] = { 0x0A, 0x04, 0x00, 0x00 };                   // B5 62 0A 04 00 00 0E 34
    CHECK(bw::sum_compute(sum("FLETCHER-8"), mon_ver, sizeof(mon_ver)) == 0x340E);
    const std::uint8_t ack_ack[] = { 0x05, 0x01, 0x02, 0x00, 0x06, 0x01 };       // B5 62 05 01 02 00 06 01 0F 38
    CHECK(bw::sum_compute(sum("FLETCHER-8"), ack_ack, sizeof(ack_ack)) == 0x380F);

    // NMEA 0183, the sentence of every description: the characters between the dollar and the star.
    CHECK(compute("XOR-8", text("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,")) == 0x47);

    // Fletcher-16, as in the literature: modulo 255.
    CHECK(compute("FLETCHER-16", text("abcde")) == 0xC8F0);
    CHECK(compute("FLETCHER-16", text("abcdef")) == 0x2057);
    CHECK(compute("FLETCHER-16", text("abcdefgh")) == 0x0627);
    // And modulo 256, which is the one UBX uses.
    CHECK(compute("FLETCHER-8", text("abcde")) == 0xC3EF);
    CHECK(compute("FLETCHER-8", text("abcdef")) == 0x1855);
    CHECK(compute("FLETCHER-8", text("abcdefgh")) == 0xF824);

    // The sum, and the byte that makes the sum of everything 0 (the LRC of Modbus ASCII): 1+3+0+0+0+10 = 14.
    const std::uint8_t request[] = { 0x01, 0x03, 0x00, 0x00, 0x00, 0x0A };
    CHECK(bw::sum_compute(sum("SUM-8"), request, sizeof(request)) == 0x0E);
    CHECK(bw::sum_compute(sum("SUM-8/NEGATED"), request, sizeof(request)) == 0xF2);
}

TEST_CASE("sums: the two moduli are not the same sum") {
    // 0xFF is 0 modulo 255 and 255 modulo 256.
    const std::uint8_t data[] = { 0xFF, 0x01 };
    CHECK(bw::sum_compute(sum("FLETCHER-8"), data, 2) == 0xFF00);
    CHECK(bw::sum_compute(sum("FLETCHER-16"), data, 2) == 0x0101);
    // The sum wraps at 256, and the sum of the sums does too.
    const std::uint8_t wrap[] = { 0xFF, 0xFF, 0x02 };
    CHECK(bw::sum_compute(sum("SUM-8"), wrap, 3) == 0x00);
    CHECK(bw::sum_compute(sum("SUM-8/NEGATED"), wrap, 3) == 0x00);
    CHECK(bw::sum_compute(sum("XOR-8"), wrap, 3) == 0x02);
}

TEST_CASE("sums: nothing gives zero, and so does a sum that is not on the list") {
    for (std::size_t i = 0; i < bw::sum_count(); ++i) {
        CHECK(bw::sum_compute(bw::sums()[i], nullptr, 0) == 0);
    }
    const bw::SumSpec other = { "NOT-A-SUM", 8 };
    const std::uint8_t data[] = { 1, 2, 3 };
    CHECK(bw::sum_compute(other, data, 3) == 0);
}

TEST_CASE("sums: the library agrees with the test's own definition on random data") {
    fixtures::Random rng(11);
    for (int round = 0; round < 200; ++round) {
        Bytes data;
        const std::size_t n = rng.byte() % 40;
        for (std::size_t i = 0; i < n; ++i) {
            data.push_back(rng.byte());
        }
        CHECK(compute("XOR-8", data) == xor_of(data));
        CHECK(compute("SUM-8", data) == sum_of(data));
        CHECK(compute("SUM-8/NEGATED", data) == static_cast<std::uint8_t>(0x100 - sum_of(data)));
        CHECK(compute("FLETCHER-8", data) == fletcher(data, 256));
        CHECK(compute("FLETCHER-16", data) == fletcher(data, 255));
    }
}

TEST_CASE("sums, stage 2: every sum is found where it is, by name, with the evidence it gives") {
    struct Row {
        const char* name;
        Encoder     encode;
        unsigned    width;
        ByteOrder   order;
    };
    const Row rows[] = {
        { "XOR-8",         enc_xor,    8,  ByteOrder::NotApplicable },
        { "SUM-8",         enc_sum,    8,  ByteOrder::NotApplicable },
        { "SUM-8/NEGATED", enc_neg,    8,  ByteOrder::NotApplicable },
        { "FLETCHER-8",    enc_f8_le,  16, ByteOrder::Little },
        { "FLETCHER-8",    enc_f8_be,  16, ByteOrder::Big },
        { "FLETCHER-16",   enc_f16_le, 16, ByteOrder::Little },
    };
    for (std::size_t r = 0; r < sizeof(rows) / sizeof(rows[0]); ++r) {
        CAPTURE(rows[r].name);
        CAPTURE(r);
        const ChecksumFinding f = search(frames_of(5, 20, 2, 7, -1, rows[r].encode, 1));
        REQUIRE(f.found);
        CHECK(bw::checksum_algorithm_name(f.algorithm) == rows[r].name);
        CHECK(f.algorithm >= bw::catalog_size());
        CHECK(f.candidates == 1);
        CHECK_FALSE(f.truncated);
        CHECK(f.width_bits == rows[r].width);
        CHECK(f.byte_order == rows[r].order);
        CHECK_FALSE(f.ascii_hex);
        CHECK(f.header_skip == 2);
        CHECK(f.trailer_skip == 1);
        CHECK(f.gap_bytes == 0);
        CHECK(f.frames == 20);
        CHECK(f.distinct_frames == 20);
        CHECK(f.evidence_bits == 20 * rows[r].width);
    }
}

TEST_CASE("sums, stage 2: where it sits can be anywhere the CRCs are looked for, and not further") {
    // As far as the search goes: 4 bytes of header and 2 after.
    const ChecksumFinding far = search(frames_of(6, 20, 4, 6, -1, enc_f8_le, 2));
    REQUIRE(far.found);
    CHECK(far.header_skip == 4);
    CHECK(far.trailer_skip == 2);
    // One more in either direction and it is not there to be found.
    const ChecksumFinding header = search(frames_of(6, 20, 5, 6, -1, enc_f8_le, 0));
    CHECK_FALSE(header.found);
    CHECK(header.candidates == 0);
    CHECK(header.evidence_bits == 0);
    const ChecksumFinding trailer = search(frames_of(6, 20, 0, 6, -1, enc_f8_le, 3));
    CHECK_FALSE(trailer.found);
    CHECK(trailer.candidates == 0);
    // And every place in between.
    for (std::size_t h = 0; h <= 4; ++h) {
        for (std::size_t t = 0; t <= 2; ++t) {
            CAPTURE(h);
            CAPTURE(t);
            const ChecksumFinding f = search(frames_of(7, 12, h, 5, -1, enc_xor, t));
            REQUIRE(f.found);
            CHECK(f.header_skip == h);
            CHECK(f.trailer_skip == t);
        }
    }
}

TEST_CASE("sums, stage 2: the first sum of Fletcher's is a part of it, not another answer") {
    // A frame that ends with Fletcher's two sums ends, in front of the second, with the plain sum of
    // the same bytes: SUM-8 explains the frame too, shorter by a byte. It is one finding.
    const ChecksumFinding f = search(frames_of(8, 30, 2, 8, -1, enc_f8_le, 0));
    REQUIRE(f.found);
    CHECK(f.candidates == 1);
    CHECK(bw::checksum_algorithm_name(f.algorithm) == "FLETCHER-8");
    CHECK(f.trailer_skip == 0);
    CHECK(f.evidence_bits == 30 * 16);          // 16, not the 8 of the part
    // With the sums the other way round, the part is not there to be one.
    const ChecksumFinding be = search(frames_of(8, 30, 2, 8, -1, enc_f8_be, 0));
    REQUIRE(be.found);
    CHECK(be.candidates == 1);
    CHECK(be.byte_order == ByteOrder::Big);
}

TEST_CASE("sums, stage 2: as text, after a separator, the way NMEA 0183 writes it") {
    // $ payload * two hexadecimal characters CR LF
    fixtures::Random rng(9);
    std::vector<Bytes> sentences;
    for (int i = 0; i < 20; ++i) {
        Bytes s(1, '$');
        const Bytes body = frame(&rng, 0, 9, '*', enc_hex_upper, 0);
        s.insert(s.end(), body.begin(), body.end());
        s.push_back('\r');
        s.push_back('\n');
        sentences.push_back(s);
    }
    const ChecksumFinding f = search(sentences);
    REQUIRE(f.found);
    CHECK(bw::checksum_algorithm_name(f.algorithm) == "XOR-8");
    CHECK(f.ascii_hex);
    CHECK(f.width_bits == 16);                  // on the wire
    CHECK(f.byte_order == ByteOrder::Big);
    CHECK(f.header_skip == 1);
    CHECK(f.gap_bytes == 1);
    CHECK(f.trailer_skip == 2);
    CHECK(f.candidates == 1);
    CHECK(f.evidence_bits == 20 * 8);           // what it holds, not what it takes

    // Without the separator the same text is in the same place.
    const ChecksumFinding bare = search(frames_of(10, 20, 1, 9, -1, enc_hex_upper, 2));
    REQUIRE(bare.found);
    CHECK(bare.ascii_hex);
    CHECK(bare.gap_bytes == 0);
    CHECK(bare.header_skip == 1);
    CHECK(bare.trailer_skip == 2);

    // Lower case is the same number.
    const ChecksumFinding lower = search(frames_of(11, 20, 1, 9, '*', enc_hex_lower, 2));
    REQUIRE(lower.found);
    CHECK(lower.ascii_hex);
    CHECK(lower.gap_bytes == 1);

    // What is written is any of the sums of one byte, not only the exclusive or.
    const ChecksumFinding sum_text = search(frames_of(12, 20, 1, 9, '*', enc_hex_sum, 2));
    REQUIRE(sum_text.found);
    CHECK(bw::checksum_algorithm_name(sum_text.algorithm) == "SUM-8");
    CHECK(sum_text.ascii_hex);

    // A character that is not a digit is not a checksum, and nothing else explains it.
    const ChecksumFinding broken = search(frames_of(13, 20, 1, 9, '*', enc_not_hex, 2));
    CHECK_FALSE(broken.found);
    CHECK(broken.candidates == 0);
}

TEST_CASE("sums, stage 2: a character that is not a digit is not a checksum, whichever it is") {
    // The second character is what the exclusive or would be if 'G' were the digit before 'A' minus one:
    // 0x3F is "4" and then nothing, 4 * 16 - 1, which is what reading 'G' as -1 comes to.
    fixtures::Random   rng(20);
    std::vector<Bytes> frames;
    for (int i = 0; i < 20; ++i) {
        Bytes f(1, '$');
        std::uint8_t x = 0;
        for (int k = 0; k < 8; ++k) {
            f.push_back(rng.byte());
            x = static_cast<std::uint8_t>(x ^ f.back());
        }
        f.push_back(static_cast<std::uint8_t>(x ^ 0x3F));    // the exclusive or of all of them is 0x3F
        f.push_back('4');
        f.push_back('G');
        frames.push_back(f);
    }
    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 0);
}

TEST_CASE("sums, stage 2: nothing before the checksum is not something it covers, however it is separated") {
    // '*00': the sum of no bytes is 0, and 0 is what the two characters say, but the covered range would be
    // empty. What explains these frames is the byte '0' as the sum of the byte '0' before it (the exclusive
    // or and the sum of one byte are that byte), and nothing that is text.
    const ChecksumFinding f = search(std::vector<Bytes>(8, text("*00")));
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 2);
    CHECK(f.distinct_frames == 1);
}

TEST_CASE("sums, stage 2: the separator before a text checksum is a byte at most") {
    // Two different bytes between what is covered and the two characters (the same one twice would cancel
    // in an exclusive or): with a gap of one, one of them is covered, and then the sum is not what is written.
    const std::vector<Bytes> one = frames_of(21, 20, 1, 9, '*', enc_hex_upper, 2);
    REQUIRE(search(one).found);                 // with one it is
    std::vector<Bytes> two = one;
    for (std::size_t i = 0; i < two.size(); ++i) {
        two[i].insert(two[i].end() - 4, '#');   // ... * # h h and two bytes after
    }
    const ChecksumFinding g = search(two);
    CHECK_FALSE(g.found);
    CHECK(g.candidates == 0);
}

TEST_CASE("sums, stage 2: Fletcher is not read from text, nor a sum of two bytes as one") {
    // A two-byte sum that is written as bytes is a number, not text, even when its bytes could be digits.
    const ChecksumFinding f = search(frames_of(14, 20, 0, 8, -1, enc_f8_le, 0));
    REQUIRE(f.found);
    CHECK_FALSE(f.ascii_hex);
    CHECK(f.width_bits == 16);
}

TEST_CASE("sums, stage 2: the evidence has to reach 32 bits, and a repeated frame is one frame") {
    // Four different frames of an 8-bit checksum are exactly enough.
    const ChecksumFinding four = search(frames_of(15, 4, 0, 7, -1, enc_xor, 0));
    REQUIRE(four.found);
    CHECK(four.evidence_bits == 32);
    // Three are not, and the finding says there is one candidate on thin evidence.
    const ChecksumFinding three = search(frames_of(15, 3, 0, 7, -1, enc_xor, 0));
    CHECK_FALSE(three.found);
    CHECK(three.candidates == 1);
    CHECK(three.evidence_bits == 24);
    // Two of 16 bits are enough, one (seen three times) is not.
    CHECK(search(frames_of(16, 2, 2, 7, -1, enc_f8_le, 0)).found);
    const ChecksumFinding one = search(std::vector<Bytes>(3, frames_of(16, 1, 2, 7, -1, enc_f8_le, 0)[0]));
    CHECK_FALSE(one.found);
    CHECK(one.distinct_frames == 1);
    CHECK(one.evidence_bits <= 16);             // less if a chance match of a byte is among the candidates
    // The same three frames, each ten times: nothing new has been seen.
    std::vector<Bytes> repeated;
    const std::vector<Bytes> base = frames_of(15, 3, 0, 7, -1, enc_xor, 0);
    for (int i = 0; i < 10; ++i) {
        repeated.insert(repeated.end(), base.begin(), base.end());
    }
    const ChecksumFinding many = search(repeated);
    CHECK_FALSE(many.found);
    CHECK(many.frames == 30);
    CHECK(many.distinct_frames == 3);
    CHECK(many.evidence_bits == 24);
}

TEST_CASE("sums, stage 2: when two sums explain the frames equally it says so") {
    // The sum of one byte and the exclusive or of one byte are that byte.
    fixtures::Random   rng(17);
    std::vector<Bytes> frames;
    for (int i = 0; i < 30; ++i) {
        const std::uint8_t b = static_cast<std::uint8_t>(i * 7 + 1);
        frames.push_back(Bytes(2, b));
    }
    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK(f.candidates >= 2);
    CHECK(f.evidence_bits == 30 * 8);
    CHECK_FALSE(f.truncated);
}

TEST_CASE("sums, stage 2: a sum of nothing is not a checksum") {
    // The covered bytes would be none: the text '00' after nothing is the exclusive or of nothing.
    // Only the bytes as they are can still be explained, since a byte is the sum of itself.
    const std::vector<Bytes> frames(8, text("00"));
    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK(f.distinct_frames == 1);
    CHECK(f.candidates == 2);                   // XOR-8 and SUM-8 over the first byte, as the second
}

TEST_CASE("sums, stage 2: frames of three zeros are explained by the CRCs and by seven sums, and the evidence is the narrowest's") {
    // The CRCs that start from nothing and end with nothing, and seven sums: one byte of three bytes, at two
    // places, by three sums, is inside the field of Fletcher's two sums (in either of its orders, and
    // either of its moduli), so those six are not findings of their own. A zero byte is not a digit, so none
    // is text.
    const std::vector<Bytes> frames(6, Bytes(3, 0));
    std::vector<bw::Frame>   given(frames.size());
    for (std::size_t i = 0; i < frames.size(); ++i) {
        given[i].bytes = frames[i];
    }
    const bw::SearchReport crcs = bw::search(given);
    REQUIRE_FALSE(crcs.truncated);
    REQUIRE(crcs.candidates.size() + 7 <= 64);

    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK_FALSE(f.truncated);
    CHECK(f.candidates == crcs.candidates.size() + 7);
    CHECK(f.distinct_frames == 1);
    CHECK(f.evidence_bits == 8);                // a byte, in the narrowest of them
}

TEST_CASE("sums, stage 2: what it covers is the same bytes, for one to be a part of another") {
    // A byte that sums to nothing in front of Fletcher's field: the plain sum of the bytes before it
    // explains its first half as well, but over other bytes, so it is a second explanation and not a part.
    const Bytes prefix_two = [] { Bytes b; b.push_back(0x01); b.push_back(0xFF); return b; }();
    fixtures::Random   rng(22);
    std::vector<Bytes> frames;
    for (int i = 0; i < 20; ++i) {
        Bytes f = prefix_two;
        Bytes covered;
        for (int k = 0; k < 6; ++k) {
            covered.push_back(rng.byte());
        }
        f.insert(f.end(), covered.begin(), covered.end());
        const Bytes field = enc_f8_le(covered);
        f.insert(f.end(), field.begin(), field.end());
        frames.push_back(f);
    }
    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 2);                   // Fletcher's two sums after two bytes, and the sum of all from the start

    // And a sum over all of it, field included, written after it, is another explanation, not a part of the first.
    const ChecksumFinding outer = search(frames_of(23, 20, 0, 6, -1, enc_f8_then_sum, 0));
    CHECK_FALSE(outer.found);
    CHECK(outer.candidates == 2);
}

TEST_CASE("sums, stage 2: a sum beside Fletcher's two, not inside them, is another answer") {
    // The plain sum of the bytes, then Fletcher's two over the bytes and that sum: the first of them is
    // before the field of the second two, not in it.
    fixtures::Random   rng(24);
    std::vector<Bytes> frames;
    for (int i = 0; i < 20; ++i) {
        Bytes covered;
        for (int k = 0; k < 8; ++k) {
            covered.push_back(rng.byte());
        }
        Bytes f = covered;
        f.push_back(sum_of(covered));
        const Bytes field = enc_f8_le(f);
        f.insert(f.end(), field.begin(), field.end());
        frames.push_back(f);
    }
    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 2);
}

TEST_CASE("sums, stage 2: the CRCs and the sums are asked together, and the cap is shared") {
    // A CRC frame is not explained by a sum, and the finding names the CRC.
    fixtures::Random   rng(18);
    std::vector<Bytes> frames;
    for (int i = 0; i < 20; ++i) {
        Bytes f;
        for (int k = 0; k < 8; ++k) {
            f.push_back(rng.byte());
        }
        const std::uint16_t crc = fixtures::crc16_modbus(f, 0, f.size());
        f.push_back(static_cast<std::uint8_t>(crc & 0xFF));
        f.push_back(static_cast<std::uint8_t>(crc >> 8));
        frames.push_back(f);
    }
    const ChecksumFinding crc = search(frames);
    REQUIRE(crc.found);
    CHECK(bw::checksum_algorithm_name(crc.algorithm) == "CRC-16/MODBUS");
    CHECK(crc.algorithm < bw::catalog_size());
    CHECK(crc.candidates == 1);
    CHECK_FALSE(crc.ascii_hex);

    // Frames of zeros are explained by all the sums and many of the CRCs: it keeps none, and says it was cut.
    const ChecksumFinding zeros = search(std::vector<Bytes>(6, Bytes(12, 0)));
    CHECK_FALSE(zeros.found);
    CHECK(zeros.truncated);
    CHECK(zeros.candidates == 64);
}

TEST_CASE("sums, stage 2: frames that are not explained have no candidates and no evidence") {
    fixtures::Random   rng(19);
    std::vector<Bytes> frames;
    for (int i = 0; i < 30; ++i) {
        Bytes f;
        for (int k = 0; k < 10; ++k) {
            f.push_back(rng.byte());
        }
        frames.push_back(f);
    }
    const ChecksumFinding f = search(frames);
    CHECK_FALSE(f.found);
    CHECK(f.candidates == 0);
    CHECK(f.evidence_bits == 0);
    CHECK(f.frames == 30);
    CHECK(f.distinct_frames == 30);
}
