// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Byte stuffing: a flag byte marks the edge of a frame, so it cannot be sent inside one, and
// whatever would look like it is sent as an escape and a code. SLIP (RFC 1055) is that and
// nothing else; PPP in HDLC-like framing (RFC 1662) adds a frame check sequence that is worked
// out over the bytes as they were before they were stuffed. Checked against values from the
// descriptions of the two, against a stuffing and a CRC written again here, and, as for the
// others, against the Python implementation (tests/mirror/mirror.py) through the captures
// checked in. The vectors of PPP below were worked out by that implementation, not by the code
// under test.

#include "doctest.h"

#include <algorithm>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

#include "bw/analyze.h"
#include "bw/crc.h"
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

struct Stuffing {
    std::uint8_t flag, escape, flag_code, escape_code;
};
const Stuffing kSlip = { 0xC0, 0xDB, 0xDC, 0xDD };
const Stuffing kHdlc = { 0x7E, 0x7D, 0x5E, 0x5D };

// CRC-16/X-25, typed here from RFC 1662 and not taken from the catalogue of the library (which does not
// have it: see the baseline below). The second is the register, without the final xor, whose value over a
// frame that includes its FCS is the same whatever the frame is.
const bw::CrcSpec kX25      = { "CRC-16/X-25", 16, 0x1021, 0xFFFF, true, true, 0xFFFF, 0x906E };
const bw::CrcSpec kX25Plain = { "CRC-16/X-25, no final xor", 16, 0x1021, 0xFFFF, true, true, 0x0000, 0 };

std::uint64_t crc(const bw::CrcSpec& spec, const Bytes& bytes) {
    return bw::crc_compute(spec, bytes.empty() ? nullptr : &bytes[0], bytes.size());
}

template <std::size_t N>
Bytes bytes_of(const std::uint8_t (&array)[N]) {
    return Bytes(array, array + N);
}

Dataset make(const char* name, std::uint64_t seed, std::uint32_t frames, std::uint32_t jitter = 0) {
    GenerateOptions o;
    o.seed            = seed;
    o.frames          = frames;
    o.jitter_permille = jitter;
    return bw::generate_protocol(name, o);
}

Bytes wire_of(const Dataset& d, std::size_t i) {
    return bw::frame_bytes(d.capture(), d.frame(i));
}

std::string csv(const Dataset& d) {
    return bw::format_capture_csv(d.capture());
}

std::uint64_t be(const Bytes& b, std::size_t at, std::size_t size) {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < size; ++i) {
        v = (v << 8) | b[at + i];
    }
    return v;
}

// A frame as it is on the line, taken apart: what is between its two flags with the stuffing undone.
// ok is false for what is not one: a flag missing at either end or inside, an escape that is followed by
// anything but one of the two codes (at the very end it is followed by the flag, which is not one).
struct Unstuffed {
    bool        ok = false;
    Bytes       content;
    std::size_t flags_escaped   = 0;     // flags that were sent as escape and flag code
    std::size_t escapes_escaped = 0;     // and escapes as escape and escape code
    std::size_t raw_codes       = 0;     // codes that were not after an escape: plain data
};

Unstuffed destuff(const Bytes& wire, const Stuffing& s) {
    Unstuffed out;
    if (wire.size() < 2 || wire.front() != s.flag || wire.back() != s.flag) {
        return out;
    }
    for (std::size_t i = 1; i + 1 < wire.size(); ++i) {
        if (wire[i] == s.flag) {
            return out;
        }
        if (wire[i] == s.escape) {
            if (wire[i + 1] == s.flag_code) {
                out.content.push_back(s.flag);
                ++out.flags_escaped;
            } else if (wire[i + 1] == s.escape_code) {
                out.content.push_back(s.escape);
                ++out.escapes_escaped;
            } else {
                return out;
            }
            ++i;
        } else {
            out.raw_codes += (wire[i] == s.flag_code || wire[i] == s.escape_code) ? 1 : 0;
            out.content.push_back(wire[i]);
        }
    }
    out.ok = true;
    return out;
}

// The other way, written again: the flags, and the stuffing of what is between them.
Bytes enstuff(const Bytes& content, const Stuffing& s) {
    Bytes wire(1, s.flag);
    for (std::size_t i = 0; i < content.size(); ++i) {
        if (content[i] == s.flag || content[i] == s.escape) {
            wire.push_back(s.escape);
            wire.push_back(content[i] == s.flag ? s.flag_code : s.escape_code);
        } else {
            wire.push_back(content[i]);
        }
    }
    wire.push_back(s.flag);
    return wire;
}

// Between two flags, as it is.
Bytes flagged(const Bytes& between, const Stuffing& s) {
    Bytes wire(1, s.flag);
    wire.insert(wire.end(), between.begin(), between.end());
    wire.push_back(s.flag);
    return wire;
}

// A PPP frame as it goes on the line, from what comes before its FCS.
Bytes ppp_wire(Bytes content) {
    const std::uint64_t fcs = crc(kX25, content);
    content.push_back(static_cast<std::uint8_t>(fcs & 0xFF));
    content.push_back(static_cast<std::uint8_t>(fcs >> 8));
    return enstuff(content, kHdlc);
}

std::size_t count(const Bytes& b, std::uint8_t value) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < b.size(); ++i) {
        n += (b[i] == value) ? 1 : 0;
    }
    return n;
}

// What the model says each frame holds once its stuffing is taken out: its size, and every constant of it
// where it says.
void check_model_describes_frames(const Dataset& d, const Stuffing& s) {
    const bw::Model m = d.model();
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        CAPTURE(i);
        const std::uint32_t t = d.frame_message_type(i);
        const Unstuffed     u = destuff(wire_of(d, i), s);
        REQUIRE(u.ok);
        std::uint64_t bits = 0;
        for (std::size_t f = 0; f < m.field_count(t); ++f) {
            bits += m.field(t, f).bit_size;
        }
        REQUIRE(u.content.size() == bits / 8);
        for (std::size_t f = 0; f < m.field_count(t); ++f) {
            const bw::FieldInfo info = m.field(t, f);
            if (info.kind == FieldKind::Constant) {
                CAPTURE(f);
                CHECK(be(u.content, static_cast<std::size_t>(m.field_position(t, f).bit_offset / 8), info.bit_size / 8) ==
                      info.constant);
            }
        }
    }
}

const std::uint64_t kChar = 10ULL * 1000000000ULL / 115200ULL;      // 86805 ns: 10 bits at 115200 baud

} // namespace

// ---- Values from the descriptions ------------------------------------------

TEST_CASE("hdlc-ppp: the FCS is the CRC-16/X-25, and a frame with its FCS leaves the register at 0xF0B8") {
    const char* digits = "123456789";
    CHECK(bw::crc_spec_self_test(kX25));                       // the published check value, 0x906E
    CHECK(bw::crc_compute(kX25, reinterpret_cast<const std::uint8_t*>(digits), 9) == 0x906E);

    // Three frames worked out by the Python implementation, a table at a time and as RFC 1662 gives the code:
    // an LCP echo whose magic number has a flag in it, an IPCP request with nothing to stuff, and a datagram
    // with an escape and a flag among its data.
    struct Vector {
        const char*   name;
        Bytes         content;        // from the address to the end of the information
        std::uint16_t fcs;
        Bytes         between;        // what goes between the flags: stuffed, the FCS sent low byte first
    };
    std::vector<Vector> vectors;
    {
        const std::uint8_t c[] = { 0xFF, 0x03, 0xC0, 0x21, 0x09, 0x00, 0x00, 0x08, 0x0B, 0x7E, 0x9A, 0x31 };
        const std::uint8_t w[] = { 0xFF, 0x03, 0xC0, 0x21, 0x09, 0x00, 0x00, 0x08, 0x0B, 0x7D, 0x5E, 0x9A, 0x31, 0x4A, 0xFA };
        Vector v = { "lcp echo", bytes_of(c), 0xFA4A, bytes_of(w) };
        vectors.push_back(v);
    }
    {
        const std::uint8_t c[] = { 0xFF, 0x03, 0x80, 0x21, 0x01, 0x05, 0x00, 0x0A, 0x03, 0x06, 0x0A, 0x00, 0x00, 0x01 };
        const std::uint8_t w[] = { 0xFF, 0x03, 0x80, 0x21, 0x01, 0x05, 0x00, 0x0A, 0x03, 0x06, 0x0A, 0x00, 0x00, 0x01, 0xD1, 0xDA };
        Vector v = { "ipcp request", bytes_of(c), 0xDAD1, bytes_of(w) };
        vectors.push_back(v);
    }
    {
        Vector v = { "ip datagram", Bytes(), 0xE63D, Bytes() };
        const std::uint8_t head[] = { 0xFF, 0x03, 0x00, 0x21 };
        v.content = bytes_of(head);
        v.between = bytes_of(head);
        for (unsigned b = 0x70; b <= 0x87; ++b) {                  // 24 bytes, with 0x7D and 0x7E among them
            v.content.push_back(static_cast<std::uint8_t>(b));
            if (b == 0x7D) {
                v.between.push_back(0x7D);
                v.between.push_back(0x5D);
            } else if (b == 0x7E) {
                v.between.push_back(0x7D);
                v.between.push_back(0x5E);
            } else {
                v.between.push_back(static_cast<std::uint8_t>(b));
            }
        }
        v.between.push_back(0x3D);
        v.between.push_back(0xE6);
        vectors.push_back(v);
    }
    for (std::size_t n = 0; n < vectors.size(); ++n) {
        const Vector& v = vectors[n];
        INFO(v.name);
        CHECK(crc(kX25, v.content) == v.fcs);

        Bytes whole = v.content;
        whole.push_back(static_cast<std::uint8_t>(v.fcs & 0xFF));
        whole.push_back(static_cast<std::uint8_t>(v.fcs >> 8));
        CHECK(crc(kX25Plain, whole) == 0xF0B8);

        // The line is the stuffed frame, and the decoder of the protocol takes it.
        const Bytes wire = flagged(v.between, kHdlc);
        const Unstuffed u = destuff(wire, kHdlc);
        REQUIRE(u.ok);
        CHECK(u.content == whole);
        CHECK(enstuff(whole, kHdlc) == wire);
        CHECK(ppp_wire(v.content) == wire);
        CHECK(bw::protocol_conforms("hdlc-ppp", wire));

        // A bit of any of its bytes, flags included, and it is a frame no longer: the CRC sees a bit that is
        // in the data, the checks of the stuffing the ones that turn a byte into a flag or an escape, and the
        // flags and sizes the rest.
        for (std::size_t i = 0; i < wire.size(); ++i) {
            for (unsigned bit = 0; bit < 8; ++bit) {
                Bytes bad = wire;
                bad[i] = static_cast<std::uint8_t>(bad[i] ^ (1u << bit));
                CAPTURE(i);
                CAPTURE(bit);
                CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", bad));
            }
        }
    }
}

TEST_CASE("slip: the two escapes of RFC 1055, and a code that is not after an escape is data") {
    // type 0x10, sequence 5, time 1000 ms, then six readings: 0x00C0 (an END), 0xDB00 (an ESC), and four others.
    const std::uint8_t sample[] = { 0xC0, 0x10, 0x00, 0x05, 0x00, 0x00, 0x03, 0xE8, 0x00, 0xDB, 0xDC, 0xDB, 0xDD, 0x00,
                                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xC0 };
    const Unstuffed u = destuff(bytes_of(sample), kSlip);
    REQUIRE(u.ok);
    CHECK(u.content.size() == 19);
    CHECK(u.flags_escaped == 1);
    CHECK(u.escapes_escaped == 1);
    CHECK(be(u.content, 7, 2) == 0x00C0);
    CHECK(be(u.content, 9, 2) == 0xDB00);
    CHECK(bw::protocol_conforms("slip", bytes_of(sample)));
    CHECK(enstuff(u.content, kSlip) == bytes_of(sample));

    // A status: type 0x20, sequence 6, time 0xC0 ms, state 3, battery 12000 mV.
    const std::uint8_t status[] = { 0xC0, 0x20, 0x00, 0x06, 0x00, 0x00, 0x00, 0xDB, 0xDC, 0x03, 0x2E, 0xE0, 0xC0 };
    CHECK(bw::protocol_conforms("slip", bytes_of(status)));

    // 0xDC and 0xDD outside an escape are bytes like any: a first reading of 0xDCDD goes as it is.
    const std::uint8_t plain[] = { 0xC0, 0x10, 0x00, 0x05, 0x00, 0x00, 0x03, 0xE8, 0xDC, 0xDD, 0x12, 0x34, 0x56, 0x78,
                                   0x9A, 0xBC, 0xDE, 0xF0, 0x01, 0x02, 0xC0 };
    CHECK(bw::protocol_conforms("slip", bytes_of(plain)));
    const Unstuffed p = destuff(bytes_of(plain), kSlip);
    REQUIRE(p.ok);
    CHECK(p.raw_codes == 2);
    CHECK(p.content.size() == 19);
    CHECK(be(p.content, 7, 2) == 0xDCDD);
}

TEST_CASE("slip: the decoder refuses each way a frame can be wrong") {
    const std::uint8_t sample[] = { 0xC0, 0x10, 0x00, 0x05, 0x00, 0x00, 0x03, 0xE8, 0x00, 0xDB, 0xDC, 0xDB, 0xDD, 0x00,
                                    0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0xC0 };
    const Bytes good = bytes_of(sample);
    REQUIRE(bw::protocol_conforms("slip", good));

    CHECK_FALSE(bw::protocol_conforms("slip", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("slip", Bytes(2, 0xC0)));                // nothing between the ENDs
    CHECK_FALSE(bw::protocol_conforms("slip", Bytes(3, 0xC0)));
    {
        Bytes bad = good; bad.erase(bad.begin());                                // no END at the start
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad.pop_back();                                              // and none at the end
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad.front() = 0x00;                                          // something else where it is: the record is whole
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad.back() = 0x00;
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
    }
    {
        Bytes bad = good; bad[10] = 0x00;                                        // an ESC with no code after it
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[10] = 0xDE;                                              // or one that is not a code
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[10] = 0xDB;                                              // an ESC before an ESC
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[10] = 0xC0;                                              // an END inside
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[14] = 0xC0;                                              // and one in the middle of the data
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[bad.size() - 2] = 0xDB;                                  // an ESC that is the last byte
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
    }
    {
        Bytes bad = good; bad.insert(bad.end() - 1, 0x00);                       // a byte more: 20 bytes
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad.erase(bad.end() - 2);                                    // and one less: 18
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[1] = 0x20;                                               // a status as long as a sample
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[1] = 0x11;                                               // a type there is not
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
        bad = good; bad[1] = 0x00;
        CHECK_FALSE(bw::protocol_conforms("slip", bad));
    }
    // The other way round: a sample that is the size of a status.
    const std::uint8_t short_sample[] = { 0xC0, 0x10, 0x00, 0x06, 0x00, 0x00, 0x00, 0x00, 0x03, 0x2E, 0xE0, 0xC0 };
    CHECK_FALSE(bw::protocol_conforms("slip", bytes_of(short_sample)));
    // A record whose first byte is an END, stuffed, with 18 bytes after it: the size of a sample, and no type.
    const std::uint8_t stuffed_type[] = { 0xC0, 0xDB, 0xDC, 0x00, 0x05, 0x00, 0x00, 0x03, 0xE8, 0x12, 0x34, 0x56, 0x78, 0x9A,
                                          0xBC, 0xDE, 0xF0, 0x01, 0x02, 0x03, 0x04, 0xC0 };
    REQUIRE(destuff(bytes_of(stuffed_type), kSlip).content.size() == 19);
    CHECK_FALSE(bw::protocol_conforms("slip", bytes_of(stuffed_type)));
    // Two frames in one are not a frame.
    Bytes two = good;
    two.insert(two.end(), good.begin() + 1, good.end());
    CHECK_FALSE(bw::protocol_conforms("slip", two));
}

TEST_CASE("hdlc-ppp: the decoder refuses a frame whose FCS is right and whose shape is not") {
    const std::uint8_t lcp[] = { 0xFF, 0x03, 0xC0, 0x21, 0x09, 0x00, 0x00, 0x08, 0x0B, 0x7E, 0x9A, 0x31 };
    const Bytes        good  = bytes_of(lcp);
    REQUIRE(bw::protocol_conforms("hdlc-ppp", ppp_wire(good)));

    CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", Bytes()));
    CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", Bytes(2, 0x7E)));
    {
        Bytes bad = good; bad.push_back(0x00);                                   // a byte more, FCS still right
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", ppp_wire(bad)));
        bad = good; bad.pop_back();                                              // and one less
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", ppp_wire(bad)));
        bad = good; bad[0] = 0xFE;                                               // not the all-stations address
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", ppp_wire(bad)));
        bad = good; bad[1] = 0x13;                                               // not unnumbered information
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", ppp_wire(bad)));
        bad = good; bad[3] = 0x23;                                               // a protocol of ours with a size of another
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", ppp_wire(bad)));
        bad = good; bad[2] = 0x80;                                               // 0x8021 (IPCP) with the size of an LCP echo
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", ppp_wire(bad)));
    }
    // The flags and the stuffing.
    const Bytes wire = ppp_wire(good);
    {
        Bytes bad = wire; bad.erase(bad.begin());
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", bad));
        bad = wire; bad.pop_back();
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", bad));
        bad = wire;                                                              // two frames in one
        bad.insert(bad.end(), wire.begin() + 1, wire.end());
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", bad));
        bad = wire; bad[bad.size() - 2] = 0x7D;                                  // an escape that is the last byte
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", bad));
    }
    // A flag in the middle of the data that is not stuffed is the end of one frame and the start of the next, even
    // when the bytes of both, taken together, have the right FCS.
    {
        Bytes unstuffed = good;
        const std::uint64_t fcs = crc(kX25, unstuffed);
        unstuffed.push_back(static_cast<std::uint8_t>(fcs & 0xFF));
        unstuffed.push_back(static_cast<std::uint8_t>(fcs >> 8));
        REQUIRE(count(unstuffed, 0x7E) == 1);
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", flagged(unstuffed, kHdlc)));
    }
    // An FCS sent high byte first is the wrong FCS.
    {
        Bytes content = good;
        const std::uint64_t fcs = crc(kX25, content);
        content.push_back(static_cast<std::uint8_t>(fcs >> 8));
        content.push_back(static_cast<std::uint8_t>(fcs & 0xFF));
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", enstuff(content, kHdlc)));
    }
    // An FCS taken over the stuffed bytes is the wrong one too: the CRC is of what the frame holds.
    {
        Bytes stuffed = enstuff(good, kHdlc);
        stuffed.pop_back();
        stuffed.erase(stuffed.begin());
        const std::uint64_t fcs = crc(kX25, stuffed);
        REQUIRE(stuffed.size() == good.size() + 1);                              // the magic number had one flag in it
        Bytes line = flagged(stuffed, kHdlc);
        line.insert(line.end() - 1, static_cast<std::uint8_t>(fcs & 0xFF));
        line.insert(line.end() - 1, static_cast<std::uint8_t>(fcs >> 8));
        CHECK_FALSE(bw::protocol_conforms("hdlc-ppp", line));
    }
}

// ---- The models ------------------------------------------------------------

TEST_CASE("slip: its model is the documented one") {
    const bw::Model m = bw::protocol_model("slip");
    const bw::FramingInfo f = m.framing();
    CHECK(f.kind == bw::FramingKind::Flagged);
    CHECK(f.delimiter == 0xC0);
    CHECK(f.escaped);
    CHECK(f.escape == 0xDB);
    CHECK(f.delimiter_code == 0xDC);
    CHECK(f.escape_code == 0xDD);

    REQUIRE(m.message_type_count() == 2);
    CHECK(m.message_type_name(0) == "sample");
    CHECK(m.message_type_name(1) == "status");
    CHECK(m.field_count(0) == 9);
    CHECK(m.field_count(1) == 5);
    const std::uint64_t bits[2] = { 8 * 19, 8 * 10 };                   // as they are once the stuffing is taken out
    for (std::size_t t = 0; t < 2; ++t) {
        CAPTURE(t);
        std::uint64_t total = 0;
        for (std::size_t i = 0; i < m.field_count(t); ++i) {
            total += m.field(t, i).bit_size;
        }
        CHECK(total == bits[t]);
        CHECK(m.field(t, 0).kind == FieldKind::Constant);
        CHECK(m.field(t, 0).constant == (t == 0 ? 0x10u : 0x20u));
        CHECK(m.field(t, 1).kind == FieldKind::Counter);
        CHECK(m.field(t, 1).bit_size == 16);
        CHECK(m.field(t, 1).byte_order == bw::ByteOrder::Big);
        CHECK(m.field_detail(t, 1) == "step 1");
        CHECK(m.field(t, 2).kind == FieldKind::Timestamp);
        CHECK(m.field(t, 2).bit_size == 32);
        CHECK(m.field_detail(t, 2) == "step 100");
    }
    CHECK(m.field_name(0, 3) == "reading0");
    CHECK(m.field_name(0, 8) == "reading5");
    CHECK(m.field(0, 8).kind == FieldKind::Payload);
    CHECK(m.field_name(1, 3) == "state");
    CHECK(m.field(1, 3).kind == FieldKind::Enum);
    CHECK(m.field_name(1, 4) == "battery");
    // Everything has a fixed place, in the frame as it is once the stuffing is taken out.
    for (std::size_t f = 0; f < m.field_count(0); ++f) {
        CHECK(m.field_position(0, f).fixed);
    }
}

TEST_CASE("hdlc-ppp: its model is the documented one") {
    const bw::Model m = bw::protocol_model("hdlc-ppp");
    const bw::FramingInfo f = m.framing();
    CHECK(f.kind == bw::FramingKind::Flagged);
    CHECK(f.delimiter == 0x7E);
    CHECK(f.escaped);
    CHECK(f.escape == 0x7D);
    CHECK(f.delimiter_code == 0x5E);
    CHECK(f.escape_code == 0x5D);

    REQUIRE(m.message_type_count() == 3);
    const char*         names[3]     = { "lcp_echo", "ipcp_request", "ip_datagram" };
    const std::size_t   fields[3]    = { 8, 10, 5 };
    const std::uint64_t sizes[3]     = { 14, 16, 30 };                  // with the FCS, as the stuffing leaves them
    const std::uint64_t protocols[3] = { 0xC021, 0x8021, 0x0021 };
    for (std::size_t t = 0; t < 3; ++t) {
        CAPTURE(t);
        CHECK(m.message_type_name(t) == names[t]);
        REQUIRE(m.field_count(t) == fields[t]);
        std::uint64_t total = 0;
        for (std::size_t i = 0; i < m.field_count(t); ++i) {
            total += m.field(t, i).bit_size;
        }
        CHECK(total == 8 * sizes[t]);
        CHECK(m.field(t, 0).constant == 0xFF);
        CHECK(m.field(t, 1).constant == 0x03);
        CHECK(m.field(t, 2).constant == protocols[t]);
        CHECK(m.field(t, 2).bit_size == 16);

        const std::size_t   last = m.field_count(t) - 1;
        const bw::FieldInfo fcs  = m.field(t, last);
        CHECK(m.field_name(t, last) == "fcs");
        CHECK(fcs.kind == FieldKind::Checksum);
        CHECK(fcs.bit_size == 16);
        CHECK(fcs.byte_order == bw::ByteOrder::Little);                 // sent low byte first
        CHECK(fcs.covers_first == 0);                                   // from the address, flags not included
        CHECK(fcs.covers_last == last - 1);
        CHECK_FALSE(fcs.ascii_hex);
        CHECK(m.field_detail(t, last) == "CRC-16/X-25 (the FCS-16 of RFC 1662)");
    }
    CHECK(m.field_name(0, 6) == "magic_number");
    CHECK(m.field(0, 6).constant == 0x0B7E9A31);
    CHECK(m.field(0, 5).kind == FieldKind::Length);
    CHECK(m.field_name(1, 8) == "ip_address");
    CHECK(m.field(1, 8).kind == FieldKind::Enum);
    CHECK(m.field_name(2, 3) == "datagram");
    CHECK(m.field(2, 3).bit_size == 192);
    CHECK(m.field(0, 4).kind == FieldKind::Counter);
    CHECK(m.field(1, 4).kind == FieldKind::Counter);
}

// ---- The captures ----------------------------------------------------------

TEST_CASE("slip and hdlc-ppp: a seed is a capture, the same on every platform") {
    // Written by an independent implementation in Python, from the algorithms documented in slip.cpp and hdlc_ppp.cpp.
    // The seeds are such that each capture has both kinds of escape in it.
    CHECK(golden::first_difference(csv(make("slip", 3, 30)), golden::read_file("synth_slip_seed3_30frames.csv")) == "");
    CHECK(golden::first_difference(csv(make("slip", 3, 40, 300)),
                                   golden::read_file("synth_slip_seed3_40frames_jitter300.csv")) == "");
    CHECK(golden::first_difference(csv(make("hdlc-ppp", 2, 30)), golden::read_file("synth_hdlc_ppp_seed2_30frames.csv")) == "");
    CHECK(golden::first_difference(csv(make("hdlc-ppp", 2, 40, 300)),
                                   golden::read_file("synth_hdlc_ppp_seed2_40frames_jitter300.csv")) == "");
}

TEST_CASE("slip: every frame is an END, a stuffed record and an END, and the model says what the record holds") {
    const Dataset d = make("slip", 21, 300);
    REQUIRE(d.frame_count() == 300);
    check_model_describes_frames(d, kSlip);

    std::size_t kinds[2] = { 0, 0 }, flags = 0, escapes = 0, raw = 0, longest = 0, shortest = 1000;
    std::uint64_t next_event = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        CAPTURE(i);
        const Bytes     wire = wire_of(d, i);
        const Unstuffed u    = destuff(wire, kSlip);
        REQUIRE(u.ok);
        const std::uint32_t t = d.frame_message_type(i);
        REQUIRE(t < 2);
        ++kinds[t];
        CHECK(u.content.size() == (t == 0 ? 19u : 10u));
        CHECK(u.content[0] == (t == 0 ? 0x10 : 0x20));
        // An END or an ESC of the record costs a byte more; nothing else does.
        CHECK(wire.size() == u.content.size() + 2 + count(u.content, 0xC0) + count(u.content, 0xDB));
        CHECK(u.flags_escaped == count(u.content, 0xC0));
        CHECK(u.escapes_escaped == count(u.content, 0xDB));
        CHECK(bw::protocol_conforms("slip", wire));
        flags += u.flags_escaped;
        escapes += u.escapes_escaped;
        raw += u.raw_codes;
        longest  = std::max(longest, wire.size());
        shortest = std::min(shortest, wire.size());

        // The frames follow one another with nothing between them: each starts where the one before ended.
        CHECK(d.frame(i).first_event == next_event);
        next_event += d.frame(i).event_count;
    }
    CHECK(next_event == d.capture().event_count());
    CHECK(kinds[0] > 100);
    CHECK(kinds[1] > 100);
    CHECK(flags > 0);                          // both kinds of escape are in this capture
    CHECK(escapes > 0);
    CHECK(raw > 0);                            // and the codes alone, which are data
    CHECK(longest > 21);                       // so the frames of a kind differ in length, which the stages meet as types
    CHECK(shortest == 12);
}

TEST_CASE("slip: what the records hold") {
    const Dataset d = make("slip", 22, 400);
    std::set<std::uint64_t> readings;
    std::set<unsigned>      states;
    std::uint64_t           first_time = 0, low = 99999, high = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        CAPTURE(i);
        const Bytes c = destuff(wire_of(d, i), kSlip).content;
        CHECK(be(c, 1, 2) == i);                                          // the sequence is the number of the frame
        const std::uint64_t time = be(c, 3, 4);
        if (i == 0) {
            first_time = time;
            CHECK(first_time < 1000000);
        }
        CHECK(time == first_time + 100 * i);                              // 100 ms for each frame
        if (c[0] == 0x10) {
            for (std::size_t r = 0; r < 6; ++r) {
                readings.insert(be(c, 7 + 2 * r, 2));
            }
        } else {
            CHECK(c[7] < 4);
            states.insert(c[7]);
            const std::uint64_t battery = be(c, 8, 2);
            CHECK(battery >= 11000);
            CHECK(battery < 12600);
            low  = std::min(low, battery);
            high = std::max(high, battery);
        }
    }
    CHECK(readings.size() > 1000);                                        // 1200 or so readings, of 65536 values
    CHECK(states == std::set<unsigned>({ 0, 1, 2, 3 }));
    CHECK(low < 11100);                                                   // the battery uses its range
    CHECK(high > 12500);
}

TEST_CASE("hdlc-ppp: every frame is a flag, a stuffed PPP frame with its FCS and a flag, and the model says what it holds") {
    const Dataset d = make("hdlc-ppp", 23, 900);
    REQUIRE(d.frame_count() == 900);
    check_model_describes_frames(d, kHdlc);

    const std::size_t sizes[3] = { 14, 16, 30 };
    std::size_t kinds[3] = { 0, 0, 0 }, flags = 0, escapes = 0, raw = 0, fcs_escaped = 0;
    std::set<std::size_t> lengths[3];
    std::uint8_t lcp_id = 0, ipcp_id = 0;
    std::set<std::uint64_t> addresses;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        CAPTURE(i);
        const Bytes     wire = wire_of(d, i);
        const Unstuffed u    = destuff(wire, kHdlc);
        REQUIRE(u.ok);
        const std::uint32_t t = d.frame_message_type(i);
        REQUIRE(t < 3);
        ++kinds[t];
        const Bytes& c = u.content;
        REQUIRE(c.size() == sizes[t]);
        CHECK(wire.size() == c.size() + 2 + count(c, 0x7E) + count(c, 0x7D));
        CHECK(bw::protocol_conforms("hdlc-ppp", wire));
        lengths[t].insert(wire.size());
        flags += u.flags_escaped;
        escapes += u.escapes_escaped;
        raw += u.raw_codes;

        // The FCS: low byte first, over the frame without it, and the register over the whole is constant.
        const std::uint64_t fcs = c[c.size() - 2] | (static_cast<std::uint64_t>(c[c.size() - 1]) << 8);
        CHECK(crc(kX25, Bytes(c.begin(), c.end() - 2)) == fcs);
        CHECK(crc(kX25Plain, c) == 0xF0B8);
        fcs_escaped += (c[c.size() - 2] == 0x7E || c[c.size() - 2] == 0x7D || c[c.size() - 1] == 0x7E || c[c.size() - 1] == 0x7D) ? 1 : 0;

        if (t == 0) {                                                       // LCP Echo-Request
            CHECK(be(c, 2, 2) == 0xC021);
            CHECK(c[4] == 9);
            CHECK(c[5] == lcp_id);
            ++lcp_id;
            CHECK(be(c, 6, 2) == 8);                                        // the length, from the code to the magic number
            CHECK(be(c, 8, 4) == 0x0B7E9A31);
            CHECK(wire.size() >= 17);                                       // the flag in the magic number is always stuffed
        } else if (t == 1) {                                                // IPCP Configure-Request
            CHECK(be(c, 2, 2) == 0x8021);
            CHECK(c[4] == 1);
            CHECK(c[5] == ipcp_id);
            ++ipcp_id;
            CHECK(be(c, 6, 2) == 10);                                       // code, identifier, length and a 6-byte option
            CHECK(c[8] == 3);
            CHECK(c[9] == 6);
            addresses.insert(be(c, 10, 4));
        } else {                                                            // an IP datagram
            CHECK(be(c, 2, 2) == 0x0021);
        }
    }
    CHECK(kinds[0] > 250);
    CHECK(kinds[1] > 250);
    CHECK(kinds[2] > 250);
    CHECK(flags > 0);                                                       // both kinds of escape are in this capture
    CHECK(escapes > 0);
    CHECK(raw > 0);
    CHECK(fcs_escaped > 0);                                                 // and some FCS needed stuffing itself
    CHECK(addresses == std::set<std::uint64_t>({ 0xC0000201, 0xC0000202, 0x0A000001, 0x0A000002 }));
    CHECK(lcp_id == static_cast<std::uint8_t>(kinds[0]));                   // 8 bits: the identifier went round
    CHECK(kinds[0] > 256);
    for (int t = 0; t < 3; ++t) {
        CHECK(lengths[t].size() >= 2);                                      // each kind has frames of more than one length
    }
}

TEST_CASE("hdlc-ppp: the flags before a frame are idle fill and belong to no frame") {
    const Dataset d = make("hdlc-ppp", 24, 600);
    const Capture c = d.capture();
    std::map<std::uint64_t, std::size_t> fill;                              // idle flags before a frame -> how often
    std::uint64_t end = 0;
    for (std::size_t i = 0; i < d.frame_count(); ++i) {
        CAPTURE(i);
        REQUIRE(d.frame(i).first_event >= end);
        const std::uint64_t idle = d.frame(i).first_event - end;
        ++fill[idle];
        for (std::uint64_t k = end; k < d.frame(i).first_event; ++k) {
            CHECK(c.event_bytes(static_cast<std::size_t>(k)) == Bytes(1, 0x7E));
        }
        // The frame itself starts and ends with a flag, and has none inside.
        CHECK(c.event_bytes(static_cast<std::size_t>(d.frame(i).first_event)) == Bytes(1, 0x7E));
        end = d.frame(i).first_event + d.frame(i).event_count;
    }
    CHECK(end == c.event_count());                                          // nothing after the last frame
    REQUIRE(fill.size() == 3);                                              // none, one or two
    CHECK(fill.count(0) == 1);
    CHECK(fill.count(1) == 1);
    CHECK(fill.count(2) == 1);
    for (std::map<std::uint64_t, std::size_t>::const_iterator it = fill.begin(); it != fill.end(); ++it) {
        CHECK(it->second > 100);                                            // about a third of 600 each
    }
}

TEST_CASE("slip and hdlc-ppp: a byte every character time, and the noise moves timestamps and nothing else") {
    const char* names[2] = { "slip", "hdlc-ppp" };
    for (int n = 0; n < 2; ++n) {
        INFO(names[n]);
        const Dataset quiet = make(names[n], 7, 60, 0);
        const Dataset noisy = make(names[n], 7, 60, 300);
        const Capture a = quiet.capture(), b = noisy.capture();
        REQUIRE(a.event_count() == b.event_count());
        REQUIRE(a.event_count() > 600);
        CHECK(a.event(0).time_ns == 0);
        for (std::size_t k = 1; k < a.event_count(); ++k) {
            CHECK(a.event(k).time_ns - a.event(k - 1).time_ns == static_cast<std::int64_t>(kChar));
        }
        // 300 thousandths of a character: at most 26041 ns late, each byte on its own.
        std::size_t late = 0;
        for (std::size_t k = 0; k < a.event_count(); ++k) {
            const std::int64_t delay = b.event(k).time_ns - a.event(k).time_ns;
            CHECK(delay >= 0);
            CHECK(delay < 26041);
            late += delay > 0 ? 1 : 0;
            CHECK(a.event_bytes(k) == b.event_bytes(k));
        }
        CHECK(late > a.event_count() / 2);
        REQUIRE(quiet.frame_count() == noisy.frame_count());
        for (std::size_t i = 0; i < quiet.frame_count(); ++i) {
            CHECK(quiet.frame(i).first_event == noisy.frame(i).first_event);
            CHECK(quiet.frame(i).event_count == noisy.frame(i).event_count);
            CHECK(quiet.frame_message_type(i) == noisy.frame_message_type(i));
        }
    }
}

// ---- Where the stages start ------------------------------------------------

TEST_CASE("slip and hdlc-ppp baseline: no gaps to cut at, and types that follow the stuffing, not the protocol") {
    // The first stuffed protocols, and what the stages that exist do with them, which the next steps of wave 1
    // change (docs/roadmap.md). Nothing is found by gaps: the bytes are a character apart throughout.
    const char* names[2] = { "slip", "hdlc-ppp" };
    for (int n = 0; n < 2; ++n) {
        for (unsigned jitter = 0; jitter <= 300; jitter += 300) {
            CAPTURE(names[n]);
            CAPTURE(jitter);
            CHECK_FALSE(bw::segment_by_gaps(make(names[n], 5, 120, jitter).capture(), bw::SegmentationOptions()).info().found);
        }
    }

    // Given the true frames, with their flags and as they are on the line, a message type is a size. The
    // stuffing makes the frames of a kind differ in size, so there are more types than the protocol has
    // (3 for 2 in SLIP, 4 for 3 in HDLC), the frames of the rarest sizes are left out for being too few, and
    // a checksum is found in none. The numbers are those of seed 3, 300 frames.
    //
    // For HDLC, two things stand between this and the FCS, and both are for the stage 2 of wave 1: the
    // catalogue does not have CRC-16/X-25, and the CRC is over the bytes as they were before the stuffing,
    // so that a frame that has an escape in it is not one the search lines up. (With the entry added to a
    // copy of the catalogue, the FCS of the frames without an escape was found, and the others were not.)
    struct Expected {
        const char*   name;
        std::uint64_t ignored;
        std::set<std::pair<std::uint32_t, std::uint32_t> > types;     // (size, frames)
    };
    Expected expected[2];
    expected[0].name    = "slip";
    expected[0].ignored = 3;
    expected[0].types.insert(std::make_pair(21u, 148u));
    expected[0].types.insert(std::make_pair(12u, 135u));
    expected[0].types.insert(std::make_pair(22u, 14u));
    expected[1].name    = "hdlc-ppp";
    expected[1].ignored = 5;
    expected[1].types.insert(std::make_pair(17u, 102u));
    expected[1].types.insert(std::make_pair(18u, 100u));
    expected[1].types.insert(std::make_pair(32u, 78u));
    expected[1].types.insert(std::make_pair(33u, 15u));
    for (int n = 0; n < 2; ++n) {
        INFO(expected[n].name);
        const Dataset d = make(expected[n].name, 3, 300);
        bw::SegmentationInfo info;
        info.found = true;
        const bw::Analysis a = bw::analyze_frames(d.capture(), bw::Segmentation(info, d.frames()), bw::AnalyzeOptions());
        std::set<std::pair<std::uint32_t, std::uint32_t> > found;
        for (std::size_t t = 0; t < a.type_count(); ++t) {
            found.insert(std::make_pair(a.type_report(t).frame_bytes, a.type_report(t).frames));
            CHECK_FALSE(a.type_report(t).checksum.found);
        }
        CHECK(found == expected[n].types);
        CHECK(a.info().ignored_frames == expected[n].ignored);
    }
}
