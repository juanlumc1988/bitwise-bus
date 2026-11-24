// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/synthetic.h"

#include <algorithm>
#include <set>
#include <stdexcept>
#include <string>

#include "protocols/common.h"

namespace bw {

namespace {

// ---- The checksums: their own code, not the catalogue's -----------------------------------------------------

struct Algo {
    const char*   name;
    unsigned      width;
    int           type;          // 0 a CRC, 1 the XOR of the bytes, 2 their sum
    std::uint32_t poly, init;
    bool          refin, refout;
    std::uint32_t xorout;
};

const Algo kAlgos[] = {
    { "CRC-8",           8,  0, 0x07,       0x00,       false, false, 0x00       },
    { "CRC-8/MAXIM-DOW", 8,  0, 0x31,       0x00,       true,  true,  0x00       },
    { "CRC-16/MODBUS",   16, 0, 0x8005,     0xFFFF,     true,  true,  0x0000     },
    { "CRC-16/ARC",      16, 0, 0x8005,     0x0000,     true,  true,  0x0000     },
    { "CRC-16/XMODEM",   16, 0, 0x1021,     0x0000,     false, false, 0x0000     },
    { "CRC-16/IBM-3740", 16, 0, 0x1021,     0xFFFF,     false, false, 0x0000     },
    { "CRC-16/IBM-SDLC", 16, 0, 0x1021,     0xFFFF,     true,  true,  0xFFFF     },
    { "CRC-16/MCRF4XX",  16, 0, 0x1021,     0xFFFF,     true,  true,  0x0000     },
    { "CRC-32/ISO-HDLC", 32, 0, 0x04C11DB7, 0xFFFFFFFF, true,  true,  0xFFFFFFFF },
    { "CRC-32/MPEG-2",   32, 0, 0x04C11DB7, 0xFFFFFFFF, false, false, 0x00000000 },
    { "XOR-8",           8,  1, 0,          0,          false, false, 0          },
    { "SUM-8",           8,  2, 0,          0,          false, false, 0          },
};
const std::size_t kAlgoCount = sizeof(kAlgos) / sizeof(kAlgos[0]);

std::uint64_t reflect_bits(std::uint64_t value, unsigned width) {
    std::uint64_t out = 0;
    for (unsigned i = 0; i < width; ++i) {
        if ((value >> i) & 1) {
            out |= std::uint64_t(1) << (width - 1 - i);
        }
    }
    return out;
}

// The check value of bytes [from, to) of `data`, and then of `extra` if it is not negative: a byte that is in no frame.
std::uint64_t check_of(const Algo& a, const std::vector<std::uint8_t>& data, std::size_t from, std::size_t to,
                       int extra) {
    std::vector<std::uint8_t> bytes(data.begin() + static_cast<std::ptrdiff_t>(from),
                                    data.begin() + static_cast<std::ptrdiff_t>(to));
    if (extra >= 0) {
        bytes.push_back(static_cast<std::uint8_t>(extra));
    }
    if (a.type == 1 || a.type == 2) {
        unsigned v = 0;
        for (std::size_t i = 0; i < bytes.size(); ++i) {
            v = a.type == 1 ? (v ^ bytes[i]) : ((v + bytes[i]) & 0xFF);
        }
        return v;
    }
    const std::uint64_t mask = a.width == 32 ? 0xFFFFFFFFULL : ((std::uint64_t(1) << a.width) - 1);
    const std::uint64_t top  = std::uint64_t(1) << (a.width - 1);
    std::uint64_t       reg  = a.init & mask;
    for (std::size_t i = 0; i < bytes.size(); ++i) {
        const std::uint64_t byte = a.refin ? reflect_bits(bytes[i], 8) : bytes[i];
        reg ^= byte << (a.width - 8);
        for (int bit = 0; bit < 8; ++bit) {
            reg = (reg & top) ? (((reg << 1) ^ a.poly) & mask) : ((reg << 1) & mask);
        }
    }
    if (a.refout) {
        reg = reflect_bits(reg, a.width);
    }
    return (reg ^ a.xorout) & mask;
}

// ---- The shape of a protocol -----------------------------------------------------------------------------------

enum Mode { kGap = 0, kSync = 1, kFlags = 2 };

struct Item {                                    // a field of the fixed part of a payload
    FieldKind                  kind  = FieldKind::Payload;
    unsigned                   bytes = 1;
    ByteOrder                  order = ByteOrder::NotApplicable;
    std::uint64_t              constant = 0;
    std::vector<std::uint64_t> table;            // Enum and Flags: the values it takes
    std::uint64_t              first = 0;        // Counter
    std::uint64_t              step  = 1;
    unsigned                   exp_base = 0, exp_span = 0;      // Float
};

struct TypePlan {
    std::uint8_t          id = 0;
    std::vector<Item>     items;
    std::vector<unsigned> blob_sizes;            // not empty: a payload of no structure, of one of these sizes
    int                   seed_byte = -1;        // the byte that is in no frame, for the checksum
    std::uint64_t         sent      = 0;         // frames of this type so far, for its counters
};

struct Plan {
    Mode                       mode        = kGap;
    std::vector<std::uint8_t>  sync;             // kSync: one or two bytes
    unsigned                   length_bytes = 1; // kSync
    bool                       length_big   = false;
    unsigned                   length_mode  = 0; // kSync: 0 the payload, 1 what follows the length, 2 the whole frame
    std::uint8_t               address      = 0; // kFlags
    bool                       seq          = false;
    std::uint8_t               flag = 0, escape = 0, flag_code = 0, escape_code = 0;
    int                        algo         = -1;   // index in kAlgos, or none
    bool                       check_big    = false;
    unsigned                   check_skip   = 0;    // bytes at the start that the checksum leaves out
    std::uint64_t              char_ns      = 0;
    std::vector<TypePlan>      types;
};

unsigned header_bytes(const Plan& p) {
    switch (p.mode) {
        case kSync:  return static_cast<unsigned>(p.sync.size()) + p.length_bytes + 1 + (p.seq ? 1 : 0);
        case kFlags: return 2 + (p.seq ? 1 : 0);
        default:     return 1 + (p.seq ? 1 : 0);
    }
}

unsigned check_bytes(const Plan& p) {
    return p.algo < 0 ? 0 : kAlgos[p.algo].width / 8;
}

unsigned fixed_payload(const TypePlan& t) {
    unsigned size = 0;
    for (std::size_t i = 0; i < t.items.size(); ++i) {
        size += t.items[i].bytes;
    }
    return size;
}

Item make_item(Rng* rng) {
    Item item;
    const std::uint64_t pick = rng->below(100);
    const bool wide          = rng->below(100) < 40;
    const ByteOrder order    = rng->below(2) == 0 ? ByteOrder::Little : ByteOrder::Big;
    if (pick < 15) {
        item.kind     = FieldKind::Constant;
        item.bytes    = 1 + static_cast<unsigned>(rng->below(2));
        item.constant = rng->below(item.bytes == 1 ? 256 : 65536);
    } else if (pick < 40) {
        item.kind  = FieldKind::Enum;
        item.bytes = wide ? 2 : 1;
        const std::uint64_t values = 2 + rng->below(7);
        for (std::uint64_t v = 0; v < values; ++v) {
            item.table.push_back(rng->below(item.bytes == 1 ? 256 : 65536));
        }
    } else if (pick < 55) {
        item.kind  = FieldKind::Counter;
        item.bytes = wide ? (rng->below(2) == 0 ? 2 : 4) : 1;
        item.first = rng->below(1000);
        item.step  = 1 + rng->below(item.bytes == 1 ? 7 : 1000);
    } else if (pick < 70) {
        item.kind     = FieldKind::Float;
        item.bytes    = 4;
        item.exp_base = 0x78 + static_cast<unsigned>(rng->below(8));
        item.exp_span = 1 + static_cast<unsigned>(rng->below(6));
    } else if (pick < 80) {
        item.kind  = FieldKind::Flags;
        item.bytes = 1;
        const std::uint64_t values = 3 + rng->below(6);
        for (std::uint64_t v = 0; v < values; ++v) {
            item.table.push_back(rng->below(256));
        }
    } else {
        item.kind  = FieldKind::Payload;
        item.bytes = 1 + static_cast<unsigned>(rng->below(4));
    }
    if (item.bytes > 1 && item.kind != FieldKind::Payload) {
        item.order = order;
    }
    return item;
}

Plan make_plan(Rng* rng) {
    Plan p;
    const std::uint64_t m = rng->below(100);
    p.mode = m < 40 ? kSync : (m < 70 ? kGap : kFlags);
    static const unsigned bauds[4] = { 9600, 19200, 57600, 115200 };
    p.char_ns = 10ULL * 1000000000ULL / bauds[rng->below(4)];
    p.seq     = rng->below(100) < 40;

    if (p.mode == kSync) {
        p.sync.push_back(static_cast<std::uint8_t>(0x80 + rng->below(0x7F)));
        if (rng->below(100) < 30) {
            p.sync.push_back(static_cast<std::uint8_t>(rng->below(256)));
        }
        p.length_bytes = rng->below(100) < 80 ? 1 : 2;
        p.length_big   = rng->below(2) == 0;
    } else if (p.mode == kFlags) {
        if (rng->below(2) == 0) {
            p.flag = 0x7E; p.escape = 0x7D; p.flag_code = 0x5E; p.escape_code = 0x5D;       // HDLC
        } else {
            p.flag = 0xC0; p.escape = 0xDB; p.flag_code = 0xDC; p.escape_code = 0xDD;       // SLIP
        }
        p.address = static_cast<std::uint8_t>(rng->below(256));
    }

    // Frames of several sizes need a checksum to be put together, and a length to say the size.
    const bool variable_allowed = p.mode == kSync && rng->below(100) < 35;
    // In a stream with nothing between the frames, one size for all of them would make any byte that never changes a
    // place to cut at: a rotation of the frame is as good as the frame. Two kinds of message tell them apart.
    const std::size_t types     = (p.mode == kSync ? 2 : 1) + static_cast<std::size_t>(rng->below(p.mode == kSync ? 3 : 4));
    const std::uint8_t id0      = static_cast<std::uint8_t>(rng->below(200));
    const unsigned stride       = 1 + static_cast<unsigned>(rng->below(7));
    bool any_variable           = false;
    for (std::size_t k = 0; k < types; ++k) {
        TypePlan t;
        t.id = static_cast<std::uint8_t>(id0 + k * stride);
        if (variable_allowed && rng->below(100) < 65) {
            any_variable = true;
            const unsigned base = 2 + static_cast<unsigned>(rng->below(10));
            const unsigned sizes = 2 + static_cast<unsigned>(rng->below(2));
            unsigned at = base;
            for (unsigned s = 0; s < sizes; ++s) {
                t.blob_sizes.push_back(at);
                at += 1 + static_cast<unsigned>(rng->below(6));
            }
        } else {
            const std::size_t items = 2 + static_cast<std::size_t>(rng->below(5));
            for (std::size_t i = 0; i < items; ++i) {
                t.items.push_back(make_item(rng));
            }
        }
        p.types.push_back(t);
    }
    p.length_mode = any_variable ? 0 : static_cast<unsigned>(rng->below(3));

    // The checksum: none, a sum or a CRC; a CRC of 16 or more bits may have a byte of its own for each kind of message.
    const std::uint64_t c = rng->below(100);
    if (any_variable || c >= 10) {
        p.algo = static_cast<int>(rng->below(kAlgoCount));
    }
    p.check_big  = rng->below(2) == 0;
    p.check_skip = (p.mode == kSync && rng->below(2) == 0) ? static_cast<unsigned>(p.sync.size()) : 0;
    if (p.algo >= 0 && kAlgos[p.algo].type == 0 && kAlgos[p.algo].width >= 16 && p.mode == kSync &&
        rng->below(100) < 25) {
        for (std::size_t k = 0; k < p.types.size(); ++k) {
            p.types[k].seed_byte = static_cast<int>(rng->below(256));
        }
    }

    // No two kinds of message share a size, so that a size says which one it is: the fixed ones get a payload of
    // bytes with no structure added until they differ, and the sizes of a payload that varies are moved up.
    std::set<unsigned> used;
    const unsigned     overhead = header_bytes(p) + check_bytes(p);
    for (std::size_t k = 0; k < p.types.size(); ++k) {
        TypePlan& t = p.types[k];
        for (;;) {
            bool clash = false;
            if (t.blob_sizes.empty()) {
                clash = used.count(overhead + fixed_payload(t)) != 0;
                if (clash) {
                    Item extra;
                    extra.kind  = FieldKind::Payload;
                    extra.bytes = 1;
                    t.items.push_back(extra);
                }
            } else {
                for (std::size_t s = 0; s < t.blob_sizes.size(); ++s) {
                    clash = clash || used.count(overhead + t.blob_sizes[s]) != 0;
                }
                if (clash) {
                    for (std::size_t s = 0; s < t.blob_sizes.size(); ++s) {
                        ++t.blob_sizes[s];
                    }
                }
            }
            if (!clash) {
                break;
            }
        }
        if (t.blob_sizes.empty()) {
            used.insert(overhead + fixed_payload(t));
        } else {
            for (std::size_t s = 0; s < t.blob_sizes.size(); ++s) {
                used.insert(overhead + t.blob_sizes[s]);
            }
        }
    }
    return p;
}

// ---- The truth ----------------------------------------------------------------------------------------------------

FieldInfo field(FieldKind kind, unsigned bytes, ByteOrder order) {
    FieldInfo info;
    info.kind       = kind;
    info.bit_size   = 8 * bytes;
    info.byte_order = bytes > 1 ? order : ByteOrder::NotApplicable;
    return info;
}

FieldInfo constant(std::uint64_t value, unsigned bytes) {
    FieldInfo info = field(FieldKind::Constant, bytes, ByteOrder::Little);
    info.constant  = value;
    return info;
}

std::string check_detail(const Plan& p, const TypePlan& t) {
    std::string name = kAlgos[p.algo].name;
    if (t.seed_byte >= 0) {
        name += " seeded with " + std::to_string(t.seed_byte);
    }
    return name;
}

Model make_model(const Plan& p) {
    Model       model;
    FramingInfo framing;
    if (p.mode == kGap) {
        framing.kind        = FramingKind::IdleGap;
        framing.idle_gap_ns = 5 * p.char_ns;
    } else if (p.mode == kSync) {
        framing.kind = FramingKind::Contiguous;
    } else {
        framing.kind           = FramingKind::Flagged;
        framing.delimiter      = p.flag;
        framing.escaped        = true;
        framing.escape         = p.escape;
        framing.delimiter_code = p.flag_code;
        framing.escape_code    = p.escape_code;
    }
    model.set_framing(framing);

    for (std::size_t k = 0; k < p.types.size(); ++k) {
        const TypePlan&   t     = p.types[k];
        const std::size_t index = model.add_message_type("type" + std::to_string(k));
        std::size_t       length_field = 0;
        std::size_t       first_covered = 0;
        std::size_t       count = 0;                   // fields so far
        const unsigned    skip  = p.check_skip;
        unsigned          offset = 0;                  // bytes so far
        const auto add = [&](const std::string& name, const FieldInfo& info, unsigned bytes) {
            if (offset == skip) {
                first_covered = count;
            }
            model.add_field(index, name, info, "");
            offset += bytes;
            ++count;
        };
        if (p.mode == kSync) {
            for (std::size_t s = 0; s < p.sync.size(); ++s) {
                add("sync" + std::to_string(s), constant(p.sync[s], 1), 1);
            }
            length_field = count;
            add("length", field(FieldKind::Length, p.length_bytes, p.length_big ? ByteOrder::Big : ByteOrder::Little),
                p.length_bytes);
        } else if (p.mode == kFlags) {
            add("address", constant(p.address, 1), 1);
        }
        add("id", constant(t.id, 1), 1);
        if (p.seq) {
            add("seq", field(FieldKind::Counter, 1, ByteOrder::NotApplicable), 1);
        }
        if (!t.blob_sizes.empty()) {
            FieldInfo payload;
            payload.kind       = FieldKind::Payload;
            payload.size_kind  = SizeKind::FromField;
            payload.size_field = static_cast<std::uint32_t>(length_field);
            model.add_field(index, "payload", payload, "");
            ++count;
        } else {
            for (std::size_t i = 0; i < t.items.size(); ++i) {
                const Item& item = t.items[i];
                FieldInfo   info = field(item.kind, item.bytes, item.order);
                if (item.kind == FieldKind::Constant) {
                    info.constant = item.constant;
                }
                add("f" + std::to_string(i), info, item.bytes);
            }
        }
        if (p.algo >= 0) {
            FieldInfo cs = field(FieldKind::Checksum, check_bytes(p), p.check_big ? ByteOrder::Big : ByteOrder::Little);
            cs.covers_first = static_cast<std::uint32_t>(first_covered);
            cs.covers_last  = static_cast<std::uint32_t>(count - 1);
            model.add_field(index, "checksum", cs, check_detail(p, t));
        }
    }
    return model;
}

// ---- The frames --------------------------------------------------------------------------------------------------

void put_number(std::vector<std::uint8_t>* out, std::uint64_t value, unsigned bytes, ByteOrder order) {
    for (unsigned i = 0; i < bytes; ++i) {
        const unsigned shift = 8 * (order == ByteOrder::Big ? bytes - 1 - i : i);
        out->push_back(static_cast<std::uint8_t>((value >> shift) & 0xFF));
    }
}

std::uint64_t modulo(std::uint64_t value, unsigned bytes) {
    return bytes >= 8 ? value : (value & ((std::uint64_t(1) << (8 * bytes)) - 1));
}

// The frame as it is before any stuffing: what the checksum is of, and what the fields are.
std::vector<std::uint8_t> make_frame(const Plan& p, TypePlan* t, Rng* rng) {
    std::vector<std::uint8_t> payload;
    if (!t->blob_sizes.empty()) {
        const unsigned size = t->blob_sizes[static_cast<std::size_t>(rng->below(t->blob_sizes.size()))];
        for (unsigned i = 0; i < size; ++i) {
            payload.push_back(static_cast<std::uint8_t>(rng->below(256)));
        }
    } else {
        for (std::size_t i = 0; i < t->items.size(); ++i) {
            const Item& item = t->items[i];
            switch (item.kind) {
                case FieldKind::Constant:
                    put_number(&payload, item.constant, item.bytes, item.order);
                    break;
                case FieldKind::Enum:
                case FieldKind::Flags:
                    put_number(&payload, item.table[static_cast<std::size_t>(rng->below(item.table.size()))],
                               item.bytes, item.order);
                    break;
                case FieldKind::Counter:
                    put_number(&payload, modulo(item.first + item.step * t->sent, item.bytes), item.bytes, item.order);
                    break;
                case FieldKind::Float:
                    put_number(&payload, random_float_bits(rng, item.exp_base, item.exp_span), 4, item.order);
                    break;
                default:
                    for (unsigned b = 0; b < item.bytes; ++b) {
                        payload.push_back(static_cast<std::uint8_t>(rng->below(256)));
                    }
                    break;
            }
        }
    }

    const unsigned total = header_bytes(p) + static_cast<unsigned>(payload.size()) + check_bytes(p);
    std::vector<std::uint8_t> frame;
    if (p.mode == kSync) {
        frame.insert(frame.end(), p.sync.begin(), p.sync.end());
        const std::uint64_t value = p.length_mode == 0 ? payload.size()
                                  : p.length_mode == 1 ? total - p.sync.size() - p.length_bytes
                                                       : total;
        put_number(&frame, value, p.length_bytes, p.length_big ? ByteOrder::Big : ByteOrder::Little);
    } else if (p.mode == kFlags) {
        frame.push_back(p.address);
    }
    frame.push_back(t->id);
    if (p.seq) {
        frame.push_back(static_cast<std::uint8_t>(t->sent & 0xFF));
    }
    frame.insert(frame.end(), payload.begin(), payload.end());
    if (p.algo >= 0) {
        const std::uint64_t check = check_of(kAlgos[p.algo], frame, p.check_skip, frame.size(), t->seed_byte);
        put_number(&frame, check, check_bytes(p), p.check_big ? ByteOrder::Big : ByteOrder::Little);
    }
    ++t->sent;
    return frame;
}


// ---- Lines of text --------------------------------------------------------------------------------------------------

// A field of a sentence: the same in all of them (possibly nothing at all), a whole number, a decimal number, or one of a few
// words.
struct Word {
    enum Sort { kSame, kWhole, kDecimal, kChoice } sort = kSame;
    std::string              same;               // kSame
    unsigned                 digits = 1;         // kWhole: at most this many; kDecimal: before the point
    std::vector<std::string> choices;            // kChoice
};

struct Sentence {
    std::string       address;                   // letters, in front of the first separator
    std::vector<Word> words;
};

struct TextPlan {
    char                  separator = ',';
    std::string           start;                 // nothing, or one character that the checksum leaves out
    bool                  check     = false;     // the exclusive or of what is between, as two characters after a star
    bool                  crlf      = false;
    std::uint64_t         char_ns   = 0;
    std::vector<Sentence> kinds;
};

std::string letters(Rng* rng, unsigned n) {
    std::string out;
    for (unsigned i = 0; i < n; ++i) {
        out += static_cast<char>('A' + rng->below(26));
    }
    return out;
}

TextPlan make_text_plan(Rng* rng) {
    static const char kSeparators[4] = { ',', ';', '|', ' ' };
    static const char kStarts[4]     = { '$', '!', '#', '\0' };
    static const std::uint64_t kChars[3] = { 2083333, 1041666, 86805 };

    TextPlan p;
    p.separator = kSeparators[rng->below(4)];
    const char start = kStarts[rng->below(4)];
    p.start     = start == '\0' ? std::string() : std::string(1, start);
    p.check     = rng->below(3) != 0;
    p.crlf      = rng->below(2) == 0;
    p.char_ns   = kChars[rng->below(3)];
    const unsigned kinds = 1 + static_cast<unsigned>(rng->below(3));
    while (p.kinds.size() < kinds) {
        Sentence s;
        s.address = letters(rng, 2 + static_cast<unsigned>(rng->below(5)));
        bool again = false;
        for (std::size_t k = 0; k < p.kinds.size(); ++k) {
            again = again || p.kinds[k].address == s.address;
        }
        if (again) {
            continue;
        }
        const unsigned words = 2 + static_cast<unsigned>(rng->below(6));
        for (unsigned w = 0; w < words; ++w) {
            Word word;
            switch (rng->below(5)) {
                case 0:
                    word.sort = Word::kSame;
                    word.same = letters(rng, static_cast<unsigned>(rng->below(4)));       // nothing, sometimes
                    break;
                case 1:
                    word.sort   = Word::kWhole;
                    word.digits = 1 + static_cast<unsigned>(rng->below(6));
                    break;
                case 2:
                    word.sort   = Word::kDecimal;
                    word.digits = 1 + static_cast<unsigned>(rng->below(4));
                    break;
                default: {
                    word.sort = Word::kChoice;
                    const unsigned n = 2 + static_cast<unsigned>(rng->below(3));
                    while (word.choices.size() < n) {
                        const std::string choice = letters(rng, 1);
                        if (std::find(word.choices.begin(), word.choices.end(), choice) == word.choices.end()) {
                            word.choices.push_back(choice);
                        }
                    }
                }
            }
            s.words.push_back(word);
        }
        p.kinds.push_back(s);
    }
    return p;
}

// A number with the digits that it needs, without a leading zero.
std::string number_text(Rng* rng, unsigned digits) {
    std::string out;
    for (unsigned i = 0; i < 1 + rng->below(digits); ++i) {
        out += static_cast<char>((out.empty() ? '1' : '0') + rng->below(out.empty() ? 9 : 10));
    }
    return out;
}

std::string word_text(const Word& w, Rng* rng) {
    switch (w.sort) {
        case Word::kSame:
            return w.same;
        case Word::kWhole:
            return number_text(rng, w.digits);
        case Word::kDecimal: {
            std::string out = number_text(rng, w.digits) + ".";
            for (unsigned i = 0; i < 1 + rng->below(3); ++i) {
                out += static_cast<char>('0' + rng->below(10));
            }
            return out;
        }
        case Word::kChoice:
            return w.choices[static_cast<std::size_t>(rng->below(w.choices.size()))];
    }
    return std::string();
}

char last_delimiter(const TextPlan& p) {
    return p.check ? '*' : (p.crlf ? '\r' : '\n');
}

std::vector<std::uint8_t> make_sentence(const TextPlan& p, const Sentence& s, Rng* rng) {
    std::string line = p.start + s.address + p.separator;
    for (std::size_t w = 0; w < s.words.size(); ++w) {
        line += word_text(s.words[w], rng);
        line += w + 1 < s.words.size() ? p.separator : last_delimiter(p);
    }
    if (p.check) {
        // What is between the start and the star, as two characters, and then the end.
        unsigned x = 0;
        for (std::size_t i = p.start.size(); i + 1 < line.size(); ++i) {
            x ^= static_cast<unsigned char>(line[i]);
        }
        static const char digits[] = "0123456789ABCDEF";
        line += digits[(x >> 4) & 15];
        line += digits[x & 15];
        line += p.crlf ? "\r\n" : "\n";
    } else if (p.crlf) {
        line += "\n";                                   // the carriage return was the last field's
    }
    return std::vector<std::uint8_t>(line.begin(), line.end());
}

FieldInfo text_constant(const std::string& text) {
    FieldInfo info = field(FieldKind::Constant, static_cast<unsigned>(text.size()), ByteOrder::Big);
    for (std::size_t i = 0; i < text.size(); ++i) {
        info.constant = (info.constant << 8) | static_cast<unsigned char>(text[i]);
    }
    return info;
}

Model make_text_model(const TextPlan& p) {
    Model       model;
    FramingInfo framing;
    framing.kind      = FramingKind::Terminated;
    framing.delimiter = 0x0A;
    model.set_framing(framing);
    for (std::size_t k = 0; k < p.kinds.size(); ++k) {
        const Sentence&   s    = p.kinds[k];
        const std::size_t type = model.add_message_type("kind" + std::to_string(k));
        if (!p.start.empty()) {
            model.add_field(type, "start", text_constant(p.start), "");
        }
        const std::size_t address = model.add_field(type, "address", text_constant(s.address + p.separator), "");
        std::size_t       last    = address;
        for (std::size_t w = 0; w < s.words.size(); ++w) {
            const char delimiter = w + 1 < s.words.size() ? p.separator : last_delimiter(p);
            FieldInfo  info;
            if (s.words[w].sort == Word::kSame) {
                info = text_constant(s.words[w].same + delimiter);
            } else {
                info.kind      = FieldKind::Text;
                info.size_kind = SizeKind::Delimited;
                info.delimiter = static_cast<std::uint8_t>(delimiter);
            }
            last = model.add_field(type, "field_" + std::to_string(w), info, "");
        }
        if (p.check) {
            FieldInfo check = field(FieldKind::Checksum, 2, ByteOrder::Big);
            check.ascii_hex    = true;
            check.covers_first = static_cast<std::uint32_t>(address);
            check.covers_last  = static_cast<std::uint32_t>(last);
            model.add_field(type, "checksum", check, "XOR-8");
        }
        // After the checksum the line ends with a carriage return and a line feed, or a line feed; with none the last
        // field ends with the first of them.
        const std::string end = p.check ? (p.crlf ? "\r\n" : "\n") : (p.crlf ? "\n" : "");
        if (!end.empty()) {
            model.add_field(type, "end", text_constant(end), "");
        }
    }
    return model;
}

} // namespace

Dataset generate_synthetic(const SyntheticOptions& options) {
    if (options.frames > 100000) {
        throw std::invalid_argument("frames is at most 100000");
    }
    if (options.jitter_permille > 500) {
        throw std::invalid_argument("jitter_permille is at most 500");
    }

    Rng  rng(options.seed);
    Plan plan = make_plan(&rng);
    const Model model = make_model(plan);

    Capture             capture;
    const std::uint32_t channel   = capture.add_channel("line");
    const std::uint64_t max_delay = plan.char_ns * options.jitter_permille / 1000;

    std::vector<FrameSpan>     spans;
    std::vector<std::uint32_t> types;
    std::uint64_t              start  = 0;
    std::uint64_t              events = 0;
    for (std::uint32_t i = 0; i < options.frames; ++i) {
        const std::size_t kind  = static_cast<std::size_t>(rng.below(plan.types.size()));
        std::vector<std::uint8_t> frame = make_frame(plan, &plan.types[kind], &rng);
        if (plan.mode == kFlags) {
            std::vector<std::uint8_t> line(1, plan.flag);
            const std::vector<std::uint8_t> sent = stuff(frame, plan.flag, plan.escape, plan.flag_code, plan.escape_code);
            line.insert(line.end(), sent.begin(), sent.end());
            line.push_back(plan.flag);
            frame = line;
        }
        start = emit_bytes(&capture, channel, start, plan.char_ns, max_delay, &rng, frame);
        if (plan.mode == kGap) {
            start += plan.char_ns * (5 + rng.below(16));
        }

        FrameSpan span;
        span.first_event = events;
        span.event_count = frame.size();
        spans.push_back(span);
        types.push_back(static_cast<std::uint32_t>(kind));
        events += frame.size();
    }
    return Dataset(capture, model, spans, types);
}

Dataset generate_synthetic_text(const SyntheticOptions& options) {
    if (options.frames > 100000) {
        throw std::invalid_argument("frames is at most 100000");
    }
    if (options.jitter_permille > 500) {
        throw std::invalid_argument("jitter_permille is at most 500");
    }

    Rng            rng(options.seed);
    const TextPlan plan  = make_text_plan(&rng);
    const Model    model = make_text_model(plan);

    Capture             capture;
    const std::uint32_t channel   = capture.add_channel("line");
    const std::uint64_t max_delay = plan.char_ns * options.jitter_permille / 1000;

    std::vector<FrameSpan>     spans;
    std::vector<std::uint32_t> types;
    std::uint64_t              start  = 0;
    std::uint64_t              events = 0;
    for (std::uint32_t i = 0; i < options.frames; ++i) {
        const std::size_t               kind = static_cast<std::size_t>(rng.below(plan.kinds.size()));
        const std::vector<std::uint8_t> line = make_sentence(plan, plan.kinds[kind], &rng);
        start = emit_bytes(&capture, channel, start, plan.char_ns, max_delay, &rng, line);
        // A pause after some of them, as after a burst of sentences.
        if (rng.below(3) == 0) {
            start += plan.char_ns * (5 + rng.below(16));
        }

        FrameSpan span;
        span.first_event = events;
        span.event_count = line.size();
        spans.push_back(span);
        types.push_back(static_cast<std::uint32_t>(kind));
        events += line.size();
    }
    return Dataset(capture, model, spans, types);
}

Dataset add_noise(const Dataset& clean, const NoiseOptions& options) {
    if (options.corrupt_permille > 1000 || options.lose_permille > 1000) {
        throw std::invalid_argument("a rate is at most 1000 per thousand");
    }
    Rng           rng(options.seed);
    const Capture source = clean.capture();
    Capture       out;
    for (std::uint32_t c = 1; c < source.channel_count(); ++c) {
        out.add_channel(source.channel_name(c));
    }

    std::vector<FrameSpan>     spans;
    std::vector<std::uint32_t> types;
    std::uint64_t              at = 0;            // the next event of the source to be copied
    const auto copy_events = [&](std::uint64_t from, std::uint64_t to) {
        for (std::uint64_t e = from; e < to; ++e) {
            out.add_event(source.event(static_cast<std::size_t>(e)), source.event_bytes(static_cast<std::size_t>(e)));
        }
    };
    for (std::size_t f = 0; f < clean.frame_count(); ++f) {
        const FrameSpan span = clean.frame(f);
        copy_events(at, span.first_event);
        at = span.first_event + span.event_count;

        // The same draws for every frame, so that a rate changes which frames are chosen and nothing else.
        const std::uint64_t lose    = rng.below(1000);
        const std::uint64_t corrupt = rng.below(1000);
        const std::uint64_t where   = rng.next();
        const std::uint64_t change  = 1 + rng.below(255);
        if (lose < options.lose_permille) {
            continue;
        }
        std::uint64_t bytes = 0;
        for (std::uint64_t e = span.first_event; e < at; ++e) {
            bytes += source.event_size(static_cast<std::size_t>(e));
        }
        bool          damage = corrupt < options.corrupt_permille && bytes > 0;
        std::uint64_t target = damage ? where % bytes : 0;       // which byte of the frame, counting from its first
        FrameSpan     kept;
        kept.first_event = out.event_count();
        kept.event_count = span.event_count;
        for (std::uint64_t e = span.first_event; e < at; ++e) {
            std::vector<std::uint8_t> data = source.event_bytes(static_cast<std::size_t>(e));
            if (damage) {
                if (target < data.size()) {
                    data[static_cast<std::size_t>(target)] =
                        static_cast<std::uint8_t>(data[static_cast<std::size_t>(target)] ^ change);
                    damage = false;
                } else {
                    target -= data.size();
                }
            }
            out.add_event(source.event(static_cast<std::size_t>(e)), data);
        }
        spans.push_back(kept);
        types.push_back(clean.frame_message_type(f));
    }
    copy_events(at, source.event_count());
    return Dataset(out, clean.model(), spans, types);
}

} // namespace bw
