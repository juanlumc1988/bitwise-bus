// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/kaitai.h"

#include <set>
#include <stdexcept>
#include <vector>

namespace bw {

namespace {

std::string number(std::uint64_t value) {
    return std::to_string(static_cast<unsigned long long>(value));
}

bool is_id(const std::string& text) {
    if (text.empty() || text[0] < 'a' || text[0] > 'z') {
        return false;
    }
    for (std::size_t i = 1; i < text.size(); ++i) {
        const char c = text[i];
        if (!((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_')) {
            return false;
        }
    }
    return true;
}

// A YAML double-quoted scalar on one line. Control characters are escaped; other
// bytes, UTF-8 included, are written as they are.
std::string quoted(const std::string& text) {
    static const char digits[] = "0123456789abcdef";
    std::string       out      = "\"";
    for (std::size_t i = 0; i < text.size(); ++i) {
        const unsigned char c = static_cast<unsigned char>(text[i]);
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20 || c == 0x7F) {
                    out += "\\x";
                    out += digits[c >> 4];
                    out += digits[c & 15];
                } else {
                    out += static_cast<char>(c);
                }
        }
    }
    return out + "\"";
}

std::string hex_byte(unsigned value) {
    static const char digits[] = "0123456789abcdef";
    std::string       out      = "0x";
    out += digits[(value >> 4) & 15];
    out += digits[value & 15];
    return out;
}

bool is_number(FieldKind kind) {
    return kind != FieldKind::Text && kind != FieldKind::Payload && kind != FieldKind::Unknown;
}

// u1, u2be, f8le...: the Kaitai type for a number that is 8, 16, 32 or 64 bits,
// or an empty string for any other size.
std::string number_type(const FieldInfo& info) {
    const char* prefix = info.kind == FieldKind::Float ? "f" : "u";
    const std::string order = info.byte_order == ByteOrder::Big ? "be" : "le";
    switch (info.bit_size) {
        case 8:  return std::string(prefix) + "1";
        case 16: return std::string(prefix) + "2" + order;
        case 32: return std::string(prefix) + "4" + order;
        case 64: return std::string(prefix) + "8" + order;
        default: return std::string();
    }
}

std::string contents_of(const FieldInfo& info) {
    const std::uint32_t bytes = info.bit_size / 8;
    std::string         out   = "[";
    for (std::uint32_t i = 0; i < bytes; ++i) {
        // The byte that is i-th in the frame: the most significant first in a
        // big-endian number, the least significant first in a little-endian one.
        const std::uint32_t shift = 8 * (info.byte_order == ByteOrder::Little ? i : bytes - 1 - i);
        if (i != 0) {
            out += ", ";
        }
        out += hex_byte(static_cast<unsigned>((info.constant >> shift) & 0xFF));
    }
    return out + "]";
}

std::string doc_of(const Model& model, std::size_t type, std::size_t index, const FieldInfo& info) {
    std::string doc = field_kind_name(info.kind);
    const std::string detail = model.field_detail(type, index);
    if (!detail.empty()) {
        doc += ", " + detail;
    }
    if (info.kind == FieldKind::Checksum) {
        if (info.ascii_hex) {
            doc += ", written as hexadecimal text";
        }
        doc += ", over " + model.field_name(type, info.covers_first) + " to " +
               model.field_name(type, info.covers_last) + " (Kaitai does not check it)";
    }
    if (info.evidence_bits != 0) {
        doc += "; evidence " + number(info.evidence_bits) + " bits";
    }
    return doc;
}

} // namespace

std::string export_kaitai(const Model& model, std::size_t message_type, const std::string& id) {
    if (message_type >= model.message_type_count()) {
        throw std::out_of_range("message type out of range");
    }
    if (!is_id(id)) {
        throw std::invalid_argument("'" + id + "' is not a Kaitai identifier (a lower-case letter, "
                                    "then lower-case letters, digits and underscores)");
    }

    // Checked before anything is written, so that a refusal writes nothing.
    std::set<std::string> names;
    const std::size_t     count = model.field_count(message_type);
    for (std::size_t i = 0; i < count; ++i) {
        const std::string name = model.field_name(message_type, i);
        const FieldInfo   info = model.field(message_type, i);
        if (!is_id(name)) {
            throw std::invalid_argument("the field name '" + name + "' is not a Kaitai identifier");
        }
        if (!names.insert(name).second) {
            throw std::invalid_argument("two fields are named '" + name + "'");
        }
        if (info.size_kind != SizeKind::Fixed) {
            throw std::invalid_argument("the field '" + name + "' has a size that depends on the frame, "
                                        "which the Kaitai exporter does not write yet");
        }
        if (info.bit_size == 0 || info.bit_size % 8 != 0) {
            throw std::invalid_argument("the field '" + name + "' is not a whole number of bytes, "
                                        "which the Kaitai exporter does not write yet");
        }
    }

    std::string doc = "Message type '" + model.message_type_name(message_type) + "'. Written by bitwise-bus.";
    const FramingInfo framing = model.framing();
    if (framing.kind == FramingKind::IdleGap) {
        doc += " Frames are separated by silences of at least " + number(framing.idle_gap_ns) + " ns.";
    } else if (framing.kind == FramingKind::ByEvent) {
        doc += " Each capture event is one frame.";
    } else if (framing.kind == FramingKind::Contiguous) {
        doc += " Frames follow one another with nothing between them.";
    } else if (framing.kind == FramingKind::Terminated) {
        doc += " A frame ends with the byte " + hex_byte(framing.delimiter) + ".";
    } else if (framing.kind == FramingKind::Flagged) {
        doc += " A frame lies between two bytes " + hex_byte(framing.delimiter) + ".";
        if (framing.escaped) {
            doc += " Inside it " + hex_byte(framing.delimiter) + " is sent as " + hex_byte(framing.escape) + " " +
                   hex_byte(framing.delimiter_code) + " and " + hex_byte(framing.escape) + " as " +
                   hex_byte(framing.escape) + " " + hex_byte(framing.escape_code) + ".";
        }
    }

    std::string out = "meta:\n  id: " + id + "\ndoc: " + quoted(doc) + "\n";
    if (count == 0) {
        return out + "seq: []\n";
    }
    out += "seq:\n";
    for (std::size_t i = 0; i < count; ++i) {
        const FieldInfo info = model.field(message_type, i);
        out += "  - id: " + model.field_name(message_type, i) + "\n";
        const std::uint32_t bytes = info.bit_size / 8;
        if (info.kind == FieldKind::Constant) {
            out += "    contents: " + contents_of(info) + "\n";
        } else if (info.kind == FieldKind::Text || info.ascii_hex) {
            out += "    type: str\n    size: " + number(bytes) + "\n    encoding: ASCII\n";
        } else if (is_number(info.kind) && !number_type(info).empty()) {
            out += "    type: " + number_type(info) + "\n";
        } else {
            out += "    size: " + number(bytes) + "\n";
        }
        std::string line = doc_of(model, message_type, i, info);
        if (is_number(info.kind) && number_type(info).empty() && info.kind != FieldKind::Constant) {
            // A whole number of bytes that Kaitai has no integer type for.
            line += info.byte_order == ByteOrder::Big ? ", big-endian" : ", little-endian";
        }
        out += "    doc: " + quoted(line) + "\n";
    }
    return out;
}

} // namespace bw
