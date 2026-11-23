// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/model.h"

#include <algorithm>
#include <cstdio>
#include <stdexcept>

namespace bw {

namespace {

[[noreturn]] void refuse(const std::string& what) {
    throw std::invalid_argument(what);
}

// Everything that holds a number, as opposed to bytes or text.
bool is_number(FieldKind kind) {
    switch (kind) {
        case FieldKind::Constant:
        case FieldKind::Enum:
        case FieldKind::Counter:
        case FieldKind::Length:
        case FieldKind::Checksum:
        case FieldKind::Timestamp:
        case FieldKind::Float:
        case FieldKind::Flags:
            return true;
        case FieldKind::Unknown:
        case FieldKind::Text:
        case FieldKind::Payload:
            break;
    }
    return false;
}

std::string number(unsigned long long v) {
    return std::to_string(v);
}

std::string hex(unsigned long long v) {
    char buffer[32];
    std::snprintf(buffer, sizeof(buffer), "0x%llX", v);
    return buffer;
}

std::string padded(const std::string& s, std::size_t width) {
    return s.size() >= width ? s : s + std::string(width - s.size(), ' ');
}

} // namespace

// ---- Model -----------------------------------------------------------------

void Model::set_framing(const FramingInfo& framing) {
    if (framing.kind != FramingKind::IdleGap && framing.idle_gap_ns != 0) {
        refuse("idle_gap_ns belongs to idle-gap framing only");
    }
    const bool delimited = framing.kind == FramingKind::Terminated || framing.kind == FramingKind::Flagged;
    if (!delimited && framing.delimiter != 0) {
        refuse("a delimiter belongs to terminated and flagged framing only");
    }
    if (framing.escaped && framing.kind != FramingKind::Flagged) {
        refuse("an escape belongs to flagged framing only");
    }
    if (!framing.escaped && (framing.escape != 0 || framing.delimiter_code != 0 || framing.escape_code != 0)) {
        refuse("the escape and its codes are set without `escaped`");
    }
    if (framing.escaped && (framing.escape == framing.delimiter || framing.delimiter_code == framing.escape_code)) {
        refuse("the escape byte differs from the delimiter, and so do the two codes");
    }
    framing_ = framing;
}

FramingInfo Model::framing() const {
    return framing_;
}

std::size_t Model::add_message_type(const std::string& name) {
    TypeRecord record;
    record.name = name;
    types_.push_back(record);
    return types_.size() - 1;
}

std::size_t Model::add_field(std::size_t message_type, const std::string& name,
                             const FieldInfo& info, const std::string& detail) {
    if (message_type >= types_.size()) {
        refuse("there is no message type " + number(message_type));
    }
    TypeRecord&       type  = types_[message_type];
    const std::size_t index = type.fields.size();
    const std::string who   = "field " + number(index) + " '" + name + "'";

    if (index > 0 && type.fields.back().info.size_kind == SizeKind::ToEnd) {
        refuse(who + " comes after a field that runs to the end of the frame");
    }

    // Size, and the values that only one size kind has.
    if (info.size_kind == SizeKind::Fixed) {
        if (info.bit_size == 0) {
            refuse(who + " is fixed-size and has no bit_size");
        }
    } else if (info.bit_size != 0) {
        refuse(who + " has a bit_size but is not fixed-size");
    }
    if (info.size_kind != SizeKind::FromField && info.size_field != 0) {
        refuse(who + " has a size_field but is not sized from a field");
    }
    if (info.size_kind != SizeKind::Delimited && info.delimiter != 0) {
        refuse(who + " has a delimiter but is not delimited");
    }
    if (info.kind != FieldKind::Constant && info.constant != 0) {
        refuse(who + " has a constant but is not a Constant");
    }
    if (info.kind != FieldKind::Checksum &&
        (info.covers_first != 0 || info.covers_last != 0)) {
        refuse(who + " covers fields but is not a Checksum");
    }

    // Numbers.
    if (is_number(info.kind)) {
        if (info.size_kind != SizeKind::Fixed) {
            refuse(who + " is a number and must be fixed-size");
        }
        if (info.bit_size > 64) {
            refuse(who + " is a number wider than 64 bits");
        }
        if (info.kind == FieldKind::Float && info.bit_size != 32 && info.bit_size != 64) {
            refuse(who + " is a Float and must be 32 or 64 bits");
        }
        if (info.bit_size > 8) {
            if (info.byte_order == ByteOrder::NotApplicable) {
                refuse(who + " is wider than 8 bits and needs a byte order");
            }
        } else if (info.byte_order != ByteOrder::NotApplicable) {
            refuse(who + " is 8 bits or fewer and has no byte order");
        }
    } else if (info.byte_order != ByteOrder::NotApplicable) {
        refuse(who + " is not a number and has no byte order");
    }

    if (info.ascii_hex) {
        if (info.kind != FieldKind::Checksum) {
            refuse(who + " is written as hexadecimal text but is not a Checksum");
        }
        if (info.bit_size % 16 != 0 || info.byte_order != ByteOrder::Big) {
            refuse(who + " is written as hexadecimal text: two characters for each byte of the value, "
                         "most significant first, so a multiple of 16 bits and big-endian");
        }
    }

    if (info.kind == FieldKind::Constant && info.bit_size < 64 &&
        (info.constant >> info.bit_size) != 0) {
        refuse(who + " has a constant that does not fit in " + number(info.bit_size) + " bits");
    }

    // References to earlier fields.
    if (info.size_kind == SizeKind::FromField) {
        if (info.size_field >= index) {
            refuse(who + " is sized from a field that does not come before it");
        }
        if (type.fields[info.size_field].info.kind != FieldKind::Length) {
            refuse(who + " is sized from a field that is not a Length");
        }
    }
    if (info.kind == FieldKind::Checksum &&
        !(info.covers_first <= info.covers_last && info.covers_last < index)) {
        refuse(who + " must cover a range of earlier fields");
    }

    FieldRecord record;
    record.info   = info;
    record.name   = name;
    record.detail = detail;
    type.fields.push_back(record);
    return index;
}

std::size_t Model::message_type_count() const {
    return types_.size();
}

std::string Model::message_type_name(std::size_t message_type) const {
    return types_.at(message_type).name;
}

std::size_t Model::field_count(std::size_t message_type) const {
    return types_.at(message_type).fields.size();
}

FieldInfo Model::field(std::size_t message_type, std::size_t index) const {
    return types_.at(message_type).fields.at(index).info;
}

std::string Model::field_name(std::size_t message_type, std::size_t index) const {
    return types_.at(message_type).fields.at(index).name;
}

std::string Model::field_detail(std::size_t message_type, std::size_t index) const {
    return types_.at(message_type).fields.at(index).detail;
}

FieldPosition Model::field_position(std::size_t message_type, std::size_t index) const {
    const std::vector<FieldRecord>& fields = types_.at(message_type).fields;
    if (index >= fields.size()) {
        throw std::out_of_range("there is no field " + number(index));
    }
    FieldPosition position;
    position.fixed = true;
    for (std::size_t i = 0; i < index; ++i) {
        if (fields[i].info.size_kind != SizeKind::Fixed) {
            return FieldPosition();         // something before it has no fixed size
        }
        position.bit_offset += fields[i].info.bit_size;
    }
    return position;
}

// ---- Description -----------------------------------------------------------

std::string field_kind_name(FieldKind kind) {
    switch (kind) {
        case FieldKind::Unknown:   return "unknown";
        case FieldKind::Constant:  return "constant";
        case FieldKind::Enum:      return "enum";
        case FieldKind::Counter:   return "counter";
        case FieldKind::Length:    return "length";
        case FieldKind::Checksum:  return "checksum";
        case FieldKind::Timestamp: return "timestamp";
        case FieldKind::Float:     return "float";
        case FieldKind::Text:      return "text";
        case FieldKind::Flags:     return "flags";
        case FieldKind::Payload:   return "payload";
    }
    return "unknown";
}

std::string describe_model(const Model& model) {
    std::string out = "framing: ";
    const FramingInfo framing = model.framing();
    switch (framing.kind) {
        case FramingKind::Unknown:
            out += "unknown";
            break;
        case FramingKind::IdleGap:
            out += "idle gap, at least " + number(framing.idle_gap_ns) + " ns";
            break;
        case FramingKind::ByEvent:
            out += "one frame per event";
            break;
        case FramingKind::Contiguous:
            out += "contiguous, nothing between frames";
            break;
        case FramingKind::Terminated:
            out += "ends with " + hex(framing.delimiter);
            break;
        case FramingKind::Flagged:
            out += "between " + hex(framing.delimiter);
            if (framing.escaped) {
                out += ", escape " + hex(framing.escape) + ": " + hex(framing.delimiter) + " as " +
                       hex(framing.escape) + " " + hex(framing.delimiter_code) + ", " +
                       hex(framing.escape) + " as " + hex(framing.escape) + " " + hex(framing.escape_code);
            }
            break;
    }
    out += "\n";

    for (std::size_t t = 0; t < model.message_type_count(); ++t) {
        out += "message type " + number(t) + " \"" + model.message_type_name(t) + "\"\n";

        std::size_t name_width = 0;
        for (std::size_t f = 0; f < model.field_count(t); ++f) {
            name_width = std::max(name_width, model.field_name(t, f).size() + 2);
        }
        for (std::size_t f = 0; f < model.field_count(t); ++f) {
            const FieldInfo     info     = model.field(t, f);
            const FieldPosition position = model.field_position(t, f);

            out += "  " + number(f) + " " +
                   padded("\"" + model.field_name(t, f) + "\"", name_width) + " " +
                   padded(field_kind_name(info.kind), 9) + " ";
            switch (info.size_kind) {
                case SizeKind::Fixed:
                    out += number(info.bit_size) + " bits";
                    break;
                case SizeKind::FromField:
                    out += "sized by field " + number(info.size_field);
                    break;
                case SizeKind::ToEnd:
                    out += "to the end";
                    break;
                case SizeKind::Delimited:
                    out += "up to " + hex(info.delimiter);
                    break;
            }
            out += position.fixed ? " @" + number(position.bit_offset) : std::string(" @?");
            if (info.byte_order == ByteOrder::Big)    out += " big-endian";
            if (info.byte_order == ByteOrder::Little) out += " little-endian";
            if (info.ascii_hex) out += " as hex text";
            if (info.kind == FieldKind::Constant) {
                out += " = " + hex(info.constant);
            }
            if (info.kind == FieldKind::Checksum) {
                out += " covers " + number(info.covers_first) + ".." + number(info.covers_last);
            }
            if (info.evidence_bits != 0) {
                out += " evidence " + number(info.evidence_bits) + " bits";
            }
            if (!model.field_detail(t, f).empty()) {
                out += " " + model.field_detail(t, f);
            }
            out += "\n";
        }
    }
    return out;
}

} // namespace bw
