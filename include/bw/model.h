// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// What a protocol looks like: how its frames are delimited, which kinds of
// message it has, and for each message the ordered list of fields.
//
// One type does four jobs, which is the point of it. A generator of synthetic
// captures starts from a Model: the ground truth. The pipeline ends with one:
// the inference. An exporter prints one. And the evaluation harness compares
// two. Making the answer and the ground truth the same type is what lets every
// stage be measured.
//
// A model is never half-built. add_field() checks each field against the ones
// before it and refuses what would make the model inconsistent, so whatever
// holds a Model can rely on it. A field is also in canonical form: what does
// not apply to its kind stays at the default (a checksum has no constant, a
// constant has no coverage), so two models that say the same thing compare and
// print the same.
//
// The shape of this API follows the rule in docs/roadmap.md: <cstdint> types,
// plain structs for what crosses the boundary, the collection behind a class.

#ifndef BW_MODEL_H
#define BW_MODEL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace bw {

// How frames are told apart in the capture. Unknown means the model says
// nothing about it, as for a model built from frames that were already cut.
// More kinds (a length prefix that decides where a frame ends, say) come with
// the segmentation stage.
enum class FramingKind : std::uint8_t {
    Unknown    = 0,
    IdleGap    = 1,     // two consecutive events whose timestamps are at least
                        //   idle_gap_ns apart are in different frames. Timestamps
                        //   are when an event started and its duration is not
                        //   recorded, so this is all a capture can say.
    ByEvent    = 2,     // each event is a frame: a CAN frame, say
    Contiguous = 3,     // frames follow one another with nothing between them,
                        //   and where one ends is in its own layout: a fixed
                        //   size, a length field (UBX, MAVLink)
    Terminated = 4,     // a frame ends with the byte `delimiter`, which is part of
                        //   it (NMEA 0183: the line feed after the carriage return)
    Flagged    = 5      // a frame lies between two bytes `delimiter`: the flag of
                        //   SLIP and of HDLC. With `escaped`, a flag or an escape
                        //   byte inside a frame is sent as `escape` and a code
};

struct FramingInfo {
    FramingKind   kind        = FramingKind::Unknown;
    std::uint64_t idle_gap_ns = 0;      // IdleGap only
    std::uint8_t  delimiter   = 0;      // Terminated and Flagged only
    // Flagged only. The byte `delimiter` inside a frame is sent as `escape` then
    // `delimiter_code`, and the byte `escape` as `escape` then `escape_code`:
    // SLIP is 0xDB 0xDC and 0xDB 0xDD, HDLC is 0x7D 0x5E and 0x7D 0x5D.
    bool          escaped        = false;
    std::uint8_t  escape         = 0;
    std::uint8_t  delimiter_code = 0;
    std::uint8_t  escape_code    = 0;
};

enum class FieldKind : std::uint8_t {
    Unknown   = 0,
    Constant  = 1,      // always the same value: a magic number, a version
    Enum      = 2,      // a few distinct values
    Counter   = 3,      // goes up by a constant step from one frame to the next
    Length    = 4,      // how many bytes another field holds
    Checksum  = 5,
    Timestamp = 6,
    Float     = 7,      // IEEE 754
    Text      = 8,
    Flags     = 9,      // independent bits
    Payload   = 10      // data with no structure that could be found
};

enum class SizeKind : std::uint8_t {
    Fixed     = 0,      // bit_size bits
    FromField = 1,      // as many bytes as an earlier Length field says
    ToEnd     = 2,      // the rest of the frame; only the last field can be
    Delimited = 3       // up to and including the byte `delimiter`
};

enum class ByteOrder : std::uint8_t {
    NotApplicable = 0,  // text and payload, and numbers of 8 bits or fewer
    Big           = 1,
    Little        = 2
};

struct FieldInfo {
    FieldKind     kind          = FieldKind::Unknown;
    SizeKind      size_kind     = SizeKind::Fixed;
    std::uint32_t bit_size      = 0;    // Fixed
    std::uint32_t size_field    = 0;    // FromField: the index of the Length field
    std::uint8_t  delimiter     = 0;    // Delimited
    ByteOrder     byte_order    = ByteOrder::NotApplicable;
    std::uint64_t constant      = 0;    // Constant
    std::uint32_t covers_first  = 0;    // Checksum: the first and last field it
    std::uint32_t covers_last   = 0;    //   covers, both included
    bool          ascii_hex     = false;    // Checksum: written as text, two hexadecimal
                                            //   digits for each byte of the value, the most
                                            //   significant first (NMEA 0183's "*47"). bit_size
                                            //   is the size on the wire: 16 for a byte.
    std::uint32_t evidence_bits = 0;    // an inferred field: bits of evidence behind
                                        //   it, as in the CRC stage. A ground truth
                                        //   leaves it at 0.
};

// Where a field starts. fixed is false when anything before it has no fixed
// size, because then its offset depends on the frame.
struct FieldPosition {
    bool          fixed      = false;
    std::uint64_t bit_offset = 0;       // meaningful only when fixed
};

class Model {
public:
    void        set_framing(const FramingInfo& framing);
    FramingInfo framing() const;

    // Returns the index of the new message type.
    std::size_t add_message_type(const std::string& name);

    // Appends a field to a message type and returns its index. `detail` is free
    // text: for a checksum, the algorithm ("CRC-16/MODBUS"). Throws
    // std::invalid_argument, changing nothing, if the field breaks a rule:
    //   - a message type that does not exist, or a field after a ToEnd one;
    //   - a Fixed field with no size, or any other size kind with a bit_size;
    //   - a number (every kind but Text, Payload and Unknown) that is not Fixed,
    //     is wider than 64 bits, or has a byte order that does not fit its
    //     size: Big or Little above 8 bits, NotApplicable otherwise;
    //   - a Float that is not 32 or 64 bits;
    //   - a Constant that does not fit its size;
    //   - a FromField whose size_field is not an earlier, Fixed Length field;
    //   - a Checksum whose coverage is not a range of earlier fields;
    //   - a value set for a kind it does not belong to.
    std::size_t add_field(std::size_t message_type, const std::string& name,
                          const FieldInfo& info, const std::string& detail);

    std::size_t   message_type_count() const;
    std::string   message_type_name(std::size_t message_type) const;
    std::size_t   field_count(std::size_t message_type) const;
    FieldInfo     field(std::size_t message_type, std::size_t index) const;
    std::string   field_name(std::size_t message_type, std::size_t index) const;
    std::string   field_detail(std::size_t message_type, std::size_t index) const;
    FieldPosition field_position(std::size_t message_type, std::size_t index) const;
    // The accessors above throw std::out_of_range for an index that is not there.

private:
    struct FieldRecord {
        FieldInfo   info;
        std::string name;
        std::string detail;
    };
    struct TypeRecord {
        std::string              name;
        std::vector<FieldRecord> fields;
    };

    FramingInfo             framing_;
    std::vector<TypeRecord> types_;
};

std::string field_kind_name(FieldKind kind);

// A stable, human-readable listing, for tests and for a first look at a model:
//
//   framing: idle gap, at least 4000000 ns
//   message type 0 "request"
//     0 "address"   enum      8 bits @0
//     1 "function"  enum      8 bits @8
//     2 "crc"       checksum 16 bits @16 little-endian covers 0..1 CRC-16/MODBUS
std::string describe_model(const Model& model);

} // namespace bw

#endif // BW_MODEL_H
