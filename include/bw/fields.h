// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stages 4 and 5: where are the fields of a message, and what are they?
//
// A message type is, for now, a frame size: the frames of one size are looked
// at together, byte offset by byte offset. (What tells message types apart
// within a size, and frames of varying length, are for later: docs/roadmap.md.)
//
// Stage 4, discover_fields, splits the frame into regions. Each byte offset is
// classed by how many distinct values it takes over the frames: one (a
// Constant), a few that each recur (Few), or too many to see anything in (Many).
// A run of Many bytes is one region: a stretch with no structure this stage
// can see is, by definition, one payload field, and cutting it into bytes would
// claim boundaries that nothing supports. A Constant or a Few byte is a region
// of its own. The checksum that stage 2 found is a region too, and the places
// where its coverage begins and ends are boundaries.
//
// Stage 5, type_fields, says what each region is: a Constant with its value, an
// Enum, a Counter (successive frames differ by the same non-zero step) or a
// Payload, the answer for anything else, which claims nothing. Every claim
// carries its evidence in bits, on the same footing as the CRC stage's.
//
// With few frames nothing is claimed at all: fewer than min_frames and the map
// has no regions.
//
// The shape of this API follows the rule in docs/roadmap.md: plain structs,
// the collection behind a class.

#ifndef BW_FIELDS_H
#define BW_FIELDS_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bw/capture.h"
#include "bw/checksum.h"
#include "bw/model.h"
#include "bw/segmentation.h"

namespace bw {

enum class FieldStructure : std::uint8_t {
    Constant = 0,       // one value in every frame
    Few      = 1,       // a few values, each of them recurring (see FieldOptions)
    Many     = 2,       // no structure that stage 4 could see
    Checksum = 3        // the bytes of the checksum that stage 2 found
};

struct FieldRegion {
    std::uint32_t  byte_offset = 0;
    std::uint32_t  byte_size   = 0;
    FieldStructure structure   = FieldStructure::Many;

    // Stage 5 fills in the rest (stage 4 does for a Checksum, from stage 2).
    // kind stays Unknown until then.
    FieldKind      kind          = FieldKind::Unknown;
    ByteOrder      byte_order    = ByteOrder::NotApplicable;
    bool           ascii_hex     = false; // Checksum: written as text, two hexadecimal characters
    std::uint64_t  constant      = 0;     // Constant
    std::uint64_t  step          = 0;     // Counter: how much it goes up from one frame to the next
    std::uint32_t  evidence_bits = 0;     // bits of evidence behind the kind; 0 for Payload
};

struct FieldOptions {
    // With fewer frames of a size than this, nothing is claimed about it.
    std::uint32_t min_frames      = 4;
    // A byte is Few when it takes at most this many distinct values and every
    // value was seen on four frames or more on average.
    std::uint32_t max_enum_values = 16;
};

// The regions of one message type, in order. They tile the frame: each starts
// where the one before it ends, and the last ends at the frame's end (a map
// without regions is one where nothing was claimed).
class FieldMap {
public:
    // No frames, no regions.
    FieldMap();
    FieldMap(std::uint32_t frame_bytes, std::uint32_t frames);

    // Appends a region. Throws std::invalid_argument, changing nothing, unless
    // it is not empty, starts where the previous one ended and ends inside the frame.
    void add_region(const FieldRegion& region);

    std::uint32_t frame_bytes() const;     // the size of the frames this map is of
    std::uint32_t frames() const;          // how many frames of that size were looked at
    std::size_t   region_count() const;
    FieldRegion   region(std::size_t index) const;      // throws std::out_of_range

private:
    std::uint32_t            frame_bytes_ = 0;
    std::uint32_t            frames_      = 0;
    std::vector<FieldRegion> regions_;
};

// Stage 4. `checksum` is stage 2's finding for the same size, or one with found
// false; a found checksum that does not fit frames of that size is a caller's
// error, std::invalid_argument.
FieldMap discover_fields(const Capture& capture, const Segmentation& segmentation,
                         const ChecksumFinding& checksum, std::uint32_t size_bytes,
                         const FieldOptions& options);

// Stage 5. The same regions with their kinds, from the same capture and
// segmentation. A region that already has a kind (the checksum) keeps it.
// Throws std::invalid_argument if the layout is not of the frames these give.
FieldMap type_fields(const FieldMap& layout, const Capture& capture,
                     const Segmentation& segmentation);

} // namespace bw

#endif // BW_FIELDS_H
