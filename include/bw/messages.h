// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 4, first part: which frames are of one kind of message when a kind has
// frames of different sizes.
//
// Until now a message type was a frame size. That is wrong as soon as a kind of
// message does not always have the same size, as in MAVLink 2, where the zeros at
// the end of a payload are not sent: four messages came out as seven types. What
// ties the frames of a kind together is a discriminator, a few bytes near the
// start (the message id) that are the same in every frame of the kind and differ
// from kind to kind; and what makes their sizes differ is a length: a field whose
// value is the frame's size less a constant.
//
// So this looks for both, in the frames of all the sizes there are enough of:
//
//   - a length field: one or two bytes, at an offset below 16, whose value plus
//     some constant is the size of every frame (two or more sizes are needed, or
//     any constant byte would do). The narrower is taken before the wider, and the
//     lower offset first, as the sync byte stage does;
//   - the key: the offsets, before where the frame's length constant says the
//     header and trailer end, at which every size has a single value and the sizes
//     do not all have the same one (the length field is not one of them);
//   - the kinds: the sizes that have the same bytes at the key, when two or more.
//
// The frames of a kind are those of its sizes, and also those of a size of which
// there are too few to be a type, when their key is the kind's and their length
// says their size: a size with plenty of frames and another with a few, that have
// the same key, are a kind too. Whether the frames of a kind are really one is for
// the caller to confirm: a checksum that explains all of them, with the same
// hidden byte, is the evidence that analyze() asks for.
//
// This header is not one of those that the bindings are made from: it speaks in
// vectors.

#ifndef BW_MESSAGES_H
#define BW_MESSAGES_H

#include <cstdint>
#include <vector>

#include "bw/capture.h"
#include "bw/checksum.h"
#include "bw/segmentation.h"

namespace bw {

// A field whose value is the size of the frame less `adjust`: size = value + adjust.
struct LengthField {
    std::uint32_t offset     = 0;
    std::uint32_t bytes      = 0;       // 1 or 2
    bool          big_endian = false;
    std::int64_t  adjust     = 0;
    // Bits of evidence: eight for each byte, for each size after the first, since the first is what
    // says what the constant is and each other one is a value that it predicts.
    std::uint32_t evidence_bits = 0;
};

struct MessageKind {
    std::vector<std::uint32_t> sizes;          // those of its frames: two or more, ascending
    std::vector<std::uint8_t>  key;            // the bytes at MessageKinds::key_offsets
    std::uint64_t              frames = 0;     // of those sizes, and the rare ones that belong
};

struct MessageKinds {
    bool                       found = false;  // a length field and a key were found
    LengthField                length;
    std::vector<std::uint32_t> key_offsets;
    std::vector<MessageKind>   kinds;          // only those with two sizes or more
    // For each frame of the segmentation, the index of its kind, or -1.
    std::vector<std::int32_t>  frame_kind;
};

// `min_frames` is how many frames a size needs to be looked at, as in FieldOptions.
MessageKinds find_message_kinds(const Capture& capture, const Segmentation& segmentation,
                                std::uint32_t min_frames);

// Stage 2 over frames of different sizes, as of one kind: the search is anchored at
// the ends of the frame, so it takes any mix of sizes, and the evidence is that of
// the different frames of all of them.
ChecksumFinding find_checksum_of_frames(const std::vector<std::vector<std::uint8_t> >& frames);

} // namespace bw

#endif // BW_MESSAGES_H
