// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Protocols made up from a seed, and noise to put on any capture with a known answer.
//
// Six protocols with a name can only show that the pipeline works on those six,
// and whoever wrote the pipeline knew them. A synthetic protocol is a different
// one for each seed: how its frames are told apart (by a gap, by a sync byte and a
// length, or between flags with byte stuffing), a header, from one to four kinds of
// message with fields of the kinds the pipeline claims (constants, enumerations,
// counters, floats, flags, bytes with no structure) or a payload of several
// sizes, and a checksum from the catalogue (or a sum, or none), sometimes with a
// byte that is in no frame. What is true of each one is in its model, as for the
// protocols with a name, so the same evaluation applies, and a property can be
// tried over thousands of them.
//
// Noise is what a real line does: a byte of a frame that arrives wrong, and a frame
// that does not arrive. add_noise() puts it on a capture and leaves the answer true
// of what is left: the frames that were lost are not frames of the truth, and the
// ones that arrived wrong are, with the same model, since that is what they were
// meant to be.
//
// Like the generators of the protocols with a name, everything is integer
// arithmetic on a seed, so the same seed gives the same capture on every platform,
// and nothing here shares code with the inference stages.

#ifndef BW_SYNTHETIC_H
#define BW_SYNTHETIC_H

#include <cstdint>

#include "bw/dataset.h"

namespace bw {

struct SyntheticOptions {
    std::uint64_t seed            = 1;      // what the protocol is, and what it sends
    std::uint32_t frames          = 200;    // at most 100000
    // Timing noise, in thousandths of a character time, 0 to 500, as in GenerateOptions.
    std::uint32_t jitter_permille = 0;
};

// Throws std::invalid_argument for options out of range.
Dataset generate_synthetic(const SyntheticOptions& options);

// The same for lines of text, as NMEA 0183 has them: from one to three kinds of sentence, each with an address
// (letters), then from two to seven fields that are the same in all of them (or empty), whole numbers, decimal
// numbers or one of a few letters, with a separator (a comma, a semicolon, a bar or a space) after each and a
// character in front of all of it, or none; a checksum, the exclusive or as two hexadecimal characters after a star,
// or none; and a carriage return and a line feed, or a line feed. The frames are the lines, one event for each
// byte, with a pause after some of them. What is true of each kind is in its model, with the text of the fields as
// Text up to the byte that ends them, and what is the same in all of them as Constant. The options are those of
// generate_synthetic.
Dataset generate_synthetic_text(const SyntheticOptions& options);

struct NoiseOptions {
    std::uint64_t seed             = 1;
    // Of every thousand frames, how many have one byte changed to another value
    // (any byte of the frame as it is on the line, a flag or a sync byte included), and
    // how many are not in the capture at all. 0 to 1000 each.
    std::uint32_t corrupt_permille = 0;
    std::uint32_t lose_permille    = 0;
};

// The capture of `clean` with noise, and its truth: the frames that are left, in the
// places they have in the new capture, with the message types they had. Events that are
// in no frame are kept. The same seed makes the same noise whatever the rates are, up to
// which frames the rates choose. Throws std::invalid_argument for a rate over 1000.
Dataset add_noise(const Dataset& clean, const NoiseOptions& options);

} // namespace bw

#endif // BW_SYNTHETIC_H
