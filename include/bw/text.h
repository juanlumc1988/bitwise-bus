// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 4 for text: the kinds and the fields of lines of text with a separator, as NMEA 0183
// has them.
//
// A line of text is not a row of bytes with a place for each, the way stage 4 reads a binary
// frame. Its fields have the width of what they hold: "$GPGGA,123519,4807.038,N,...*47" has as
// many sizes as the numbers have digits, and the three kinds of sentence share them. What ties
// the lines of a kind together is how they start, up to a separator, and how many separators
// they have; and what a field is, is what lies between two of them.
//
// So this looks for the separator: of the bytes that are not letters or digits, those with which four lines in five
// or more fall into kinds (a kind being the lines that start with the same bytes up to their first one of it, and
// have as many of it: at least `FieldOptions::min_frames` of them), and of those the one with the most separators in
// the lines that are in kinds; then the one with more lines, more kinds and more bytes at the start that are the
// same in all of a kind's lines, and the lowest byte on a tie. The `$` of NMEA is in every line once, and bounds
// one kind, and so a kind of two fields; the comma bounds three kinds of fifteen, thirteen and nine, with
// more separators; and for lines with a single comma, where the two have as many, the comma, which has the
// address in front of it, wins. Without a byte that makes kinds of four lines in five, there is no separator, and
// nothing is found.
//
// The fields of a kind are then:
//
//   - the head, up to the first separator, which is the same in all the lines of the kind: a
//     Constant (of up to eight bytes each, so several when it is longer);
//   - each field between two separators, and the last one after the last separator, up to where
//     the line ends or the checksum starts: a Constant when it is the same in all the lines, else
//     Text up to the separator, whose detail says which values there are when there are a few
//     and each one recurs;
//   - the checksum that stage 2 finds over the lines of the kind, when it is written as text:
//     two hexadecimal characters after one byte that it does not cover (NMEA's star), which
//     ends the last field. The head is cut where the checksum starts to cover, so that the
//     `$` is a field of its own;
//   - what the lines end with after it, a Constant.
//
// With no checksum the last field ends at the first of the carriage return and line feed that
// close the lines, and the rest of them is the end.
//
// A field that is only a delimiter (an empty value) is part of what stage 5 would call a constant
// of the kind if it is always empty, and Text if it is not.
//
// Evidence, in bits: a Constant has eight for each byte it holds, for every line after the
// first; Text has one for each line that has it where the kind says.
//
// This header is not one of those that the bindings are made from: it speaks in vectors.

#ifndef BW_TEXT_H
#define BW_TEXT_H

#include <cstdint>
#include <string>
#include <vector>

#include "bw/checksum.h"
#include "bw/fields.h"
#include "bw/model.h"

namespace bw {

// A field of a kind of text, as it goes into the model.
struct TextField {
    FieldKind                 kind          = FieldKind::Unknown;      // Constant, Text or Checksum
    SizeKind                  size_kind     = SizeKind::Fixed;         // Fixed (a Constant, the checksum) or Delimited (Text)
    std::vector<std::uint8_t> bytes;                                   // a Constant's value
    std::uint8_t              delimiter     = 0;                       // Text: the byte it ends with, which is part of it
    std::string               detail;                                  // Text with few values: which
    std::uint32_t             evidence_bits = 0;
    std::uint32_t             covers_first  = 0;                       // Checksum: the fields it covers, as indexes
    std::uint32_t             covers_last   = 0;
};

struct TextType {
    std::vector<TextField> fields;
    std::uint32_t          frames   = 0;        // lines of this kind
    std::uint32_t          smallest = 0;        // the shortest and the longest of them, in bytes
    std::uint32_t          largest  = 0;
    // What stage 2 found over them. found is false when the checksum is not one that the text has a
    // place for (not written as text, or with no byte before it): its fields are then the end of the last.
    ChecksumFinding        checksum;
};

struct TextTypes {
    bool                  found     = false;    // lines of text with a separator, in kinds of enough lines
    std::uint8_t          separator = 0;
    std::vector<TextType> types;                // most lines first, then by how the lines start
    std::uint64_t         ignored   = 0;        // lines that are in none
};

// The kinds of a capture of lines, each as the bytes of a line with the line feed that ends it, and the
// fields of each. Nothing is found for a capture that is not text (95% of its bytes characters, a tab, a
// carriage return or a line feed, and 95% of the lines ending with a line feed), for one that has no separator
// as above, and for a capture of which less than four lines in five are in a kind with fields.
TextTypes find_text_types(const std::vector<std::vector<std::uint8_t> >& lines, const FieldOptions& options);

} // namespace bw

#endif // BW_TEXT_H
