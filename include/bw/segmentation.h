// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Stage 3: where do the frames begin and end?
//
// The skeleton version looks only at time. A byte on a serial bus follows the
// previous byte of its frame closely and a new frame follows a silence, so the
// gaps between consecutive events fall in two groups: short ones inside a
// frame and long ones between frames. The stage finds the widest hole between
// the two groups, in ratio, and cuts at every gap on the long side of it.
//
// It says so when there is no such hole instead of guessing: a capture
// without timestamps, with the same gap everywhere, or with gaps that spread
// evenly from short to long has no framing this stage can see.
//
// The second way to cut is by flags, for a capture that has no timing to cut
// by (a UART capture with no timestamps, or a byte every character time with
// nothing between the frames): a byte that bounds a frame on both sides, as the
// END of SLIP and the flag of HDLC do, with more flags between one frame and the
// next as often as not. What shows it is that two of them follow each other: the
// close of a frame and the open of the next.
//
// The third is for frames that follow one another with nothing between them and
// say how long they are: a sync byte, then a length somewhere in the first few
// bytes (UBX, MAVLink). If frames are what the stream is made of, a frame ends
// where its length says and the next begins there, with the sync byte again; so
// from one occurrence of a candidate sync byte the stage follows that chain, and
// a candidate (a byte, and where and how wide the length is) is the framing when
// the chain covers the capture with almost no break. A sync byte that happens to
// occur inside a payload breaks nothing, which is what a length is for.
//
// A flag that two frames share (one flag between frames, which is how HDLC is
// usually sent) looks, in the bytes, like any byte that occurs once per frame, and
// such a byte cuts a frame somewhere, at its end, its start or its middle, that the
// bytes alone do not tell (docs/roadmap.md). What does tell is the stuffing, which
// is why a flag is wanted twice in a row or with stuffing: a flag that has to be
// kept out of the frames has an escape byte, which is always followed by one of
// two codes, and nothing else in a capture is.
//
// The same is true of a terminator, and it is told by a convention instead: if
// the capture is text, its frames are the lines, which end with a line feed (and
// the carriage return before it, which is part of the frame). NMEA 0183 is that.
// A terminator of another kind (an ETX, a NUL after binary data) is a byte that
// occurs once in a frame like any other, and is not found.
//
// Everything is integer arithmetic, so the same capture is cut in the same
// places on every platform.
//
// The shape of this API follows the rule in docs/roadmap.md: plain structs,
// the collection behind a class.

#ifndef BW_SEGMENTATION_H
#define BW_SEGMENTATION_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bw/capture.h"
#include "bw/evaluate.h"
#include "bw/model.h"

namespace bw {

struct SegmentationOptions {
    // The shortest gap between frames must be at least this many times the
    // longest gap inside a frame. Below that the two groups are not told apart.
    std::uint32_t min_gap_ratio = 3;
    // A byte is taken as a flag only if it bounds at least this many frames.
    std::uint32_t min_flag_frames = 8;
    // A sync byte and a length are taken as the framing only if the chain they
    // make has at least this many frames.
    std::uint32_t min_sync_frames = 8;
    // Lines of text are taken as frames only if there are at least this many.
    std::uint32_t min_line_frames = 8;
};

struct SegmentationInfo {
    // False when the capture shows no division into frames. Everything else
    // here is zero then.
    bool          found                = false;
    // What cut the frames: IdleGap, Flagged, Terminated (lines of text) or
    // Contiguous (a sync byte and a length), and Unknown for frames that were
    // given (a segmentation built by hand, a generator's truth).
    FramingKind   kind                 = FramingKind::Unknown;
    // Flagged: the flag, and how many bytes of the capture are that byte. Terminated:
    // the byte that ends each frame, and how many of them the capture has. With
    // `escaped`, the capture shows the stuffing that keeps the flag out of the
    // frames: the flag inside one is sent as `escape` and `delimiter_code`, and
    // `escape` as `escape` and `escape_code`.
    std::uint8_t  delimiter            = 0;
    std::uint64_t flags                = 0;
    bool          escaped              = false;
    std::uint8_t  escape               = 0;
    std::uint8_t  delimiter_code       = 0;
    std::uint8_t  escape_code          = 0;
    // Contiguous: every frame starts with the byte `sync`. Its size is the
    // number in the `length_bytes` bytes that start `length_offset` bytes after
    // the sync byte (the sync byte is at offset 0), little-endian unless
    // length_big_endian, plus length_adjust, which may be negative. When every
    // frame has the same size there is no length to read: length_bytes is 0 and
    // frame_size is the size. `breaks` is how many times the chain failed and
    // started again at the next sync byte.
    std::uint8_t  sync                 = 0;
    std::uint32_t length_offset        = 0;
    std::uint32_t length_bytes         = 0;
    bool          length_big_endian    = false;
    std::int32_t  length_adjust        = 0;
    std::uint32_t frame_size           = 0;
    std::uint64_t breaks               = 0;
    // A gap of at least this many nanoseconds, between two consecutive events,
    // ends a frame: the shortest gap that was classed as between frames.
    std::uint64_t idle_gap_ns          = 0;
    std::uint64_t longest_inner_gap_ns = 0;     // the longest gap inside a frame
    std::uint64_t inner_gaps           = 0;     // how many gaps were classed as inside a frame
    std::uint64_t outer_gaps           = 0;     // ...and as between frames
};

class Segmentation {
public:
    // Nothing found, no frames.
    Segmentation();
    Segmentation(const SegmentationInfo& info, const std::vector<FrameSpan>& frames);

    SegmentationInfo info() const;

    std::size_t            frame_count() const;
    FrameSpan              frame(std::size_t index) const;      // throws std::out_of_range
    std::vector<FrameSpan> frames() const;

private:
    SegmentationInfo       info_;
    std::vector<FrameSpan> frames_;
};

// Cuts a capture at its long gaps. Every frame is a run of events; together
// they cover the capture. Nothing found (found false) when the capture has
// fewer than two events, an event without a time, or no hole of the ratio the
// options ask for between its short gaps and its long ones.
Segmentation segment_by_gaps(const Capture& capture, const SegmentationOptions& options);

// Cuts a capture of single-byte events at its flags: the byte that, with the
// frames it makes, is the best explained as one. Each frame is a run of bytes
// from a flag to the next flag, both included, with something between them. Two
// flags in a row bound nothing: of the three or more that may lie between two
// frames, the first closes one, the last opens the next, and the others, and the
// bytes before the first flag and after the last one, are in no frame, so the
// frames do not cover the capture. (A flag that two frames share belongs to the
// first.) A byte counts as the flag when
//   - at least a quarter of its occurrences are followed by another one, or the
//     capture shows its stuffing (an escape byte that is followed, at least three
//     times and every time, by one of two codes, each of them at least once: the
//     flag and the escape with bit 5 flipped, as RFC 1662 has it, or the C0 DB DC
//     DD of SLIP);
//   - it bounds at least min_flag_frames frames;
//   - at most 4 distinct bytes start the frames (the byte after the flag), and
//     at least 95% of the frames start with one of them;
//   - at least 95% of the frames are within a factor of 4 of the median size.
// The flag with the most frames wins, and the lower byte if they tie. Nothing
// found (found false) when an event holds more or fewer than one byte, or no byte
// qualifies. Timing plays no part.
Segmentation segment_by_flags(const Capture& capture, const SegmentationOptions& options);

// Cuts a capture of single-byte events into frames that start with a sync byte
// and say how long they are (a kind of Contiguous). For each byte that occurs at
// least min_sync_frames times (a run of the same byte counts once, at its first:
// FF FF is one sync byte), each place and width of a length in the 8 bytes after
// it (1 byte, or 2 in either order), and each of the three most frequent distances
// between a sync byte and the next one beyond the length it reads (the overhead,
// which is the rest of the frame), the stage follows the chain of
// frames: from a sync byte to where its length says the frame ends, which has to
// be another sync byte (or the end), and after a break at the next sync byte.
// The chain is the framing when it has at least min_sync_frames frames, at most
// one break in 50 of them, and covers at least 90% of the bytes. A frame cut
// short by the end of the capture is in no frame, nor are the bytes that the
// chain did not follow.
//
// Candidates that explain the capture the same way are told apart by rules, since
// the bytes cannot: one whose lengths are not all the same over one of a fixed
// size; then the one that the most different bytes come before, so that a frame
// starts where the bytes before it stop being the same (UBX is found at 0xB5 and
// not at the 0x62 that follows it, whose byte before is always 0xB5); then, for
// lengths that vary, the later length, which is the sync that comes earliest in
// the frame, and the narrower (a 16-bit length whose high byte is always 0 is
// found as 1 byte); and for a fixed size, the one with more frames. The first of
// the candidates, the lower byte, wins a tie. A frame that ends with a byte that
// is always the same is cut so that the byte starts the next frame. Nothing
// found (found false) when an event holds more or fewer than one byte, or no
// candidate is the framing.
Segmentation segment_by_sync(const Capture& capture, const SegmentationOptions& options);

// Cuts a capture of single-byte events that is text into its lines (a kind of
// Terminated, the delimiter 0x0A): every frame is a run of bytes up to and
// including a line feed, so a carriage return before it is in the frame. The
// capture is text when at least 95% of its bytes are printable ASCII, tab, carriage
// return or line feed. A line of nothing (a line feed, or a carriage return and a
// line feed) is no frame, and the bytes after the last line feed, which end with
// none, are in no frame. The lines are the frames when there are at least
// min_line_frames of them, they start with at most 4 distinct bytes (95% of them),
// and 95% are within a factor of 4 of the median size, as for flags. Nothing found
// (found false) when an event holds more or fewer than one byte, or those do not
// hold.
Segmentation segment_by_lines(const Capture& capture, const SegmentationOptions& options);

// The way the pipeline cuts: by flags if the capture has them; else by gaps, and
// by a sync byte and a length, or by lines if it is text, where there are no gaps
// or where that cuts at every place the gaps do and in more (frames that come in
// bursts); else by whichever finds something. Lines come before a sync byte and a
// length: text that has lines is lines, since a chain of frames that start with one
// byte and say their length can be found in text that is regular enough, with no
// break in it, and the bytes do not tell that from the real one.
Segmentation segment_frames(const Capture& capture, const SegmentationOptions& options);

// The frames of a segmentation as a capture of their own: one event for each,
// holding what the frame holds, in the order of the segmentation. A flagged frame
// (a kind of Flagged) holds what is between its flags: the flags are taken off
// (a frame that shares its opening flag with the one before has no opening flag
// to take) and, when the segmentation says `escaped`, the stuffing is undone, so
// that an escape and the code after it are the one byte they stand for. An
// escape that is not followed by a code is kept as it is, and so is the byte
// after it. The frames of any other kind are as they are, their events joined.
// An event has the channel and the time of the first event of its frame. It is
// the frame as the later stages read it: the bytes of the protocol, which is
// what a checksum is taken over and what a field is of.
Capture frame_contents(const Capture& capture, const Segmentation& segmentation);

// The bytes of a frame, in order, as one run. Throws std::out_of_range for a
// frame that is not inside the capture.
std::vector<std::uint8_t> frame_bytes(const Capture& capture, const FrameSpan& frame);

// How many bytes a frame holds, and the frames of a segmentation that hold
// exactly `size_bytes` of them, in capture order.
std::uint64_t          frame_size(const Capture& capture, const FrameSpan& frame);
std::vector<FrameSpan> frames_of_size(const Capture& capture, const Segmentation& segmentation,
                                      std::uint64_t size_bytes);

} // namespace bw

#endif // BW_SEGMENTATION_H
