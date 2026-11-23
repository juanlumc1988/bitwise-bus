// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The pipeline, from a capture to a model: segmentation (stage 3), then for the
// frames of each size a checksum search (stage 2), field discovery (stage 4)
// and field typing (stage 5). Each stage is a function of its own over value
// types, and this composes them; `bitwise analyze` is this and a printer.
//
// The answer is a Model, the same type a generator's ground truth is, so the
// evaluation harness can score it. Whatever the stages could not tell is not in
// it: no framing found means a model with no message types, a size with fewer
// frames than FieldOptions::min_frames has no message type, and a field with
// no structure found is a Payload. The report next to the model says what was
// seen and how much evidence there is.
//
// Message types are, for now, frame sizes, named type0, type1... in order of
// how many frames each has (most first, the smaller size first on a tie). The
// fields of a type are named field_N after the byte offset N they start at, and
// the checksum is "checksum".
//
// The shape of this API follows the rule in docs/roadmap.md: plain structs,
// the collections behind a class.

#ifndef BW_ANALYZE_H
#define BW_ANALYZE_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "bw/capture.h"
#include "bw/checksum.h"
#include "bw/fields.h"
#include "bw/model.h"
#include "bw/segmentation.h"

namespace bw {

struct AnalyzeOptions {
    SegmentationOptions segmentation;
    FieldOptions        fields;
};

// What stage 2 saw in the frames of one message type.
struct MessageTypeReport {
    std::uint32_t   frame_bytes = 0;
    std::uint32_t   frames      = 0;
    ChecksumFinding checksum;
};

struct AnalysisInfo {
    std::uint64_t    events         = 0;
    std::uint64_t    bytes          = 0;
    std::uint64_t    frames         = 0;    // as segmentation cut them
    std::uint64_t    ignored_frames = 0;    // those of a size with too few frames to say anything
    SegmentationInfo segmentation;
};

class Analysis {
public:
    // Nothing found.
    Analysis();

    // `reports` has one entry per message type of the model; throws
    // std::invalid_argument if it does not.
    Analysis(const AnalysisInfo& info, const Segmentation& segmentation, const Model& model,
             const std::vector<MessageTypeReport>& reports);

    AnalysisInfo info() const;
    Segmentation segmentation() const;
    Model        model() const;

    std::size_t       type_count() const;
    MessageTypeReport type_report(std::size_t message_type) const;   // throws std::out_of_range

private:
    AnalysisInfo                   info_;
    Segmentation                   segmentation_;
    Model                          model_;
    std::vector<MessageTypeReport> reports_;
};

// Segments with segment_frames(): by flags, by a sync byte and a length, by lines, or by gaps.
Analysis analyze(const Capture& capture, const AnalyzeOptions& options);

// The same from frames that are already cut, whatever cut them: stage 3 is
// not run, and the segmentation is taken as it is. It is how a stage after
// segmentation is measured on its own, with the frames of a generator's truth,
// and how frames that something else found (a delimiter, a length) can be
// analysed. The model's framing is what the segmentation says cut the frames:
// the idle gap (idle_gap_ns is not 0), a flag (a kind of Flagged, and the
// byte), lines of text (a kind of Terminated, and the byte) or frames that
// follow one another (a kind of Contiguous); unknown otherwise. A segmentation that
// says it found nothing (`found` false) is not analysed.
Analysis analyze_frames(const Capture& capture, const Segmentation& segmentation,
                        const AnalyzeOptions& options);

// What `bitwise analyze` prints: one line for each thing the stages found, then
// the model as describe_model() prints it. Stable, so that tests can compare it.
std::string describe_analysis(const Analysis& analysis);

} // namespace bw

#endif // BW_ANALYZE_H
