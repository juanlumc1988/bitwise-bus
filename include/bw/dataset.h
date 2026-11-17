// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// A synthetic capture together with its answer: what a generator hands back.
//
// The capture is what a stage is given. The model is what it was generated
// from, and the frames are where each one of them starts and ends in the
// capture. Score what a stage found against these with score_segmentation()
// and score_fields() in bw/evaluate.h.
//
// A Dataset is checked when it is built, so a test never has to wonder whether
// the truth it scores against is itself consistent.

#ifndef BW_DATASET_H
#define BW_DATASET_H

#include <cstddef>
#include <cstdint>
#include <vector>

#include "bw/capture.h"
#include "bw/evaluate.h"
#include "bw/model.h"

namespace bw {

class Dataset {
public:
    // No events, no message types, no frames.
    Dataset();

    // `frames` and `message_types` have one entry per true frame: where it is,
    // and which message type of the model it is. Throws std::invalid_argument
    // unless every frame has at least one event and lies inside the capture,
    // the frames are in order and do not overlap, and each message type is one
    // the model has.
    Dataset(const Capture& capture, const Model& model,
            const std::vector<FrameSpan>& frames,
            const std::vector<std::uint32_t>& message_types);

    Capture capture() const;
    Model   model() const;

    std::size_t   frame_count() const;
    FrameSpan     frame(std::size_t index) const;                // throws std::out_of_range
    std::uint32_t frame_message_type(std::size_t index) const;   // throws std::out_of_range
    std::vector<FrameSpan> frames() const;                       // all of them, in order

private:
    Capture                    capture_;
    Model                      model_;
    std::vector<FrameSpan>     frames_;
    std::vector<std::uint32_t> message_types_;
};

} // namespace bw

#endif // BW_DATASET_H
