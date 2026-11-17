// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/dataset.h"

#include <stdexcept>
#include <string>

namespace bw {

Dataset::Dataset() {}

Dataset::Dataset(const Capture& capture, const Model& model,
                 const std::vector<FrameSpan>& frames,
                 const std::vector<std::uint32_t>& message_types)
    : capture_(capture), model_(model), frames_(frames), message_types_(message_types) {
    if (frames.size() != message_types.size()) {
        throw std::invalid_argument("there are " + std::to_string(frames.size()) +
                                    " frames and " + std::to_string(message_types.size()) +
                                    " message types");
    }

    const std::uint64_t events    = capture.event_count();
    std::uint64_t       next_free = 0;          // the first event no frame has claimed
    for (std::size_t i = 0; i < frames.size(); ++i) {
        const std::string who = "frame " + std::to_string(i);
        const FrameSpan&  f   = frames[i];
        if (f.event_count == 0) {
            throw std::invalid_argument(who + " has no events");
        }
        if (f.first_event < next_free) {
            throw std::invalid_argument(who + " overlaps the frame before it, or is out of order");
        }
        if (f.first_event > events || f.event_count > events - f.first_event) {
            throw std::invalid_argument(who + " runs outside the capture, which has " +
                                        std::to_string(events) + " events");
        }
        if (message_types[i] >= model.message_type_count()) {
            throw std::invalid_argument(who + " is of message type " +
                                        std::to_string(message_types[i]) + " and the model has " +
                                        std::to_string(model.message_type_count()));
        }
        next_free = f.first_event + f.event_count;
    }
}

Capture Dataset::capture() const {
    return capture_;
}

Model Dataset::model() const {
    return model_;
}

std::size_t Dataset::frame_count() const {
    return frames_.size();
}

FrameSpan Dataset::frame(std::size_t index) const {
    return frames_.at(index);
}

std::uint32_t Dataset::frame_message_type(std::size_t index) const {
    return message_types_.at(index);
}

std::vector<FrameSpan> Dataset::frames() const {
    return frames_;
}

} // namespace bw
