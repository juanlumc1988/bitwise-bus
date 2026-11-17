// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/checksum.h"

#include <limits>
#include <stdexcept>

#include "bw/catalog.h"
#include "bw/crc_search.h"

namespace bw {

namespace {

std::uint32_t saturate(std::uint64_t value) {
    const std::uint64_t max = std::numeric_limits<std::uint32_t>::max();
    return static_cast<std::uint32_t>(value > max ? max : value);
}

} // namespace

ChecksumFinding find_checksum(const Capture& capture, const Segmentation& segmentation,
                              std::uint32_t size_bytes) {
    std::vector<Frame> frames;
    const std::vector<FrameSpan> spans = frames_of_size(capture, segmentation, size_bytes);
    for (std::size_t i = 0; i < spans.size(); ++i) {
        Frame frame;
        frame.bytes = frame_bytes(capture, spans[i]);
        frames.push_back(frame);
    }

    ChecksumFinding finding;
    finding.frames = saturate(frames.size());
    if (frames.empty()) {
        return finding;
    }

    const SearchReport report = search(frames, SearchOptions());
    finding.distinct_frames = saturate(report.distinct_frames);
    finding.candidates      = saturate(report.candidates.size());
    finding.truncated       = report.truncated;
    finding.evidence_bits   = report.evidence_bits;
    if (report.confident()) {
        const Candidate& only = report.candidates[0];
        finding.found        = true;
        finding.header_skip  = saturate(only.layout.header_skip);
        finding.trailer_skip = saturate(only.layout.trailer_skip);
        finding.width_bits   = only.layout.width;
        finding.byte_order   = only.layout.width <= 8 ? ByteOrder::NotApplicable
                             : only.layout.big_endian ? ByteOrder::Big : ByteOrder::Little;
        finding.algorithm    = saturate(static_cast<std::uint64_t>(only.spec - catalog()));
    }
    return finding;
}

std::string checksum_algorithm_name(std::uint32_t index) {
    if (index >= catalog_size()) {
        throw std::out_of_range("checksum algorithm index out of range");
    }
    return catalog()[index].name;
}

} // namespace bw
