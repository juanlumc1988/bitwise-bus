// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/messages.h"

#include <algorithm>
#include <map>
#include <set>

namespace bw {

namespace {

typedef std::vector<std::uint8_t> Bytes;

// Offsets below this are looked at for a length: a length is in the header.
const std::uint32_t kMaxLengthOffset = 16;

std::uint64_t value_at(const Bytes& frame, std::uint32_t offset, std::uint32_t bytes, bool big_endian) {
    std::uint64_t value = 0;
    for (std::uint32_t k = 0; k < bytes; ++k) {
        const std::uint32_t index = big_endian ? offset + k : offset + bytes - 1 - k;
        value = (value << 8) | frame[index];
    }
    return value;
}

// The frames of the sizes there are enough of, and their sizes.
struct Sized {
    std::vector<std::uint64_t>            sizes;
    std::vector<std::vector<std::size_t> > frames;       // for each size, the indexes of its frames
};

bool length_holds(const std::vector<Bytes>& all, const Sized& sized, const LengthField& length) {
    for (std::size_t g = 0; g < sized.sizes.size(); ++g) {
        for (std::size_t i = 0; i < sized.frames[g].size(); ++i) {
            const Bytes& frame = all[sized.frames[g][i]];
            const std::int64_t value =
                static_cast<std::int64_t>(value_at(frame, length.offset, length.bytes, length.big_endian));
            if (static_cast<std::int64_t>(frame.size()) - value != length.adjust) {
                return false;
            }
        }
    }
    return true;
}

bool find_length(const std::vector<Bytes>& all, const Sized& sized, LengthField* length) {
    const std::uint64_t smallest = sized.sizes.front();
    const Bytes&        first    = all[sized.frames.front().front()];
    for (std::uint32_t offset = 0; offset < kMaxLengthOffset; ++offset) {
        for (std::uint32_t bytes = 1; bytes <= 2; ++bytes) {
            for (int order = 0; order < (bytes == 1 ? 1 : 2); ++order) {
                if (offset + bytes > smallest) {
                    continue;
                }
                LengthField candidate;
                candidate.offset     = offset;
                candidate.bytes      = bytes;
                candidate.big_endian = order == 1;
                candidate.adjust     = static_cast<std::int64_t>(first.size()) -
                    static_cast<std::int64_t>(value_at(first, offset, bytes, candidate.big_endian));
                // The frame is at least as long as the field that says how long it is.
                if (candidate.adjust < static_cast<std::int64_t>(offset + bytes)) {
                    continue;
                }
                if (length_holds(all, sized, candidate)) {
                    *length = candidate;
                    return true;
                }
            }
        }
    }
    return false;
}

} // namespace

MessageKinds find_message_kinds(const Capture& capture, const Segmentation& segmentation,
                                std::uint32_t min_frames) {
    MessageKinds out;
    const std::size_t count = segmentation.frame_count();
    out.frame_kind.assign(count, -1);

    std::vector<Bytes>                                  all(count);
    std::map<std::uint64_t, std::vector<std::size_t> > by_size;
    for (std::size_t i = 0; i < count; ++i) {
        all[i] = frame_bytes(capture, segmentation.frame(i));
        by_size[all[i].size()].push_back(i);
    }
    Sized sized;
    for (std::map<std::uint64_t, std::vector<std::size_t> >::const_iterator it = by_size.begin();
         it != by_size.end(); ++it) {
        if (it->first > 0 && it->second.size() >= min_frames && !it->second.empty()) {
            sized.sizes.push_back(it->first);
            sized.frames.push_back(it->second);
        }
    }
    // Two sizes at least, or any byte that does not change would be the length.
    if (sized.sizes.size() < 2 || !find_length(all, sized, &out.length)) {
        return out;
    }
    out.length.evidence_bits = static_cast<std::uint32_t>((sized.sizes.size() - 1) * 8 * out.length.bytes);

    // The key: before the end of the header and trailer, where every size has one value and the
    // sizes do not all have the same.
    const std::uint64_t limit = std::min<std::uint64_t>(static_cast<std::uint64_t>(out.length.adjust),
                                                        sized.sizes.front());
    for (std::uint32_t p = 0; p < limit; ++p) {
        if (p >= out.length.offset && p < out.length.offset + out.length.bytes) {
            continue;
        }
        std::set<std::uint8_t> values;
        bool                   constant = true;
        for (std::size_t g = 0; g < sized.sizes.size() && constant; ++g) {
            const std::uint8_t first = all[sized.frames[g].front()][p];
            values.insert(first);
            for (std::size_t i = 0; i < sized.frames[g].size() && constant; ++i) {
                constant = all[sized.frames[g][i]][p] == first;
            }
        }
        if (constant && values.size() >= 2) {
            out.key_offsets.push_back(p);
        }
    }
    if (out.key_offsets.empty()) {
        return out;
    }
    out.found = true;

    // The classes: the sizes with the same bytes at the key.
    std::map<Bytes, std::vector<std::uint64_t> > by_key;
    for (std::size_t g = 0; g < sized.sizes.size(); ++g) {
        Bytes key;
        for (std::size_t k = 0; k < out.key_offsets.size(); ++k) {
            key.push_back(all[sized.frames[g].front()][out.key_offsets[k]]);
        }
        by_key[key].push_back(sized.sizes[g]);
    }

    // The frames of each class: those of its sizes, and the rare ones whose key is its key and whose
    // length says how long they are. A class is a kind when its frames have two sizes or more.
    std::map<Bytes, std::size_t> class_of_key;
    std::vector<std::set<std::uint64_t> > sizes_of;
    std::vector<Bytes>                    keys;
    for (std::map<Bytes, std::vector<std::uint64_t> >::const_iterator it = by_key.begin();
         it != by_key.end(); ++it) {
        class_of_key[it->first] = keys.size();
        keys.push_back(it->first);
        sizes_of.push_back(std::set<std::uint64_t>());
    }
    std::vector<std::int64_t> class_of_frame(count, -1);
    for (std::size_t i = 0; i < count; ++i) {
        const Bytes& frame = all[i];
        if (frame.size() < limit || frame.size() < out.length.offset + out.length.bytes) {
            continue;
        }
        Bytes key;
        for (std::size_t k = 0; k < out.key_offsets.size(); ++k) {
            key.push_back(frame[out.key_offsets[k]]);
        }
        const std::map<Bytes, std::size_t>::const_iterator found = class_of_key.find(key);
        if (found == class_of_key.end()) {
            continue;
        }
        const std::vector<std::uint64_t>& own = by_key[key];
        const bool of_its_sizes = std::find(own.begin(), own.end(), frame.size()) != own.end();
        const std::int64_t said = static_cast<std::int64_t>(
            value_at(frame, out.length.offset, out.length.bytes, out.length.big_endian)) + out.length.adjust;
        if (of_its_sizes || said == static_cast<std::int64_t>(frame.size())) {
            class_of_frame[i] = static_cast<std::int64_t>(found->second);
            sizes_of[found->second].insert(frame.size());
        }
    }
    std::vector<std::int32_t> kind_of_class(keys.size(), -1);
    for (std::size_t c = 0; c < keys.size(); ++c) {
        if (sizes_of[c].size() >= 2) {
            MessageKind kind;
            kind.sizes = std::vector<std::uint32_t>(sizes_of[c].begin(), sizes_of[c].end());
            kind.key   = keys[c];
            kind_of_class[c] = static_cast<std::int32_t>(out.kinds.size());
            out.kinds.push_back(kind);
        }
    }
    for (std::size_t i = 0; i < count; ++i) {
        if (class_of_frame[i] >= 0 && kind_of_class[static_cast<std::size_t>(class_of_frame[i])] >= 0) {
            out.frame_kind[i] = kind_of_class[static_cast<std::size_t>(class_of_frame[i])];
            ++out.kinds[static_cast<std::size_t>(out.frame_kind[i])].frames;
        }
    }
    return out;
}

} // namespace bw
