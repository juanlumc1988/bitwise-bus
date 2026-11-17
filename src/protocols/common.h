// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// What the generators have in common. Deliberately not shared with the
// inference stages: see bw/protocol.h.

#ifndef BW_PROTOCOLS_COMMON_H
#define BW_PROTOCOLS_COMMON_H

#include <cstdint>
#include <stdexcept>

#include "bw/protocol.h"

namespace bw {

// splitmix64: a few lines, every operation defined on every platform, and the
// same sequence for the same seed wherever it runs. The standard library's
// distributions are not, so nothing here uses them.
class Rng {
public:
    explicit Rng(std::uint64_t seed) : state_(seed) {}

    std::uint64_t next() {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }

    // 0 to n-1. The bias of the remainder is far too small to matter for the
    // small n used here.
    std::uint64_t below(std::uint64_t n) { return next() % n; }

private:
    std::uint64_t state_;
};

inline void check_generate_options(const GenerateOptions& options) {
    if (options.frames > 100000) {
        throw std::invalid_argument("frames is at most 100000");
    }
    if (options.jitter_permille > 500) {
        throw std::invalid_argument("jitter_permille is at most 500");
    }
}

} // namespace bw

#endif // BW_PROTOCOLS_COMMON_H
