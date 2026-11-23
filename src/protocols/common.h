// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// What the generators have in common. Deliberately not shared with the
// inference stages: see bw/protocol.h.

#ifndef BW_PROTOCOLS_COMMON_H
#define BW_PROTOCOLS_COMMON_H

#include <cstdint>
#include <stdexcept>
#include <vector>

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

// Adds `bytes` to a capture as one event each. Byte k is due k character times
// after `start`, plus the timing noise: for each byte, always, one draw of the
// generator, so that the same seed gives the same frames whatever the noise.
// Returns when the byte after the last one is due.
inline std::uint64_t emit_bytes(Capture* capture, std::uint32_t channel, std::uint64_t start,
                                std::uint64_t char_ns, std::uint64_t max_delay, Rng* rng,
                                const std::vector<std::uint8_t>& bytes) {
    for (std::size_t k = 0; k < bytes.size(); ++k) {
        const std::uint64_t draw  = rng->next();
        const std::uint64_t delay = (max_delay == 0) ? 0 : draw % max_delay;
        EventInfo info;
        info.has_time = true;
        info.time_ns  = static_cast<std::int64_t>(start + k * char_ns + delay);
        info.channel  = channel;
        capture->add_event(info, std::vector<std::uint8_t>(1, bytes[k]));
    }
    return start + bytes.size() * char_ns;
}

inline void put_le(std::vector<std::uint8_t>* out, std::uint64_t value, unsigned bytes) {
    for (unsigned i = 0; i < bytes; ++i) {
        out->push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xFF));
    }
}

// The bits of an IEEE 754 binary32 whose sign, exponent in [base, base + span)
// and mantissa are drawn: a float that is made of integers only, so that it is
// the same on every platform.
inline std::uint32_t random_float_bits(Rng* rng, unsigned base, unsigned span) {
    const std::uint32_t sign     = static_cast<std::uint32_t>(rng->below(2));
    const std::uint32_t exponent = base + static_cast<std::uint32_t>(rng->below(span));
    const std::uint32_t mantissa = static_cast<std::uint32_t>(rng->below(1u << 23));
    return (sign << 31) | (exponent << 23) | mantissa;
}

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
