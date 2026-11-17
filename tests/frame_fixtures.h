// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Frames the stage tests build by hand: a capture made of given frames, a
// small random number generator and a CRC of their own, so that a test of a
// stage does not rest on the code the stage uses.

#ifndef BW_TESTS_FRAME_FIXTURES_H
#define BW_TESTS_FRAME_FIXTURES_H

#include <cstdint>
#include <vector>

#include "bw/capture.h"

namespace fixtures {

typedef std::vector<std::uint8_t> Bytes;

// splitmix64: the same generator as the protocol generators, written again.
class Random {
public:
    explicit Random(std::uint64_t seed) : state_(seed) {}
    std::uint64_t next() {
        state_ += 0x9E3779B97F4A7C15ULL;
        std::uint64_t z = state_;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    std::uint8_t byte() { return static_cast<std::uint8_t>(next() & 0xFF); }

private:
    std::uint64_t state_;
};

// CRC-16/MODBUS, bit by bit: polynomial 0xA001 reflected, initial value 0xFFFF.
inline std::uint16_t crc16_modbus(const Bytes& data, std::size_t from, std::size_t to) {
    std::uint16_t crc = 0xFFFF;
    for (std::size_t i = from; i < to; ++i) {
        crc = static_cast<std::uint16_t>(crc ^ data[i]);
        for (int bit = 0; bit < 8; ++bit) {
            crc = (crc & 1u) ? static_cast<std::uint16_t>((crc >> 1) ^ 0xA001u)
                             : static_cast<std::uint16_t>(crc >> 1);
        }
    }
    return crc;
}

// A capture of one-byte events: 1000 ns between the bytes of a frame and
// 100000 ns between one frame and the next, which segmentation cuts exactly.
inline bw::Capture capture_of(const std::vector<Bytes>& frames) {
    bw::Capture capture;
    std::int64_t now = 0;
    for (std::size_t f = 0; f < frames.size(); ++f) {
        for (std::size_t i = 0; i < frames[f].size(); ++i) {
            bw::EventInfo info;
            info.has_time = true;
            info.time_ns  = now;
            capture.add_event(info, Bytes(1, frames[f][i]));
            now += 1000;
        }
        now += 99000;
    }
    return capture;
}

} // namespace fixtures

#endif // BW_TESTS_FRAME_FIXTURES_H
