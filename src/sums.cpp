// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/sums.h"

#include <cstring>

namespace bw {

namespace {

const SumSpec kSums[] = {
    { "XOR-8",         8  },
    { "SUM-8",         8  },
    { "SUM-8/NEGATED", 8  },
    { "FLETCHER-8",    16 },
    { "FLETCHER-16",   16 }
};

} // namespace

const SumSpec* sums() {
    return kSums;
}

std::size_t sum_count() {
    return sizeof(kSums) / sizeof(kSums[0]);
}

const SumSpec* sum_find(const char* name) {
    if (name == nullptr) {
        return nullptr;
    }
    for (std::size_t i = 0; i < sum_count(); ++i) {
        if (std::strcmp(kSums[i].name, name) == 0) {
            return &kSums[i];
        }
    }
    return nullptr;
}

u64 sum_compute(const SumSpec& spec, const u8* data, std::size_t len) {
    u32 a = 0;
    u32 b = 0;
    u32 x = 0;
    const bool fletcher16 = std::strcmp(spec.name, "FLETCHER-16") == 0;
    const u32  modulus    = fletcher16 ? 255u : 256u;
    for (std::size_t i = 0; i < len; ++i) {
        x ^= data[i];
        a = (a + data[i]) % modulus;
        b = (b + a) % modulus;
    }
    if (fletcher16 || std::strcmp(spec.name, "FLETCHER-8") == 0) {
        return (static_cast<u64>(b) << 8) | a;
    }
    if (std::strcmp(spec.name, "XOR-8") == 0) {
        return x;
    }
    if (std::strcmp(spec.name, "SUM-8") == 0) {
        return a;
    }
    if (std::strcmp(spec.name, "SUM-8/NEGATED") == 0) {
        return (256u - a) & 0xFFu;
    }
    return 0;                                  // not one of the list
}

} // namespace bw
