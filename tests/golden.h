// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Reading a checked-in file, and saying where two byte strings first differ.

#ifndef BW_TESTS_GOLDEN_H
#define BW_TESTS_GOLDEN_H

#include <algorithm>
#include <fstream>
#include <iterator>
#include <sstream>
#include <string>

#include "doctest.h"

namespace golden {

// A file of tests/corpus, byte for byte.
inline std::string read_file(const std::string& name) {
    const std::string path = std::string(BW_CORPUS_DIR) + "/" + name;
    std::ifstream in(path.c_str(), std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

// "" when the two are the same bytes; otherwise where they first differ. Two
// captures that differ in a CR or a trailing space print as two identical
// pages, and a failure that cannot be read costs a round trip to the CI.
inline std::string first_difference(const std::string& actual, const std::string& expected) {
    const std::size_t common = std::min(actual.size(), expected.size());
    std::size_t       at     = 0;
    while (at < common && actual[at] == expected[at]) {
        ++at;
    }
    if (at == actual.size() && at == expected.size()) {
        return std::string();
    }
    std::ostringstream out;
    out << "sizes " << actual.size() << " and " << expected.size() << ", first difference at byte " << at;
    const char* names[2] = {"actual", "expected"};
    const std::string* sides[2] = {&actual, &expected};
    for (int k = 0; k < 2; ++k) {
        out << "; " << names[k] << " ";
        if (at < sides[k]->size()) {
            static const char digits[] = "0123456789abcdef";
            const unsigned char byte = static_cast<unsigned char>((*sides[k])[at]);
            out << "0x" << digits[byte >> 4] << digits[byte & 15];
        } else {
            out << "ends";
        }
    }
    return out.str();
}

} // namespace golden

#endif // BW_TESTS_GOLDEN_H
