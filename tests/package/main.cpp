// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Link check for the installed package: two real Modbus RTU requests go in,
// CRC-16/MODBUS, whole frame, little-endian has to come out. A one-line capture
// is read as well, so the capture header is checked as C++11 and linked.

#include <cstdio>
#include <cstring>
#include <vector>

#include "bw/capture.h"
#include "bw/crc_search.h"

int main() {
    static const bw::u8 a[] = {0x01, 0x03, 0x00, 0x00, 0x00, 0x0A, 0xC5, 0xCD};
    static const bw::u8 b[] = {0x01, 0x04, 0x00, 0x00, 0x00, 0x01, 0x31, 0xCA};

    std::vector<bw::Frame> frames(2);
    frames[0].bytes.assign(a, a + sizeof(a));
    frames[1].bytes.assign(b, b + sizeof(b));

    // The capture header has to be plain C++11 too, and its code has to be in the package.
    const bw::Capture capture = bw::parse_capture_csv("time_ns,data\n5,0a 0b\n");
    if (capture.event_count() != 1 || capture.event_size(0) != 2) {
        std::fprintf(stderr, "the packaged capture reader read the wrong thing\n");
        return 1;
    }

    const bw::SearchReport report = bw::search(frames);
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        const bw::Candidate& c = report.candidates[i];
        if (std::strcmp(c.spec->name, "CRC-16/MODBUS") == 0 &&
            c.layout.header_skip == 0 && c.layout.trailer_skip == 0 &&
            !c.layout.big_endian) {
            std::printf("found %s after %u bits of evidence\n", c.spec->name,
                        report.evidence_bits);
            return 0;
        }
    }
    std::fprintf(stderr, "CRC-16/MODBUS not found among %zu candidates\n",
                 report.candidates.size());
    return 1;
}
