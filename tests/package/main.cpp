// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Link check for the installed package: two real Modbus RTU requests go in,
// CRC-16/MODBUS, whole frame, little-endian has to come out. A one-line capture
// is read as well, a model is built and scored, a synthetic capture is made and analysed, so that
// the capture, model, evaluation, protocol, pipeline and exporter headers are checked as C++11 and linked.

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/capture.h"
#include "bw/crc_search.h"
#include "bw/evaluate.h"
#include "bw/kaitai.h"
#include "bw/model.h"
#include "bw/protocol.h"

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

    bw::Model model;
    const std::size_t type = model.add_message_type("m");
    bw::FieldInfo field;
    field.kind     = bw::FieldKind::Enum;
    field.bit_size = 8;
    model.add_field(type, "a", field, "");
    const bw::FieldScore score = bw::score_fields(model, type, model, type);
    if (score.exact_fields != 1 || !score.checksum_match) {
        std::fprintf(stderr, "the packaged model and evaluation code scored the wrong thing\n");
        return 1;
    }

    // A generator is in the package too, and runs.
    bw::GenerateOptions generate;
    generate.frames = 2;
    const bw::Dataset dataset = bw::generate_protocol("modbus-rtu", generate);
    if (dataset.frame_count() != 2 || dataset.capture().event_count() != 16) {
        std::fprintf(stderr, "the packaged generator made the wrong capture\n");
        return 1;
    }

    // So is the pipeline: the checksum comes out of a synthetic capture as the last field of the model.
    generate.frames = 20;
    const bw::Analysis analysis =
        bw::analyze(bw::generate_protocol("modbus-rtu", generate).capture(), bw::AnalyzeOptions());
    if (analysis.type_count() != 1 ||
        analysis.model().field_detail(0, analysis.model().field_count(0) - 1) != "CRC-16/MODBUS") {
        std::fprintf(stderr, "the packaged pipeline found the wrong model\n");
        return 1;
    }

    // ...and a Kaitai definition of it is written.
    if (bw::export_kaitai(analysis.model(), 0, "type0").find("  - id: checksum\n    type: u2le\n") ==
        std::string::npos) {
        std::fprintf(stderr, "the packaged exporter wrote the wrong definition\n");
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
