// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
//   bitwise crc-catalog         list the algorithms that will be tried
//   bitwise crc-find FILE...    work out which one a set of frames uses

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "bw/crc_search.h"

namespace {

int usage() {
    std::fprintf(stderr,
        "bitwise -- infer undocumented bus protocols from captures\n"
        "\n"
        "usage:\n"
        "  bitwise crc-catalog\n"
        "  bitwise crc-find FILE [FILE...] [--header-skip N] [--trailer-skip N]\n"
        "\n"
        "Each FILE is one captured frame, raw bytes. Give it as many frames\n"
        "as you have: a single narrow checksum proves nothing, and the tool\n"
        "will say so rather than pick a winner.\n");
    return 2;
}

bool read_frame(const char* path, bw::Frame* out) {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        std::fprintf(stderr, "bitwise: cannot open %s\n", path);
        return false;
    }
    bw::u8      chunk[4096];
    std::size_t n;
    while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
        out->bytes.insert(out->bytes.end(), chunk, chunk + n);
    }
    const bool bad = std::ferror(f) != 0;
    std::fclose(f);
    return !bad;
}

int cmd_catalog() {
    std::printf("%-20s %6s  %-18s %-18s %-5s %-6s %s\n",
                "name", "width", "poly", "init", "refin", "refout", "xorout");
    for (std::size_t i = 0; i < bw::catalog_size(); ++i) {
        const bw::CrcSpec& s = bw::catalog()[i];
        std::printf("%-20s %6u  0x%-16llX 0x%-16llX %-5s %-6s 0x%llX\n",
                    s.name, s.width,
                    (unsigned long long)s.poly, (unsigned long long)s.init,
                    s.refin ? "yes" : "no", s.refout ? "yes" : "no",
                    (unsigned long long)s.xorout);
    }
    std::printf("\n%zu algorithms. Widths that are not a multiple of eight "
                "(CAN, CAN-FD)\nare computed correctly but cannot yet be "
                "located in a byte-aligned\nframe, so crc-find skips them.\n",
                bw::catalog_size());
    return 0;
}

int cmd_find(const std::vector<std::string>& paths,
             const bw::SearchOptions& options) {
    if (paths.empty()) {
        std::fprintf(stderr, "bitwise: crc-find needs at least one frame\n");
        return 2;
    }

    std::vector<bw::Frame> frames;
    for (std::size_t i = 0; i < paths.size(); ++i) {
        bw::Frame frame;
        if (!read_frame(paths[i].c_str(), &frame)) {
            return 1;
        }
        if (frame.bytes.empty()) {
            std::fprintf(stderr, "bitwise: %s is empty\n", paths[i].c_str());
            return 1;
        }
        frames.push_back(frame);
    }

    const bw::SearchReport report = bw::search(frames, options);

    std::printf("%zu frames, %zu algorithms x %zu layouts tried\n\n",
                report.frames, report.specs_tried, report.layouts_tried);

    if (report.candidates.empty()) {
        std::printf("No CRC in the catalogue explains these frames.\n\n"
                    "That could mean the checksum is not a catalogued CRC, or\n"
                    "that it covers a range outside the skips tried. Widen\n"
                    "them with --header-skip and --trailer-skip.\n");
        return 1;
    }

    std::printf("%-20s %-6s %-8s %-8s %s\n",
                "algorithm", "width", "header", "trailer", "byte order");
    for (std::size_t i = 0; i < report.candidates.size(); ++i) {
        const bw::Candidate& c = report.candidates[i];
        std::printf("%-20s %-6u %-8zu %-8zu %s\n",
                    c.spec->name, c.layout.width, c.layout.header_skip,
                    c.layout.trailer_skip,
                    c.layout.big_endian ? "big-endian" : "little-endian");
    }

    if (report.truncated) {
        std::printf("\n...and more: the list above is capped. Whatever else\n"
                    "matched is not shown, so do not read it as complete.\n");
    }

    std::printf("\n%u bits of evidence.\n", report.evidence_bits);
    if (report.confident()) {
        std::printf("One candidate, comfortably more evidence than chance "
                    "could produce.\n");
        return 0;
    }
    if (report.candidates.size() > 1) {
        std::printf("Several candidates fit. Capture more frames to tell "
                    "them apart.\n");
    } else {
        std::printf("Only one candidate, but on thin evidence -- a wrong "
                    "answer could\nfit this well by chance. Capture more "
                    "frames before trusting it.\n");
    }
    return 0;
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        return usage();
    }

    const std::string command = argv[1];
    if (command == "-h" || command == "--help" || command == "help") {
        usage();
        return 0;
    }
    if (command == "crc-catalog") {
        return cmd_catalog();
    }
    if (command != "crc-find") {
        std::fprintf(stderr, "bitwise: unknown command '%s'\n", command.c_str());
        return usage();
    }

    bw::SearchOptions        options;
    std::vector<std::string> paths;
    for (int i = 2; i < argc; ++i) {
        const std::string arg = argv[i];
        const bool has_value = (i + 1 < argc);
        if (arg == "--header-skip" && has_value) {
            options.max_header_skip = (std::size_t)std::strtoul(argv[++i], nullptr, 10);
        } else if (arg == "--trailer-skip" && has_value) {
            options.max_trailer_skip = (std::size_t)std::strtoul(argv[++i], nullptr, 10);
        } else if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "bitwise: unknown option '%s'\n", arg.c_str());
            return usage();
        } else {
            paths.push_back(arg);
        }
    }
    return cmd_find(paths, options);
}
