// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
//   bitwise crc-catalog         list the algorithms that will be tried
//   bitwise crc-find FILE...    work out which one a set of frames uses
//   bitwise capture-info FILE   a first look at a capture file
//   bitwise protocols [NAME]    the known protocols, or the model of one
//   bitwise synth NAME          a synthetic capture of a known protocol
//   bitwise analyze FILE        infer the protocol of a capture
//   bitwise export FILE         the inferred protocol as a Kaitai Struct definition

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <stdexcept>
#include <string>
#include <vector>

#include "bw/analyze.h"
#include "bw/capture.h"
#include "bw/kaitai.h"
#include "bw/crc_search.h"
#include "bw/protocol.h"

namespace {

int usage() {
    std::fprintf(stderr,
        "bitwise -- infer undocumented bus protocols from captures\n"
        "\n"
        "usage:\n"
        "  bitwise crc-catalog\n"
        "  bitwise crc-find FILE [FILE...] [--header-skip N] [--trailer-skip N]\n"
        "  bitwise capture-info FILE\n"
        "  bitwise protocols [NAME]\n"
        "  bitwise synth NAME [--seed N] [--frames N] [--jitter-permille N]\n"
        "  bitwise analyze FILE [--min-gap-ratio N] [--min-frames N]\n"
        "  bitwise export FILE [--format kaitai] [--type N] [--id NAME] [--min-gap-ratio N] [--min-frames N]\n"
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

bool read_text_file(const char* path, std::string* out) {
    std::FILE* f = std::fopen(path, "rb");
    if (f == nullptr) {
        return false;
    }
    char        chunk[4096];
    std::size_t n;
    while ((n = std::fread(chunk, 1, sizeof(chunk), f)) > 0) {
        out->append(chunk, n);
    }
    const bool bad = std::ferror(f) != 0;
    std::fclose(f);
    return !bad;
}

unsigned long long ull(std::uint64_t v) { return static_cast<unsigned long long>(v); }
long long          sll(std::int64_t v)  { return static_cast<long long>(v); }

int cmd_capture_info(const std::vector<std::string>& paths) {
    if (paths.size() != 1) {
        std::fprintf(stderr, "bitwise: capture-info takes exactly one file\n");
        return 2;
    }
    std::string text;
    if (!read_text_file(paths[0].c_str(), &text)) {
        std::fprintf(stderr, "bitwise: cannot read %s\n", paths[0].c_str());
        return 1;
    }
    bw::Capture capture;
    try {
        capture = bw::parse_capture_csv(text);
    } catch (const bw::CaptureError& e) {
        std::fprintf(stderr, "bitwise: %s: %s\n", paths[0].c_str(), e.what());
        return 1;
    }

    const bw::CaptureStats stats = bw::capture_stats(capture);
    std::printf("%-10s %llu (%llu bytes)\n", "events", ull(stats.events), ull(stats.bytes));

    std::vector<std::uint64_t> per_channel(capture.channel_count(), 0);
    std::uint64_t              rx = 0, tx = 0, unknown = 0;
    for (std::size_t i = 0; i < capture.event_count(); ++i) {
        const bw::EventInfo info = capture.event(i);
        ++per_channel[info.channel];
        if (info.direction == bw::Direction::Rx)      ++rx;
        else if (info.direction == bw::Direction::Tx) ++tx;
        else                                          ++unknown;
    }
    std::string channels;
    std::size_t listed = 0;
    for (std::size_t c = 0; c < per_channel.size(); ++c) {
        if (per_channel[c] == 0) {
            continue;                 // the unnamed channel, when nothing is on it
        }
        const std::string name = capture.channel_name(static_cast<std::uint32_t>(c));
        channels += (listed++ ? ", " : "") + (name.empty() ? std::string("(unnamed)") : name) +
                    " (" + std::to_string(per_channel[c]) + ")";
    }
    if (listed == 0) {
        std::printf("%-10s none\n", "channels");
    } else {
        std::printf("%-10s %zu: %s\n", "channels", listed, channels.c_str());
    }
    std::printf("%-10s rx %llu, tx %llu, unknown %llu\n", "direction", ull(rx), ull(tx),
                ull(unknown));

    if (stats.timed_events == 0) {
        std::printf("%-10s none: no event has a timestamp\n", "time");
    } else {
        if (stats.timed_events < stats.events) {
            std::printf("%-10s %llu of %llu events have a timestamp\n", "time",
                        ull(stats.timed_events), ull(stats.events));
        }
        std::printf("%-10s first %lld ns, last %lld ns\n",
                    stats.timed_events < stats.events ? "" : "time",
                    sll(stats.first_time_ns), sll(stats.last_time_ns));
    }
    if (stats.interval_count > 0) {
        std::printf("%-10s %llu between timed events: min %llu ns, median %llu ns, max %llu ns\n",
                    "intervals", ull(stats.interval_count), ull(stats.min_interval_ns),
                    ull(stats.median_interval_ns), ull(stats.max_interval_ns));
    }
    return 0;
}

// A whole number, digits only, from 0 to `max`.
bool parse_unsigned(const std::string& text, std::uint64_t max, std::uint64_t* out) {
    if (text.empty()) {
        return false;
    }
    std::uint64_t value = 0;
    for (std::size_t i = 0; i < text.size(); ++i) {
        if (text[i] < '0' || text[i] > '9') {
            return false;
        }
        const std::uint64_t digit = static_cast<std::uint64_t>(text[i] - '0');
        if (value > (max - digit) / 10) {
            return false;
        }
        value = value * 10 + digit;
    }
    *out = value;
    return true;
}

int cmd_protocols(const std::vector<std::string>& args) {
    if (args.size() > 1) {
        std::fprintf(stderr, "bitwise: protocols takes at most one name\n");
        return 2;
    }
    try {
        if (args.empty()) {
            const std::vector<std::string> names = bw::protocol_names();
            for (std::size_t i = 0; i < names.size(); ++i) {
                std::printf("%-12s %s\n", names[i].c_str(), bw::protocol_summary(names[i]).c_str());
            }
            return 0;
        }
        std::printf("%s\n\n%s", bw::protocol_summary(args[0]).c_str(),
                    bw::describe_model(bw::protocol_model(args[0])).c_str());
        return 0;
    } catch (const std::invalid_argument& e) {
        std::fprintf(stderr, "bitwise: %s\n", e.what());
        return 1;
    }
}

int cmd_synth(const std::vector<std::string>& args) {
    std::string       name;
    bw::GenerateOptions options;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string&  arg       = args[i];
        const bool          has_value = (i + 1 < args.size());
        std::uint64_t       number    = 0;
        if ((arg == "--seed" || arg == "--frames" || arg == "--jitter-permille") && !has_value) {
            std::fprintf(stderr, "bitwise: %s needs a value\n", arg.c_str());
            return 2;
        }
        if (arg == "--seed" && has_value) {
            if (!parse_unsigned(args[++i], ~std::uint64_t(0), &number)) {
                std::fprintf(stderr, "bitwise: --seed: '%s' is not a whole number\n", args[i].c_str());
                return 2;
            }
            options.seed = number;
        } else if (arg == "--frames" && has_value) {
            if (!parse_unsigned(args[++i], 100000, &number)) {
                std::fprintf(stderr, "bitwise: --frames: '%s' is not a whole number from 0 to 100000\n",
                             args[i].c_str());
                return 2;
            }
            options.frames = static_cast<std::uint32_t>(number);
        } else if (arg == "--jitter-permille" && has_value) {
            if (!parse_unsigned(args[++i], 500, &number)) {
                std::fprintf(stderr, "bitwise: --jitter-permille: '%s' is not a whole number from 0 to 500\n",
                             args[i].c_str());
                return 2;
            }
            options.jitter_permille = static_cast<std::uint32_t>(number);
        } else if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "bitwise: unknown option '%s'\n", arg.c_str());
            return 2;
        } else if (name.empty()) {
            name = arg;
        } else {
            std::fprintf(stderr, "bitwise: synth takes one protocol name\n");
            return 2;
        }
    }
    if (name.empty()) {
        std::fprintf(stderr, "bitwise: synth needs a protocol name; try 'bitwise protocols'\n");
        return 2;
    }
    try {
        const std::string text = bw::format_capture_csv(bw::generate_protocol(name, options).capture());
        std::fwrite(text.data(), 1, text.size(), stdout);
        return 0;
    } catch (const std::invalid_argument& e) {
        std::fprintf(stderr, "bitwise: %s\n", e.what());
        return 1;
    }
}

int cmd_analyze(const std::vector<std::string>& args) {
    std::string        path;
    bw::AnalyzeOptions options;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg    = args[i];
        std::uint64_t      number = 0;
        if ((arg == "--min-gap-ratio" || arg == "--min-frames") && i + 1 >= args.size()) {
            std::fprintf(stderr, "bitwise: %s needs a value\n", arg.c_str());
            return 2;
        }
        if (arg == "--min-gap-ratio") {
            if (!parse_unsigned(args[++i], 1000000, &number) || number == 0) {
                std::fprintf(stderr, "bitwise: --min-gap-ratio: '%s' is not a whole number from 1 to 1000000\n",
                             args[i].c_str());
                return 2;
            }
            options.segmentation.min_gap_ratio = static_cast<std::uint32_t>(number);
        } else if (arg == "--min-frames") {
            if (!parse_unsigned(args[++i], 1000000, &number) || number == 0) {
                std::fprintf(stderr, "bitwise: --min-frames: '%s' is not a whole number from 1 to 1000000\n",
                             args[i].c_str());
                return 2;
            }
            options.fields.min_frames = static_cast<std::uint32_t>(number);
        } else if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "bitwise: unknown option '%s'\n", arg.c_str());
            return 2;
        } else if (path.empty()) {
            path = arg;
        } else {
            std::fprintf(stderr, "bitwise: analyze takes exactly one file\n");
            return 2;
        }
    }
    if (path.empty()) {
        std::fprintf(stderr, "bitwise: analyze takes exactly one file\n");
        return 2;
    }

    std::string text;
    if (!read_text_file(path.c_str(), &text)) {
        std::fprintf(stderr, "bitwise: cannot read %s\n", path.c_str());
        return 1;
    }
    try {
        const std::string report = bw::describe_analysis(bw::analyze(bw::parse_capture_csv(text), options));
        std::fwrite(report.data(), 1, report.size(), stdout);
        return 0;
    } catch (const bw::CaptureError& e) {
        std::fprintf(stderr, "bitwise: %s: %s\n", path.c_str(), e.what());
        return 1;
    }
}

int cmd_export(const std::vector<std::string>& args) {
    std::string        path;
    std::string        id;
    std::uint64_t      type = 0;
    bw::AnalyzeOptions options;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const std::string& arg    = args[i];
        std::uint64_t      number = 0;
        const bool         takes_value = arg == "--format" || arg == "--type" || arg == "--id" ||
                                         arg == "--min-gap-ratio" || arg == "--min-frames";
        if (takes_value && i + 1 >= args.size()) {
            std::fprintf(stderr, "bitwise: %s needs a value\n", arg.c_str());
            return 2;
        }
        if (arg == "--format") {
            if (args[++i] != "kaitai") {
                std::fprintf(stderr, "bitwise: --format: unknown format '%s'; known: kaitai\n", args[i].c_str());
                return 2;
            }
        } else if (arg == "--type") {
            if (!parse_unsigned(args[++i], 1000000, &number)) {
                std::fprintf(stderr, "bitwise: --type: '%s' is not a whole number from 0 to 1000000\n",
                             args[i].c_str());
                return 2;
            }
            type = number;
        } else if (arg == "--id") {
            id = args[++i];
        } else if (arg == "--min-gap-ratio") {
            if (!parse_unsigned(args[++i], 1000000, &number) || number == 0) {
                std::fprintf(stderr, "bitwise: --min-gap-ratio: '%s' is not a whole number from 1 to 1000000\n",
                             args[i].c_str());
                return 2;
            }
            options.segmentation.min_gap_ratio = static_cast<std::uint32_t>(number);
        } else if (arg == "--min-frames") {
            if (!parse_unsigned(args[++i], 1000000, &number) || number == 0) {
                std::fprintf(stderr, "bitwise: --min-frames: '%s' is not a whole number from 1 to 1000000\n",
                             args[i].c_str());
                return 2;
            }
            options.fields.min_frames = static_cast<std::uint32_t>(number);
        } else if (!arg.empty() && arg[0] == '-') {
            std::fprintf(stderr, "bitwise: unknown option '%s'\n", arg.c_str());
            return 2;
        } else if (path.empty()) {
            path = arg;
        } else {
            std::fprintf(stderr, "bitwise: export takes exactly one file\n");
            return 2;
        }
    }
    if (path.empty()) {
        std::fprintf(stderr, "bitwise: export takes exactly one file\n");
        return 2;
    }

    std::string text;
    if (!read_text_file(path.c_str(), &text)) {
        std::fprintf(stderr, "bitwise: cannot read %s\n", path.c_str());
        return 1;
    }
    try {
        const bw::Analysis analysis = bw::analyze(bw::parse_capture_csv(text), options);
        const bw::Model    model    = analysis.model();
        if (model.message_type_count() == 0) {
            std::fprintf(stderr, "bitwise: nothing to export: the analysis of %s found no message type "
                                 "(try 'bitwise analyze')\n", path.c_str());
            return 1;
        }
        if (type >= model.message_type_count()) {
            std::fprintf(stderr, "bitwise: --type %llu: the analysis found %llu message type(s)\n",
                         ull(type), ull(model.message_type_count()));
            return 1;
        }
        const std::string name = id.empty() ? model.message_type_name(static_cast<std::size_t>(type)) : id;
        const std::string out  = bw::export_kaitai(model, static_cast<std::size_t>(type), name);
        std::fwrite(out.data(), 1, out.size(), stdout);
        return 0;
    } catch (const bw::CaptureError& e) {
        std::fprintf(stderr, "bitwise: %s: %s\n", path.c_str(), e.what());
        return 1;
    } catch (const std::invalid_argument& e) {
        std::fprintf(stderr, "bitwise: %s\n", e.what());
        return 1;
    }
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
    if (command == "protocols" || command == "synth" || command == "analyze" || command == "export") {
        std::vector<std::string> args;
        for (int i = 2; i < argc; ++i) {
            args.push_back(argv[i]);
        }
        return command == "protocols" ? cmd_protocols(args)
             : command == "synth"     ? cmd_synth(args)
             : command == "analyze"   ? cmd_analyze(args) : cmd_export(args);
    }
    if (command == "capture-info") {
        std::vector<std::string> args;
        for (int i = 2; i < argc; ++i) {
            args.push_back(argv[i]);
        }
        return cmd_capture_info(args);
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
