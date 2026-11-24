// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/text.h"

#include <algorithm>
#include <limits>
#include <map>
#include <utility>

#include "bw/messages.h"

namespace bw {

namespace {

typedef std::vector<std::uint8_t> Bytes;

const std::size_t kConstantBytes = 8;       // what a Constant holds

std::uint32_t saturate(std::uint64_t value) {
    return value > std::numeric_limits<std::uint32_t>::max() ? std::numeric_limits<std::uint32_t>::max()
                                                             : static_cast<std::uint32_t>(value);
}

bool is_character(std::uint8_t b) {
    return (b >= 0x20 && b <= 0x7E) || b == 0x09 || b == 0x0D || b == 0x0A;
}

bool is_alphanumeric(std::uint8_t b) {
    return (b >= '0' && b <= '9') || (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z');
}

// The same test that cuts the capture into lines.
bool is_text(const std::vector<Bytes>& lines) {
    std::uint64_t bytes = 0, characters = 0, ended = 0;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        bytes += lines[i].size();
        for (std::size_t j = 0; j < lines[i].size(); ++j) {
            characters += is_character(lines[i][j]) ? 1 : 0;
        }
        ended += !lines[i].empty() && lines[i].back() == 0x0A ? 1 : 0;
    }
    return bytes != 0 && characters * 100 >= bytes * 95 && ended * 100 >= lines.size() * 95;
}

// ---- Kinds -----------------------------------------------------------------------------------------------

struct Kind {
    Bytes                    head;              // up to and including the first separator
    std::uint32_t            count = 0;         // separators in a line
    std::vector<std::size_t> lines;             // indexes
};

struct Split {
    std::vector<Kind> kinds;
    std::uint64_t     in_kinds   = 0;           // lines
    std::uint64_t     separators = 0;           // in those lines
    std::uint64_t     head_bytes = 0;           // the bytes of those lines that are the head of their kind
};

// The kinds that `separator` makes: the lines that start with the same bytes up to the first one, and
// have as many of them, when there are at least `min_lines` of them.
Split split_by(const std::vector<Bytes>& lines, std::uint8_t separator, std::uint32_t min_lines) {
    typedef std::pair<Bytes, std::uint32_t> Key;
    std::map<Key, std::vector<std::size_t> > groups;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const Bytes&          line  = lines[i];
        const Bytes::const_iterator first = std::find(line.begin(), line.end(), separator);
        if (first == line.end()) {
            continue;
        }
        const std::uint32_t count = saturate(static_cast<std::uint64_t>(std::count(line.begin(), line.end(), separator)));
        groups[Key(Bytes(line.begin(), first + 1), count)].push_back(i);
    }
    Split out;
    for (std::map<Key, std::vector<std::size_t> >::const_iterator it = groups.begin(); it != groups.end(); ++it) {
        if (it->second.size() >= min_lines) {
            Kind kind;
            kind.head  = it->first.first;
            kind.count = it->first.second;
            kind.lines = it->second;
            out.in_kinds += kind.lines.size();
            out.separators += static_cast<std::uint64_t>(kind.lines.size()) * kind.count;
            out.head_bytes += static_cast<std::uint64_t>(kind.lines.size()) * kind.head.size();
            out.kinds.push_back(kind);
        }
    }
    return out;
}

// Which separator cuts the lines best: the one with the most separators in the lines that it puts in kinds, then
// the one that has more lines in them, then more kinds, and then the one whose kinds start with more bytes that are
// the same in all their lines, the lowest byte of all winning a tie. (Lines that all start with a dollar are in one kind
// of a single separator, and so are lines with one comma: the comma has the address in front of it.)
bool better_split(const Split& a, const Split& b) {
    if (a.separators != b.separators) {
        return a.separators > b.separators;
    }
    if (a.in_kinds != b.in_kinds) {
        return a.in_kinds > b.in_kinds;
    }
    if (a.kinds.size() != b.kinds.size()) {
        return a.kinds.size() > b.kinds.size();
    }
    return a.head_bytes > b.head_bytes;
}

bool more_lines(const Kind& a, const Kind& b) {
    return a.lines.size() > b.lines.size();
}

// ---- The fields of a kind --------------------------------------------------------------------------------

// How the lines of a kind end, which is the same in all of them: the byte that ends the last field (part of it),
// what comes after the checksum, and whether there is one and how many characters it takes.
struct Ending {
    std::size_t  skip      = 0;                 // bytes at the start that the checksum does not cover
    std::size_t  check     = 0;                 // characters of the checksum, 0 if there is none
    Bytes        tail;                          // after the checksum
    std::uint8_t delimiter = 0;                 // the last byte of the last field
};

// The most common of the keys; the first of them on a tie.
Bytes most_common(const std::vector<Bytes>& keys) {
    std::map<Bytes, std::size_t> votes;
    for (std::size_t i = 0; i < keys.size(); ++i) {
        ++votes[keys[i]];
    }
    Bytes       best;
    std::size_t best_votes = 0;
    for (std::map<Bytes, std::size_t>::const_iterator it = votes.begin(); it != votes.end(); ++it) {
        if (it->second > best_votes) {
            best       = it->first;
            best_votes = it->second;
        }
    }
    return best;
}

// With a checksum written as two characters after the byte that ends the last field: the bytes after the
// checksum are the trailer. False when the lines do not say one byte and one trailer.
bool ending_with_checksum(const std::vector<const Bytes*>& lines, const ChecksumFinding& checksum, std::size_t head,
                          Ending* out) {
    out->skip  = checksum.header_skip;
    out->check = checksum.width_bits / 8;
    const std::size_t after = out->check + checksum.trailer_skip;
    std::vector<Bytes> keys;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const Bytes& line = *lines[i];
        if (line.size() > head + after) {
            Bytes key(line.end() - static_cast<std::ptrdiff_t>(checksum.trailer_skip), line.end());
            key.push_back(line[line.size() - after - 1]);
            keys.push_back(key);
        }
    }
    if (keys.empty()) {
        return false;
    }
    const Bytes key = most_common(keys);
    out->delimiter  = key.back();
    out->tail       = Bytes(key.begin(), key.end() - 1);
    return true;
}

// Without one: the last field ends with the first of the carriage return and line feed that close the lines, and
// the others are the tail.
bool ending_without_checksum(const std::vector<const Bytes*>& lines, Ending* out) {
    std::vector<Bytes> keys;
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const Bytes& line = *lines[i];
        std::size_t  at   = line.size();
        while (at > 0 && (line[at - 1] == 0x0D || line[at - 1] == 0x0A)) {
            --at;
        }
        if (at < line.size()) {
            keys.push_back(Bytes(line.begin() + static_cast<std::ptrdiff_t>(at), line.end()));
        }
    }
    if (keys.empty()) {
        return false;
    }
    const Bytes key = most_common(keys);
    out->delimiter  = key.front();
    out->tail       = Bytes(key.begin() + 1, key.end());
    return true;
}

// Where the fields of a line end, as offsets after the byte that ends each: the head, each field between
// separators, and the last. False for a line that does not have the ending, or whose separators are not those of
// the kind (the ones that are not where the kind has them are what a wrong byte makes).
bool cut(const Bytes& line, const Ending& ending, std::uint8_t separator, const Kind& kind, std::size_t in_body,
         std::vector<std::size_t>* ends) {
    const std::size_t after = ending.check + ending.tail.size();
    if (line.size() < kind.head.size() + 1 + after) {
        return false;
    }
    const std::size_t body = line.size() - after;
    if (!ending.tail.empty() && !std::equal(ending.tail.begin(), ending.tail.end(), line.end() - static_cast<std::ptrdiff_t>(ending.tail.size()))) {
        return false;
    }
    if (line[body - 1] != ending.delimiter) {
        return false;
    }
    ends->clear();
    for (std::size_t i = 0; i < body; ++i) {
        if (line[i] == separator) {
            ends->push_back(i + 1);
        }
    }
    if (ends->size() != in_body) {
        return false;
    }
    // The last field is up to the first delimiter.
    const Bytes::const_iterator last = line.begin() + static_cast<std::ptrdiff_t>(ends->back());
    if (std::find(last, line.begin() + static_cast<std::ptrdiff_t>(body - 1), ending.delimiter) !=
        line.begin() + static_cast<std::ptrdiff_t>(body - 1)) {
        return false;
    }
    ends->push_back(body);
    return true;
}

// What a field holds, over the lines.
struct Column {
    bool                         constant = true;
    Bytes                        first;
    std::map<Bytes, std::size_t> seen;               // up to one more than is worth saying
    std::size_t                  lines = 0;
};

void add_constant(std::vector<TextField>* fields, const Bytes& bytes, std::size_t from, std::size_t to,
                  std::uint64_t lines) {
    for (std::size_t at = from; at < to; at += kConstantBytes) {
        TextField field;
        field.kind  = FieldKind::Constant;
        field.bytes = Bytes(bytes.begin() + static_cast<std::ptrdiff_t>(at),
                            bytes.begin() + static_cast<std::ptrdiff_t>(std::min(at + kConstantBytes, to)));
        field.evidence_bits = saturate(8 * static_cast<std::uint64_t>(field.bytes.size()) * (lines - 1));
        fields->push_back(field);
    }
}

// "one of "A", "V"": the values of a field with a few that recur, without the byte that ends it; empty when there
// are more, or when one is not something to write plainly.
std::string values_of(const Column& column, std::size_t max_values) {
    if (column.seen.size() > max_values || column.lines < 4 * column.seen.size()) {
        return std::string();
    }
    std::string out = "one of ";
    for (std::map<Bytes, std::size_t>::const_iterator it = column.seen.begin(); it != column.seen.end(); ++it) {
        if (it != column.seen.begin()) {
            out += ", ";
        }
        out += "\"";
        for (std::size_t i = 0; i + 1 < it->first.size(); ++i) {
            const std::uint8_t c = it->first[i];
            if (c < 0x20 || c > 0x7E || c == '"' || c == '\\') {
                return std::string();
            }
            out += static_cast<char>(c);
        }
        out += "\"";
    }
    return out;
}

void add_column(std::vector<TextField>* fields, const Column& column, std::uint8_t delimiter, std::size_t max_values) {
    if (column.constant) {
        add_constant(fields, column.first, 0, column.first.size(), column.lines);
        return;
    }
    TextField field;
    field.kind          = FieldKind::Text;
    field.size_kind     = SizeKind::Delimited;
    field.delimiter     = delimiter;
    field.evidence_bits = saturate(column.lines);
    field.detail        = values_of(column, max_values);
    fields->push_back(field);
}

// The fields of one kind, or false when its lines do not have enough in common to say.
bool build_type(const std::vector<Bytes>& lines, const Kind& kind, std::uint8_t separator, const FieldOptions& options,
                TextType* out) {
    std::vector<Bytes>        of_kind;
    std::vector<const Bytes*> pointers;
    out->smallest = std::numeric_limits<std::uint32_t>::max();
    out->largest  = 0;
    for (std::size_t i = 0; i < kind.lines.size(); ++i) {
        of_kind.push_back(lines[kind.lines[i]]);
        out->smallest = std::min(out->smallest, saturate(of_kind.back().size()));
        out->largest  = std::max(out->largest, saturate(of_kind.back().size()));
    }
    for (std::size_t i = 0; i < of_kind.size(); ++i) {
        pointers.push_back(&of_kind[i]);
    }
    out->frames = saturate(of_kind.size());

    // The checksum, if stage 2 finds one that the text has a place for: two characters of hexadecimal after one byte
    // that it does not cover, which is not the separator, and starting to cover no later than the end of the head.
    // The head is the first field, so the byte that ends it is the first separator.
    ChecksumFinding found = find_checksum_of_frames(of_kind);
    Ending          ending;
    bool            with_checksum = found.found && found.ascii_hex && found.gap_bytes == 1 &&
                                    found.header_skip <= kind.head.size() &&
                                    ending_with_checksum(pointers, found, kind.head.size(), &ending) &&
                                    ending.delimiter != separator;
    if (!with_checksum) {
        found.found   = false;
        ending        = Ending();
        if (!ending_without_checksum(pointers, &ending) || ending.delimiter == separator) {
            return false;
        }
    }
    out->checksum = found;

    // Each field, over the lines that are cut the way the kind says. Some of the separators of the kind may be in what
    // follows the checksum, which is constant, and are not between fields.
    const std::size_t        in_tail = static_cast<std::size_t>(std::count(ending.tail.begin(), ending.tail.end(), separator));
    const std::size_t        in_body = kind.count > in_tail ? kind.count - in_tail : 0;
    std::vector<Column>      columns(in_body + 1);
    std::vector<std::size_t> ends;
    std::size_t              conforming = 0;
    for (std::size_t i = 0; i < of_kind.size(); ++i) {
        if (!cut(of_kind[i], ending, separator, kind, in_body, &ends)) {
            continue;
        }
        ++conforming;
        for (std::size_t t = 0; t < columns.size(); ++t) {
            const Bytes value(of_kind[i].begin() + static_cast<std::ptrdiff_t>(t == 0 ? 0 : ends[t - 1]),
                              of_kind[i].begin() + static_cast<std::ptrdiff_t>(ends[t]));
            Column& column = columns[t];
            if (column.lines == 0) {
                column.first = value;
            } else if (value != column.first) {
                column.constant = false;
            }
            ++column.lines;
            if (column.seen.size() <= options.max_enum_values) {
                ++column.seen[value];
            }
        }
    }
    if (conforming < std::max<std::size_t>(options.min_frames, 1)) {
        return false;
    }

    // The head is the same in all of them (it is what makes the kind). It is cut where the checksum starts to cover.
    const std::size_t skip = with_checksum ? ending.skip : 0;
    add_constant(&out->fields, columns[0].first, 0, skip, columns[0].lines);
    const std::uint32_t first_covered = saturate(out->fields.size());
    add_constant(&out->fields, columns[0].first, skip, columns[0].first.size(), columns[0].lines);
    for (std::size_t t = 1; t < columns.size(); ++t) {
        add_column(&out->fields, columns[t], t + 1 == columns.size() ? ending.delimiter : separator,
                   options.max_enum_values);
    }
    if (with_checksum) {
        TextField checksum;
        checksum.kind         = FieldKind::Checksum;
        checksum.covers_first = first_covered;
        checksum.covers_last  = saturate(out->fields.size() - 1);
        out->fields.push_back(checksum);
    }
    add_constant(&out->fields, ending.tail, 0, ending.tail.size(), columns[0].lines);
    return true;
}

} // namespace

TextTypes find_text_types(const std::vector<std::vector<std::uint8_t> >& lines, const FieldOptions& options) {
    TextTypes out;
    out.ignored = lines.size();
    if (!is_text(lines)) {
        return out;
    }

    // How many lines have each byte: one that is in fewer than four in five of them cannot make kinds of enough of them.
    std::vector<std::uint64_t> present(256, 0);
    for (std::size_t i = 0; i < lines.size(); ++i) {
        bool in_line[256] = {false};
        for (std::size_t j = 0; j < lines[i].size(); ++j) {
            in_line[lines[i][j]] = true;
        }
        for (int b = 0; b < 256; ++b) {
            present[static_cast<std::size_t>(b)] += in_line[b] ? 1 : 0;
        }
    }
    Split best;
    int   best_byte = -1;
    for (int b = 0x20; b <= 0x7E; ++b) {
        if (is_alphanumeric(static_cast<std::uint8_t>(b)) || present[static_cast<std::size_t>(b)] * 5 < lines.size() * 4) {
            continue;
        }
        const Split split = split_by(lines, static_cast<std::uint8_t>(b), options.min_frames);
        if (split.in_kinds * 5 < lines.size() * 4) {
            continue;
        }
        if (best_byte < 0 || better_split(split, best)) {
            best      = split;
            best_byte = b;
        }
    }
    if (best_byte < 0) {
        return out;
    }

    std::stable_sort(best.kinds.begin(), best.kinds.end(), more_lines);
    std::uint64_t typed = 0;
    for (std::size_t k = 0; k < best.kinds.size(); ++k) {
        TextType type;
        if (build_type(lines, best.kinds[k], static_cast<std::uint8_t>(best_byte), options, &type)) {
            typed += type.frames;
            out.types.push_back(type);
        }
    }
    if (typed * 5 < lines.size() * 4) {
        out.types.clear();
        return out;
    }
    out.found     = true;
    out.separator = static_cast<std::uint8_t>(best_byte);
    out.ignored   = lines.size() - typed;
    return out;
}

} // namespace bw
