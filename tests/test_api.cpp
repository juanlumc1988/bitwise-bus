// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// What 1.0 freezes (docs/api.md) is written down for every header that is installed, and the
// words of the document that can be checked are.

#include "doctest.h"

#include <fstream>
#include <iterator>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string read_doc(const std::string& name) {
    const std::string path = std::string(BW_DOCS_DIR) + "/" + name;
    std::ifstream     in(path.c_str(), std::ios::binary);
    REQUIRE_MESSAGE(in.good(), "cannot open " << path);
    return std::string((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
}

std::vector<std::string> words(const std::string& text) {
    std::vector<std::string> out;
    std::istringstream       in(text);
    std::string              word;
    while (in >> word) {
        out.push_back(word);
    }
    return out;
}

} // namespace

TEST_CASE("api: every installed header is in docs/api.md, and nothing else is there as a header") {
    const std::string              doc     = read_doc("api.md");
    const std::vector<std::string> headers = words(BW_PUBLIC_HEADERS);
    CHECK(headers.size() >= 19);
    for (std::size_t i = 0; i < headers.size(); ++i) {
        CAPTURE(headers[i]);
        CHECK(doc.find("`" + headers[i] + "`") != std::string::npos);
    }
    // Every `name.h` that the document puts in backticks is a header that there is.
    std::size_t at = 0;
    while ((at = doc.find(".h`", at)) != std::string::npos) {
        const std::size_t start = doc.rfind('`', at);
        REQUIRE(start != std::string::npos);
        const std::string name = doc.substr(start + 1, at + 2 - start - 1);
        bool              found = false;
        for (std::size_t i = 0; i < headers.size(); ++i) {
            found = found || headers[i] == name;
        }
        CAPTURE(name);
        CHECK(found);
        at += 3;
    }
}

TEST_CASE("api: the version is 1.x, and the docs say how it is asked for") {
    const std::string version = BW_PROJECT_VERSION;
    CHECK(version.compare(0, 2, "1.") == 0);
    const std::string doc = read_doc("api.md");
    CHECK(doc.find("find_package(bitwise-bus 1 CONFIG REQUIRED)") != std::string::npos);
    CHECK(doc.find("SameMajorVersion") != std::string::npos);
}
