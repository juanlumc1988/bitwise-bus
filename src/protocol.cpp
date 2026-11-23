// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.

#include "bw/protocol.h"

#include <algorithm>
#include <stdexcept>

#include "protocols/mavlink1.h"
#include "protocols/mavlink2.h"
#include "protocols/modbus_rtu.h"
#include "protocols/nmea0183.h"
#include "protocols/ubx.h"

namespace bw {

namespace {

bool by_name(const Protocol* a, const Protocol* b) {
    return a->name() < b->name();
}

std::vector<const Protocol*> make_registry() {
    std::vector<const Protocol*> list;
    list.push_back(&mavlink1_protocol());
    list.push_back(&mavlink2_protocol());
    list.push_back(&modbus_rtu_protocol());
    list.push_back(&nmea0183_protocol());
    list.push_back(&ubx_protocol());
    std::sort(list.begin(), list.end(), by_name);
    return list;
}

// Built on first use, once, so that nothing depends on the order in which
// static objects of different files are initialised.
const std::vector<const Protocol*>& registry() {
    static const std::vector<const Protocol*> list = make_registry();
    return list;
}

const Protocol& get(const std::string& name) {
    const Protocol* protocol = find_protocol(name);
    if (protocol == nullptr) {
        std::string known;
        const std::vector<std::string> names = protocol_names();
        for (std::size_t i = 0; i < names.size(); ++i) {
            known += (i == 0 ? "" : ", ") + names[i];
        }
        throw std::invalid_argument("unknown protocol '" + name + "'; known: " + known);
    }
    return *protocol;
}

} // namespace

const Protocol* find_protocol(const std::string& name) {
    const std::vector<const Protocol*>& list = registry();
    for (std::size_t i = 0; i < list.size(); ++i) {
        if (list[i]->name() == name) {
            return list[i];
        }
    }
    return nullptr;
}

std::vector<std::string> protocol_names() {
    std::vector<std::string> names;
    const std::vector<const Protocol*>& list = registry();
    for (std::size_t i = 0; i < list.size(); ++i) {
        names.push_back(list[i]->name());
    }
    return names;
}

std::string protocol_summary(const std::string& name) {
    return get(name).summary();
}

Model protocol_model(const std::string& name) {
    return get(name).model();
}

Dataset generate_protocol(const std::string& name, const GenerateOptions& options) {
    return get(name).generate(options);
}

bool protocol_conforms(const std::string& name, const std::vector<std::uint8_t>& frame) {
    return get(name).conforms(frame);
}

} // namespace bw
