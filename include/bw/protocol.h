// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// Known protocols: for each, the model that describes it, a generator of
// synthetic captures of it, and a reference decoder that says whether a frame
// belongs to it.
//
// They exist to test the pipeline, not to feed it. The inference stages never
// see a Protocol: a stage that did would be recognising protocols it already
// knew instead of working out ones it does not. What varies from one protocol
// to the next is data (a model) and a way to produce it, so a protocol is
// found by name in a registry; there is no hierarchy of factories behind it.
//
// A generator shares no code with the inference stages. A bug that both had
// would make a test agree with itself and be wrong, so a protocol brings its
// own checksum and its own random numbers, and the tests then cross-check the
// two implementations against each other.
//
// Everything a generator does is integer arithmetic on a seed, so the same
// seed gives the same capture on every platform.

#ifndef BW_PROTOCOL_H
#define BW_PROTOCOL_H

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

#include "bw/dataset.h"
#include "bw/model.h"

namespace bw {

struct GenerateOptions {
    std::uint64_t seed            = 1;
    std::uint32_t frames          = 20;     // at most 100000
    // Timing noise, in thousandths of a character time, 0 to 500: each byte may
    // start that late, at most. Frames do not change with it, only their
    // timestamps. Past 500 the pauses inside a frame would reach the limit that
    // Modbus RTU puts on them.
    std::uint32_t jitter_permille = 0;
};

class Protocol {
public:
    virtual ~Protocol() {}

    virtual std::string name() const = 0;       // what it is called in the registry
    virtual std::string summary() const = 0;    // one line
    virtual Model       model() const = 0;      // the ground truth

    // Throws std::invalid_argument for options out of range.
    virtual Dataset generate(const GenerateOptions& options) const = 0;

    // Does this frame belong to the protocol: its length, its fields, its
    // checksum? Written from the protocol's rules, not from what the generator
    // happens to emit, so it accepts any valid frame.
    virtual bool conforms(const std::vector<std::uint8_t>& frame) const = 0;
};

// nullptr when there is no such protocol. The protocols live as long as the
// program does.
const Protocol* find_protocol(const std::string& name);

// The names, in alphabetical order.
std::vector<std::string> protocol_names();

// The following throw std::invalid_argument, naming the protocols there are,
// for a name that is not in the registry.
std::string protocol_summary(const std::string& name);
Model       protocol_model(const std::string& name);
Dataset     generate_protocol(const std::string& name, const GenerateOptions& options);
bool        protocol_conforms(const std::string& name, const std::vector<std::uint8_t>& frame);

} // namespace bw

#endif // BW_PROTOCOL_H
