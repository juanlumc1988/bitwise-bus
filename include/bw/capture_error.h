// SPDX-License-Identifier: Apache-2.0
// Part of bitwise-bus -- inferring undocumented bus protocols from captures.
//
// The exception that reading a capture file throws. It has a header of its own
// so that a binding generator can be given capture.h and the others without
// it: see the note at the top of capture.h.

#ifndef BW_CAPTURE_ERROR_H
#define BW_CAPTURE_ERROR_H

#include <cstddef>
#include <stdexcept>
#include <string>

namespace bw {

// A malformed capture file. what() starts with "line N: " when the problem is
// on a line.
class CaptureError : public std::runtime_error {
public:
    CaptureError(std::size_t line, const std::string& message);
    std::size_t line() const;            // 1-based; 0 when not tied to a line

private:
    std::size_t line_;
};

} // namespace bw

#endif // BW_CAPTURE_ERROR_H
