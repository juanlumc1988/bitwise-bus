# bitwise-bus

[![CI](https://github.com/juanlumc1988/bitwise-bus/actions/workflows/ci.yml/badge.svg)](https://github.com/juanlumc1988/bitwise-bus/actions/workflows/ci.yml)

Infer undocumented bus protocols from captures. The command it builds is
`bitwise`.

**Status: early.** The CRC identification stage works end to end and is
covered by tests. The rest of the pipeline — frame segmentation, field
discovery, field typing — is designed and not written. See
[What this does not do yet](#what-this-does-not-do-yet).

## The problem

There is a device on a bus — CAN, RS-485, a UART link to a module whose
vendor went out of business — and no documentation. The usual workflow is a
logic analyser, a spreadsheet, and a week of staring at hex.

Most of that week is mechanical. This automates the mechanical part.

## Demo

Six Modbus RTU frames, handed over as raw bytes with no explanation of what
they are:

```console
$ xxd frame0.bin
00000000: 1103 a54d ca18 2530 bb1d ebb6            ..M..%0....

$ bitwise crc-find frame*.bin
6 frames, 17 algorithms x 450 layouts tried

algorithm            width  header   trailer  byte order
CRC-16/MODBUS        16     0        0        little-endian

96 bits of evidence.
One candidate, comfortably more evidence than chance could produce.
```

It recovered the algorithm, that the checksum covers the whole frame, and
that it is stored little-endian — from the bytes alone.

## Why a parametric CRC

Every CRC in use is one algorithm under six numbers: width, polynomial,
initial value, whether input bits are reflected, whether the output is, and a
final XOR. Naming a protocol names a point in that space.

That framing matters because the job here is the inverse one. The question is
not "compute a CRC" but "which point in this space explains these bytes?" —
and that is a search, which needs the parameters to be data rather than code.

The implementation works a bit at a time rather than a byte at a time. That
is eight times slower and buys two things worth more than the speed:

- **Widths that are not a multiple of eight.** CAN's CRC is 15 bits; CAN-FD
  uses 17 and 21. The byte-wise formulation everyone writes first cannot do
  those at all, which would rule out the buses this project exists for.
- **No table to build.** A search evaluates thousands of parameter sets
  against a handful of short frames. Building a 256-entry table to checksum
  twelve bytes loses badly.

The catalogue holds 20 algorithms, each carrying its published check value
(the CRC of `123456789`), and the test suite verifies every one on each run.
A mistyped parameter is worse than a missing one: it silently never matches,
and the tool reports "nothing found" for a protocol that is right there in
the list.

## Knowing when the answer means nothing

Finding a match is easy. Knowing whether it means anything is the actual
problem, and it is where a tool like this earns or loses trust.

A wrong candidate validates *N* frames of *W*-bit checksum by chance with
probability 2^-(N·W). Against a search space of roughly 2^10 candidates, the
expected number of false positives is 2^(10 − N·W) — so it takes about 17
bits of evidence before a single match is more likely right than lucky, and
32 before it stops being worth worrying about.

One 8-bit checksum on one frame is eight bits. It proves nothing, and
reporting it as an answer would be worse than reporting nothing:

```console
$ bitwise crc-find single-frame.bin
CRC-8                8      0        0        big-endian

8 bits of evidence.
Only one candidate, but on thin evidence -- a wrong answer could
fit this well by chance. Capture more frames before trusting it.
```

**Identical frames count once.** A quiet bus repeating the same heartbeat
forty times carries exactly as much evidence as one heartbeat. Counting it
forty times would manufacture confidence out of nothing, and captures like
that are the normal case, not an edge case.

## Downloads

Each [tagged release](https://github.com/juanlumc1988/bitwise-bus/releases/latest)
carries the `bitwise` CLI and the `bw_core` static library with its headers,
one archive per platform. The links below always point at the latest release.

| Platform | Archive |
| --- | --- |
| Linux x86-64 | [`bitwise-bus-linux-x86_64.tar.gz`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-linux-x86_64.tar.gz) |
| Linux aarch64 | [`bitwise-bus-linux-aarch64.tar.gz`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-linux-aarch64.tar.gz) |
| Linux armv7 (hard float) | [`bitwise-bus-linux-armv7.tar.gz`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-linux-armv7.tar.gz) |
| macOS (arm64 + x86-64) | [`bitwise-bus-macos-universal.tar.gz`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-macos-universal.tar.gz) |
| Windows x64, MSVC | [`bitwise-bus-windows-x64-msvc.zip`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-windows-x64-msvc.zip) |
| Windows arm64, MSVC | [`bitwise-bus-windows-arm64-msvc.zip`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-windows-arm64-msvc.zip) |
| Windows x64, MinGW-w64 | [`bitwise-bus-windows-x64-mingw.zip`](https://github.com/juanlumc1988/bitwise-bus/releases/latest/download/bitwise-bus-windows-x64-mingw.zip) |

An archive unpacks to `bitwise-bus-<version>-<platform>/`, holding `bin/bitwise`,
`lib/`, `include/bw/` and the CMake package files. `SHA256SUMS` is attached to
the release.

To use the library from CMake, point `CMAKE_PREFIX_PATH` at the unpacked
directory:

```cmake
find_package(bitwise-bus 0.1 CONFIG REQUIRED)
target_link_libraries(my_tool PRIVATE bw::core)
```

Or by hand: `-I<dir>/include` and `<dir>/lib/libbw_core.a` (`bw_core.lib` with
MSVC).

- **Static only.** The API passes `std::vector`, so a shared library's ABI
  would tie every consumer to one compiler and C++ runtime. The headers need
  C++11; the library itself is built as C++17.
- **MSVC** packages use the dynamic runtime (`/MD`). They ship both
  `bw_core.lib` and `bw_cored.lib`, because Release and Debug are not
  link-compatible under MSVC; `find_package` picks the right one.
- **Linux** binaries are built on Ubuntu 22.04, so the CLI needs glibc 2.35 or
  newer and nothing else. **macOS** needs 11 or newer.
- Before 1.0 the API can change between minor versions, so
  `find_package(bitwise-bus 0.1 ...)` accepts 0.1.x only.

## Build and test

Needs CMake 3.16+, Ninja, and a C++17 compiler. No library dependencies to
install: doctest is vendored, nothing else is used.

On Ubuntu/Debian, that's:

```console
sudo apt install cmake ninja-build g++
```

(`g++` pulls in the compiler; swap it for `clang` if you'd rather use Clang.
If you'd rather not install Ninja, drop `-G Ninja` below — CMake falls back
to Unix Makefiles, which `build-essential`/`g++` already provides `make`
for.)

```console
git clone https://github.com/juanlumc1988/bitwise-bus.git
cd bitwise-bus
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=RelWithDebInfo
cmake --build build -j
ctest --test-dir build
```

C++17 throughout. Unlike [rewind-mcu](https://github.com/juanlumc1988/rewind-mcu),
where the recording side is pinned to strict C++98 because it cross-compiles
to a microcontroller, nothing here ever leaves a workstation.

## Commands

```console
bitwise crc-catalog                 list the algorithms that will be tried
bitwise crc-find FILE [FILE...]     work out which one a set of frames uses
    --header-skip N                 how many leading bytes may sit outside
                                    the covered range (default 4)
    --trailer-skip N                how many bytes may follow the checksum
                                    (default 2)
```

Each `FILE` is one captured frame, raw bytes.

## What this does not do yet

The CRC stage is one of four in the intended pipeline. The other three are
designed and unwritten:

- **Frame segmentation.** Right now each frame is a separate file, already
  cut. Real captures are a byte stream; inter-byte gap timing gives the
  boundaries on an idle-delimited bus, and where it does not, candidate
  lengths have to be scored by how much structure each one exposes.
- **Field discovery.** Per-bit-offset entropy across a corpus of aligned
  frames separates constants (magic numbers, headers, padding) from payload,
  and the discontinuities in that profile are the field boundaries.
- **Field typing.** Once fields are known, classify them by behaviour across
  the corpus: constant delta between frames is a sequence counter, monotonic
  with a delta proportional to inter-frame time is a timestamp, correlating
  with frame length is a length field, small cardinality is an enum.
- **Non-byte-aligned checksum fields.** `crc_compute` handles 15-, 17- and
  21-bit widths correctly, and the catalogue includes CAN and CAN-FD. But
  *locating* such a field in a capture needs bit-level framing, so
  `crc-find` skips those widths rather than guessing.
- **Uncatalogued polynomials.** The search tries 20 known algorithms. A
  protocol using a polynomial nobody catalogued needs a real search of the
  parameter space — which has a neat shortcut, since for a fixed width and
  reflection the polynomial can be recovered algebraically from a few frames
  differing in one byte, rather than brute-forced.
- **No GUI.** A Wireshark-style view with fields coloured by inferred type is
  the eventual Qt layer.

## Roadmap

1. Uncatalogued polynomial recovery — the algebraic shortcut above.
2. Frame segmentation from a raw byte stream with timing.
3. Field discovery by entropy, and field typing.
4. Generated output: a C++ header or a Kaitai Struct definition.
5. Qt view over a capture.

## Relationship to rewind-mcu

Independent projects that share a spine.
[rewind-mcu](https://github.com/juanlumc1988/rewind-mcu) records what crossed
the HAL boundary and replays it; this infers structure in what crossed a
wire. They are deliberately *not* sharing a library: the obvious common
ground turns out to be about four hundred lines of trivia, and the two CRC
implementations want opposite things — one fixed algorithm optimised for
flash size there, any algorithm with parameters as data here.

If real duplication shows up later, extracting it then will be better
informed than guessing at the interface now.

## License

Apache-2.0. See [LICENSE](LICENSE).
