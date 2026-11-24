# bitwise-bus

[![CI](https://github.com/juanlumc1988/bitwise-bus/actions/workflows/ci.yml/badge.svg)](https://github.com/juanlumc1988/bitwise-bus/actions/workflows/ci.yml)

Infer undocumented bus protocols from captures. The command it builds is
`bitwise`.

**Status: early.** The whole pipeline now runs end to end on synthetic Modbus
RTU captures: `bitwise analyze` cuts a capture into frames at the long gaps,
finds the checksum and splits the frames into typed fields, and `bitwise
export` writes what it found as a Kaitai Struct definition. Every stage is a
first version, the simplest thing that can work, to be deepened one at a time;
and none has met a real capture yet. See
[What this does not do yet](#what-this-does-not-do-yet) and the
[roadmap](docs/roadmap.md).

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
6 frames, 63 algorithms x 1569 layouts tried

algorithm            width  header   trailer  byte order
CRC-16/MODBUS        16     0        0        little-endian

96 bits of evidence.
One candidate, comfortably more evidence than chance could produce.
```

It recovered the algorithm, that the checksum covers the whole frame, and
that it is stored little-endian — from the bytes alone.

### From a capture to a Kaitai definition

The same pipeline, from a capture file to a definition that the
[Kaitai Struct](https://kaitai.io/) compiler turns into a parser for most
languages. Fifty synthetic Modbus RTU requests, one event per byte, with timing
noise:

```console
$ bitwise synth modbus-rtu --seed 1 --frames 50 --jitter-permille 300 > capture.csv
$ bitwise export capture.csv
meta:
  id: type0
doc: "Message type 'type0'. Written by bitwise-bus. Frames are separated by silences of at least 6918373 ns."
seq:
  - id: field_0
    type: u1
    doc: "enum; evidence 300 bits"
  - id: field_1
    type: u1
    doc: "enum; evidence 350 bits"
  - id: field_2
    size: 2
    doc: "payload"
  - id: field_4
    contents: [0x00]
    doc: "constant; evidence 392 bits"
  - id: field_5
    size: 1
    doc: "payload"
  - id: checksum
    type: u2le
    doc: "checksum, CRC-16/MODBUS, over field_0 to field_5 (Kaitai does not check it); evidence 800 bits"
```

Nothing but the timing and the bytes went in. The names are positions
(`field_N`) because nothing in a capture says what a field is called; rename
them in the file. This is checked against the real Kaitai tools: the compiler
accepts the definition and the parser it makes reads every frame of the capture
back into the same bytes, with the checksum it reads equal to the CRC of the
frame (`tests/roundtrip/`).

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

The catalogue holds 66 algorithms, from 8 bits to 64, each carrying its published
check value (the CRC of `123456789`), and the test suite verifies every one on
each run, and that each is the only answer for frames that use it.
A mistyped parameter is worse than a missing one: it silently never matches,
and the tool reports "nothing found" for a protocol that is right there in
the list.

## Knowing when the answer means nothing

Finding a match is easy. Knowing whether it means anything is the actual
problem, and it is where a tool like this earns or loses trust.

A wrong candidate validates *N* frames of *W*-bit checksum by chance with
probability 2^-(N·W). Against a search space of roughly 2^11 candidates, the
expected number of false positives is 2^(11 − N·W) — so it takes about 18
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
find_package(bitwise-bus 0.2 CONFIG REQUIRED)
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
  `find_package(bitwise-bus 0.2 ...)` accepts 0.2.x only.

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
    --hidden-byte                   also try each CRC with one more byte after
                                    what it covers that is in no frame (MAVLink's
                                    CRC_EXTRA): give it frames of one kind of
                                    message, three different ones or more
bitwise capture-info FILE           a first look at a capture file: events,
                                    channels, directions, timing
bitwise protocols [NAME]            the known protocols, or the model of one
bitwise synth NAME                  a synthetic capture of a known protocol,
                                    as a capture file, on standard output
    --seed N                        the same seed gives the same capture on
                                    every platform (default 1)
    --frames N                      how many frames, 0 to 100000 (default 20)
    --jitter-permille N             timing noise, 0 to 500 (default 0)
bitwise analyze FILE                infer the protocol of a capture file
    --min-gap-ratio N               how many times longer the gaps between
                                    frames must be than those inside one
                                    (default 3)
    --min-frames N                  fewest frames of a size to say anything
                                    about it (default 4)
bitwise export FILE                 the inferred protocol as a Kaitai Struct
                                    definition, on standard output
    --format kaitai                 the only format so far
    --type N                        which message type, from 0 (default 0)
    --id NAME                       the name of the type in the definition
                                    (default: its name in the model)
    --min-gap-ratio N, --min-frames N   as for analyze
```

For `crc-find`, each `FILE` is one captured frame, raw bytes. `capture-info`
reads the capture format described in
[docs/capture-format.md](docs/capture-format.md): a plain CSV with one row per
event, which is what the later stages of the pipeline will read.

`synth` needs no hardware: it writes a capture of a protocol the project knows,
with a known answer, which is also what the tests of every stage are scored
against.

```console
$ bitwise protocols
hdlc-ppp     PPP in HDLC-like framing (RFC 1662): LCP echo, IPCP request and IP datagram, FCS-16, 115200 baud 8N1, one event per byte
mavlink1     MAVLink 1: HEARTBEAT, SYS_STATUS and ATTITUDE, 57600 baud 8N1, back to back, one event per byte
mavlink2     MAVLink 2: HEARTBEAT, SYS_STATUS, ATTITUDE and PROTOCOL_VERSION, payloads without their trailing zeros, 57600 baud 8N1, back to back, one event per byte
modbus-rtu   Modbus RTU requests for functions 3 and 4, 9600 baud 8N1, one event per byte
nmea0183     NMEA 0183: GGA, RMC and VTG sentences, 4800 baud 8N1, three back to back each second, one event per byte
slip         SLIP (RFC 1055): sample and status records between ENDs with byte stuffing, 115200 baud 8N1, one event per byte
ubx          u-blox UBX: ACK-ACK, CFG-RATE and NAV-STATUS, 115200 baud 8N1, back to back, one event per byte
$ bitwise synth modbus-rtu --seed 1 --frames 3 | head -5
# bitwise-capture 1
time_ns,channel,direction,id,data
0,rs485,,,03
1145833,rs485,,,04
2291666,rs485,,,55
```

`analyze` runs the pipeline on a capture file and prints what each stage
found, then the model. On 50 synthetic Modbus RTU requests with timing noise
(`tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv`):

```console
$ bitwise analyze tests/corpus/synth_modbus_rtu_seed1_50frames_jitter300.csv
events     400 (400 bytes)
framing    idle gap: a gap of at least 6918373 ns ends a frame (49 gaps between frames, 350 inside them, the longest 1464359 ns)
frames     50
type0      8 bytes, 50 frames; checksum CRC-16/MODBUS, 16 bits little-endian, evidence 800 bits
framing: idle gap, at least 6918373 ns
message type 0 "type0"
  0 "field_0"  enum      8 bits @0 evidence 300 bits
  1 "field_1"  enum      8 bits @8 evidence 350 bits
  2 "field_2"  payload   16 bits @16
  3 "field_4"  constant  8 bits @32 = 0x0 evidence 392 bits
  4 "field_5"  payload   8 bits @40
  5 "checksum" checksum  16 bits @48 little-endian covers 0..4 evidence 800 bits CRC-16/MODBUS
```

It found the frames from the timing alone, the CRC and what it covers, the two
enumerations (address and function) and the two 16-bit values with nothing to
find in them. The one cut that is not in the generator's own model is at byte
5: the high byte of the quantity is always 0, so it comes out as a constant of
its own, and nothing in the capture says it belongs with the byte after it.
Random bytes at the same timing come out as one payload field and no checksum;
without timing there is no framing and it says so.

Six protocols of the first wave of the corpus (UBX, MAVLink 1 and MAVLink 2,
binary; NMEA 0183, text; SLIP and PPP in HDLC-like framing, byte stuffing) are there to
be generated, and `analyze` makes more of them as the stages come. SLIP and PPP follow
each other at the pace of the line, but a flag byte bounds each frame, and `analyze` cuts
them there, reads them without the flags and with the stuffing undone, and finds the FCS of
PPP. UBX and MAVLink follow one another with nothing between them and have no flag, but each
frame starts with a sync byte and says how long it is, and `analyze` cuts them there. What it
makes of them next is limited by what the later stages do not know yet: the frames of
MAVLink 2 that differ in length for the same message because the zeros at the end of a
payload are not sent. The Fletcher-8 of UBX is found, and so are the sums of one byte, also
when they are written as two hexadecimal characters, and the CRC of MAVLink, with the byte of
each message that is not in the frame. NMEA
sentences are text, and come three at a time with a second of silence after them: the gaps
find the seconds, and `analyze` cuts them into lines, which are the sentences; they differ in
length, and the exclusive-or checksum, written as two hexadecimal characters after the star,
is found in each kind. That is the
starting point of the next steps of the [roadmap](docs/roadmap.md), measured in its table of
the baseline.

## What this does not do yet

What follows is where the library stops today, and, for most of it, where it will
stop at 1.0 (the [roadmap](docs/roadmap.md) says which is which). It has been
tested on synthetic captures with a known answer and on published test vectors,
and on nothing else: there are no real captures in it.

- **Frame segmentation** cuts at the long gaps, at flags (with their byte
  stuffing), from a sync byte by the length the frame says it has, and in lines of
  text. A terminator other than a line feed is not found, a stuffing other than the
  two known (RFC 1662 and SLIP) is not recognised, and a capture without
  timestamps, flags, sync byte or lines is not segmented.
- **Message types** are frame sizes, or, when a length field says the size of the
  frames and a discriminator (a message id) is the same in all the frames of a
  kind, all the sizes of a kind, if a checksum explains them all. A size that two
  messages share, and a capture in which a frame has a wrong length, are not
  handled yet.
- **Field discovery** works byte by byte: a byte that never changes, one that
  takes a few values, or one with no visible structure, with a run of the last kind
  taken as one field. Fields smaller than a byte are not handled, a number of
  several bytes whose high bytes never change comes out as several fields, and text
  of varying size is not split into fields.
- **Field typing** claims constants, enumerations, counters and, in a type of
  several sizes, the length, with the evidence for each in bits, and calls
  everything else payload without claiming anything. Timestamps, floats, text and
  flags are not recognised, and neither are counters that span bytes which
  discovery has already cut apart.
- **Non-byte-aligned checksum fields.** `crc_compute` handles 15-, 17- and
  21-bit widths correctly, and the catalogue includes CAN and CAN-FD. But
  *locating* such a field in a capture needs bit-level framing, so
  `crc-find` skips those widths rather than guessing.
- **Uncatalogued polynomials.** The search tries 66 known algorithms. A
  protocol using a polynomial nobody catalogued needs a real search of the
  parameter space — which has a neat shortcut, since for a fixed width and
  reflection the polynomial can be recovered algebraically from a few frames
  differing in one byte, rather than brute-forced.
- **Only Kaitai Struct is written.** The exporter refuses what it does not write
  (fields that are not a whole number of bytes, or whose size runs to the end or up
  to a delimiter, or is given by a length that is not an integer of 8, 16, 32 or
  64 bits) instead of approximating it. It cannot say what a field is called, and
  what an enumeration's values mean.
- **No GUI, no other exporters, no live capture.** Not planned.

## Roadmap

The plan is short on purpose; the detail is in [docs/roadmap.md](docs/roadmap.md).

**Done:** the capture model and importers, segmentation (idle gaps, flags with byte
stuffing, a sync byte and a length, lines of text), the checksum stage (66 CRCs,
five sums, checksums written as text, a CRC with a byte that is in no frame), message
types by discriminator, field discovery and typing for the six protocols of the
corpus, and the Kaitai Struct exporter, checked with the real Kaitai tools.

**What is left for 1.0**, in three pull requests: the fields that are still wrong
(numbers of two or three bytes with a constant high byte, lengths, text), a
parametric generator of protocol shapes with noise to test the generality that six
named protocols cannot, and the closing of the API, the thresholds and the release.

**Not planned:** more protocols with a name, a Wireshark dissector, DBC, live
capture, bit-level framing, a Qt viewer, and real captures. The library has only
been tested on synthetic captures with a known answer and on published test vectors,
and that is as far as this goes.

## Relationship to rewind-mcu

Independent projects that share a spine.
[rewind-mcu](https://github.com/juanlumc1988/rewind-mcu) records what crossed
the HAL boundary and replays it; this infers structure in what crossed a
wire. They are deliberately *not* sharing a library: the obvious common
ground turns out to be about four hundred lines of trivia, and the two CRC
implementations want opposite things — one fixed algorithm optimised for
flash size there, any algorithm with parameters as data here.

Where they can meet is data, not code: the bytes a firmware read from a UART
in a `rewind` trace are a capture, with cycle-accurate timing. A neutral
capture format, the first stage of the [roadmap](docs/roadmap.md), is where an
exporter on that side and an importer here would plug in.

If real duplication shows up later, extracting it then will be better
informed than guessing at the interface now.

## License

Apache-2.0. See [LICENSE](LICENSE).
