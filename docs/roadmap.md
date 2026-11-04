# Roadmap

This is a plan, not a record of what exists. What works today is in the
[README](../README.md): the CRC identification stage, end to end. Everything
below is intended and unwritten, and the order is a proposal that the first
results are allowed to change.

## Scope and principles

- **A tool for the community, not a product.** When choosing what to cover,
  gaps weigh more than popularity: a widely used protocol usually has tools
  already, a rare one usually has none. Wireshark, Kaitai Struct and DBC
  tooling *consume* a description of a protocol. This project *produces* that
  description from captures when none exists, and hands it over in their
  formats.
- **Many protocols, not one.** Protocol knowledge lives in data and test
  fixtures. The inference stages never contain it, or they would classify
  known protocols instead of inferring unknown ones.
- **Honest evidence, everywhere.** The CRC stage already says "one candidate,
  but on thin evidence" instead of picking a winner. Every stage does the same:
  it reports how sure it is, keeps the alternatives it could not rule out, and
  has an *unknown* answer. Random, encrypted or compressed payloads have to
  come out as "no structure found", the way random bytes already come out as
  "no CRC found".
- **Synthetic first, real welcome.** There are no real captures yet, so every
  stage is built and measured against synthetic ones with a known answer.
  Real captures are welcome later (see [Corpus](#the-synthetic-corpus)).
- **Deterministic output.** The same capture gives the same bytes, in every
  exporter: no timestamps, no absolute paths, stable ordering.

## Architecture

### One type for protocols: the model

A protocol is described by a *model*: framing, message types, and for each
message type an ordered list of fields (position, size, kind, endianness,
evidence), plus the checksum if there is one. The size of a field is fixed,
taken from another field, delimited, or "to the end".

That one type is the common currency:

- a synthetic-capture generator **starts** from a model: the ground truth;
- the pipeline **ends** with a model: the inference;
- every exporter **prints** a model;
- the evaluation harness **compares** two models.

Making the inferred result and the ground truth the same type is what makes
every stage measurable.

### Known protocols: a registry of data

Known protocols implement one small interface: a name, their model, a
generator (`seed`, `count`, noise options → a capture) and a reference decoder.
They are looked up by name in a registry. The inference stages never see this
interface; it serves the test corpus, the ground truth and optional hints.

A factory *hierarchy* (an abstract factory per protocol family) would add
structure with nothing to vary: what differs between protocols is data, not
behaviour. So the variation sits in models, and the registry only finds them.

### The pipeline

```
raw capture ─▶ frames ─▶ message types ─▶ fields ─▶ typed fields ─▶ model ─▶ Kaitai / Lua / DBC / C++
 1 capture    3 segmentation   4 discovery            5 typing                   6 export
                  ▲                  │
                  │      2 checksums ◀┘
                  └── a checksum that validates a segmentation is evidence for it
```

Each stage takes the previous stage's result and returns its own plus a
report: evidence, alternatives kept, unknowns. Stages are plain functions over
value types in `bw_core`, so each is tested alone and `bitwise analyze`
composes them. Alternatives stay alive between stages, because later stages
are often what decides: the CRC settles where a frame ends.

### Shape of the public API

A proposal that keeps the Python bindings (B5) cheap, from what bridgefex
accepted and rejected (see [Related projects](#related-projects-no-shared-code)).
It applies to the stage APIs from now on; the existing CRC headers are bound
through a facade instead:

- Public headers use the `<cstdint>` types, not aliases such as `bw::u8`.
- Result types are plain data: no methods, no raw pointers, no strings, no
  containers inside them.
- Collections live in a class that owns them privately and exposes them
  through accessors; what crosses the boundary is scalars, strings, vectors of
  scalars and vectors of plain structs.
- Code that needs more than that goes behind a facade instead of bending the
  core API.

## Track A: the pipeline

### First, a vertical skeleton

Before deepening any stage, build the thinnest slice that goes all the way
through, so the interfaces between stages are fixed while they are cheap to
change.

> A Modbus RTU capture with timestamps in, a Kaitai Struct definition out.

Every stage starts as the simplest thing that can work:

| Stage | Skeleton version |
|---|---|
| 1 capture | A CSV importer with timestamps. |
| 2 checksums | The existing CRC search, run over the segmented frames. |
| 3 segmentation | Split at the large idle gaps. |
| 4 discovery | Byte-offset entropy among frames of the same length and first byte. |
| 5 typing | Constant, enum, counter, length. |
| 6 export | Kaitai Struct. |

It also brings the pieces that are not stages: the model type, a Modbus RTU
generator, a first parametric generator, the evaluation harness and
`bitwise analyze`.

**Done when** `bitwise analyze` on synthetic Modbus RTU captures recovers the
framing, the checksum and the field boundaries of the generator's model, and
the exported definition parses the capture back into the same bytes.

### Then, stage by stage

Each deepening step adds protocols to the corpus, tests against them, and
updates the baseline of the metrics.

| Stage | What gets added | Measured by |
|---|---|---|
| 1 capture | More importers: `candump -L`, Saleae async-serial CSV, hex dumps. Direction and channel. | Importer tests over fixtures. |
| 2 checksums | Sums (8 and 16 bit, two's complement), XOR and LRC, Fletcher, Adler, Internet checksum, LIN classic and enhanced. CRCs with a hidden seed byte. Checksums written as ASCII hex. Recovery of uncatalogued polynomials (algebraically, from frames that differ in one byte). | Identified, or honestly unknown; false positives on noise. |
| 3 segmentation | Clustering of inter-byte gaps into "inside a frame" and "between frames". Delimiters and byte stuffing. Length-field-guided and checksum-guided segmentation for captures without timing. Direction and channel. | Boundary precision and recall; behaviour on noise. |
| 4 discovery | Message-type clustering (by ID, first bytes, length), entropy per type instead of over the mixture. Variable-length fields: length-prefixed, TLV, delimiter-separated text. Bit-level fields. | Field-boundary precision and recall. |
| 5 typing | Constants, enums, counters, timestamps, lengths, floats (IEEE 754 plausibility), ASCII text, flag sets; endianness, signedness, scale. Request/response pairing (a request for N registers gets 2N bytes back). | Accuracy per kind, and the *unknown* rate on opaque payload. |
| 6 export | Wireshark Lua dissector, DBC for CAN, a C++ header (embedded-friendly: fixed arrays, no heap, no exceptions), JSON. | Round trip: re-parsing the original capture with the generated artefact reproduces its bytes. The generated C++ is compiled as strict C++11 in CI. |

### An idea to try, not a commitment

When several segmentations or field layouts compete, choose the one that
describes the capture in the fewest bits (minimum description length). It is
the same thinking as the bits of evidence in the CRC stage, and it could give
stages 3 to 5 one shared objective. Worth trying while building 3 and 4.

## The synthetic corpus

Two kinds of synthetic data, both generated from models with a known answer.

**Named protocols** are the anchors. They are documented, so the answer is
verifiable, and each one stresses something different. The parameters of each
(polynomials, seeds, framing bytes) are checked against its specification and
published test vectors before it enters the corpus.

| Protocol | Framing | Checksum | What it stresses | Wave |
|---|---|---|---|---|
| Modbus RTU | idle gap | CRC-16/MODBUS, little-endian | timing segmentation, function-code discriminator, request/response lengths | skeleton |
| NMEA 0183 | `$` … `*hh` CRLF, text | XOR, written as ASCII hex | text framing, variable-length comma-separated fields | 1 |
| SLIP | `0xC0` delimiter, `0xDB` escape | none | byte stuffing | 1 |
| HDLC / PPP async | `0x7E` flag, `0x7D` escape | CRC-16/X-25 | stuffing, then a CRC over the de-stuffed bytes | 1 |
| MAVLink 1 and 2 | start byte and length | CRC-16 with a per-message extra seed | a hidden seed, sequence counter, length field, message-id discriminator | 1 |
| u-blox UBX | two sync bytes and a length | Fletcher-8 | sync bytes, a non-CRC checksum | 1 |
| Modbus ASCII | `:` … CRLF, hex text | LRC | text framing with hex-encoded fields | 2 |
| Modbus TCP | MBAP header with a length | none | transaction counter, length field, no checksum | 2 |
| LIN | break and sync byte | classic and enhanced sum | a protected ID with derived parity bits, short frames | 2 |
| Dynamixel 1.0 and 2.0 | header bytes | inverted sum, CRC-16 | header-pattern stuffing in 2.0 | 2 |
| SBUS | fixed length | none | 16 channels of 11 bits packed across bytes: fields that are not byte-aligned | 2 |
| CAN with DBC-style signals | already framed by the controller; 11- or 29-bit ID | counter and CRC inside the payload | multiplexing by ID, Intel and Motorola byte order, scale, alive counters | 2 |
| DMX512 | break, start code, up to 512 slots | none | long frames with sparse structure | 3 |

**Parametric random protocols** matter more than any list: a generator of
protocol *shapes*, which picks a framing (gap, delimiter, length prefix,
stuffing), a header (magic, version, counter, timestamp), a type discriminator
with a layout per type, field kinds, endianness, a checksum family and
coverage, bit-packed fields. Thousands of seeds give what a handful of named
protocols cannot: the odd, undocumented-looking cases the tool is for.

Rules for both:

- **Generators and inference share no code.** A bug copied into both would
  make the tests agree and be wrong. Reference checksums are checked against
  published check values and an independent implementation.
- **Noise is a parameter:** timing jitter, corrupted bytes, lost frames.
- **Negative controls:** random bytes, and payloads that look encrypted or
  compressed, must produce "no structure".
- **Deterministic seeds**, so a failure in CI reproduces locally.

**Real captures.** `tests/corpus/` is for them. A capture comes with a
provenance note (device, bus, licence) and must contain nothing personal or
secret. Real data is the check that the synthetic corpus is not flattering the
tool.

## Track B: independent features

These do not go through the skeleton. Each is built and finished on its own,
later, and several will lean on code written for Track A.

| | Feature |
|---|---|
| B1 | **Stimulus labelling.** The user notes "at t=12.3 s I pressed the button"; changes in a field are correlated with those events. This is what a human reverse engineer does by hand. |
| B2 | **Session state machines.** Handshakes and message-type sequences, learned from the capture. |
| B3 | **Live capture** (SocketCAN, serial) and **UART parameter detection** (baud rate, parity, stop bits) from raw logic-analyser samples. |
| B4 | **Bit-level framing.** Raw CAN samples, bit stuffing and non-byte-aligned checksum fields: the limitation the README documents. |
| B5 | **Python bindings**, for notebooks and plotting, through [bridgefex](https://github.com/juanlumc1988/bridgefex) and a facade of handles and accessors. Tried and working on Linux for the CRC stage; see [Related projects](#related-projects-no-shared-code). |
| B6 | **rewind-mcu interop**, through a neutral capture format. See below. |
| B7 | **Qt viewer**, with fields coloured by inferred type. A separate target behind an option: `bw_core` stays free of Qt. |

## Delivery

- **Pull requests.** One concern each, reviewable in one sitting, around 800
  changed lines at most, not counting vendored code, fixtures and golden
  files. `main` stays green and releasable after every merge. A stage stays
  behind its interface until it is wired in, so unfinished work never reaches
  the command line.
- **The skeleton is three pull requests,** along its seams:
  1. the capture model, importers, model type, generators and evaluation
     harness: the test infrastructure;
  2. the skeleton stages and `bitwise analyze`;
  3. the Kaitai exporter, round-trip checking, a README demo and a release.
- **Deepening** is one pull request per stage per wave of protocols, each with
  its corpus additions and the new metrics baseline. **Track B** is one pull
  request per feature, or a short series for the large ones.
- **Versions.** A minor version once the skeleton works, and one per completed
  wave afterwards. 1.0 when the API is stable and the stages meet thresholds
  across the corpus. The thresholds are set once the harness gives a baseline,
  not before.

## Related projects (no shared code)

Same author, different jobs. None of them shares a library with this one, for
the reason the README gives for `rewind-mcu`.

- **[rewind-mcu](https://github.com/juanlumc1988/rewind-mcu)** records what
  crosses a microcontroller's hardware boundary. A trace of firmware that reads
  a UART's data register is, in effect, a capture of the bytes that arrived,
  with cycle-accurate timing, and with the timing shaped by what the firmware
  does. That makes it a possible source of synthetic captures more physical
  than a generator's. Today only its toy simulator produces them; traces from
  real silicon are its own future. The meeting point is a **neutral capture
  format**, defined in stage 1: an exporter on the `rewind` side and an importer
  here, with no shared code.
- **[bridgefex](https://github.com/juanlumc1988/bridgefex)** generates a pure C
  layer and Python bindings from C++ headers. It was tried against `bw_core`
  0.1.0 (bridgefex at `f18687b`, libclang 20.1.2, Python 3.13), in three steps.

  1. **The headers as they are are rejected.** It is all-or-nothing, so it
     generated nothing, and it reported 28 errors:
     - 15 type aliases: `bw::u8`, `u16`, `u32`, `u64`;
     - 7 methods on value structs: `Layout` (5) and `SearchReport` (2);
     - 4 raw pointers: the `data` parameter of `crc_compute`, the results of
       `catalog()` and `catalog_find()`, and `Candidate::spec`;
     - 1 string member: `CrcSpec::name`, a `const char*`;
     - 1 container inside a value struct: `SearchReport::candidates`.

     With the aliases replaced by the `<cstdint>` types they stand for, 14
     errors remain: the 13 above that are not aliases, plus the `std::vector`
     inside `Frame`, which an alias error had been hiding. The count and the
     text of the errors are identical before and after bridgefex gained its
     Python directors, which did not touch the supported subset.
  2. **A facade of handles and accessors is accepted.** This shape, a class
     that owns the frames and the report privately and exposes them through
     accessors, generated 11 files:

     ```cpp
     // abridged: the constructor and the includes are left out
     struct Match {                       // plain value struct: scalars only
         std::uint32_t header_skip;
         std::uint32_t trailer_skip;
         std::uint32_t width;
         bool          big_endian;
     };
     class Search {
     public:
         void add_frame(const std::vector<std::uint8_t>& bytes);
         void run();
         std::size_t         candidate_count() const;
         std::string         candidate_name(std::size_t index) const;
         Match               candidate_layout(std::size_t index) const;
         std::vector<Match>  layouts() const;
         std::uint32_t       evidence_bits() const;
         bool                confident() const;
     private:
         std::vector<bw::Frame> frames_;  // types bridgefex does not wrap are fine here
         bw::SearchReport       report_;
     };
     ```

     The generated C layer, built with the facade and the `bw_core` sources
     into a shared library (`g++ -std=c++17 -fPIC -fvisibility=hidden -Wall
     -Wextra`), compiles without warnings and exports the 16 C functions and
     no `bw::` or `bwf::` symbol.
  3. **It works from Python,** checked end to end against the `bitwise` CLI,
     which is the direct C++ path, on the same frames. Given two real Modbus
     RTU requests, the bindings report CRC-16/MODBUS with header 0, trailer 0,
     16 bits, little-endian, with the same candidates, the same evidence (32
     bits) and the same verdict as the CLI. A corrupted CRC byte and random
     bytes give no candidate, as in the CLI. A C++ exception (`.at()` out of
     range) arrives as `bwf.Error`. 300 create/destroy cycles complete. The
     same 11 checks pass with the library built with ASan and UBSan and no
     finding (leak detection off, because the interpreter leaks by design;
     libstdc++ has to be preloaded, because Python does not link it).

  Not tried: any platform other than Linux x86-64, threads, callbacks and
  directors, large captures, Python versions other than 3.13. To repeat the
  first step, from a directory holding `include/bw/`:

  ```console
  bridgefex --module bw --output out --std c++17 -I include --include-root include \
      include/bw/types.h include/bw/crc.h include/bw/catalog.h include/bw/crc_search.h
  ```

  A gap found when binding is also feedback for bridgefex.

- **[mirrortest](https://github.com/juanlumc1988/mirrortest)** generates test
  and class stubs for GoogleTest and Qt Test. This project's tests use
  doctest, so the tool itself does not apply. Two things carry over: its
  principles for generated output (deterministic, never pretend, all-or-nothing
  writes, golden tests, compile-checking what it emits), which the exporters
  adopt; and its CI recipe for Qt 5 and 6 (`qt6-base-dev`, `qtbase5-dev`),
  which is the starting point for B7.

## Non-goals

- Decryption, or defeating any protection.
- Injecting traffic into a live bus. Live *capture* (B3) is passive.
- Replacing Wireshark, Kaitai Struct or DBC tools. The output is for them.
- Dissecting protocols that already have complete, standard descriptions
  (TCP/IP and the like).

## Prior art to read first

Field and message-format inference: Netzob, Discoverer, AutoFormat,
BinaryInferno. CRC recovery: CRC RevEng. CAN signal reverse engineering: READ
and LibreCAN. The point of reading them before designing stages 3 to 5 is to
learn where they failed, so the corpus can contain those cases.

## Open questions

- The neutral capture format: columns, units, how direction and channel are
  written.
- How evidence is represented across stages: bits, probabilities, or both.
- How alternatives are carried between stages without the cost exploding.
- Whether a model has its own serialisation, for storing an inference and
  diffing it against a ground truth.
- Whether minimum description length earns its place (see above).
