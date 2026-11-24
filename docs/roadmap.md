# Roadmap

This is a plan, not a record of what exists. What works today is in the
[README](../README.md): the skeleton of the pipeline, end to end, on synthetic
Modbus RTU captures. What is described below beyond it is intended and
unwritten, and the order is a proposal that the first results are allowed to
change.

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
| 2 checksums | The existing CRC search, run over the segmented frames of each size. |
| 3 segmentation | Split at the large idle gaps: the widest hole, in ratio, between the short gaps and the long ones. |
| 4 discovery | Byte-offset statistics among frames of the same length; a run of bytes with no structure is one field. |
| 5 typing | Constant, enum, counter; payload, which claims nothing, for the rest. |
| 6 export | Kaitai Struct. |

Two things changed from the first plan, both for the same reason: a first
version should not claim what it cannot support. Frames are grouped by length
alone, not by length and first byte: in Modbus the first byte is an address, and
grouping by it would split one message type into one per device. And a length
field cannot be told apart from a constant among frames of one length, so
typing it waits for frames of varying length, with the message-type work in the
deepening of stage 4.

It also brings the pieces that are not stages: the model type, a Modbus RTU
generator, the evaluation harness and `bitwise analyze`. The parametric
generator waits for the first deepening step: the skeleton needs one protocol,
not a family of them.

**Done when** `bitwise analyze` on synthetic Modbus RTU captures recovers the
framing, the checksum and the field boundaries of the generator's model, and
the exported definition parses the capture back into the same bytes.

Both halves are met. The first (`tests/test_analyze.cpp`): on 100 captures of 50 frames
(25 seeds, four levels of timing noise up to the generator's maximum), every
frame is found exactly, every boundary of the true model is found, and the
checksum matches in position, size, byte order, coverage and algorithm. The
found model has one boundary more than the truth: the high byte of the quantity
is always 0, so it is a constant of its own, and nothing in a capture says it
belongs with the byte after it. That is the baseline stage 4 starts from.

The second (`tests/roundtrip/kaitai_roundtrip.py`) is checked with the real Kaitai
tools, not with an interpreter of ours. For nine synthetic Modbus RTU captures (three
seeds, three noise levels) of 50 frames, `bitwise export` writes the definition, the
official compiler (the JavaScript build, 0.11) accepts it and makes a Python parser,
and the parser reads each of the 450 frames, uses all of it, and gives back the frame's
bytes. Reading back alone cannot tell a wrong byte order from a right one, since a
number read one way is written the same way, so the script also checks that what the
parser reads as the checksum is the CRC-16/MODBUS of the frame, worked out in the
script. A second capture with constant bytes before and after the CRC checks that the
constants are `contents` and that the parser refuses a frame where they are wrong, and
a third definition, checked in and compared with the exporter's output by the unit
tests, holds every kind of field the exporter writes (all the integer and float widths
and byte orders, text, bytes, constants of several bytes in both orders) and is read
with expected values. The script is a job of the CI workflow, with the compiler and
the runtime at fixed versions.

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
| NMEA 0183 | `$` … `*hh` CRLF, text | XOR-8, written as ASCII hex | text framing, variable-length comma-separated fields | 1 (done) |
| SLIP | `0xC0` delimiter, `0xDB` escape | none | byte stuffing | 1 (done) |
| HDLC / PPP async | `0x7E` flag, `0x7D` escape | CRC-16/X-25 | stuffing, then a CRC over the de-stuffed bytes | 1 (done) |
| MAVLink 1 and 2 | start byte and length | CRC-16 with a per-message extra seed | a hidden seed, sequence counter, length field, message-id discriminator; in 2, payloads cut of their trailing zeros | 1 (done) |
| u-blox UBX | two sync bytes and a length | Fletcher-8 (FLETCHER-8) | sync bytes, a non-CRC checksum | 1 (done) |
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
  changed lines of code at most, not counting tests, documentation, vendored
  code, fixtures and golden files: tests are as large as what they test and
  are read differently. `main` stays green and releasable after every merge. A stage stays
  behind its interface until it is wired in, so unfinished work never reaches
  the command line.
- **The skeleton is five pull requests,** along its seams. It was three until
  the size limit above said otherwise, then four:
  1. the capture model and its file format (done: see
     [capture-format.md](capture-format.md));
  2. the model type and the evaluation harness (done: `bw/model.h` and
     `bw/evaluate.h`);
  3. the protocol registry, the Modbus RTU generator and `bitwise synth` (done:
     `bw/protocol.h` and `bw/dataset.h`);
  4. the skeleton stages and `bitwise analyze` (done: `bw/segmentation.h`,
     `bw/checksum.h`, `bw/fields.h` and `bw/analyze.h`);
  5. the Kaitai exporter, round-trip checking, a README demo and a release
     (done: `bw/kaitai.h` and `tests/roundtrip/`; the release is 0.2.0).
- **Deepening** is one pull request per stage per wave of protocols, each with
  its corpus additions and the new metrics baseline. **Track B** is one pull
  request per feature, or a short series for the large ones.
- **Wave 1** (NMEA 0183, SLIP, HDLC/PPP, MAVLink 1 and 2, UBX) goes in this
  order, each step with its corpus and its change to the baseline below:
  1. the model says contiguous, terminated and flagged framing, and UBX and
     MAVLink 1 are generated, with an independent implementation and the
     baseline (done: `bw/model.h`, `tests/mirror/mirror.py`);
  2. NMEA 0183 (text, fields of varying length, some of them empty, and a
     checksum written as two hex characters, which the model now can say; done:
     `src/protocols/nmea0183.cpp`), then MAVLink 2 (flags, a message id of
     three bytes, and a payload whose trailing zeros are cut, so that frames of
     one message differ in length; done: `src/protocols/mavlink2.cpp`);
  3. SLIP and HDLC/PPP (byte stuffing: the model describes the frame as it is
     once the stuffing is taken out; done: `src/protocols/slip.cpp` and
     `src/protocols/hdlc_ppp.cpp`);
  4. stage 3, in three steps, all done. (a) Frames bounded by a flag on both sides,
     which is what SLIP and HDLC have (`segment_by_flags` in `bw/segmentation.h`).
     (b) Frames that start with a sync byte and say their length, which is what
     UBX and MAVLink have (`segment_by_sync`): from a sync byte the stage follows
     the chain, from where each length says a frame ends to the next sync byte,
     and it is the framing when the chain covers the capture with almost no break.
     A sync byte that happens to occur inside a payload breaks nothing, and a frame
     starts where the byte before it stops being the same: UBX is found at 0xB5 and
     not at the 0x62 after it, which makes as many frames, each shifted. (c) What
     was left: a terminator and a flag that two frames share, which are, in the
     bytes, a byte that occurs once in each frame, and such a byte cuts the frame
     somewhere that the bytes alone do not tell: on 200 NMEA sentences a line feed,
     a carriage return, `$` and `P` all make 200 frames, and on shared-flag HDLC
     `0x7E`, `0xFF` and `0x03` do. Two pieces of evidence settle them. A flag is a
     flag when the capture shows its stuffing: an escape byte that is always
     followed by one of two codes, both seen (the two ways known are RFC 1662's, the
     flag and the escape with bit 5 flipped, and SLIP's C0 DB DC DD), which a
     capture of text does not have, whatever its carriage returns and line feeds
     (a line feed is the star with bit 5 flipped, and one of the two codes is not
     enough: a first version took the star of an NMEA capture for a flag). The model
     gets the escape and its codes. And text is cut in lines, which end with a line
     feed with the carriage return before it, by convention: a terminator of
     another kind (an ETX, a NUL after binary data) is not found. The pipeline cuts
     by flags if the capture has them, by gaps if it has them, and by a sync byte
     and a length or by lines if not, or where they cut the gaps' frames finer;
  5. stage 2, in steps. (a) Done: the later stages read the frames as the protocol
     sends them (`frame_contents` in `bw/segmentation.h`: flags off, stuffing
     undone), and the catalogue has CRC-16/IBM-SDLC (X-25), the FCS of HDLC, PPP and
     X.25, so that the FCS of PPP is found in every kind of frame. (b) Done: the sums
     that are not CRCs (`bw/sums.h`: XOR-8, SUM-8, SUM-8/NEGATED, FLETCHER-8,
     FLETCHER-16), searched with the CRCs, as bytes (a byte, or two in either
     order) and, those of a byte, as two hexadecimal characters with or without a
     byte of separator between what they cover and them: Fletcher-8 of UBX, and the
     `*hh` of NMEA. A sum that is the first byte of a wider one over the same bytes
     (Fletcher's first sum is the plain sum) is a part of it and not a second
     answer. The rest, in the order it is likely to go in: more CRCs of the
     catalogue; and a CRC with a hidden seed byte (MAVLink's CRC_EXTRA), which needs
     the frames grouped by message id and so belongs partly to stage 4. Modbus
     ASCII's LRC is over the bytes that its hexadecimal text stands for, which is
     wave 2;
  6. stages 4 and 5: length fields, fields of varying size, text, and the
     numbers of two bytes whose high byte never changes.
- **Versions.** A minor version once the skeleton works, and one per completed
  wave afterwards. 1.0 when the API is stable and the stages meet thresholds
  across the corpus. The thresholds are set once the harness gives a baseline,
  not before.
- **Where it ends.** The pipeline is finished when 1.0 is: the three waves, the
  parametric generator (which matters more than any list of protocols), and the
  thresholds. Track B is independent and optional, feature by feature. The
  largest unknown is not in this list: no real capture has gone through the tool
  yet, and a few should before wave 3, because a synthetic corpus can only flatter
  what its author thought of.

### Wave 1 baseline

Stage 3 against the captures of UBX and MAVLink 1, and stages 2, 4 and 5 given
the true frames (`analyze_frames`), on 200 frames of seed 3 and without timing
noise. A boundary is a place where a field starts or ends; `exact` is a found
field with the position and size of a true one, `kind` also its kind. Pinned by
`tests/test_analyze.cpp`, which a pull request that improves a number changes.

| Protocol, message | Frames found by gaps | By sync byte and length | Checksum | Fields, truth / found | Boundaries, truth / found / hit | Exact | Kind |
|---|---|---|---|---|---|---|---|
| UBX ACK-ACK | none | exact | 2 candidates | 8 / 10 | 9 / 11 / 9 | 6 | 5 |
| UBX CFG-RATE | none | exact | Fletcher-8 | 9 / 13 | 10 / 14 / 10 | 5 | 5 |
| UBX NAV-STATUS | none | exact | Fletcher-8 | 13 / 21 | 14 / 22 / 14 | 9 | 6 |
| MAVLink 1 HEARTBEAT | none | exact | none | 13 / 16 | 14 / 17 / 14 | 12 | 8 |
| MAVLink 1 SYS_STATUS | none | exact | none | 20 / 37 | 21 / 38 / 20 | 6 | 4 |
| MAVLink 1 ATTITUDE | none | exact | none | 14 / 23 | 15 / 24 / 15 | 7 | 4 |

The checksum column is stage 2, searching the CRCs of the catalogue and the sums
that are not CRCs (`bw/sums.h`). UBX's Fletcher-8 is found in two of its three
messages, in the same position, width, order, coverage and algorithm as the truth,
and in the same two kinds of the 30 frames of the corpus. ACK-ACK has 3 different
frames among its 60, and the same bytes are explained by Fletcher-8 and by
Fletcher-16, which differ only when a sum reaches 255: with 48 bits of evidence
and two candidates it says it cannot tell, and that is the right answer. MAVLink's
CRC has a seed that nothing in the frame holds, so it is none.

The first of the two frame columns is stage 3 by gaps, which finds nothing in a
capture whose frames follow one another with nothing between them; the second is
stage 3 by a sync byte and a length (UBX at 0xB5, a length of one byte at offset 4
plus 8; MAVLink 1 at 0xFE, offset 1 plus 8), which finds every frame, and only
the true ones: 200 of 200 on seeds 1 to 4, with and without timing noise. What
the later columns say is the same whether the frames are the true ones or the
ones found, which is how they are pinned (`tests/test_sync.cpp` compares them).

MAVLink 2 has the same two columns, none and exact, and one of its own: the
payload is cut of its trailing zeros, so one message has frames of several
sizes. Its sync byte is 0xFD and the length is at offset 1 plus 12, and the
frames are found exactly. On 300 frames of seed 3 the true frames of the four
messages have seven sizes, and the stages, which group by size, make seven message
types of them; no checksum.

NMEA 0183 is of another kind and has its own baseline, on 90 sentences of
seed 3: by gaps, 30 frames are found where there are 90, none of them a true
sentence (they are the seconds, three sentences each), and every cut it makes is
a real one, so 31 of the 91 true boundaries are hit. By lines, which is what the
pipeline cuts text into, every sentence is found and only them: 200 of 200 on
seeds 1 to 4, and the pipeline takes the lines over the gaps because they cut at
every place the gaps do and in more. With the true sentences given, or the ones
found, the stages group them by size, and the sentences of two kinds share
sizes: they make seven message types where there are three, and the exclusive or
is found in every one of the seven, written as two hexadecimal characters after
the star, with the dollar not covered (header skip 1), the star not covered
either (a gap of one byte) and the line end after (trailer skip 2): the evidence
is 8 bits for each different sentence, since the two characters hold a byte. Scoring the
fields of a sentence needs the harness to place fields that have no fixed place,
which is part of stage 4, so the checksum does not yet count as matching the
truth.

SLIP and PPP in HDLC-like framing are the first protocols with byte stuffing. On 300
frames of seed 3 the line has a byte every character time throughout, so no gap is found,
with or without timing noise, but both are cut exactly by their flags (stage 3): on 200
frames of seeds 1 to 4, with and without timing noise, every frame found is a true frame,
and the idle flags of PPP are in none. A flag or an escape in the data costs a byte more,
so frames of one kind differ in size on the line: SLIP's status frames are 12 bytes and
sometimes 13, its sample frames 21 and sometimes 22 or 23, and PPP's LCP echo is always 17
bytes or more because its magic number holds a flag byte. Read as they come, the stages,
which group by size, make three message types for SLIP's two records and four for PPP's three,
leave out the frames of the rarest sizes, and find the FCS of PPP only in the frames that
had nothing to stuff, with the flags skipped (the types of 18 and 32 bytes). Read as the
protocol sends them (`frame_contents`: the flags off and the stuffing undone, which is what
the model describes and what a CRC is taken over), SLIP has its two types, of 19 and 10
bytes, and PPP its three, of 14, 16 and 30, none of them left out, and **the FCS of PPP is
found in all three** (CRC-16/IBM-SDLC, 16 bits, little-endian, from the address): the same
checksum as the truth, in position, width, order, coverage and algorithm. Before that the
catalogue had no CRC-16/X-25, the FCS of HDLC, PPP and X.25, and the search was over the
bytes with their stuffing in.

| Protocol, message | Checksum | Fields, truth / found | Boundaries, truth / found / hit | Exact | Kind |
|---|---|---|---|---|---|
| SLIP sample | none | 9 / 6 | 10 / 7 / 4 | 1 | 1 |
| SLIP status | none | 5 / 9 | 6 / 10 / 6 | 2 | 2 |
| PPP LCP echo | CRC-16/IBM-SDLC | 8 / 13 | 9 / 14 / 9 | 5 | 5 |
| PPP IPCP request | CRC-16/IBM-SDLC | 10 / 15 | 11 / 16 / 11 | 7 | 7 |
| PPP IP datagram | CRC-16/IBM-SDLC | 5 / 6 | 6 / 7 / 6 | 4 | 4 |

On 200 frames of seed 3, cut by the stage as it is; pinned by `tests/test_unstuff.cpp`. The
SLIP rows are low because their fields are numbers that the stages do not yet type (a sequence
number of 16 bits whose high byte never changes, a time in milliseconds, readings of 16 bits
that are random): the checksum column is as good as it can be, and the rest is for stages 4 and 5.

Nothing is found by gaps in the binary protocols because there are none: the frames follow one another
at the pace of the line. With the frames given, no checksum is found for lack
of the algorithm, and the fields are cut too fine and typed with few of the
kinds the truth has: a two-byte number with a high byte that never changes is two
fields, an incrementing time is a counter, and the lengths, the sequence number
and the floats come out as constants and payload. Every step of the list above
moves a column of this table.

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

  **The skeleton's headers** were tried afterwards, with bridgefex at
  `adb22af`, libclang 20.1.2 and Python 3.13, and two small remedies came out of
  it, both now in the repository:

  - `CaptureError` derives from `std::runtime_error`, which cannot be wrapped.
    It has a header of its own, `bw/capture_error.h`, that is not given to
    bridgefex; `capture.h` includes it, so nothing changes for a C++ user, and
    exceptions reach Python as `bw.Error` with their message.
  - `find_protocol` returns a raw pointer to a wrapped class, so an annotations
    file, `bindings/annotations.toml`, says who owns it: it is borrowed.

  With those, bridgefex accepts `capture.h`, `model.h`, `evaluate.h`,
  `dataset.h`, `protocol.h`, `segmentation.h`, `checksum.h`, `fields.h`,
  `analyze.h` and `kaitai.h` as they are, together (a header that uses a class
  of another is refused when given alone) and generates 45 files. The shared library built
  from them and `bw_core` works from Python: a synthetic Modbus RTU capture
  generated and analysed there gives a report byte for byte the one `bitwise
  analyze` prints, its Kaitai definition is the one `bitwise export` writes, `find_protocol` returns the borrowed protocol, and an
  unknown protocol name and a malformed capture raise `bw.Error` with the
  library's message. The stage headers were written to the shape rule above,
  and that is what made this work without a facade. Not run on these headers:
  the sanitizers and any other platform.

  **After the first step of stage 3** (segmentation by flags, which added two
  functions and three fields to `segmentation.h`) the same command generated the
  same 45 files without a change to the headers or the annotations. From Python,
  over the shared library built from them, SLIP and PPP captures of 300 frames
  were cut by flags (`segment_by_gaps` found nothing, `segment_by_flags` and
  `segment_frames` found the 300 frames, the flag and its count), the model's
  framing came out as `FramingKind.Flagged` with its byte, and
  `describe_analysis` printed the same flags line as the CLI; a Modbus RTU
  capture was still cut by gaps. 18 checks, all passing, with the same libstdc++
  preload as before.

  **After the sync byte and length of stage 3** (`segment_by_sync`, one more
  option and seven more fields in `SegmentationInfo`) it was the same again: the
  same 45 files, no change to the headers or the annotations. From Python, 38
  checks pass: UBX, MAVLink 1 and MAVLink 2 captures of 300 frames with timing
  noise are cut at their sync byte (`segment_by_gaps` and `segment_by_flags` find
  nothing, `segment_by_sync` and `segment_frames` the 300 true frames, with the
  byte, the offset of the length and what is added to it), the model's framing is
  `FramingKind.Contiguous`, `describe_analysis` prints the same line as the CLI,
  SLIP and PPP are still cut by their flags, and Modbus RTU by its gaps.

  **After the stuffing and the lines of stage 3** (`segment_by_lines`, one more
  option and four more fields in `SegmentationInfo`) it was the same once more:
  the same 45 files, no change to the headers or the annotations. From Python, 24
  checks pass: the stuffing of SLIP and PPP (the escape and its two codes) in the
  info of the segmentation and in the model's framing, the sentences of NMEA cut
  by lines where the gaps find the seconds (the 90 true sentences, the byte, the
  count), `FramingKind.Terminated` as an enum, the line of `describe_analysis`, and
  UBX, MAVLink and Modbus RTU as before.

  **After the unstuffing of stage 2** (`frame_contents`, a function that returns a
  `Capture`, which bridgefex already wraps) it was the same once more: the same 45
  files, no change to the headers or the annotations. From Python, 16 checks pass:
  `frame_contents` of SLIP and PPP, with one event per frame and the sizes the
  protocols have once unstuffed (19 and 10; 14, 16 and 30), `analyze` finding their
  types, the FCS of PPP in each of the three (`CRC-16/IBM-SDLC`, 16 bits, from the
  address to the end), and the frames of UBX as they are.

  **After the simple checksums** (`ChecksumFinding` gets `ascii_hex` and
  `gap_bytes`, and `FieldRegion` gets `ascii_hex`) it was the same once more: the
  same 45 files, no change to the annotations, and the two new fields in the
  dataclasses. From Python, 19 checks pass: the exclusive or of NMEA in each of
  its seven types (`XOR-8`, as text, 16 bits on the line and 8 of evidence each,
  after the dollar and the star and before the line end), the checksum of the
  model as text covering from the first character after the dollar, the
  `describe_analysis` line, the export of that checksum as two characters, the
  Fletcher-8 of UBX in the two types that have it (header skip 2, little-endian)
  and the third type with two candidates, the names of the algorithms past the
  catalogue (the five sums, and an error after them), and Modbus RTU, PPP and
  MAVLink 1 as before. `bw/sums.h` is not bound: nothing in it is needed from a
  binding that `checksum_algorithm_name` does not say.

  Not tried: any platform other than Linux x86-64, threads, callbacks and
  directors, large captures, Python versions other than 3.13. To repeat the
  first step, from a directory holding `include/bw/`:

  ```console
  bridgefex --module bw --output out --std c++17 -I include --include-root include \
      include/bw/types.h include/bw/crc.h include/bw/catalog.h include/bw/crc_search.h
  ```

  For the headers of the skeleton, from the root of the repository:

  ```console
  bridgefex --module bw --output out --std c++17 -I include --include-root include \
      --annotations bindings/annotations.toml \
      include/bw/capture.h include/bw/model.h include/bw/evaluate.h include/bw/dataset.h \
      include/bw/protocol.h include/bw/segmentation.h include/bw/checksum.h \
      include/bw/fields.h include/bw/analyze.h include/bw/kaitai.h
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

Two are no longer open. The neutral capture format is specified in
[capture-format.md](capture-format.md). Evidence is a count of bits, as it
already is in the CRC stage: `FieldInfo::evidence_bits` in `bw/model.h`, left at
0 in a ground truth.

- How alternatives are carried between stages without the cost exploding.
- Whether a model has its own serialisation, for storing an inference and
  diffing it against a ground truth.
- Whether minimum description length earns its place (see above).
