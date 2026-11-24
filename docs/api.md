# API and what 1.0 freezes

From 1.0.0 the library follows [semantic versioning](https://semver.org/): what
is listed as frozen below does not change in a 1.x release, and a change to it is
2.0. `find_package(bitwise-bus 1 CONFIG REQUIRED)` accepts any 1.x (the package
version file is `SameMajorVersion`).

## The headers

Every header under `include/bw/` is installed and public. They are plain C++11
(each one compiles by itself, which the package check builds on every platform),
and the library is built as C++17 and ships as a static library only.

| Header | What it is | Bound with bridgefex |
|---|---|---|
| `capture.h`, `capture_error.h` | the capture model, the CSV reader and writer, the error it throws | yes (the error through `capture.h`) |
| `model.h` | the model of a protocol: framing, message types, fields | yes |
| `evaluate.h` | scoring a found segmentation or model against a truth | yes |
| `dataset.h` | a capture with its truth | yes |
| `protocol.h` | the six named protocols: their models and generators | yes |
| `segmentation.h` | stage 3: gaps, flags, sync and length, lines | yes |
| `checksum.h` | stage 2 over the frames of a capture | yes |
| `fields.h` | stages 4 and 5 over frames of one size | yes |
| `analyze.h` | the pipeline, from a capture to a model | yes |
| `kaitai.h` | the Kaitai Struct exporter | yes |
| `messages.h`, `text.h` | stage 4 for kinds of message of several sizes, and for lines of text; they speak in vectors | no |
| `synthetic.h` | protocols made up from a seed, and noise | no |
| `crc.h`, `catalog.h`, `crc_search.h`, `sums.h`, `types.h` | the CRC and sum engines and the search, with their aliases (`bw::u8`), pointers and methods | no |

The bound headers are the ones written to the rule in the
[roadmap](roadmap.md#shape-of-the-public-api): `<cstdint>` types, plain structs
for what crosses the boundary, collections behind a class. The Python bindings
of a bridgefex run over them are not a part of this package.

## Frozen in 1.x

- The names, signatures and namespaces of every function and type in the
  installed headers, the members of every struct (their names, types, order and
  meaning), and the classes' public members.
- The numeric values of the enumerations, and what each value means. (The
  framing kinds, the field kinds, the size kinds and the byte orders are all in
  `model.h`.)
- The defaults of the options structs (`SegmentationOptions`, `FieldOptions`,
  `SearchOptions`, `AnalyzeOptions`, ...).
- The exceptions a function documents, and the type that it throws.
- The commands and options of `bitwise` (`crc-catalog`, `crc-find`,
  `capture-info`, `protocols`, `synth`, `analyze`, `export`, `--version`), and
  the capture file format ([capture-format.md](capture-format.md)).
- What a model means and what the Kaitai exporter writes for it: the same model
  gives the same bytes, with no timestamp and no path, and a field of the model
  is the Kaitai construct that `kaitai.h` says it is.
- The named protocols: for a seed, a frame count and a jitter, `protocols` and
  `synth` write the same capture on every platform, in every 1.x. (The captures in
  `tests/corpus/` are pinned to the bytes, and a second implementation in Python
  writes them again.)

A new function, type, enumeration value, struct member (at the end), option (with
a default that keeps the old behaviour), command or exporter is a minor version.

## Not frozen

- **What the pipeline infers.** A better stage may find a checksum that was not
  found, put together fields that were apart, or name a type differently, for the
  same capture, in a minor or a patch version. The evidence is in the answer, and
  the tests measure it (see [the baselines](roadmap.md#baseline-over-made-up-protocols)).
- **The words of `describe_analysis` and of what `bitwise` prints**, and the names
  that the pipeline gives (`type0`, `field_12`, `checksum`): they are there to be
  read, and the tests pin them, but they are not an interface to parse. The
  Kaitai definition, which is, has them as `id`s only because Kaitai wants one.
- **`synth random` and `synth random-text`**: protocols made up from a seed are
  what the thresholds are measured on, and a seed may mean another protocol
  in a later version.
- **The bit-exact value of `evidence_bits`** (it is a measure, and is reported,
  not promised).
- **The ABI.** The library is static and the API passes `std::vector` and
  `std::string`, so what is linked has to be built with the compiler and runtime
  of the consumer, which is what the packages are for.

## What 1.0 does not say

It has been measured on synthetic captures with a known answer, and on the
published test vectors of the CRCs. No real capture has gone through it. The
numbers in the README and in the roadmap are what it does on those, and not on a
bus; an answer on a real capture is a hypothesis with its evidence, to be checked
against what the device is known to do.
