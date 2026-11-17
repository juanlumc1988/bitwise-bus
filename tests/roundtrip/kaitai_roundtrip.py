#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.
"""Round trip of the Kaitai exporter, with the real Kaitai tools.

For each capture, `bitwise export` writes a definition, the official Kaitai
Struct compiler turns it into a Python parser, and the parser reads every frame
of the capture. What it read, written back out as bytes with the types the
definition says, has to be the frame, and the parser has to have used all of it.

The frames are taken from the capture here, by what is known of how it was made
(Modbus RTU: eight one-byte events), and not by the pipeline, so that the
segmentation under test is not also the one that checks it.

Needs: the `bitwise` binary, node and the compiler (npm: kaitai-struct-compiler),
and PyYAML and kaitaistruct (pip). CI installs exact versions. Usage:

    kaitai_roundtrip.py --bitwise build/bitwise --compiler node_modules/kaitai-struct-compiler
"""

import argparse
import importlib.util
import json
import pathlib
import struct
import subprocess
import sys
import tempfile

import kaitaistruct
import yaml

HERE = pathlib.Path(__file__).resolve().parent
FAILURES = []


def check(condition, message):
    if not condition:
        FAILURES.append(message)
        print("FAIL: " + message)


def run(args, **kwargs):
    return subprocess.run([str(a) for a in args], capture_output=True, text=True, **kwargs)


def class_name(ksy_id):
    return "".join(part.capitalize() for part in ksy_id.split("_"))


def compile_ksy(text, compiler, work):
    """The parser class that the Kaitai compiler makes of a definition."""
    definition = yaml.safe_load(text)            # also says the YAML is valid
    ksy_id = definition["meta"]["id"]
    (work / (ksy_id + ".json")).write_text(json.dumps(definition))
    done = run(["node", HERE / "compile.js", compiler, work / (ksy_id + ".json"), work])
    if done.returncode != 0:
        raise RuntimeError("the Kaitai compiler refused %s: %s" % (ksy_id, done.stderr.strip()))
    spec = importlib.util.spec_from_file_location(ksy_id, work / (ksy_id + ".py"))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return definition, getattr(module, class_name(ksy_id))


TYPE_FORMATS = {"u1": "B", "u2be": ">H", "u2le": "<H", "u4be": ">I", "u4le": "<I",
                "u8be": ">Q", "u8le": "<Q", "f4be": ">f", "f4le": "<f", "f8be": ">d", "f8le": "<d"}


def pack(entry, value):
    """The bytes a parsed field stands for, from its entry in the definition."""
    if "contents" in entry:
        return bytes(value)
    kind = entry.get("type")
    if kind in TYPE_FORMATS:
        return struct.pack(TYPE_FORMATS[kind], value)
    if kind == "str":
        return value.encode("ascii")
    return bytes(value)                          # `size`: raw bytes


def read_back(definition, parser, frame):
    obj = parser.from_bytes(frame)
    consumed = obj._io.pos()
    out = b"".join(pack(entry, getattr(obj, entry["id"])) for entry in definition["seq"])
    return obj, consumed, out


def frames_of_capture(text, size):
    """The bytes of a capture of one-byte events, cut every `size` of them."""
    data = []
    for line in text.splitlines():
        if line.startswith("#") or line.startswith("time_ns"):
            continue
        data.append(int(line.split(",")[-1], 16))
    return [bytes(data[i:i + size]) for i in range(0, len(data) - size + 1, size)]


def verify_frames(label, definition, parser, frames, meaning=None):
    """Every frame is read, used up and written back to the same bytes.

    That alone cannot tell a byte order that is wrong from one that is right, since
    a number read one way is written back the same way. `meaning` is what does: it is
    given the parsed frame and the frame, and says what is true of the values that the
    capture is known to hold, from outside the exporter."""
    for number, frame in enumerate(frames):
        try:
            obj, consumed, rebuilt = read_back(definition, parser, frame)
        except (kaitaistruct.KaitaiStructError, EOFError) as error:
            check(False, "%s frame %d: the parser failed: %s" % (label, number, error))
            continue
        check(consumed == len(frame) and obj._io.is_eof(),
              "%s frame %d: the parser used %d of %d bytes" % (label, number, consumed, len(frame)))
        check(rebuilt == frame, "%s frame %d: read back as %s, was %s" % (label, number, rebuilt.hex(), frame.hex()))
        if meaning is not None:
            check(meaning(obj, frame), "%s frame %d: the values read are not the ones the frame holds" % (label, number))
    print("%s: %d frames read back, %d fields each" % (label, len(frames), len(definition["seq"])))


def modbus(bitwise, compiler, work):
    for seed in (1, 2, 3):
        for jitter in (0, 300, 500):
            label = "modbus-rtu seed %d jitter %d" % (seed, jitter)
            capture = run([bitwise, "synth", "modbus-rtu", "--seed", seed, "--frames", 50,
                           "--jitter-permille", jitter]).stdout
            path = work / "modbus.csv"
            path.write_text(capture)
            exported = run([bitwise, "export", path])
            check(exported.returncode == 0, label + ": export failed: " + exported.stderr.strip())
            if exported.returncode != 0:
                continue
            definition, parser = compile_ksy(exported.stdout, compiler, work)
            # Modbus RTU: the last two bytes are the CRC-16/MODBUS of the first six, low byte
            # first, so what the parser calls the checksum has to be that number.
            verify_frames(label, definition, parser, frames_of_capture(capture, 8),
                          lambda obj, frame: obj.checksum == crc16(frame[:6]))


def crc16(data):
    crc = 0xFFFF
    for byte in data:
        crc ^= byte
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def splitmix64(seed):
    mask = (1 << 64) - 1
    state = seed
    while True:
        state = (state + 0x9E3779B97F4A7C15) & mask
        z = state
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & mask
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & mask
        yield z ^ (z >> 31)


def framed(bitwise, compiler, work):
    """Frames with constant bytes before and after: [0x7E] [address] [4 bytes] [CRC] [0x0D]."""
    rng = splitmix64(7)
    frames = []
    for i in range(40):
        body = bytes([1 + i % 3]) + bytes(next(rng) & 0xFF for _ in range(4))
        frames.append(bytes([0x7E]) + body + struct.pack("<H", crc16(body)) + bytes([0x0D]))
    rows = ["# bitwise-capture 1", "time_ns,channel,direction,id,data"]
    now = 0
    for frame in frames:
        for byte in frame:
            rows.append("%d,,,,%02x" % (now, byte))
            now += 1000
        now += 99000
    path = work / "framed.csv"
    path.write_text("\n".join(rows) + "\n")
    exported = run([bitwise, "export", path, "--id", "framed"])
    check(exported.returncode == 0, "framed: export failed: " + exported.stderr.strip())
    if exported.returncode != 0:
        return
    definition, parser = compile_ksy(exported.stdout, compiler, work)
    check("contents: [0x7e]" in exported.stdout and "contents: [0x0d]" in exported.stdout,
          "framed: the constants are not written as contents")
    verify_frames("framed", definition, parser, frames,
                  lambda obj, frame: obj.checksum == crc16(frame[1:6]))

    # The constants are checked by the parser: a frame without them is refused.
    for name, broken in (("start", b"\x7f" + frames[0][1:]), ("end", frames[0][:-1] + b"\x0e")):
        try:
            parser.from_bytes(broken)
            check(False, "framed: a wrong %s byte was accepted" % name)
        except kaitaistruct.ValidationNotEqualError:
            pass
    print("framed: a wrong constant is refused by the parser")


def mapping(compiler, work):
    """Every kind of field the exporter writes, from the definition checked in."""
    text = (HERE / "mapping.ksy").read_text()
    definition, parser = compile_ksy(text, compiler, work)
    frame = (bytes([0x7E, 5]) + struct.pack(">H", 0x0102) + struct.pack("<I", 0x0A0B0C0D) +
             struct.pack(">Q", 0x1122334455667788) + struct.pack("<f", 1.5) + struct.pack(">d", -2.25) +
             b"BUS1" + bytes([9, 8, 7]) + bytes([0x01, 0x02, 0x03]) + bytes([0x34, 0x12]) +
             bytes([0xDE, 0xAD, 0xBE, 0xEF]))
    frame += struct.pack(">H", 0xBEEF)
    obj, consumed, rebuilt = read_back(definition, parser, frame)
    check(consumed == len(frame) and rebuilt == frame, "mapping: the frame did not read back")
    check(obj.id == 5 and obj.count == 0x0102 and obj.stamp == 0x0A0B0C0D, "mapping: u1, u2be, u4le read wrongly")
    check(obj.total == 0x1122334455667788, "mapping: u8be read wrongly")
    check(obj.ratio == 1.5 and obj.wide == -2.25, "mapping: f4le, f8be read wrongly")
    check(obj.name == "BUS1" and obj.stuff == bytes([9, 8, 7]), "mapping: text and bytes read wrongly")
    check(obj.odd == bytes([1, 2, 3]), "mapping: a 3-byte number is not 3 bytes")
    check(obj.checksum == 0xBEEF, "mapping: u2be checksum read wrongly")
    print("mapping: %d fields of every kind read back" % len(definition["seq"]))


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--bitwise", required=True, help="the bitwise binary")
    parser.add_argument("--compiler", required=True, help="node_modules/kaitai-struct-compiler")
    args = parser.parse_args()

    print("kaitaistruct %s" % kaitaistruct.__version__)
    with tempfile.TemporaryDirectory() as tmp:
        work = pathlib.Path(tmp)
        modbus(args.bitwise, args.compiler, work)
        framed(args.bitwise, args.compiler, work)
        mapping(args.compiler, work)
    if FAILURES:
        print("%d check(s) failed" % len(FAILURES))
        return 1
    print("all round trips agree")
    return 0


if __name__ == "__main__":
    sys.exit(main())
