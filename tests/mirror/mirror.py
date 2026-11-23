#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Part of bitwise-bus -- inferring undocumented bus protocols from captures.
"""A second implementation of the synthetic protocol generators, in another language.

Each generator is written from the algorithm documented at the top of its C++ file
(src/protocols/*.cpp) and from the published description of the protocol, and shares
nothing with the C++ code. It is how the checked-in captures of tests/corpus were made,
and it is what says that `bitwise synth` writes what the documentation says it does.

    mirror.py --check build/bitwise      compare with `bitwise synth` on many seeds
    mirror.py --write tests/corpus       write the captures that tests/corpus holds

It first checks itself against published values: the CRC of "123456789" for the CRC-16
variants, UBX frames from the u-blox documentation, and the CRC_EXTRA of the three MAVLink
messages, which it works out from their definitions.
"""

import argparse
import pathlib
import subprocess
import sys

M64 = (1 << 64) - 1


class SplitMix64:
    def __init__(self, seed):
        self.s = seed & M64

    def next(self):
        self.s = (self.s + 0x9E3779B97F4A7C15) & M64
        z = self.s
        z = ((z ^ (z >> 30)) * 0xBF58476D1CE4E5B9) & M64
        z = ((z ^ (z >> 27)) * 0x94D049BB133111EB) & M64
        return z ^ (z >> 31)

    def below(self, n):
        return self.next() % n


def le(value, size):
    return [(value >> (8 * i)) & 0xFF for i in range(size)]


def csv(channel, events):
    rows = ["# bitwise-capture 1", "time_ns,channel,direction,id,data"]
    rows += ["%d,%s,,,%02x" % (t, channel, b) for t, b in events]
    return "\n".join(rows) + "\n"


def emit(rng, start, char_ns, max_delay, frame, events):
    """One event per byte; one draw per byte for its delay, always."""
    for k, byte in enumerate(frame):
        draw = rng.next()
        events.append((start + k * char_ns + (0 if max_delay == 0 else draw % max_delay), byte))
    return start + len(frame) * char_ns


# ---- checksums, from their published definitions -----------------------------------------

def crc16_modbus(data):
    crc = 0xFFFF
    for b in data:
        crc ^= b
        for _ in range(8):
            crc = (crc >> 1) ^ 0xA001 if crc & 1 else crc >> 1
    return crc


def x25_accumulate(crc, byte):
    """The accumulate function of the MAVLink C headers, CRC-16/MCRF4XX a byte at a time."""
    tmp = (byte ^ (crc & 0xFF)) & 0xFF
    tmp = (tmp ^ (tmp << 4)) & 0xFF
    return ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF


def mcrf4xx(data, seed_byte=None):
    crc = 0xFFFF
    for b in data:
        crc = x25_accumulate(crc, b)
    if seed_byte is not None:
        crc = x25_accumulate(crc, seed_byte)
    return crc


def fletcher8(data):
    a = b = 0
    for byte in data:
        a = (a + byte) & 0xFF
        b = (b + a) & 0xFF
    return a, b


def crc_extra(name, fields):
    """CRC_EXTRA as the MAVLink generator defines it: the CRC of the message name and of
    each field's type and name, in wire order, folded to a byte."""
    text = name + " " + "".join("%s %s " % (t, n) for t, n in fields)
    crc = mcrf4xx(text.encode("ascii"))
    return (crc & 0xFF) ^ (crc >> 8)


# The three messages, with their fields in wire order (the larger types first).
MAVLINK = {
    "HEARTBEAT": (0, [("uint32_t", "custom_mode"), ("uint8_t", "type"), ("uint8_t", "autopilot"),
                      ("uint8_t", "base_mode"), ("uint8_t", "system_status"), ("uint8_t", "mavlink_version")], 9, 50),
    "SYS_STATUS": (1, [("uint32_t", "onboard_control_sensors_present"), ("uint32_t", "onboard_control_sensors_enabled"),
                       ("uint32_t", "onboard_control_sensors_health"), ("uint16_t", "load"),
                       ("uint16_t", "voltage_battery"), ("int16_t", "current_battery"),
                       ("uint16_t", "drop_rate_comm"), ("uint16_t", "errors_comm"), ("uint16_t", "errors_count1"),
                       ("uint16_t", "errors_count2"), ("uint16_t", "errors_count3"), ("uint16_t", "errors_count4"),
                       ("int8_t", "battery_remaining")], 31, 124),
    "ATTITUDE": (30, [("uint32_t", "time_boot_ms"), ("float", "roll"), ("float", "pitch"), ("float", "yaw"),
                      ("float", "rollspeed"), ("float", "pitchspeed"), ("float", "yawspeed")], 28, 39),
}


def self_check():
    assert crc16_modbus(b"123456789") == 0x4B37                       # CRC-16/MODBUS
    assert mcrf4xx(b"123456789") == 0x6F91                             # CRC-16/MCRF4XX
    # UBX-ACK-ACK acknowledging CFG-MSG, and the poll of UBX-CFG-PRT, from the u-blox documentation.
    assert fletcher8([0x05, 0x01, 0x02, 0x00, 0x06, 0x01]) == (0x0F, 0x38)
    assert fletcher8([0x06, 0x00, 0x00, 0x00]) == (0x06, 0x18)
    for name, (msg_id, fields, size, extra) in MAVLINK.items():
        sizes = {"uint32_t": 4, "float": 4, "uint16_t": 2, "int16_t": 2, "uint8_t": 1, "int8_t": 1}
        assert sum(sizes[t] for t, _ in fields) == size, name
        assert crc_extra(name, fields) == extra, "CRC_EXTRA of %s is %d, not %d" % (name, crc_extra(name, fields), extra)


# ---- the generators -----------------------------------------------------------------------

def modbus_rtu(seed, frames, jitter):
    char_ns = 11 * 1_000_000_000 // 9600
    max_delay = char_ns * jitter // 1000
    rng = SplitMix64(seed)
    events, start = [], 0
    for i in range(frames):
        if i > 0:
            start += 8 * char_ns + char_ns * (5 + rng.below(16))
        f = [1 + rng.below(3), 3 + rng.below(2)]
        first = rng.below(65536)
        qty = 1 + rng.below(125)
        f += [first >> 8, first & 255, qty >> 8, qty & 255]
        c = crc16_modbus(bytes(f))
        f += [c & 255, c >> 8]
        for k in range(8):
            draw = rng.next()
            events.append((start + k * char_ns + (0 if max_delay == 0 else draw % max_delay), f[k]))
    return csv("rs485", events)


def ubx(seed, frames, jitter):
    char_ns = 10 * 1_000_000_000 // 115200
    max_delay = char_ns * jitter // 1000
    rng = SplitMix64(seed)
    itow0 = 1000 * rng.below(604800)
    ttff = 20000 + rng.below(20000)
    msss0 = 60000 + rng.below(60000)
    status = 0
    events, start = [], 0
    for _ in range(frames):
        kind = rng.below(3)
        if kind == 0:
            which = rng.below(3)
            cls, mid, payload = 0x05, 0x01, [(6, 1), (6, 8), (6, 0)][which]
            payload = list(payload)
        elif kind == 1:
            rate = [100, 200, 500, 1000][rng.below(4)]
            nav = [1, 2, 5][rng.below(3)]
            ref = rng.below(2)
            cls, mid, payload = 0x06, 0x08, le(rate, 2) + le(nav, 2) + le(ref, 2)
        else:
            fix = [0, 2, 3, 3, 3][rng.below(5)]
            flags = rng.below(16)
            stat = 64 * rng.below(4)
            flags2 = 8 * rng.below(3)
            cls, mid = 0x01, 0x03
            payload = (le((itow0 + 1000 * status) % 604800000, 4) + [fix, flags, stat, flags2] +
                       le(ttff, 4) + le(msss0 + 1000 * status, 4))
            status += 1
        body = [cls, mid] + le(len(payload), 2) + payload
        a, b = fletcher8(body)
        frame = [0xB5, 0x62] + body + [a, b]
        start = emit(rng, start, char_ns, max_delay, frame, events)
    return csv("uart", events)


def float_bits(rng, base, span):
    sign = rng.below(2)
    exponent = base + rng.below(span)
    mantissa = rng.below(1 << 23)
    return (sign << 31) | (exponent << 23) | mantissa


def mavlink1(seed, frames, jitter):
    char_ns = 10 * 1_000_000_000 // 57600
    max_delay = char_ns * jitter // 1000
    rng = SplitMix64(seed)
    boot0 = rng.below(100000)
    events, start = [], 0
    names = ["HEARTBEAT", "SYS_STATUS", "ATTITUDE"]
    for i in range(frames):
        name = names[rng.below(3)]
        msg_id, _, size, extra = MAVLINK[name]
        if name == "HEARTBEAT":
            mode = [0, 3, 4, 5][rng.below(4)]
            vehicle = 1 + rng.below(2)
            base = [81, 209, 217][rng.below(3)]
            status = 3 + rng.below(2)
            payload = le(mode, 4) + [vehicle, 3, base, status, 3]
        elif name == "SYS_STATUS":
            present = [0x1FFFF, 0x1FFFF, 0xFFFF][rng.below(3)]
            enabled = present & [0xFFFF, 0x3FFF][rng.below(2)]
            health = enabled & [0xFFFF, 0x7FFF][rng.below(2)]
            payload = le(present, 4) + le(enabled, 4) + le(health, 4)
            payload += le(rng.below(1000), 2) + le(10500 + rng.below(2100), 2) + le(rng.below(3000), 2)
            payload += le(rng.below(50), 2) + le(0, 2) + le(0, 8)
            payload += [rng.below(101)]
        else:
            payload = le((boot0 + 20 * i) % (1 << 32), 4)
            for _ in range(3):
                payload += le(float_bits(rng, 126, 3), 4)
            for _ in range(3):
                payload += le(float_bits(rng, 120, 4), 4)
        assert len(payload) == size
        body = [size, i & 0xFF, 1, 1, msg_id] + payload
        crc = mcrf4xx(bytes(body), extra)
        frame = [0xFE] + body + le(crc, 2)
        start = emit(rng, start, char_ns, max_delay, frame, events)
    return csv("uart", events)


GENERATORS = {"modbus-rtu": modbus_rtu, "ubx": ubx, "mavlink1": mavlink1}

# The captures that tests/corpus holds: file name, protocol, seed, frames, jitter.
CORPUS = [
    ("synth_modbus_rtu_seed1.csv", "modbus-rtu", 1, 3, 0),
    ("synth_modbus_rtu_seed7_jitter300.csv", "modbus-rtu", 7, 3, 300),
    ("synth_modbus_rtu_seed1_50frames_jitter300.csv", "modbus-rtu", 1, 50, 300),
    ("synth_ubx_seed1_30frames.csv", "ubx", 1, 30, 0),
    ("synth_ubx_seed3_40frames_jitter300.csv", "ubx", 3, 40, 300),
    ("synth_mavlink1_seed1_30frames.csv", "mavlink1", 1, 30, 0),
    ("synth_mavlink1_seed3_40frames_jitter300.csv", "mavlink1", 3, 40, 300),
]


def check(bitwise):
    bad = n = 0
    for name, generate in GENERATORS.items():
        for seed in (0, 1, 2, 7, 12345, 2 ** 63, 2 ** 64 - 1):
            for frames in (0, 1, 3, 50):
                for jitter in (0, 1, 300, 500):
                    n += 1
                    got = subprocess.run([bitwise, "synth", name, "--seed", str(seed), "--frames", str(frames),
                                          "--jitter-permille", str(jitter)], capture_output=True, text=True).stdout
                    if got != generate(seed, frames, jitter):
                        bad += 1
                        print("MISMATCH %s seed=%d frames=%d jitter=%d" % (name, seed, frames, jitter))
    print("%d configurations compared, %d mismatches" % (n, bad))
    return 1 if bad else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--check", metavar="BITWISE", help="compare with the bitwise binary")
    parser.add_argument("--write", metavar="DIR", help="write the captures of tests/corpus into DIR")
    args = parser.parse_args()
    self_check()
    print("the mirror agrees with the published values")
    status = 0
    if args.check:
        status |= check(args.check)
    if args.write:
        for filename, protocol, seed, frames, jitter in CORPUS:
            (pathlib.Path(args.write) / filename).write_text(GENERATORS[protocol](seed, frames, jitter), newline="")
    return status


if __name__ == "__main__":
    sys.exit(main())
