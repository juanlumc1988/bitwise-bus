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
    """CRC_EXTRA as the MAVLink generator defines it: the CRC of the message name and then, for each
    field in wire order, its type, its name, and for an array its length as a byte, folded to a byte."""
    text = (name + " ").encode("ascii")
    for field in fields:
        text += ("%s %s " % (field[0], field[1])).encode("ascii")
        if len(field) > 2:
            text += bytes([field[2]])
    crc = mcrf4xx(text)
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


def nmea_checksum(body):
    """The exclusive or of the characters between the $ and the *, as two upper-case hex digits."""
    value = 0
    for ch in body.encode("ascii"):
        value ^= ch
    return "%02X" % value


MAVLINK2_EXTRA = {
    "PROTOCOL_VERSION": ([("uint16_t", "version"), ("uint16_t", "min_version"), ("uint16_t", "max_version"),
                          ("uint8_t", "spec_version_hash", 8), ("uint8_t", "library_version_hash", 8)], 22, 217),
}


def _fcs_table():
    """The table of RFC 1662 for the 16-bit frame check sequence: 0x8408, the polynomial of CRC-16/X-25 reflected."""
    table = []
    for byte in range(256):
        value = byte
        for _ in range(8):
            value = (value >> 1) ^ 0x8408 if value & 1 else value >> 1
        table.append(value)
    return table


FCS_TABLE = _fcs_table()


def fcs16(data):
    """The register of the PPP FCS-16, as RFC 1662 computes it, one table step a byte; not yet complemented."""
    register = 0xFFFF
    for byte in data:
        register = (register >> 8) ^ FCS_TABLE[(register ^ byte) & 0xFF]
    return register


def stuff(data, flag, escape, flag_code, escape_code):
    out = []
    for byte in data:
        if byte == flag:
            out += [escape, flag_code]
        elif byte == escape:
            out += [escape, escape_code]
        else:
            out.append(byte)
    return out


def self_check():
    assert crc16_modbus(b"123456789") == 0x4B37                       # CRC-16/MODBUS
    assert mcrf4xx(b"123456789") == 0x6F91                             # CRC-16/MCRF4XX
    # UBX-ACK-ACK acknowledging CFG-MSG, and the poll of UBX-CFG-PRT, from the u-blox documentation.
    assert fletcher8([0x05, 0x01, 0x02, 0x00, 0x06, 0x01]) == (0x0F, 0x38)
    assert fletcher8([0x06, 0x00, 0x00, 0x00]) == (0x06, 0x18)
    assert fcs16(b"123456789") ^ 0xFFFF == 0x906E                      # CRC-16/X-25
    frame = [0xFF, 0x03, 0xC0, 0x21, 0x09, 0x01, 0x00, 0x08, 0x0B, 0x7E, 0x9A, 0x31]
    fcs = fcs16(frame) ^ 0xFFFF
    assert fcs16(frame + [fcs & 0xFF, fcs >> 8]) == 0xF0B8             # the residue of a good PPP frame
    # Sentences as they are written in the NMEA 0183 descriptions that circulate (GGA, RMC, GLL).
    assert nmea_checksum("GPGGA,123519,4807.038,N,01131.000,E,1,08,0.9,545.4,M,46.9,M,,") == "47"
    assert nmea_checksum("GPRMC,123519,A,4807.038,N,01131.000,E,022.4,084.4,230394,003.1,W") == "6A"
    assert nmea_checksum("GPGLL,4916.45,N,12311.12,W,225444,A,") == "1D"
    for name, (msg_id, fields, size, extra) in MAVLINK.items():
        sizes = {"uint32_t": 4, "float": 4, "uint16_t": 2, "int16_t": 2, "uint8_t": 1, "int8_t": 1}
        assert sum(sizes[t] for t, _ in fields) == size, name
        assert crc_extra(name, fields) == extra, "CRC_EXTRA of %s is %d, not %d" % (name, crc_extra(name, fields), extra)
    for name, (fields, size, extra) in MAVLINK2_EXTRA.items():       # one with arrays, whose lengths count
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


def mavlink2(seed, frames, jitter):
    char_ns = 10 * 1_000_000_000 // 57600
    max_delay = char_ns * jitter // 1000
    rng = SplitMix64(seed)
    boot0 = rng.below(100000)
    hashes = rng.below(3)
    spec_hash = [rng.below(256) for _ in range(8)]
    library_hash = [rng.below(256) for _ in range(8)]
    events, start = [], 0
    for i in range(frames):
        kind = rng.below(4)
        if kind == 0:
            name = "HEARTBEAT"
            mode = [0, 3, 4, 5][rng.below(4)]
            vehicle = 1 + rng.below(2)
            base = [81, 209, 217][rng.below(3)]
            status = 3 + rng.below(2)
            payload = le(mode, 4) + [vehicle, 3, base, status, 3]
        elif kind == 1:
            name = "SYS_STATUS"
            present = [0x1FFFF, 0x1FFFF, 0xFFFF][rng.below(3)]
            enabled = present & [0xFFFF, 0x3FFF][rng.below(2)]
            health = enabled & [0xFFFF, 0x7FFF][rng.below(2)]
            payload = le(present, 4) + le(enabled, 4) + le(health, 4)
            payload += le(rng.below(1000), 2) + le(10500 + rng.below(2100), 2) + le(rng.below(3000), 2)
            payload += le(rng.below(50), 2) + le(0, 2) + le(0, 8)
            unknown = rng.below(3) == 0
            level = 1 + rng.below(100)
            payload += [0 if unknown else level]
        elif kind == 2:
            name = "ATTITUDE"
            payload = le((boot0 + 20 * i) % (1 << 32), 4)
            for _ in range(3):
                payload += le(float_bits(rng, 126, 3), 4)
            for _ in range(2):
                payload += le(float_bits(rng, 120, 4), 4)
            yaw_speed = float_bits(rng, 120, 4)
            zero = rng.below(4) == 0
            payload += le(0 if zero else yaw_speed, 4)
        else:
            name = "PROTOCOL_VERSION"
            version = [200, 200, 300][rng.below(3)]
            highest = 200 + 100 * rng.below(2)
            payload = le(version, 2) + le(100, 2) + le(highest, 2)
            payload += spec_hash if hashes >= 1 else [0] * 8
            payload += library_hash if hashes >= 2 else [0] * 8
        while len(payload) > 1 and payload[-1] == 0:
            payload.pop()
        message_id = {"HEARTBEAT": 0, "SYS_STATUS": 1, "ATTITUDE": 30, "PROTOCOL_VERSION": 300}[name]
        extra = ({k: v[3] for k, v in MAVLINK.items()}.get(name) if name in MAVLINK
                 else MAVLINK2_EXTRA[name][2])
        body = [len(payload), 0, 0, i & 0xFF, 1, 1] + le(message_id, 3) + payload
        crc = mcrf4xx(bytes(body), extra)
        frame = [0xFD] + body + le(crc, 2)
        start = emit(rng, start, char_ns, max_delay, frame, events)
    return csv("uart", events)


def slip(seed, frames, jitter):
    char_ns = 10 * 1_000_000_000 // 115200
    max_delay = char_ns * jitter // 1000
    rng = SplitMix64(seed)
    time0 = rng.below(1000000)
    events, start = [], 0
    for i in range(frames):
        kind = rng.below(2)
        content = [0x10 if kind == 0 else 0x20] + [(i >> 8) & 0xFF, i & 0xFF]
        time = time0 + 100 * i                       # never reaches 2**32: below 1000000 + 100 * 100000
        content += [(time >> 24) & 0xFF, (time >> 16) & 0xFF, (time >> 8) & 0xFF, time & 0xFF]
        if kind == 0:
            for _ in range(6):
                reading = rng.below(65536)
                content += [reading >> 8, reading & 0xFF]
        else:
            content.append(rng.below(4))
            battery = 11000 + rng.below(1600)
            content += [battery >> 8, battery & 0xFF]
        frame = [0xC0] + stuff(content, 0xC0, 0xDB, 0xDC, 0xDD) + [0xC0]
        start = emit(rng, start, char_ns, max_delay, frame, events)
    return csv("uart", events)


def hdlc_ppp(seed, frames, jitter):
    char_ns = 10 * 1_000_000_000 // 115200
    max_delay = char_ns * jitter // 1000
    rng = SplitMix64(seed)
    addresses = [0xC0000201, 0xC0000202, 0x0A000001, 0x0A000002]
    magic = 0x0B7E9A31
    events, start = [], 0
    lcp_id = ipcp_id = 0
    for _ in range(frames):
        idle = rng.below(3)
        kind = rng.below(3)
        content = [0xFF, 0x03]
        if kind == 0:
            content += [0xC0, 0x21, 9, lcp_id, 0, 8] + [(magic >> s) & 0xFF for s in (24, 16, 8, 0)]
            lcp_id = (lcp_id + 1) & 0xFF
        elif kind == 1:
            address = addresses[rng.below(4)]
            content += [0x80, 0x21, 1, ipcp_id, 0, 10, 3, 6] + [(address >> s) & 0xFF for s in (24, 16, 8, 0)]
            ipcp_id = (ipcp_id + 1) & 0xFF
        else:
            content += [0x00, 0x21] + [rng.below(256) for _ in range(24)]
        fcs = fcs16(content) ^ 0xFFFF
        content += [fcs & 0xFF, fcs >> 8]
        start = emit(rng, start, char_ns, max_delay, [0x7E] * idle, events)
        start = emit(rng, start, char_ns, max_delay, [0x7E] + stuff(content, 0x7E, 0x7D, 0x5E, 0x5D) + [0x7E], events)
    return csv("uart", events)


def nmea0183(seed, frames, jitter):
    char_ns = 10 * 1_000_000_000 // 4800
    max_delay = char_ns * jitter // 1000
    lat_range, lon_range = 90 * 6_000_000, 180 * 6_000_000
    rng = SplitMix64(seed)
    seconds = rng.below(86400)
    south = rng.below(2) == 1
    west = rng.below(2) == 1
    lat = rng.below(lat_range)
    lon = rng.below(lon_range)
    day = 1 + rng.below(28)
    month = 1 + rng.below(12)
    year = 20 + rng.below(10)
    date = "%02d%02d%02d" % (day, month, year)
    geoid = rng.below(800) - 400
    separation = ("-" if geoid < 0 else "") + tenths(abs(geoid))

    def position(units, digits):
        degrees, rest = divmod(units, 6_000_000)
        return "%0*d%02d.%05d" % (digits, degrees, rest // 100000, rest % 100000)

    events, at = [], 0
    clock = lat_text = lon_text = ""
    altitude = 0
    for i in range(frames):
        kind = i % 3
        if kind == 0:
            lat = (lat + lat_range - 1000 + rng.below(2001)) % lat_range
            lon = (lon + lon_range - 1000 + rng.below(2001)) % lon_range
            altitude = rng.below(20000)
            seconds = (seconds + (0 if i == 0 else 1)) % 86400
            clock = "%02d%02d%02d.00" % (seconds // 3600, (seconds // 60) % 60, seconds % 60)
            lat_text, lon_text = position(lat, 2), position(lon, 3)
            at = (i // 3) * 1_000_000_000
        ns, ew = ("S" if south else "N"), ("W" if west else "E")
        if kind == 0:
            quality = [1, 1, 1, 2, 4][rng.below(5)]
            satellites = 4 + rng.below(9)
            hdop = 5 + rng.below(30)
            body = "GPGGA," + ",".join([clock, lat_text, ns, lon_text, ew, str(quality), "%02d" % satellites,
                                        tenths(hdop), tenths(altitude), "M", separation, "M", "", ""])
        elif kind == 1:
            valid = rng.below(4) != 3
            speed = rng.below(1500)
            course = rng.below(3600)
            differential = rng.below(2) == 1
            body = "GPRMC," + ",".join([clock, "A" if valid else "V", lat_text, ns, lon_text, ew, tenths(speed),
                                        tenths(course), date, "", "", "D" if differential else "A"])
        else:
            course = rng.below(3600)
            speed = rng.below(1500)
            differential = rng.below(2) == 1
            body = "GPVTG," + ",".join([tenths(course), "T", "", "M", tenths(speed), "N",
                                        tenths(speed * 1852 // 1000), "K", "D" if differential else "A"])
        text = "$" + body + "*" + nmea_checksum(body) + "\r\n"
        at = emit(rng, at, char_ns, max_delay, list(text.encode("ascii")), events)
    return csv("uart", events)


def tenths(value):
    return "%d.%d" % (value // 10, value % 10)


GENERATORS = {"modbus-rtu": modbus_rtu, "ubx": ubx, "mavlink1": mavlink1, "mavlink2": mavlink2, "nmea0183": nmea0183,
              "slip": slip, "hdlc-ppp": hdlc_ppp}

# The captures that tests/corpus holds: file name, protocol, seed, frames, jitter.
CORPUS = [
    ("synth_modbus_rtu_seed1.csv", "modbus-rtu", 1, 3, 0),
    ("synth_modbus_rtu_seed7_jitter300.csv", "modbus-rtu", 7, 3, 300),
    ("synth_modbus_rtu_seed1_50frames_jitter300.csv", "modbus-rtu", 1, 50, 300),
    ("synth_ubx_seed1_30frames.csv", "ubx", 1, 30, 0),
    ("synth_ubx_seed3_40frames_jitter300.csv", "ubx", 3, 40, 300),
    ("synth_nmea0183_seed1_6frames.csv", "nmea0183", 1, 6, 0),
    ("synth_nmea0183_seed3_9frames_jitter300.csv", "nmea0183", 3, 9, 300),
    ("synth_nmea0183_seed3_60frames_jitter300.csv", "nmea0183", 3, 60, 300),
    # Seeds with frames that have both of the escapes of the protocol in them.
    ("synth_slip_seed3_30frames.csv", "slip", 3, 30, 0),
    ("synth_slip_seed3_40frames_jitter300.csv", "slip", 3, 40, 300),
    ("synth_hdlc_ppp_seed2_30frames.csv", "hdlc-ppp", 2, 30, 0),
    ("synth_hdlc_ppp_seed2_40frames_jitter300.csv", "hdlc-ppp", 2, 40, 300),
    ("synth_mavlink2_seed1_30frames.csv", "mavlink2", 1, 30, 0),
    ("synth_mavlink2_seed3_40frames_jitter300.csv", "mavlink2", 3, 40, 300),
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
