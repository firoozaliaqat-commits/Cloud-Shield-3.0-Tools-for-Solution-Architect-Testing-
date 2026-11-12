#!/usr/bin/env python3
"""Create a harmless 4-packet TCP handshake + HTTP request for a Suricata IDS lab.

Only RFC1918 documentation-style addresses are used. This NEVER sends a packet.
"""
import struct
import time
from pathlib import Path

OUT = Path(__file__).resolve().parents[1] / "config/suricata/lab-demo.pcap"
SRC = bytes([192, 168, 44, 10])
DST = bytes([192, 168, 44, 20])
PAYLOAD = b"GET /target/data HTTP/1.1\r\nHost: demo.lab\r\nUser-Agent: LAB_TEST_MARKER\r\n\r\n"


def checksum(data):
    if len(data) % 2:
        data += b"\x00"
    value = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while value >> 16:
        value = (value & 0xFFFF) + (value >> 16)
    return (~value) & 0xFFFF


def make_frame(src, dst, sport, dport, seq, ack, flags, payload, ident):
    ihl = 20
    tcp0 = struct.pack("!HHIIBBHHH", sport, dport, seq, ack, 5 << 4, flags, 8192, 0, 0)
    pseudo = src + dst + struct.pack("!BBH", 0, 6, len(tcp0) + len(payload))
    tcp = tcp0[:16] + struct.pack("!H", checksum(pseudo + tcp0 + payload)) + tcp0[18:]
    ip0 = struct.pack("!BBHHHBBH4s4s", 0x45, 0, ihl + len(tcp) + len(payload), ident, 0, 64, 6, 0, src, dst)
    ipv4 = ip0[:10] + struct.pack("!H", checksum(ip0)) + ip0[12:]
    eth = bytes.fromhex("0200000000020200000000010800") if src == SRC else bytes.fromhex("0200000000010200000000020800")
    return eth + ipv4 + tcp + payload


pkts = [
    make_frame(SRC, DST, 54210, 8080, 1000, 0, 0x02, b"", 101),
    make_frame(DST, SRC, 8080, 54210, 2000, 1001, 0x12, b"", 102),
    make_frame(SRC, DST, 54210, 8080, 1001, 2001, 0x10, b"", 103),
    make_frame(SRC, DST, 54210, 8080, 1001, 2001, 0x18, PAYLOAD, 104),
]
now = int(time.time())
blob = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1))
for i, frame in enumerate(pkts):
    blob += struct.pack("<IIII", now, i * 1000, len(frame), len(frame))
    blob += frame
OUT.write_bytes(blob)
print(f"Wrote {OUT} ({len(pkts)} synthetic TCP packets, {len(blob)} bytes)")
