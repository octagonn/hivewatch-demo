"""Pure Minecraft / PROXY-protocol wire parsing.

No configuration, no I/O, no environment - just bytes in, structures out, so
it can be shared by the containerised sentinel and the native Windows service
that sits in front of the live Minecraft server.
"""
from __future__ import annotations

import struct
from typing import Optional, Tuple

_PROXY_V2_SIG = bytes((13, 10, 13, 10, 0, 13, 10, 81, 85, 73, 84, 10))  # CR LF CR LF NUL CR LF Q U I T LF
MAX_PACKET = 32 * 1024

class Incomplete(Exception):
    """Not enough bytes buffered yet."""


def read_varint(buf: bytes, off: int = 0) -> Tuple[int, int]:
    """Return (value, new_offset). Raises Incomplete / ValueError."""
    value = 0
    for i in range(5):
        if off + i >= len(buf):
            raise Incomplete()
        b = buf[off + i]
        value |= (b & 0x7F) << (7 * i)
        if not b & 0x80:
            return value, off + i + 1
    raise ValueError("VarInt too long")


def write_varint(value: int) -> bytes:
    out = bytearray()
    v = value & 0xFFFFFFFF
    while True:
        b = v & 0x7F
        v >>= 7
        if v:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def read_string(buf: bytes, off: int, limit: int = 512) -> Tuple[str, int]:
    length, off = read_varint(buf, off)
    if length < 0 or length > limit:
        raise ValueError("string length %d out of range" % length)
    if off + length > len(buf):
        raise Incomplete()
    return buf[off:off + length].decode("utf-8", "replace"), off + length


def packet(pid: int, payload: bytes) -> bytes:
    body = write_varint(pid) + payload
    return write_varint(len(body)) + body


def string_field(s: str) -> bytes:
    raw = s.encode("utf-8")
    return write_varint(len(raw)) + raw


# ---------------------------------------------------------------------------
# PROXY protocol
# ---------------------------------------------------------------------------
def parse_proxy_header(buf: bytes) -> Tuple[Optional[str], Optional[int], int]:
    """Detect and parse a PROXY protocol header.

    Returns (src_ip, src_port, bytes_consumed). (None, None, 0) when the buffer
    does not start with one.
    """
    # v2 (binary)
    if buf.startswith(_PROXY_V2_SIG):
        if len(buf) < 16:
            raise Incomplete()
        ver_cmd = buf[12]
        fam = buf[13]
        length = struct.unpack("!H", buf[14:16])[0]
        total = 16 + length
        if len(buf) < total:
            raise Incomplete()
        if ver_cmd >> 4 != 0x2:
            return None, None, total          # unknown version, skip it
        if ver_cmd & 0x0F == 0x00:            # LOCAL (health check)
            return None, None, total
        body = buf[16:total]
        if fam >> 4 == 0x1 and len(body) >= 12:        # AF_INET
            ip = ".".join(str(b) for b in body[0:4])
            port = struct.unpack("!H", body[8:10])[0]
            return ip, port, total
        if fam >> 4 == 0x2 and len(body) >= 36:        # AF_INET6
            import ipaddress as _ip
            ip = str(_ip.IPv6Address(body[0:16]))
            port = struct.unpack("!H", body[32:34])[0]
            return ip, port, total
        return None, None, total

    # v1 (text)
    if buf.startswith(b"PROXY "):
        idx = buf.find(b"\r\n")
        if idx == -1:
            if len(buf) > 108:
                raise ValueError("malformed PROXY v1 header")
            raise Incomplete()
        parts = buf[:idx].decode("ascii", "replace").split()
        consumed = idx + 2
        if len(parts) >= 6 and parts[1] in ("TCP4", "TCP6"):
            try:
                return parts[2], int(parts[4]), consumed
            except ValueError:
                return None, None, consumed
        return None, None, consumed

    return None, None, 0


# ---------------------------------------------------------------------------
# Handshake parsing
# ---------------------------------------------------------------------------
class Handshake:
    __slots__ = ("protocol", "address", "port", "next_state")

    def __init__(self, protocol, address, port, next_state):
        self.protocol = protocol
        self.address = address
        self.port = port
        self.next_state = next_state


def parse_handshake(buf: bytes) -> Tuple[Optional[Handshake], int]:
    """Parse a handshake packet. Returns (handshake, bytes_consumed)."""
    length, off = read_varint(buf, 0)
    if length <= 0 or length > MAX_PACKET:
        raise ValueError("implausible packet length %d" % length)
    end = off + length
    if len(buf) < end:
        raise Incomplete()
    pid, off = read_varint(buf, off)
    if pid != 0x00:
        raise ValueError("expected handshake packet 0x00, got 0x%02x" % pid)
    protocol, off = read_varint(buf, off)
    address, off = read_string(buf, off, 255)
    if off + 2 > end:
        raise Incomplete()
    port = struct.unpack("!H", buf[off:off + 2])[0]
    off += 2
    next_state, off = read_varint(buf, off)
    return Handshake(protocol, address, port, next_state), end


def parse_login_name(buf: bytes) -> Optional[str]:
    """Best-effort username from a Login Start packet."""
    try:
        length, off = read_varint(buf, 0)
        if length <= 0 or length > MAX_PACKET or len(buf) < off + length:
            return None
        pid, off = read_varint(buf, off)
        if pid != 0x00:
            return None
        name, _ = read_string(buf, off, 64)
        return name
    except (Incomplete, ValueError, IndexError):
        return None
