"""Minecraft-protocol sentinel.

Speaks just enough of the Minecraft handshake to classify what hit it, then
either answers like a server (honeypot) or forwards the connection upstream to
the real server (proxy). Every connection produces exactly one event.

Why this exists
---------------
Traffic that arrives through a playit.gg tunnel reaches the Minecraft server
with the *agent's* local address as the source, so the server log records
192.0.2.10 for every player on earth. To recover the real client IP the
tunnel has to speak PROXY protocol, and the thing behind it has to understand
that header. Vanilla and Fabric do not, so this sits in front and does.

If no PROXY header is present the peer address is used, which is correct for
direct LAN connections.
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import struct
import time
from typing import Awaitable, Callable, Optional, Tuple

log = logging.getLogger("hivewatch.sentinel")

MODE = os.environ.get("HIVEWATCH_SENTINEL_MODE", "honeypot")  # honeypot | proxy
LISTEN_HOST = os.environ.get("HIVEWATCH_SENTINEL_HOST", "0.0.0.0")
LISTEN_PORT = int(os.environ.get("HIVEWATCH_SENTINEL_PORT", "25599"))
UPSTREAM_HOST = os.environ.get("HIVEWATCH_UPSTREAM_HOST", "")
UPSTREAM_PORT = int(os.environ.get("HIVEWATCH_UPSTREAM_PORT", "25565"))
MOTD = os.environ.get("HIVEWATCH_MOTD", "A Minecraft Server")
FAKE_VERSION = os.environ.get("HIVEWATCH_FAKE_VERSION", "1.21.5")
FAKE_PROTOCOL = int(os.environ.get("HIVEWATCH_FAKE_PROTOCOL", "770"))
KICK_MESSAGE = os.environ.get(
    "HIVEWATCH_KICK", "This endpoint is monitored. Your connection was logged.")

_PROXY_V2_SIG = b"\r\n\r\n\x00\r\nQUIT\n"
HANDSHAKE_TIMEOUT = 8.0
MAX_PACKET = 32 * 1024


# ---------------------------------------------------------------------------
# Minecraft wire primitives
# ---------------------------------------------------------------------------
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


# ---------------------------------------------------------------------------
# Honeypot responses
# ---------------------------------------------------------------------------
def status_response(online: int = 0, maximum: int = 20) -> bytes:
    payload = {
        "version": {"name": FAKE_VERSION, "protocol": FAKE_PROTOCOL},
        "players": {"max": maximum, "online": online, "sample": []},
        "description": {"text": MOTD},
    }
    return packet(0x00, string_field(json.dumps(payload, separators=(",", ":"))))


def disconnect_packet(message: str) -> bytes:
    return packet(0x00, string_field(json.dumps({"text": message})))


# ---------------------------------------------------------------------------
# Server
# ---------------------------------------------------------------------------
KIND_FOR_STATE = {1: "probe", 2: "login"}


class Sentinel:
    def __init__(self, emit: Callable[[dict], Awaitable[None]]):
        self.emit = emit
        self.server: Optional[asyncio.AbstractServer] = None

    async def start(self) -> None:
        self.server = await asyncio.start_server(
            self._handle, LISTEN_HOST, LISTEN_PORT)
        log.info("sentinel listening on %s:%d (mode=%s%s)", LISTEN_HOST, LISTEN_PORT,
                 MODE, ", upstream %s:%d" % (UPSTREAM_HOST, UPSTREAM_PORT)
                 if MODE == "proxy" else "")

    async def _handle(self, reader: asyncio.StreamReader,
                      writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername") or ("?", 0)
        src_ip, src_port = peer[0], peer[1]
        via_proxy = False
        buf = b""
        hs: Optional[Handshake] = None
        kind = "scan"
        detail = ""
        username = None

        try:
            deadline = time.time() + HANDSHAKE_TIMEOUT
            # ---- optional PROXY header ----
            # We can only conclude "there is no PROXY header" once enough bytes
            # are buffered to rule out both signatures: 12 for the v2 binary
            # signature, 6 for the v1 "PROXY " prefix. Deciding on an empty
            # buffer would feed the header itself to the handshake parser.
            while True:
                decided = True
                pip = pport = None
                consumed = 0
                try:
                    pip, pport, consumed = parse_proxy_header(buf)
                except Incomplete:
                    decided = False
                except ValueError as e:
                    detail = "bad PROXY header: %s" % e
                    raise _Done()

                if decided and (consumed or len(buf) >= len(_PROXY_V2_SIG)):
                    if consumed:
                        buf = buf[consumed:]
                        if pip:
                            src_ip, src_port, via_proxy = pip, pport, True
                    break

                chunk = await self._read(reader, deadline)
                if not chunk:
                    if decided:
                        break          # short connection, simply had no header
                    detail = "closed during PROXY header"
                    raise _Done()
                buf += chunk

            # ---- handshake ----
            while True:
                try:
                    hs, consumed = parse_handshake(buf)
                except Incomplete:
                    chunk = await self._read(reader, deadline)
                    if not chunk:
                        detail = detail or "closed before handshake"
                        raise _Done()
                    buf += chunk
                    continue
                except (ValueError, IndexError) as e:
                    kind = "malformed"
                    detail = "not a Minecraft handshake: %s" % e
                    raise _Done()
                break

            kind = KIND_FOR_STATE.get(hs.next_state, "scan")
            detail = "next_state=%d addr=%s:%d" % (hs.next_state, hs.address, hs.port)
            rest = buf[consumed:]

            if MODE == "proxy" and UPSTREAM_HOST:
                await self._proxy(reader, writer, buf, hs, src_ip)
                if hs.next_state == 2:
                    username = parse_login_name(rest) if rest else None
                return

            # ---- honeypot ----
            if hs.next_state == 1:
                username = None
                await self._serve_status(reader, writer, rest, deadline)
            elif hs.next_state == 2:
                if not rest:
                    rest = await self._read(reader, deadline) or b""
                username = parse_login_name(rest)
                if username:
                    detail += " user=%s" % username
                writer.write(disconnect_packet(KICK_MESSAGE))
                await writer.drain()
            else:
                kind = "scan"

        except _Done:
            pass
        except (asyncio.IncompleteReadError, ConnectionResetError, BrokenPipeError):
            detail = detail or "connection reset"
        except asyncio.TimeoutError:
            kind = "scan"
            detail = detail or "no data before timeout"
        except Exception as e:                      # never kill the listener
            kind = "error"
            detail = "%s: %s" % (type(e).__name__, e)
            log.exception("sentinel handler failed")
        finally:
            try:
                writer.close()
            except Exception:
                pass

            severity = {"login": 3, "malformed": 3, "scan": 2,
                        "probe": 1, "error": 1}.get(kind, 1)
            await self.emit({
                "ts": time.time(),
                "source": "sentinel",
                "kind": kind,
                "severity": severity,
                "ip": src_ip,
                "port": src_port,
                "username": username,
                "proto_version": hs.protocol if hs else None,
                "server_address": hs.address if hs else None,
                "detail": (detail + (" via=proxy-protocol" if via_proxy else "")).strip(),
            })

    @staticmethod
    async def _read(reader: asyncio.StreamReader, deadline: float) -> bytes:
        remaining = deadline - time.time()
        if remaining <= 0:
            raise asyncio.TimeoutError()
        return await asyncio.wait_for(reader.read(4096), timeout=remaining)

    async def _serve_status(self, reader, writer, rest: bytes, deadline: float) -> None:
        """Answer a server-list ping so scanners see a believable server."""
        writer.write(status_response())
        await writer.drain()
        # Optional ping/pong keeps the client's latency display honest.
        try:
            data = rest or await self._read(reader, deadline)
            if data and len(data) >= 2:
                length, off = read_varint(data, 0)
                pid, off = read_varint(data, off)
                if pid == 0x01 and off + 8 <= len(data):
                    writer.write(packet(0x01, data[off:off + 8]))
                    await writer.drain()
        except (Incomplete, ValueError, asyncio.TimeoutError, ConnectionError):
            pass

    async def _proxy(self, reader, writer, buffered: bytes,
                     hs: Handshake, src_ip: str) -> None:
        """Transparent pass-through to the real server."""
        try:
            up_r, up_w = await asyncio.wait_for(
                asyncio.open_connection(UPSTREAM_HOST, UPSTREAM_PORT), timeout=5)
        except Exception as e:
            log.warning("upstream %s:%d unreachable: %s", UPSTREAM_HOST, UPSTREAM_PORT, e)
            try:
                writer.write(disconnect_packet("Server is starting up, try again shortly."))
                await writer.drain()
            except Exception:
                pass
            return

        up_w.write(buffered)
        await up_w.drain()

        async def pipe(r, w):
            try:
                while True:
                    chunk = await r.read(8192)
                    if not chunk:
                        break
                    w.write(chunk)
                    await w.drain()
            except Exception:
                pass
            finally:
                try:
                    w.close()
                except Exception:
                    pass

        await asyncio.gather(pipe(reader, up_w), pipe(up_r, writer))


class _Done(Exception):
    """Internal: stop processing, still record the event."""
