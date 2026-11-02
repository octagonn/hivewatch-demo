"""Log tailers that feed Hivewatch from the rest of the homelab.

Minecraft server logs give real join/disconnect activity (LAN players plus
anything that reaches the server), and they are the only place a successful
login is recorded. Nginx Proxy Manager logs are shipped in over HTTP by
shippers/npm-shipper.sh because they live on another host.
"""
from __future__ import annotations

import asyncio
import glob
import logging
import os
import re
import time
from typing import Awaitable, Callable, Dict, List, Optional

import db

log = logging.getLogger("hivewatch.tailers")

POLL_SECONDS = float(os.environ.get("HIVEWATCH_TAIL_POLL", "3"))

# [12:34:56] [Server thread/INFO]: name[/1.2.3.4:56789] logged in with entity id 1 at (...)
RE_LOGIN = re.compile(
    r"\[(?P<time>\d{2}:\d{2}:\d{2})\].*?:\s*(?P<user>[A-Za-z0-9_]{1,16})"
    r"\[/(?P<ip>[0-9a-fA-F:.]+):(?P<port>\d+)\]\s+logged in")

# [12:34:56] [Server thread/INFO]: name lost connection: Disconnected
RE_LOST = re.compile(
    r"\[(?P<time>\d{2}:\d{2}:\d{2})\].*?:\s*(?P<user>[A-Za-z0-9_]{1,16})"
    r"\s+lost connection:\s*(?P<reason>.+)")

# Handshake / protocol errors are the interesting "someone poked it" lines.
RE_DISCONNECT = re.compile(
    r"\[(?P<time>\d{2}:\d{2}:\d{2})\].*?:\s*Disconnecting\s+.*?"
    r"/(?P<ip>[0-9a-fA-F:.]+):(?P<port>\d+).*?:\s*(?P<reason>.+)")


def _today_epoch(hhmmss: str) -> float:
    """Minecraft logs carry only a wall clock; anchor it to today."""
    try:
        h, m, s = (int(x) for x in hhmmss.split(":"))
    except ValueError:
        return time.time()
    now = time.localtime()
    t = time.mktime((now.tm_year, now.tm_mon, now.tm_mday, h, m, s,
                     0, 0, now.tm_isdst))
    # A line "in the future" is really from before midnight.
    if t > time.time() + 300:
        t -= 86400
    return t


def parse_mc_line(line: str, instance: str) -> Optional[Dict]:
    m = RE_LOGIN.search(line)
    if m:
        return {
            "ts": _today_epoch(m.group("time")),
            "source": "mclog",
            "kind": "login",
            "severity": 2,
            "ip": m.group("ip"),
            "port": int(m.group("port")),
            "username": m.group("user"),
            "detail": "%s: joined" % instance,
        }
    m = RE_DISCONNECT.search(line)
    if m:
        return {
            "ts": _today_epoch(m.group("time")),
            "source": "mclog",
            "kind": "malformed",
            "severity": 3,
            "ip": m.group("ip"),
            "port": int(m.group("port")),
            "detail": "%s: rejected - %s" % (instance, m.group("reason").strip()[:200]),
        }
    return None


class FileTailer:
    """Polls a file, surviving rotation and truncation."""

    def __init__(self, path: str, key: str):
        self.path = path
        self.key = key
        self.offset = 0
        self.inode: Optional[int] = None
        saved = db.state_get(key)
        if saved:
            try:
                self.offset = int(saved)
            except ValueError:
                self.offset = 0

    def read_new(self) -> List[str]:
        try:
            st = os.stat(self.path)
        except OSError:
            return []
        # Rotated or truncated -> start over.
        if self.inode is not None and st.st_ino != self.inode:
            self.offset = 0
        self.inode = st.st_ino
        if st.st_size < self.offset:
            self.offset = 0
        if st.st_size == self.offset:
            return []
        try:
            with open(self.path, "r", encoding="utf-8", errors="replace") as fh:
                fh.seek(self.offset)
                data = fh.read()
                self.offset = fh.tell()
        except OSError:
            return []
        db.state_set(self.key, self.offset)
        return [ln for ln in data.splitlines() if ln.strip()]


async def run_minecraft_tailers(emit: Callable[[dict], Awaitable[None]]) -> None:
    """Watch every AMP instance log we can find."""
    roots = [p for p in os.environ.get("HIVEWATCH_MC_LOGS", "").split(os.pathsep) if p]
    if not roots:
        log.info("no HIVEWATCH_MC_LOGS configured, Minecraft tailer idle")
        return

    tailers: Dict[str, FileTailer] = {}
    # Skip whatever is already in the files on first start.
    first_pass = True

    while True:
        try:
            for root in roots:
                for path in glob.glob(root):
                    if path not in tailers:
                        instance = _instance_name(path)
                        t = FileTailer(path, "tail:" + path)
                        if first_pass and not db.state_get(t.key):
                            try:
                                t.offset = os.path.getsize(path)
                                db.state_set(t.key, t.offset)
                            except OSError:
                                pass
                        tailers[path] = t
                        log.info("tailing %s (%s)", path, instance)
                    tail = tailers[path]
                    for line in tail.read_new():
                        ev = parse_mc_line(line, _instance_name(path))
                        if ev:
                            await emit(ev)
            first_pass = False
        except Exception:
            log.exception("minecraft tailer iteration failed")
        await asyncio.sleep(POLL_SECONDS)


def _instance_name(path: str) -> str:
    parts = [p for p in path.replace("\\", "/").split("/") if p]
    for i, p in enumerate(parts):
        if p.lower() == "instances" and i + 1 < len(parts):
            return parts[i + 1]
    # Mounted layout is <root>/<Instance>/Minecraft/logs/latest.log
    for i, p in enumerate(parts):
        if p.lower() == "minecraft" and i > 0:
            return parts[i - 1]
    return os.path.basename(os.path.dirname(path)) or "minecraft"
