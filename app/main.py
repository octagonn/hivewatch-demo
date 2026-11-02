"""Hivewatch - a Minecraft-aware threat map for the homelab.

Single process:
  * a Minecraft-protocol sentinel on :25599 (honeypot or transparent proxy)
  * log tailers for the AMP Minecraft instances
  * an HTTP ingest endpoint for shippers on other hosts (nginx, AdGuard)
  * a REST + WebSocket API and the web UI on :8099
"""
from __future__ import annotations

import asyncio
import secrets
import logging
import os
import time
from typing import Any, Dict, List, Optional, Set

from fastapi import FastAPI, Header, HTTPException, Request, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles

import db
import geo
import sentinel as sentinel_mod
import tailers

logging.basicConfig(
    level=os.environ.get("HIVEWATCH_LOGLEVEL", "INFO"),
    format="%(asctime)s [hivewatch] %(levelname)s %(message)s")
log = logging.getLogger("hivewatch")

WEB_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")
INGEST_TOKEN = os.environ.get("HIVEWATCH_INGEST_TOKEN", "")
RETENTION_DAYS = int(os.environ.get("HIVEWATCH_RETENTION_DAYS", "90"))
HOME_LAT = float(os.environ.get("HIVEWATCH_HOME_LAT", "0.0"))
HOME_LON = float(os.environ.get("HIVEWATCH_HOME_LON", "0.0"))
HOME_LABEL = os.environ.get("HIVEWATCH_HOME_LABEL", "demo-lab")

app = FastAPI(title="Hivewatch", docs_url=None, redoc_url=None, openapi_url=None)


# ---------------------------------------------------------------------------
# Live fan-out
# ---------------------------------------------------------------------------
class Hub:
    def __init__(self) -> None:
        self.clients: Set[WebSocket] = set()
        self._lock = asyncio.Lock()

    async def register(self, ws: WebSocket) -> None:
        async with self._lock:
            self.clients.add(ws)

    async def drop(self, ws: WebSocket) -> None:
        async with self._lock:
            self.clients.discard(ws)

    async def broadcast(self, message: Dict[str, Any]) -> None:
        if not self.clients:
            return
        async with self._lock:
            targets = list(self.clients)
        dead = []
        for ws in targets:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        if dead:
            async with self._lock:
                for ws in dead:
                    self.clients.discard(ws)


hub = Hub()


async def record(ev: Dict[str, Any]) -> None:
    """Enrich, persist and broadcast a single event. Never raises."""
    try:
        ip = ev.get("ip") or "0.0.0.0"
        ev.setdefault("ts", time.time())
        ev.setdefault("severity", 1)
        private = geo.is_private(ip)
        ev["is_private"] = 1 if private else 0

        # Geo lookups can block on the network; keep the event loop free.
        info = await asyncio.get_event_loop().run_in_executor(None, geo.lookup, ip)
        ev.update({k: info.get(k) for k in
                   ("country", "country_code", "city", "lat", "lon", "isp")})

        ev["id"] = db.insert_event(ev)
        await hub.broadcast({"type": "event", "event": ev})
        log.info("%s %s %s%s", ev["source"], ev["kind"], ip,
                 " (%s)" % ev["country_code"] if ev.get("country_code") else "")
    except Exception:
        log.exception("failed to record event")


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------
@app.get("/api/health")
async def health() -> Dict[str, Any]:
    return {
        "ok": True,
        "mode": sentinel_mod.MODE,
        "sentinel_port": sentinel_mod.LISTEN_PORT,
        "upstream": ("%s:%d" % (sentinel_mod.UPSTREAM_HOST, sentinel_mod.UPSTREAM_PORT)
                     if sentinel_mod.MODE == "proxy" else None),
        "clients": len(hub.clients),
        "retention_days": RETENTION_DAYS,
    }


@app.get("/api/config")
async def config() -> Dict[str, Any]:
    return {"home": {"lat": HOME_LAT, "lon": HOME_LON, "label": HOME_LABEL}}


@app.get("/api/events")
async def events(limit: int = 200, since: Optional[float] = None) -> List[Dict]:
    return db.recent_events(limit=limit, since=since)


@app.get("/api/stats")
async def stats(hours: int = 24) -> Dict[str, Any]:
    return db.stats(window_hours=max(1, min(hours, 24 * 90)))


@app.post("/api/ingest")
async def ingest(request: Request,
                 x_hivewatch_token: str = Header(default="")) -> JSONResponse:
    """Accept events from shippers on other homelab hosts."""
    if not INGEST_TOKEN or not secrets.compare_digest(x_hivewatch_token, INGEST_TOKEN):
        raise HTTPException(status_code=401, detail="bad or missing token")
    body = await request.json()
    items = body if isinstance(body, list) else [body]
    accepted = 0
    for raw in items[:500]:
        if not isinstance(raw, dict) or not raw.get("ip"):
            continue
        await record({
            "ts": float(raw.get("ts") or time.time()),
            "source": str(raw.get("source") or "manual")[:32],
            "kind": str(raw.get("kind") or "scan")[:32],
            "severity": int(raw.get("severity") or 2),
            "ip": str(raw["ip"])[:64],
            "port": raw.get("port"),
            "username": (str(raw["username"])[:64] if raw.get("username") else None),
            "proto_version": raw.get("proto_version"),
            "server_address": (str(raw["server_address"])[:128]
                               if raw.get("server_address") else None),
            "detail": (str(raw.get("detail") or ""))[:500],
        })
        accepted += 1
    return JSONResponse({"accepted": accepted})


@app.post("/api/clear")
async def clear(x_hivewatch_token: str = Header(default="")) -> Dict[str, Any]:
    """Wipe recorded events. Always requires a configured ingest token."""
    if not INGEST_TOKEN or not secrets.compare_digest(x_hivewatch_token, INGEST_TOKEN):
        raise HTTPException(status_code=401, detail="bad or missing token")
    removed = db.clear_events()
    log.info("cleared %d events", removed)
    await hub.broadcast({"type": "cleared"})
    return {"cleared": removed}


@app.websocket("/ws")
async def ws_endpoint(ws: WebSocket) -> None:
    await ws.accept()
    await hub.register(ws)
    try:
        await ws.send_json({"type": "hello",
                            "home": {"lat": HOME_LAT, "lon": HOME_LON,
                                     "label": HOME_LABEL}})
        while True:
            # The client does not send anything; this just detects disconnects.
            await ws.receive_text()
    except WebSocketDisconnect:
        pass
    except Exception:
        pass
    finally:
        await hub.drop(ws)


@app.get("/")
async def index() -> FileResponse:
    return FileResponse(os.path.join(WEB_DIR, "index.html"))


if os.path.isdir(WEB_DIR):
    app.mount("/static", StaticFiles(directory=WEB_DIR), name="static")


# ---------------------------------------------------------------------------
# Background workers
# ---------------------------------------------------------------------------
async def _prune_loop() -> None:
    while True:
        try:
            removed = db.prune(RETENTION_DAYS)
            if removed:
                log.info("pruned %d events older than %d days", removed, RETENTION_DAYS)
        except Exception:
            log.exception("prune failed")
        await asyncio.sleep(6 * 3600)


@app.on_event("startup")
async def startup() -> None:
    db.connect()
    log.info("database ready at %s", db.DB_PATH)

    s = sentinel_mod.Sentinel(record)
    try:
        await s.start()
    except Exception:
        log.exception("sentinel failed to bind - web UI still available")

    asyncio.create_task(tailers.run_minecraft_tailers(record))
    asyncio.create_task(_prune_loop())
    log.info("hivewatch up")
