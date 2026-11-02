# Hivewatch Demo

A Python/FastAPI connection monitor with a Minecraft-aware sentinel, SQLite
event storage, optional IP geolocation, and a live WebSocket map. The sentinel
parses Minecraft handshakes and PROXY headers, classifies connection activity,
and can operate as a honeypot or forwarding proxy.

This public edition preserves the existing protocol, storage, API, tailer, and
browser implementations. Private logs, screenshots, service wiring, machine
paths, map coordinates, and deployment documentation are omitted. Defaults and
tests were adjusted for a local demonstration.

## Run locally

```sh
docker compose up --build
```

Open http://localhost:8099. The web UI and sentinel are bound to loopback on the
host. The default is honeypot mode: connections are recorded and never
forwarded. No original game server or tunnel is contacted; log tailing and
external geolocation are disabled. The map origin is the fictional point 0,0.

To generate an event, connect a local Minecraft client to `localhost:25599`,
or use `python examples/send_probe.py` to send a local status request. A status
request is a probe, not proof of hostile intent. With geolocation disabled,
local probes appear in the feed but do not produce geographic map arcs.

Ingest and clear endpoints fail closed unless `HIVEWATCH_INGEST_TOKEN` is
explicitly configured; callers then supply it in `X-Hivewatch-Token`.
The read APIs and WebSocket are intended for this local demonstration. Before
remote deployment, add access control and restrict PROXY-header trust to your
own forwarding proxy. No internet deployment is configured here.

## Architecture

TCP handshake -> protocol classification -> optional geolocation -> SQLite
event -> FastAPI and WebSocket fan-out -> browser feed and map.

Read `app/sentinel.py` and `app/mcproto.py` for protocol handling, `app/db.py`
for persistence, and `app/main.py` for event enrichment and delivery.

## Tests

```sh
python -m pip install -r requirements-dev.txt
python -m pytest tests -q
```

Public-edition tests check VarInt parsing, event persistence, log parsing,
write-endpoint authorization, and static UI delivery using synthetic data.

The bundled world geometry is third-party geographic data retained from the
original project; the source-code reservation in LICENSE does not claim
ownership of third-party geography or dependencies.
