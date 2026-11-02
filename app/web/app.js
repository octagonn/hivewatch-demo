/* Hivewatch front end.
 *
 * No framework, no charting library. The world is a TopoJSON file decoded here
 * and painted once to an offscreen canvas; every frame is that bitmap plus the
 * currently-flying strikes, so an idle map costs almost nothing.
 *
 * Strikes are only ever created by a live WebSocket event. Nothing animates on
 * page load, by design - motion on this map always means something arrived.
 */
(() => {
  "use strict";

  const KIND_COLOR = {
    probe: "#38bdf8",
    login: "#f59e0b",
    malformed: "#ef4444",
    scan: "#a78bfa",
    error: "#6f8496",
  };

  const canvas = document.getElementById("map");
  const ctx = canvas.getContext("2d");
  const feedEl = document.getElementById("feed");
  const emptyEl = document.getElementById("empty");
  const linkDot = document.getElementById("link-dot");

  let W = 0, H = 0, dpr = 1;
  let land = null;            // decoded polygons, [[ [lon,lat], ... ], ...]
  let base = null;            // offscreen canvas with the map painted
  let home = { lat: 0.0, lon: 0.0, label: "demo-lab" };
  const strikes = [];
  const ripples = [];
  let sawAnyEvent = false;

  /* ---------------- projection ---------------- */
  const project = (lon, lat) => [
    ((lon + 180) / 360) * W,
    ((90 - lat) / 180) * H,
  ];

  /* ---------------- TopoJSON ---------------- */
  function decodeTopology(topo) {
    const { scale: [sx, sy], translate: [tx, ty] } = topo.transform;
    // Arcs are delta-encoded and quantised; rebuild absolute lon/lat.
    const arcs = topo.arcs.map((arc) => {
      let x = 0, y = 0;
      return arc.map(([dx, dy]) => {
        x += dx; y += dy;
        return [x * sx + tx, y * sy + ty];
      });
    });

    const ring = (indices) => {
      const pts = [];
      for (const idx of indices) {
        const rev = idx < 0;
        const arc = arcs[rev ? ~idx : idx];
        const seq = rev ? arc.slice().reverse() : arc;
        // Adjacent arcs share an endpoint; drop the duplicate.
        for (let i = pts.length ? 1 : 0; i < seq.length; i++) pts.push(seq[i]);
      }
      return pts;
    };

    const out = [];
    for (const geom of topo.objects.countries.geometries) {
      if (geom.type === "Polygon") {
        geom.arcs.forEach((r) => out.push(ring(r)));
      } else if (geom.type === "MultiPolygon") {
        geom.arcs.forEach((poly) => poly.forEach((r) => out.push(ring(r))));
      }
    }
    return out;
  }

  /* ---------------- base map ---------------- */
  function paintBase() {
    if (!land) return;
    base = document.createElement("canvas");
    base.width = canvas.width;
    base.height = canvas.height;
    const c = base.getContext("2d");
    c.scale(dpr, dpr);

    c.fillStyle = "#05080b";
    c.fillRect(0, 0, W, H);

    // graticule
    c.strokeStyle = "rgba(29,42,54,.55)";
    c.lineWidth = 0.5;
    for (let lon = -180; lon <= 180; lon += 30) {
      const [x] = project(lon, 0);
      c.beginPath(); c.moveTo(x, 0); c.lineTo(x, H); c.stroke();
    }
    for (let lat = -60; lat <= 60; lat += 30) {
      const [, y] = project(0, lat);
      c.beginPath(); c.moveTo(0, y); c.lineTo(W, y); c.stroke();
    }

    // land
    c.beginPath();
    for (const poly of land) {
      if (poly.length < 2) continue;
      let [x, y] = project(poly[0][0], poly[0][1]);
      c.moveTo(x, y);
      for (let i = 1; i < poly.length; i++) {
        [x, y] = project(poly[i][0], poly[i][1]);
        c.lineTo(x, y);
      }
      c.closePath();
    }
    c.fillStyle = "#101c26";
    c.fill();
    c.strokeStyle = "#223646";
    c.lineWidth = 0.7;
    c.stroke();
  }

  function resize() {
    dpr = Math.min(window.devicePixelRatio || 1, 2);
    const r = canvas.getBoundingClientRect();
    W = r.width; H = r.height;
    canvas.width = Math.round(W * dpr);
    canvas.height = Math.round(H * dpr);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    paintBase();
  }
  window.addEventListener("resize", resize);

  /* ---------------- animation ---------------- */
  function addStrike(ev) {
    if (ev.lat == null || ev.lon == null) return;   // unlocatable, feed only
    strikes.push({
      from: [ev.lon, ev.lat],
      to: [home.lon, home.lat],
      t0: performance.now(),
      dur: 1900 + Math.random() * 500,
      color: KIND_COLOR[ev.kind] || "#8aa2b4",
    });
    ripples.push({ at: [ev.lon, ev.lat], t0: performance.now(),
                   color: KIND_COLOR[ev.kind] || "#8aa2b4", r: 26 });
    if (strikes.length > 90) strikes.splice(0, strikes.length - 90);
  }

  // Quadratic bezier bowed away from the straight line, so long shots arc.
  function curve(a, b) {
    const [x1, y1] = project(a[0], a[1]);
    const [x2, y2] = project(b[0], b[1]);
    const mx = (x1 + x2) / 2, my = (y1 + y2) / 2;
    const dx = x2 - x1, dy = y2 - y1;
    const len = Math.hypot(dx, dy) || 1;
    const lift = Math.min(len * 0.28, 170);
    return [x1, y1, mx - (dy / len) * lift, my + (dx / len) * lift, x2, y2];
  }

  const qpoint = (p, t) => {
    const u = 1 - t;
    return [
      u * u * p[0] + 2 * u * t * p[2] + t * t * p[4],
      u * u * p[1] + 2 * u * t * p[3] + t * t * p[5],
    ];
  };

  function frame(now) {
    requestAnimationFrame(frame);
    if (!base) return;
    ctx.setTransform(1, 0, 0, 1, 0, 0);
    ctx.drawImage(base, 0, 0);
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);

    // home marker
    const [hx, hy] = project(home.lon, home.lat);
    const beat = 3.4 + Math.sin(now / 620) * 0.9;
    ctx.beginPath(); ctx.arc(hx, hy, beat, 0, Math.PI * 2);
    ctx.fillStyle = "#3ddc84"; ctx.fill();
    ctx.beginPath(); ctx.arc(hx, hy, 11, 0, Math.PI * 2);
    ctx.strokeStyle = "rgba(61,220,132,.28)"; ctx.lineWidth = 1; ctx.stroke();

    // origin ripples
    for (let i = ripples.length - 1; i >= 0; i--) {
      const rp = ripples[i];
      const t = (now - rp.t0) / 1100;
      if (t >= 1) { ripples.splice(i, 1); continue; }
      const [x, y] = project(rp.at[0], rp.at[1]);
      ctx.beginPath();
      ctx.arc(x, y, 3 + t * rp.r, 0, Math.PI * 2);
      ctx.strokeStyle = rp.color;
      ctx.globalAlpha = (1 - t) * 0.75;
      ctx.lineWidth = 1.4;
      ctx.stroke();
      ctx.globalAlpha = 1;
    }

    // strikes
    for (let i = strikes.length - 1; i >= 0; i--) {
      const s = strikes[i];
      const t = (now - s.t0) / s.dur;
      if (t >= 1.28) { strikes.splice(i, 1); continue; }
      const p = curve(s.from, s.to);
      const head = Math.min(t, 1);
      const tail = Math.max(0, head - 0.26);

      ctx.beginPath();
      const steps = 26;
      for (let k = 0; k <= steps; k++) {
        const tt = tail + (head - tail) * (k / steps);
        const [x, y] = qpoint(p, tt);
        k ? ctx.lineTo(x, y) : ctx.moveTo(x, y);
      }
      ctx.strokeStyle = s.color;
      ctx.globalAlpha = t < 1 ? 0.85 : Math.max(0, 1 - (t - 1) / 0.28) * 0.85;
      ctx.lineWidth = 1.6;
      ctx.shadowColor = s.color;
      ctx.shadowBlur = 8;
      ctx.stroke();
      ctx.shadowBlur = 0;

      if (t < 1) {
        const [x, y] = qpoint(p, head);
        ctx.beginPath(); ctx.arc(x, y, 2.6, 0, Math.PI * 2);
        ctx.fillStyle = "#fff"; ctx.fill();
      } else {
        // impact flash at home
        const k = (t - 1) / 0.28;
        ctx.beginPath(); ctx.arc(hx, hy, 6 + k * 20, 0, Math.PI * 2);
        ctx.strokeStyle = s.color; ctx.globalAlpha = (1 - k) * 0.7;
        ctx.lineWidth = 2; ctx.stroke();
      }
      ctx.globalAlpha = 1;
    }
  }

  /* ---------------- side panels ---------------- */
  const pad = (n) => String(n).padStart(2, "0");
  const hhmm = (ts) => {
    const d = new Date(ts * 1000);
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
  };
  const esc = (s) => String(s == null ? "" : s).replace(/[&<>"]/g,
    (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  const KIND_MEANING = {
    probe: "server-list ping (reconnaissance - the bulk of internet scanning)",
    login: "login attempt (tried to actually join the server)",
    malformed: "connected but did not speak Minecraft (generic port scanner)",
    scan: "connected then disconnected without sending anything",
    error: "handler error",
  };

  /* A self-contained block meant to be pasted straight into an AI. It carries
     enough context that the model does not have to guess what Hivewatch is. */
  function eventReport(ev) {
    const iso = new Date(ev.ts * 1000).toISOString();
    const local = new Date(ev.ts * 1000).toLocaleString();
    const geo = ev.is_private
      ? "private / LAN address - not routable on the internet"
      : [[ev.city, ev.country].filter(Boolean).join(", ") || "unknown",
         ev.country_code ? `(${ev.country_code})` : "",
         (ev.lat != null && ev.lon != null) ? `lat ${ev.lat}, lon ${ev.lon}` : ""]
        .filter(Boolean).join("  ");

    const line = (k, v) => `${(k + ":").padEnd(17)}${v}`;
    return [
      "Minecraft honeypot event captured by Hivewatch (homelab: demo-lab).",
      "The local demo sensor records connections to its Minecraft listener.",
      "These observations alone do not establish malicious intent.",
      "",
      line("Time (UTC)", iso),
      line("Time (local)", local),
      line("Source IP", ev.ip + (ev.port ? `:${ev.port}` : "")),
      line("Geolocation", geo),
      line("Network / ISP", ev.isp || "unknown"),
      line("Event type", `${ev.kind} - ${KIND_MEANING[ev.kind] || "unclassified"}`),
      line("Severity", `${ev.severity ?? "?"} (1 low, 3 high)`),
      line("Username tried", ev.username || "none"),
      line("Protocol ver.", ev.proto_version != null
        ? `${ev.proto_version} (Minecraft protocol number)` : "n/a"),
      line("Host requested", ev.server_address || "n/a"),
      line("Detected by", ev.source),
      line("Raw detail", ev.detail || "-"),
      "",
      "Note: 'via=proxy-protocol' in the raw detail means the source IP is the",
      "true client address handed over by the tunnel, not the tunnel's own IP.",
      "",
      "Please analyse this event: who is likely behind this address, whether it",
      "is a known scanner or botnet, how concerned I should be, and what (if",
      "anything) I should do about it.",
    ].join("\n");
  }

  /* navigator.clipboard is unavailable on insecure origins, and this dashboard
     can be reached over local HTTP, so fall back to the
     legacy textarea + execCommand path, which still works there. */
  async function copyText(text) {
    try {
      if (navigator.clipboard && window.isSecureContext) {
        await navigator.clipboard.writeText(text);
        return true;
      }
    } catch (e) { /* fall through */ }
    try {
      const ta = document.createElement("textarea");
      ta.value = text;
      ta.setAttribute("readonly", "");
      ta.style.cssText = "position:fixed;top:-2000px;left:-2000px;opacity:0";
      document.body.appendChild(ta);
      ta.select();
      ta.setSelectionRange(0, ta.value.length);
      const ok = document.execCommand("copy");
      document.body.removeChild(ta);
      return ok;
    } catch (e) {
      return false;
    }
  }

  /* Last-resort copy path. Browsers only expose navigator.clipboard on a
     secure origin, so over plain http (e.g. straight to 192.0.2.10:8099)
     the text is presented pre-selected for a manual Ctrl+C instead. */
  function showFallback(text, ip) {
    document.getElementById("copyfall")?.remove();
    const wrap = document.createElement("div");
    wrap.id = "copyfall";
    wrap.innerHTML =
      `<div class="box">
         <h3>Copy details for ${esc(ip)}</h3>
         <p>This page is not on HTTPS, so the browser blocks one-click copy.
            The text is selected &mdash; press <kbd>Ctrl</kbd>+<kbd>C</kbd>.
            Open <a href="https://${location.host}${location.pathname}">the HTTPS version</a>
            to copy with a single click.</p>
         <textarea readonly></textarea>
         <button class="close">Close</button>
       </div>`;
    document.body.appendChild(wrap);
    const ta = wrap.querySelector("textarea");
    ta.value = text;
    ta.focus();
    ta.select();
    const close = () => wrap.remove();
    wrap.querySelector(".close").addEventListener("click", close);
    wrap.addEventListener("click", (e) => { if (e.target === wrap) close(); });
    document.addEventListener("keydown", function esc2(e) {
      if (e.key === "Escape") { close(); document.removeEventListener("keydown", esc2); }
    });
  }

  let toastTimer = null;
  function toast(msg, bad) {
    let el = document.getElementById("toast");
    if (!el) {
      el = document.createElement("div");
      el.id = "toast";
      document.body.appendChild(el);
    }
    el.textContent = msg;
    el.className = "show" + (bad ? " bad" : "");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { el.className = ""; }, 1800);
  }

  function pushFeed(ev) {
    const li = document.createElement("li");
    const where = ev.is_private ? "LAN"
      : [ev.city, ev.country_code].filter(Boolean).join(", ") || "unknown";
    li.innerHTML =
      `<span class="t">${hhmm(ev.ts)}</span>` +
      `<span class="who"><b>${esc(ev.ip)}</b> ` +
      `<span class="cc">${esc(where)}${ev.username ? " &middot; " + esc(ev.username) : ""}</span></span>` +
      `<span class="k ${esc(ev.kind)}">${esc(ev.kind)}</span>` +
      `<button class="copy" title="Copy full details for AI analysis" ` +
      `aria-label="Copy details for ${esc(ev.ip)}">&#128203;</button>`;

    li.querySelector(".copy").addEventListener("click", async (e) => {
      e.stopPropagation();
      const btn = e.currentTarget;
      const text = eventReport(ev);
      const ok = await copyText(text);
      btn.classList.add(ok ? "ok" : "bad");
      btn.innerHTML = ok ? "&#10003;" : "&#10007;";
      if (ok) {
        toast(`Copied ${ev.ip} - paste it into any AI`);
      } else {
        // Neither the clipboard API (needs HTTPS) nor execCommand worked.
        // Hand the text over in a pre-selected box so it is never a dead end.
        showFallback(text, ev.ip);
      }
      setTimeout(() => {
        btn.classList.remove("ok", "bad");
        btn.innerHTML = "&#128203;";
      }, 1600);
    });

    feedEl.prepend(li);
    while (feedEl.children.length > 60) feedEl.lastChild.remove();
  }

  function renderStats(s) {
    const q = (id) => document.getElementById(id);
    q("k-window").textContent = s.events_in_window ?? 0;
    q("k-ips").textContent = s.unique_ips_in_window ?? 0;
    q("k-total").textContent = s.total_events ?? 0;
    const logins = (s.by_kind || []).find((k) => k.kind === "login");
    q("k-logins").textContent = logins ? logins.c : 0;

    const maxC = Math.max(1, ...(s.top_countries || []).map((c) => c.c));
    q("countries").innerHTML = (s.top_countries || []).length
      ? s.top_countries.map((c) => `
        <li>
          <div class="row"><span>${esc(c.country || c.country_code || "?")}</span><span>${c.c}</span></div>
          <div class="track"><div class="fill" style="width:${(c.c / maxC) * 100}%"></div></div>
        </li>`).join("")
      : '<li class="muted">nothing yet</li>';

    q("ips").innerHTML = (s.top_ips || []).length
      ? s.top_ips.map((r) => `
        <li><span class="meta">${esc(r.ip)} <span style="opacity:.6">${esc(r.isp || r.country_code || "")}</span></span>
        <span class="n">${r.c}</span></li>`).join("")
      : '<li class="muted">nothing yet</li>';

    q("users").innerHTML = (s.top_usernames || []).length
      ? s.top_usernames.map((u) => `<li>${esc(u.username)} &times;${u.c}</li>`).join("")
      : '<li class="muted">none attempted</li>';

    q("kinds").innerHTML = (s.by_kind || []).map((k) =>
      `<li><span class="meta"><span class="sw ${esc(k.kind)}"></span> ${esc(k.kind)}</span>
       <span class="n">${k.c}</span></li>`).join("");

    drawSpark(s.timeline || []);
  }

  function drawSpark(timeline) {
    const c = document.getElementById("spark");
    const g = c.getContext("2d");
    const w = c.clientWidth || 300, h = 46;
    const r = Math.min(window.devicePixelRatio || 1, 2);
    c.width = w * r; c.height = h * r;
    g.setTransform(r, 0, 0, r, 0, 0);
    g.clearRect(0, 0, w, h);

    const now = Math.floor(Date.now() / 1000);
    const buckets = new Array(24).fill(0);
    for (const row of timeline) {
      const age = Math.floor((now - row.bucket) / 3600);
      if (age >= 0 && age < 24) buckets[23 - age] += row.c;
    }
    const max = Math.max(1, ...buckets);
    const bw = w / 24;
    buckets.forEach((v, i) => {
      const bh = (v / max) * (h - 6);
      g.fillStyle = v ? "#3ddc84" : "#16222e";
      g.fillRect(i * bw + 1, h - Math.max(bh, 2), bw - 2, Math.max(bh, 2));
    });
  }

  async function refreshStats() {
    try {
      const r = await fetch("/api/stats?hours=24");
      renderStats(await r.json());
    } catch (e) { /* keep last render */ }
  }

  /* ---------------- boot ---------------- */
  async function boot() {
    try {
      const cfg = await (await fetch("/api/config")).json();
      if (cfg.home) home = cfg.home;
    } catch (e) { /* defaults */ }

    try {
      const h = await (await fetch("/api/health")).json();
      document.getElementById("mode-label").textContent =
        h.mode === "proxy" ? `proxy :${h.sentinel_port} → ${h.upstream}`
                           : `honeypot :${h.sentinel_port}`;
    } catch (e) { /* ignore */ }

    try {
      const topo = await (await fetch("/static/world-110m.json")).json();
      land = decodeTopology(topo);
    } catch (e) {
      console.error("world map failed to load", e);
    }
    resize();
    requestAnimationFrame(frame);

    // Seed the feed with history, but never animate it.
    try {
      const past = await (await fetch("/api/events?limit=40")).json();
      past.reverse().forEach(pushFeed);
      if (past.length) { sawAnyEvent = true; emptyEl.classList.add("hidden"); }
    } catch (e) { /* ignore */ }

    refreshStats();
    setInterval(refreshStats, 15000);
    connect();
  }

  function connect() {
    const proto = location.protocol === "https:" ? "wss" : "ws";
    const ws = new WebSocket(`${proto}://${location.host}/ws`);

    ws.onopen = () => { linkDot.classList.add("live"); linkDot.title = "live"; };
    ws.onclose = () => {
      linkDot.classList.remove("live");
      linkDot.title = "reconnecting";
      setTimeout(connect, 3000);
    };
    ws.onerror = () => ws.close();
    ws.onmessage = (m) => {
      let msg;
      try { msg = JSON.parse(m.data); } catch (e) { return; }
      if (msg.type === "hello" && msg.home) { home = msg.home; return; }
      if (msg.type !== "event") return;
      const ev = msg.event;
      if (!sawAnyEvent) { sawAnyEvent = true; emptyEl.classList.add("hidden"); }
      pushFeed(ev);
      addStrike(ev);
      refreshStatsSoon();
    };
  }

  let statsTimer = null;
  function refreshStatsSoon() {
    if (statsTimer) return;
    statsTimer = setTimeout(() => { statsTimer = null; refreshStats(); }, 1200);
  }

  boot();
})();
