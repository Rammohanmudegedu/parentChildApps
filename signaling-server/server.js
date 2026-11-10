// Smart Parent – minimal WebRTC signaling relay.
//
// What it does : pairs at most one "parent" and one "child" socket per opaque room id and
//                forwards their messages to each other. Everything after pairing is AES-GCM
//                sealed by the phones, so this server only ever sees ciphertext.
// What it never does : store, log or inspect message contents. State is in memory only and
//                      disappears when a socket closes or the process restarts.

import http from 'node:http';
import crypto from 'node:crypto';
import { WebSocketServer } from 'ws';

export const LIMITS = {
  maxMessageBytes: 64 * 1024,
  msgsPerWindow: 120,
  windowMs: 10_000,
  maxSocketsPerIp: 20,
  heartbeatMs: 30_000,
  turnRequestsPerMinute: 30,
  turnTtlSeconds: 6 * 3600,
};

const ROOM_RE = /^[A-Za-z0-9_-]{16,64}$/;

export function turnCredentials(secret, room, ttl = LIMITS.turnTtlSeconds, now = Date.now()) {
  // coturn "use-auth-secret" REST scheme: username = expiry:label, password = base64(HMAC-SHA1(secret, username))
  const username = `${Math.floor(now / 1000) + ttl}:${room.slice(0, 16)}`;
  const credential = crypto.createHmac('sha1', secret).update(username).digest('base64');
  return { username, credential, ttl };
}

export function createServer(cfg = {}) {
  const config = {
    port: Number(cfg.port ?? process.env.PORT ?? 8080),
    turnSecret: cfg.turnSecret ?? process.env.TURN_SECRET ?? '',
    turnUsername: cfg.turnUsername ?? process.env.TURN_USERNAME ?? '',
    turnCredential: cfg.turnCredential ?? process.env.TURN_CREDENTIAL ?? '',
    turnUrls: (cfg.turnUrls ?? process.env.TURN_URLS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    stunUrls: (cfg.stunUrls ?? process.env.STUN_URLS ?? 'stun:stun.l.google.com:19302,stun:stun1.l.google.com:19302')
      .split(',').map((s) => s.trim()).filter(Boolean),
    allowedOrigins: (cfg.allowedOrigins ?? process.env.ALLOWED_ORIGINS ?? '').split(',').map((s) => s.trim()).filter(Boolean),
    trustProxy: cfg.trustProxy ?? process.env.TRUST_PROXY === '1',
  };

  /** room id -> { parent?: ws, child?: ws } */
  const rooms = new Map();
  const ipSockets = new Map();
  const turnHits = new Map();
  const stats = { connections: 0, relayed: 0, rejected: 0 };

  const clientIp = (req) => (config.trustProxy && req.headers['x-forwarded-for']
    ? String(req.headers['x-forwarded-for']).split(',')[0].trim() : req.socket.remoteAddress) || 'unknown';

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, 'http://x');
    res.setHeader('Cache-Control', 'no-store');
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (url.pathname === '/health') {
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ ok: true, rooms: rooms.size, ...stats }));
    }
    if (url.pathname === '/ice') {
      const ip = clientIp(req);
      const now = Date.now();
      const h = (turnHits.get(ip) || []).filter((t) => now - t < 60_000);
      if (h.length >= LIMITS.turnRequestsPerMinute) { res.writeHead(429); return res.end(); }
      h.push(now); turnHits.set(ip, h);
      const room = url.searchParams.get('room') || '';
      if (!ROOM_RE.test(room)) { res.writeHead(400); return res.end(); }
      const iceServers = [{ urls: config.stunUrls }];
      if (config.turnSecret && config.turnUrls.length) {
        // coturn with use-auth-secret: short-lived credentials per request
        const c = turnCredentials(config.turnSecret, room);
        iceServers.push({ urls: config.turnUrls, username: c.username, credential: c.credential });
      } else if (config.turnUsername && config.turnCredential && config.turnUrls.length) {
        // hosted TURN service with a fixed username/password
        iceServers.push({ urls: config.turnUrls, username: config.turnUsername, credential: config.turnCredential });
      }
      res.writeHead(200, { 'Content-Type': 'application/json' });
      return res.end(JSON.stringify({ iceServers }));
    }
    res.writeHead(404); res.end();
  });

  const wss = new WebSocketServer({
    server,
    maxPayload: LIMITS.maxMessageBytes,
    verifyClient: ({ origin, req }, cb) => {
      // Native WebSocket clients (child foreground service) send no Origin; Capacitor WebViews send theirs.
      if (config.allowedOrigins.length && origin && !config.allowedOrigins.includes(origin)) return cb(false, 403);
      const ip = clientIp(req);
      if ((ipSockets.get(ip) || 0) >= LIMITS.maxSocketsPerIp) return cb(false, 429);
      cb(true);
    },
  });

  const send = (ws, obj) => { if (ws && ws.readyState === 1) ws.send(JSON.stringify(obj)); };

  function leave(ws) {
    if (!ws.room) return;
    const r = rooms.get(ws.room);
    if (r && r[ws.role] === ws) {
      delete r[ws.role];
      const other = r[ws.role === 'parent' ? 'child' : 'parent'];
      send(other, { t: 'peer-left' });
      if (!r.parent && !r.child) rooms.delete(ws.room);
    }
    ws.room = null;
  }

  wss.on('connection', (ws, req) => {
    const ip = clientIp(req);
    ipSockets.set(ip, (ipSockets.get(ip) || 0) + 1);
    stats.connections++;
    ws.alive = true; ws.window = []; ws.room = null; ws.role = null;
    ws.on('pong', () => { ws.alive = true; });

    ws.on('message', (data, isBinary) => {
      const now = Date.now();
      ws.window = ws.window.filter((t) => now - t < LIMITS.windowMs);
      if (ws.window.length >= LIMITS.msgsPerWindow) { stats.rejected++; return ws.close(4008, 'rate'); }
      ws.window.push(now);
      if (isBinary) return ws.close(4003, 'binary');
      let m; try { m = JSON.parse(data.toString()); } catch { return ws.close(4000, 'json'); }
      if (!m || typeof m.t !== 'string') return ws.close(4000, 'shape');

      if (m.t === 'join') {
        if (!ROOM_RE.test(m.room || '') || !['parent', 'child'].includes(m.role)) return ws.close(4001, 'join');
        leave(ws);
        let r = rooms.get(m.room);
        if (!r) { r = {}; rooms.set(m.room, r); }
        const prev = r[m.role];
        if (prev && prev !== ws) { prev.room = null; prev.close(4009, 'replaced'); }
        r[m.role] = ws; ws.room = m.room; ws.role = m.role;
        const other = r[m.role === 'parent' ? 'child' : 'parent'];
        send(ws, { t: 'joined', peer: !!other });
        send(other, { t: 'peer-joined' });
        return;
      }
      if (m.t === 'relay') {
        if (!ws.room || typeof m.d !== 'string') return;
        const r = rooms.get(ws.room);
        const other = r && r[ws.role === 'parent' ? 'child' : 'parent'];
        if (!other) return send(ws, { t: 'no-peer' });
        stats.relayed++;
        return send(other, { t: 'relay', d: m.d });
      }
      if (m.t === 'leave') return leave(ws);
      if (m.t === 'ping') return send(ws, { t: 'pong' });
    });

    ws.on('close', () => {
      leave(ws);
      const n = (ipSockets.get(ip) || 1) - 1;
      if (n <= 0) ipSockets.delete(ip); else ipSockets.set(ip, n);
    });
    ws.on('error', () => {});
  });

  const hb = setInterval(() => {
    for (const ws of wss.clients) {
      if (!ws.alive) { ws.terminate(); continue; }
      ws.alive = false; ws.ping();
    }
  }, LIMITS.heartbeatMs);
  wss.on('close', () => clearInterval(hb));

  return {
    server, wss, rooms, config,
    listen: (port = config.port) => new Promise((ok) => server.listen(port, () => ok(server.address().port))),
    close: () => new Promise((ok) => { clearInterval(hb); for (const c of wss.clients) c.terminate(); wss.close(); server.close(() => ok()); }),
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  const s = createServer();
  s.listen().then((port) => console.log(`[signaling] listening on :${port} (TURN ${s.config.turnSecret || s.config.turnUsername ? 'enabled' : 'disabled'})`));
}
