import test from 'node:test';
import assert from 'node:assert/strict';
import WebSocket from 'ws';
import { createServer, turnCredentials } from '../server.js';

const ROOM = 'AbCdEfGhIjKlMnOp1234';

function client(port) {
  const ws = new WebSocket(`ws://127.0.0.1:${port}`);
  const inbox = [];
  const waiters = [];
  ws.on('message', (d) => {
    const m = JSON.parse(d.toString());
    const w = waiters.findIndex((x) => x.pred(m));
    if (w >= 0) waiters.splice(w, 1)[0].resolve(m); else inbox.push(m);
  });
  return {
    ws,
    open: () => new Promise((r) => ws.once('open', r)),
    send: (o) => ws.send(JSON.stringify(o)),
    next: (t) => new Promise((resolve, reject) => {
      const i = inbox.findIndex((m) => m.t === t);
      if (i >= 0) return resolve(inbox.splice(i, 1)[0]);
      waiters.push({ pred: (m) => m.t === t, resolve });
      setTimeout(() => reject(new Error('timeout ' + t)), 2000);
    }),
    closed: () => new Promise((r) => ws.once('close', (code) => r(code))),
  };
}

test('relays between parent and child in the same room only', async () => {
  const s = createServer({ port: 0 }); const port = await s.listen(0);
  const c = client(port); const p = client(port); const x = client(port);
  await Promise.all([c.open(), p.open(), x.open()]);
  c.send({ t: 'join', room: ROOM, role: 'child' });
  assert.equal((await c.next('joined')).peer, false);
  p.send({ t: 'join', room: ROOM, role: 'parent' });
  assert.equal((await p.next('joined')).peer, true);
  await c.next('peer-joined');
  x.send({ t: 'join', room: 'ZZZZZZZZZZZZZZZZZZZZ', role: 'parent' });
  await x.next('joined');
  p.send({ t: 'relay', d: 'sealed-offer' });
  assert.equal((await c.next('relay')).d, 'sealed-offer');
  c.send({ t: 'relay', d: 'sealed-answer' });
  assert.equal((await p.next('relay')).d, 'sealed-answer');
  p.ws.close();
  await c.next('peer-left');
  c.ws.close(); x.ws.close();
  await s.close();
});

test('rejoining the same role replaces the old socket', async () => {
  const s = createServer({ port: 0 }); const port = await s.listen(0);
  const a = client(port); const b = client(port);
  await Promise.all([a.open(), b.open()]);
  a.send({ t: 'join', room: ROOM, role: 'child' }); await a.next('joined');
  const closed = a.closed();
  b.send({ t: 'join', room: ROOM, role: 'child' }); await b.next('joined');
  assert.equal(await closed, 4009);
  b.ws.close(); await s.close();
});

test('invalid room ids and oversized messages are rejected', async () => {
  const s = createServer({ port: 0 }); const port = await s.listen(0);
  const a = client(port); await a.open();
  const closed = a.closed();
  a.send({ t: 'join', room: '../../etc', role: 'child' });
  assert.equal(await closed, 4001);
  const b = client(port); await b.open();
  const bc = b.closed();
  b.ws.send('x'.repeat(70 * 1024));
  assert.equal(await bc, 1009);
  await s.close();
});

test('ICE endpoint returns STUN and time-limited TURN credentials', async () => {
  const s = createServer({ port: 0, turnSecret: 'topsecret', turnUrls: 'turn:turn.example.com:3478' });
  const port = await s.listen(0);
  const r = await fetch(`http://127.0.0.1:${port}/ice?room=${ROOM}`).then((x) => x.json());
  assert.equal(r.iceServers.length, 2);
  const t = r.iceServers[1];
  const [exp] = t.username.split(':');
  assert.ok(Number(exp) > Date.now() / 1000);
  assert.equal(t.credential, turnCredentials('topsecret', ROOM, 6 * 3600, (Number(exp) - 6 * 3600) * 1000).credential);
  assert.equal((await fetch(`http://127.0.0.1:${port}/ice?room=bad`)).status, 400);
  await s.close();
});

test('ICE endpoint supports fixed TURN credentials', async () => {
  const s = createServer({ port: 0, turnSecret: '', turnUsername: 'u1', turnCredential: 'p1', turnUrls: 'turn:t.example.com:3478' });
  const port = await s.listen(0);
  const r = await fetch(`http://127.0.0.1:${port}/ice?room=${ROOM}`).then((x) => x.json());
  assert.deepEqual(r.iceServers[1], { urls: ['turn:t.example.com:3478'], username: 'u1', credential: 'p1' });
  await s.close();
});
