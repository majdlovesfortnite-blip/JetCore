'use strict';
/*
 * JetCore directory server.
 * It does three things only:
 *  1. Keeps a list of usernames and their public keys (first come, first served).
 *  2. Proves that each user owns their username with a signed challenge.
 *  3. Passes small connection messages (WebRTC offers/answers and friend requests) between users.
 * Messages and DMs never go through this server. Those travel directly between people.
 */
const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { WebSocketServer } = require('ws');

const PORT = process.env.PORT || 8080;
const DATA_FILE = process.env.DATA_FILE || path.join(__dirname, 'accounts.json');
const MAX_MESSAGE_BYTES = 256 * 1024;
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;

let accounts = {};
try { accounts = JSON.parse(fs.readFileSync(DATA_FILE, 'utf8')); } catch (_) { accounts = {}; }

function saveAccounts() {
  const tmp = DATA_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(accounts));
  fs.renameSync(tmp, DATA_FILE);
}

const online = new Map(); // username -> websocket

// Must match the client's stable() exactly, so signatures verify.
function stable(v) {
  if (Array.isArray(v)) return '[' + v.map(stable).join(',') + ']';
  if (v && typeof v === 'object') {
    return '{' + Object.keys(v).sort()
      .filter(k => v[k] !== undefined)
      .map(k => JSON.stringify(k) + ':' + stable(v[k]))
      .join(',') + '}';
  }
  return JSON.stringify(v);
}

function verify(pubJwk, data, sigB64) {
  try {
    const key = crypto.createPublicKey({ key: pubJwk, format: 'jwk' });
    return crypto.verify('sha256', data, { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(sigB64, 'base64'));
  } catch (_) {
    return false;
  }
}

function publicProfile(a) {
  return { username: a.username, displayName: a.displayName, tag: a.tag, pubJwk: a.pubJwk, ecdhJwk: a.ecdhJwk };
}

function login(ws, username) {
  if (ws.user && online.get(ws.user) === ws) online.delete(ws.user);
  ws.user = username;
  online.set(username, ws);
}

const server = http.createServer((req, res) => {
  res.writeHead(200, { 'Content-Type': 'text/plain' });
  res.end('JetCore server is running.');
});
const wss = new WebSocketServer({ server, maxPayload: MAX_MESSAGE_BYTES });

wss.on('connection', ws => {
  ws.user = null;
  ws.pendingUser = null;
  ws.nonce = null;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  const send = obj => { if (ws.readyState === 1) ws.send(JSON.stringify(obj)); };
  const fail = error => send({ type: 'error', error });

  ws.on('message', raw => {
    let m;
    try { m = JSON.parse(raw); } catch (_) { return fail('bad json'); }
    switch (m.type) {
      case 'lookup': {
        const a = accounts[String(m.username || '')];
        return send({ type: 'profile', profile: a ? publicProfile(a) : null, online: a ? online.has(a.username) : false });
      }
      case 'auth-start': {
        const a = accounts[String(m.username || '')];
        if (!a) return fail('notfound');
        ws.pendingUser = a.username;
        ws.nonce = crypto.randomBytes(32).toString('base64');
        return send({ type: 'challenge', nonce: ws.nonce });
      }
      case 'auth': {
        const a = ws.pendingUser && accounts[ws.pendingUser];
        if (!a || !ws.nonce || !verify(a.pubJwk, Buffer.from(ws.nonce), String(m.sig || ''))) {
          return fail('auth failed');
        }
        ws.nonce = null;
        login(ws, a.username);
        return send({ type: 'authed', profile: publicProfile(a) });
      }
      case 'register': {
        const p = m.profile || {};
        if (!USERNAME_RE.test(p.username || '')) return fail('invalid username');
        if (accounts[p.username]) return fail('taken');
        if (!p.pubJwk || !p.ecdhJwk || typeof p.displayName !== 'string' || typeof p.tag !== 'string') {
          return fail('invalid profile');
        }
        if (!verify(p.pubJwk, Buffer.from(stable(p)), String(m.sig || ''))) return fail('bad signature');
        accounts[p.username] = {
          username: p.username,
          displayName: p.displayName.slice(0, 32),
          tag: p.tag.slice(0, 4),
          pubJwk: p.pubJwk,
          ecdhJwk: p.ecdhJwk,
        };
        saveAccounts();
        login(ws, p.username);
        return send({ type: 'registered', profile: publicProfile(accounts[p.username]) });
      }
      case 'relay': {
        if (!ws.user) return fail('not signed in');
        const target = online.get(String(m.to || ''));
        if (!target) return send({ type: 'undeliverable', to: m.to });
        if (target.readyState === 1) {
          target.send(JSON.stringify({ type: 'relay', from: ws.user, payload: m.payload }));
        }
        return;
      }
      default:
        return fail('unknown request');
    }
  });

  ws.on('close', () => {
    if (ws.user && online.get(ws.user) === ws) online.delete(ws.user);
  });
});

// Keeps idle connections open through Render's proxy and removes dead ones.
setInterval(() => {
  for (const ws of wss.clients) {
    if (!ws.isAlive) { ws.terminate(); continue; }
    ws.isAlive = false;
    ws.ping();
  }
}, 25000);

server.listen(PORT, () => console.log(`JetCore server listening on port ${PORT}`));