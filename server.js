'use strict';

/*
 * JetCore directory + WebSocket server
 *
 * Stores permanently:
 *   - usernames
 *   - display names
 *   - tags
 *   - public keys
 *   - ECDH keys
 *
 * WebRTC signaling / relay behavior remains the same.
 * Actual DMs are NOT stored by this server.
 */

const http = require('http');
const crypto = require('crypto');
const { WebSocketServer } = require('ws');
const { neon } = require('@neondatabase/serverless');

const PORT = process.env.PORT || 8080;
const MAX_MESSAGE_BYTES = 256 * 1024;
const USERNAME_RE = /^[a-z0-9_]{3,20}$/;

if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is not set');
}

const sql = neon(process.env.DATABASE_URL);

// =====================================================
// DATABASE
// =====================================================

async function initDatabase() {
  await sql`
    CREATE TABLE IF NOT EXISTS users (
      username VARCHAR(20) PRIMARY KEY,
      display_name VARCHAR(32) NOT NULL,
      tag VARCHAR(4) NOT NULL,
      pub_jwk JSONB NOT NULL,
      ecdh_jwk JSONB NOT NULL,
      created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `;

  console.log('JetCore database ready.');
}

async function getUser(username) {
  const rows = await sql`
    SELECT
      username,
      display_name,
      tag,
      pub_jwk,
      ecdh_jwk
    FROM users
    WHERE username = ${username}
    LIMIT 1
  `;

  if (rows.length === 0) return null;

  return {
    username: rows[0].username,
    displayName: rows[0].display_name,
    tag: rows[0].tag,
    pubJwk: rows[0].pub_jwk,
    ecdhJwk: rows[0].ecdh_jwk
  };
}

async function createUser(profile) {
  const rows = await sql`
    INSERT INTO users (
      username,
      display_name,
      tag,
      pub_jwk,
      ecdh_jwk
    )
    VALUES (
      ${profile.username},
      ${profile.displayName.slice(0, 32)},
      ${profile.tag.slice(0, 4)},
      ${JSON.stringify(profile.pubJwk)}::jsonb,
      ${JSON.stringify(profile.ecdhJwk)}::jsonb
    )
    RETURNING
      username,
      display_name,
      tag,
      pub_jwk,
      ecdh_jwk
  `;

  return {
    username: rows[0].username,
    displayName: rows[0].display_name,
    tag: rows[0].tag,
    pubJwk: rows[0].pub_jwk,
    ecdhJwk: rows[0].ecdh_jwk
  };
}

// =====================================================
// STABLE JSON
// Must match the client's stable() exactly.
// =====================================================

function stable(v) {
  if (Array.isArray(v)) {
    return '[' + v.map(stable).join(',') + ']';
  }

  if (v && typeof v === 'object') {
    return '{' +
      Object.keys(v)
        .sort()
        .filter(k => v[k] !== undefined)
        .map(
          k => JSON.stringify(k) + ':' + stable(v[k])
        )
        .join(',') +
      '}';
  }

  return JSON.stringify(v);
}

// =====================================================
// CRYPTO
// =====================================================

function verify(pubJwk, data, sigB64) {
  try {
    const key = crypto.createPublicKey({
      key: pubJwk,
      format: 'jwk'
    });

    return crypto.verify(
      'sha256',
      data,
      {
        key,
        dsaEncoding: 'ieee-p1363'
      },
      Buffer.from(sigB64, 'base64')
    );
  } catch (_) {
    return false;
  }
}

// =====================================================
// PUBLIC PROFILE
// =====================================================

function publicProfile(user) {
  return {
    username: user.username,
    displayName: user.displayName,
    tag: user.tag,
    pubJwk: user.pubJwk,
    ecdhJwk: user.ecdhJwk
  };
}

// =====================================================
// ONLINE USERS
// =====================================================

const online = new Map();
// username -> websocket

function login(ws, username) {
  if (ws.user && online.get(ws.user) === ws) {
    online.delete(ws.user);
  }

  ws.user = username;
  online.set(username, ws);
}

// =====================================================
// HTTP SERVER
// =====================================================

const server = http.createServer((req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/plain; charset=utf-8'
  });

  res.end('JetCore server is running.');
});

// =====================================================
// WEBSOCKET SERVER
// =====================================================

const wss = new WebSocketServer({
  server,
  maxPayload: MAX_MESSAGE_BYTES
});

wss.on('connection', ws => {
  ws.user = null;
  ws.pendingUser = null;
  ws.nonce = null;
  ws.isAlive = true;

  ws.on('pong', () => {
    ws.isAlive = true;
  });

  const send = obj => {
    if (ws.readyState === 1) {
      ws.send(JSON.stringify(obj));
    }
  };

  const fail = error => {
    send({
      type: 'error',
      error
    });
  };

  ws.on('message', async raw => {
    let m;

    try {
      m = JSON.parse(raw);
    } catch (_) {
      return fail('bad json');
    }

    try {

      // =================================================
      // LOOKUP
      // =================================================

      if (m.type === 'lookup') {
        const username = String(m.username || '');
        const user = await getUser(username);

        return send({
          type: 'profile',
          profile: user ? publicProfile(user) : null,
          online: user ? online.has(user.username) : false
        });
      }

      // =================================================
      // AUTH START
      // =================================================

      if (m.type === 'auth-start') {
        const username = String(m.username || '');
        const user = await getUser(username);

        if (!user) {
          return fail('notfound');
        }

        ws.pendingUser = user.username;

        ws.nonce = crypto
          .randomBytes(32)
          .toString('base64');

        return send({
          type: 'challenge',
          nonce: ws.nonce
        });
      }

      // =================================================
      // AUTH
      // =================================================

      if (m.type === 'auth') {
        const user =
          ws.pendingUser
            ? await getUser(ws.pendingUser)
            : null;

        if (
          !user ||
          !ws.nonce ||
          !verify(
            user.pubJwk,
            Buffer.from(ws.nonce),
            String(m.sig || '')
          )
        ) {
          return fail('auth failed');
        }

        ws.nonce = null;
        ws.pendingUser = null;

        login(ws, user.username);

        return send({
          type: 'authed',
          profile: publicProfile(user)
        });
      }

      // =================================================
      // REGISTER
      // =================================================

      if (m.type === 'register') {
        const p = m.profile || {};

        if (!USERNAME_RE.test(p.username || '')) {
          return fail('invalid username');
        }

        if (
          !p.pubJwk ||
          !p.ecdhJwk ||
          typeof p.displayName !== 'string' ||
          typeof p.tag !== 'string'
        ) {
          return fail('invalid profile');
        }

        // IMPORTANT:
        // Verify the signature before creating the account.
        if (
          !verify(
            p.pubJwk,
            Buffer.from(stable(p)),
            String(m.sig || '')
          )
        ) {
          return fail('bad signature');
        }

        // First-come-first-served username.
        const existing = await getUser(p.username);

        if (existing) {
          return fail('taken');
        }

        let user;

        try {
          user = await createUser(p);
        } catch (err) {

          // PostgreSQL primary-key race protection.
          // If two people try to register the same username
          // at nearly the same time, one will lose.
          if (
            err &&
            (
              err.code === '23505' ||
              String(err.message || '').includes('duplicate')
            )
          ) {
            return fail('taken');
          }

          throw err;
        }

        login(ws, user.username);

        return send({
          type: 'registered',
          profile: publicProfile(user)
        });
      }

      // =================================================
      // WEBRTC RELAY
      // =================================================

      if (m.type === 'relay') {
        if (!ws.user) {
          return fail('not signed in');
        }

        const targetUsername = String(m.to || '');
        const target = online.get(targetUsername);

        if (!target) {
          return send({
            type: 'undeliverable',
            to: targetUsername
          });
        }

        if (target.readyState === 1) {
          target.send(
            JSON.stringify({
              type: 'relay',
              from: ws.user,
              payload: m.payload
            })
          );
        }

        return;
      }

      return fail('unknown request');

    } catch (err) {
      console.error('JetCore request error:', err);

      return fail('server error');
    }
  });

  ws.on('close', () => {
    if (
      ws.user &&
      online.get(ws.user) === ws
    ) {
      online.delete(ws.user);
    }
  });
});

// =====================================================
// KEEP WEBSOCKET CONNECTIONS ALIVE
// =====================================================

setInterval(() => {
  for (const ws of wss.clients) {

    if (!ws.isAlive) {
      ws.terminate();
      continue;
    }

    ws.isAlive = false;
    ws.ping();
  }
}, 25000);

// =====================================================
// START
// =====================================================

async function start() {
  await initDatabase();

  server.listen(PORT, () => {
    console.log(
      `JetCore server listening on port ${PORT}`
    );
  });
}

start().catch(err => {
  console.error('Failed to start JetCore:', err);
  process.exit(1);
});
