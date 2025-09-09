// src/routes/auth.js (ESM, PostgreSQL-ready)
// Best-practice Auth with Access/Refresh JWT, rotation, sessions, email verify, password reset.

import express from 'express';
import bcrypt from 'bcrypt';
import jwt from 'jsonwebtoken';
import crypto from 'crypto';
import { db } from '../db.js';

const router = express.Router();

/* -------------------------------------------------------------------------- */
/*                                CONFIG / JWT                                */
/* -------------------------------------------------------------------------- */

const ACCESS_SECRET  = process.env.ACCESS_SECRET  || 'dev_access_secret';
const REFRESH_SECRET = process.env.REFRESH_SECRET || 'dev_refresh_secret';

const ACCESS_TTL   = '15m';                 // access token lifetime
const REFRESH_TTL  = '30d';                 // refresh token lifetime
const RESET_TTL_MS  = 60 * 60 * 1000;       // 1h password reset
const VERIFY_TTL_MS = 24 * 60 * 60 * 1000;  // 24h email verify

const isProd = process.env.NODE_ENV === 'production';

function signAccessToken(payload, opts = {}) {
  return jwt.sign(payload, ACCESS_SECRET, { expiresIn: ACCESS_TTL, ...opts });
}
function signRefreshToken(payload, opts = {}) {
  return jwt.sign(payload, REFRESH_SECRET, { expiresIn: REFRESH_TTL, ...opts });
}
function verifyAccess(token) {
  return jwt.verify(token, ACCESS_SECRET);
}
function verifyRefresh(token) {
  return jwt.verify(token, REFRESH_SECRET);
}
function hashToken(t) {
  return crypto.createHash('sha256').update(t).digest('hex');
}
function nowISO() {
  return new Date().toISOString();
}
function addMs(ms) {
  return new Date(Date.now() + ms).toISOString();
}
function sanitizeUser(u) {
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    createdAt: u.createdAt ?? null,
    emailVerified: u.emailVerified === true || u.emailVerified === 1,
  };
}

/* -------------------------------------------------------------------------- */
/*                              COOKIE UTILITIES                              */
/* -------------------------------------------------------------------------- */

function setRefreshCookie(res, token) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: true,            // true on HTTPS (Render)
    sameSite: 'lax',
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}
function clearRefreshCookie(res) {
  res.clearCookie('refresh_token', { path: '/' });
}

/* -------------------------------------------------------------------------- */
/*                                   HELPERS                                  */
/* -------------------------------------------------------------------------- */

async function storeRefreshToken({ userId, token, userAgent, ip }) {
  const tokenHash = hashToken(token);
  const createdAt = nowISO();
  const expiresAt = addMs(30 * 24 * 60 * 60 * 1000); // 30d

  await db.prepare(`
    INSERT INTO refresh_tokens (userId, tokenHash, createdAt, expiresAt, userAgent, ip)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(userId, tokenHash, createdAt, expiresAt, userAgent || null, ip || null);
}

async function revokeRefreshByHash(tokenHash) {
  await db.prepare(
    `UPDATE refresh_tokens SET revokedAt = ? WHERE tokenHash = ? AND revokedAt IS NULL`
  ).run(nowISO(), tokenHash);
}

async function revokeAllRefreshForUser(userId) {
  await db.prepare(
    `UPDATE refresh_tokens SET revokedAt = ? WHERE userId = ? AND revokedAt IS NULL`
  ).run(nowISO(), userId);
}

/* -------------------------------------------------------------------------- */
/*                                   ROUTES                                   */
/* -------------------------------------------------------------------------- */

// Register
router.post('/register', async (req, res) => {
  try {
    const { email, name, password } = req.body || {};
    if (!email || !name || !password) {
      return res.status(400).json({ error: 'email, name, password required' });
    }

    const exists = await db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(400).json({ error: 'Email already registered' });

    const passwordHash = await bcrypt.hash(password, 10);

    // Postgres: RETURNING to get inserted row
    const user = await db.prepare(`
      INSERT INTO users (email, name, passwordHash)
      VALUES (?, ?, ?)
      RETURNING id, email, name, createdAt, emailVerified
    `).get(email, name, passwordHash);

    const access_token = signAccessToken({ id: user.id, email: user.email });
    const refresh_token = signRefreshToken({ id: user.id });

    await storeRefreshToken({
      userId: user.id,
      token: refresh_token,
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });
    setRefreshCookie(res, refresh_token);

    // (Optional) issue email verify token
    const rawVerify = crypto.randomBytes(32).toString('hex');
    await db.prepare(`
      INSERT INTO email_verification_tokens (userId, tokenHash, createdAt, expiresAt)
      VALUES (?, ?, ?, ?)
    `).run(user.id, hashToken(rawVerify), nowISO(), addMs(VERIFY_TTL_MS));

    return res.status(201).json({
      user: sanitizeUser(user),
      access_token,
      token_type: 'bearer',
      ...(isProd ? {} : { dev_verify_token: rawVerify })
    });
  } catch (e) {
    console.error('[REGISTER] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Login (hardened)
router.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password required' });
    }

    const row = await db.prepare('SELECT * FROM users WHERE email = ?').get(email);
    if (!row) return res.status(400).json({ error: 'Incorrect email or password' });

    // pick stored hash regardless of column naming (legacy safety)
    const storedHash =
      row.passwordHash ??
      row.password_hash ??
      row.password ?? // legacy fallback (not recommended but avoids 500)
      null;

    if (typeof storedHash !== 'string' || storedHash.length < 20) {
      console.error('[LOGIN] invalid/missing password hash for', email, 'value:', storedHash);
      return res.status(500).json({ error: 'User password is invalid on server' });
    }

    let ok = false;
    try {
      ok = await bcrypt.compare(password, storedHash);
    } catch (cmpErr) {
      console.error('[LOGIN] bcrypt.compare error:', cmpErr);
      return res.status(500).json({ error: 'Password check failed' });
    }

    if (!ok) return res.status(400).json({ error: 'Incorrect email or password' });

    const user = {
      id: row.id,
      email: row.email,
      name: row.name,
      createdAt: row.createdAt,
      emailVerified: row.emailVerified
    };

    const access_token = signAccessToken({ id: user.id, email: user.email });
    const refresh_token = signRefreshToken({ id: user.id });

    await storeRefreshToken({
      userId: user.id,
      token: refresh_token,
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });
    setRefreshCookie(res, refresh_token);

    return res.json({ user: sanitizeUser(user), access_token, token_type: 'bearer' });
  } catch (e) {
    console.error('[LOGIN] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Refresh (rotate)
router.post('/refresh', async (req, res) => {
  try {
    const rt = req.cookies?.refresh_token;
    if (!rt) return res.status(401).json({ error: 'Missing refresh token' });

    const rtHash = hashToken(rt);
    const dbRow = await db.prepare('SELECT * FROM refresh_tokens WHERE tokenHash = ?').get(rtHash);

    const payload = verifyRefresh(rt); // { id, iat, exp }

    // Reuse detection
    if (!dbRow || dbRow.revokedAt) {
      await revokeAllRefreshForUser(payload.id);
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token reuse detected' });
    }

    // Rotate
    await revokeRefreshByHash(rtHash);

    const newRt = signRefreshToken({ id: payload.id });
    await storeRefreshToken({
      userId: payload.id,
      token: newRt,
      userAgent: req.headers['user-agent'],
      ip: req.ip
    });
    setRefreshCookie(res, newRt);

    // Issue new access
    const u = await db.prepare('SELECT email FROM users WHERE id = ?').get(payload.id);
    const newAccess = signAccessToken({ id: payload.id, email: u?.email });

    return res.json({ access_token: newAccess, token_type: 'bearer' });
  } catch (e) {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// Logout (revoke current refresh cookie)
router.post('/logout', async (req, res) => {
  try {
    const rt = req.cookies?.refresh_token;
    if (rt) await revokeRefreshByHash(hashToken(rt));
    clearRefreshCookie(res);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[LOGOUT] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Me
router.get('/me', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });

    const decoded = verifyAccess(token);
    const row = await db
      .prepare('SELECT id, email, name, createdAt, emailVerified FROM users WHERE id = ?')
      .get(decoded.id);
    if (!row) return res.status(404).json({ error: 'User not found' });
    return res.json(sanitizeUser(row));
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
});

// Update profile (name / email)
router.patch('/me', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const decoded = verifyAccess(token);

    const { name, email } = req.body || {};
    const current = await db.prepare('SELECT id, email FROM users WHERE id = ?').get(decoded.id);
    if (!current) return res.status(404).json({ error: 'User not found' });

    if (email && email !== current.email) {
      const exists = await db.prepare('SELECT id FROM users WHERE email = ?').get(email);
      if (exists) return res.status(400).json({ error: 'Email already in use' });

      await db.prepare('UPDATE users SET email = ?, emailVerified = false WHERE id = ?')
        .run(email, decoded.id);

      const raw = crypto.randomBytes(32).toString('hex');
      await db.prepare(`
        INSERT INTO email_verification_tokens (userId, tokenHash, createdAt, expiresAt)
        VALUES (?, ?, ?, ?)
      `).run(decoded.id, hashToken(raw), nowISO(), addMs(VERIFY_TTL_MS));

      return res.json({ ok: true, ...(isProd ? {} : { dev_verify_token: raw }) });
    }

    if (name) {
      await db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, decoded.id);
    }
    const row = await db
      .prepare('SELECT id, email, name, createdAt, emailVerified FROM users WHERE id = ?')
      .get(decoded.id);
    return res.json(sanitizeUser(row));
  } catch (e) {
    console.error('[PATCH /me] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Change password (auth required, hardened)
router.post('/password/change', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const decoded = verifyAccess(token);

    const { currentPassword, newPassword } = req.body || {};
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ error: 'currentPassword and newPassword required' });
    }
    const row = await db.prepare('SELECT passwordHash, password_hash, password FROM users WHERE id = ?').get(decoded.id);
    if (!row) return res.status(404).json({ error: 'User not found' });

    const storedHash =
      row.passwordHash ??
      row.password_hash ??
      row.password ??
      null;

    if (typeof storedHash !== 'string' || storedHash.length < 20) {
      console.error('[PASSWORD CHANGE] invalid/missing hash for userId:', decoded.id, 'value:', storedHash);
      return res.status(500).json({ error: 'User password is invalid on server' });
    }

    const ok = await bcrypt.compare(currentPassword, storedHash);
    if (!ok) return res.status(400).json({ error: 'Incorrect current password' });

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(newHash, decoded.id);

    await revokeAllRefreshForUser(decoded.id);
    clearRefreshCookie(res);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[PASSWORD CHANGE] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Forgot password (request reset link)
router.post('/password/forgot', async (req, res) => {
  try {
    const { email } = req.body || {};
    if (!email) return res.status(400).json({ error: 'email required' });

    const user = await db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    // Always respond OK (don’t leak existence)
    if (user) {
      const raw = crypto.randomBytes(32).toString('hex');
      await db.prepare(`
        INSERT INTO password_reset_tokens (userId, tokenHash, createdAt, expiresAt)
        VALUES (?, ?, ?, ?)
      `).run(user.id, hashToken(raw), nowISO(), addMs(RESET_TTL_MS));
      if (!isProd) console.log('[DEV] password reset token:', raw);
    }
    return res.json({ ok: true });
  } catch (e) {
    console.error('[PASSWORD FORGOT] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Reset password (confirm)
router.post('/password/reset', async (req, res) => {
  try {
    const { token, newPassword } = req.body || {};
    if (!token || !newPassword) return res.status(400).json({ error: 'token and newPassword required' });

    const th = hashToken(token);
    const row = await db.prepare('SELECT * FROM password_reset_tokens WHERE tokenHash = ?').get(th);
    if (!row) return res.status(400).json({ error: 'Invalid reset token' });
    if (row.expiresAt && new Date(row.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ error: 'Reset token expired' });
    }

    const newHash = await bcrypt.hash(newPassword, 10);
    await db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(newHash, row.userId);
    await db.prepare('DELETE FROM password_reset_tokens WHERE userId = ?').run(row.userId);
    await revokeAllRefreshForUser(row.userId);
    clearRefreshCookie(res);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[PASSWORD RESET] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Email verify: request (auth required)
router.post('/email/verify/request', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const decoded = verifyAccess(token);

    const raw = crypto.randomBytes(32).toString('hex');
    await db.prepare(`
      INSERT INTO email_verification_tokens (userId, tokenHash, createdAt, expiresAt)
      VALUES (?, ?, ?, ?)
    `).run(decoded.id, hashToken(raw), nowISO(), addMs(VERIFY_TTL_MS));
    return res.json({ ok: true, ...(isProd ? {} : { dev_verify_token: raw }) });
  } catch (e) {
    console.error('[EMAIL VERIFY REQUEST] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Email verify: confirm
router.post('/email/verify/confirm', async (req, res) => {
  try {
    const { token } = req.body || {};
    if (!token) return res.status(400).json({ error: 'token required' });

    const th = hashToken(token);
    const row = await db.prepare('SELECT * FROM email_verification_tokens WHERE tokenHash = ?').get(th);
    if (!row) return res.status(400).json({ error: 'Invalid verify token' });
    if (row.expiresAt && new Date(row.expiresAt).getTime() < Date.now()) {
      return res.status(400).json({ error: 'Verify token expired' });
    }
    await db.prepare('UPDATE users SET emailVerified = true WHERE id = ?').run(row.userId);
    await db.prepare('DELETE FROM email_verification_tokens WHERE userId = ?').run(row.userId);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[EMAIL VERIFY CONFIRM] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Sessions: list active refresh tokens (auth)
router.get('/sessions', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const decoded = verifyAccess(token);

    const list = await db.prepare(`
      SELECT id, createdAt, expiresAt, revokedAt, userAgent, ip
      FROM refresh_tokens
      WHERE userId = ? AND revokedAt IS NULL
      ORDER BY createdAt DESC
    `).all(decoded.id);
    return res.json({ sessions: list });
  } catch (e) {
    console.error('[SESSIONS LIST] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// Sessions: revoke by id (auth)
router.post('/sessions/revoke', async (req, res) => {
  try {
    const auth = req.headers.authorization || '';
    const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
    if (!token) return res.status(401).json({ error: 'Missing token' });
    const decoded = verifyAccess(token);

    const { tokenId } = req.body || {};
    if (!tokenId) return res.status(400).json({ error: 'tokenId required' });

    await db.prepare(
      `UPDATE refresh_tokens SET revokedAt = ? WHERE id = ? AND userId = ? AND revokedAt IS NULL`
    ).run(nowISO(), tokenId, decoded.id);
    return res.json({ ok: true });
  } catch (e) {
    console.error('[SESSIONS REVOKE] error', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

export default router;
