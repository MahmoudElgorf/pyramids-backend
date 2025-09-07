// routes/auth.js (ESM)
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

const ACCESS_TTL  = '15m';      // access token lifetime
const REFRESH_TTL = '30d';      // refresh token lifetime
const RESET_TTL_MS   = 60 * 60 * 1000;      // 1h password reset
const VERIFY_TTL_MS  = 24 * 60 * 60 * 1000; // 24h email verify

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
  // adjust to your schema
  return {
    id: u.id,
    email: u.email,
    name: u.name,
    createdAt: u.createdAt ?? null,
    emailVerified: u.emailVerified === 1 || u.emailVerified === true,
  };
}

/* -------------------------------------------------------------------------- */
/*                                DB MIGRATIONS                               */
/* -------------------------------------------------------------------------- */

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  passwordHash TEXT NOT NULL,
  createdAt TEXT NOT NULL
);
`);

try { db.exec(`ALTER TABLE users ADD COLUMN emailVerified INTEGER DEFAULT 0;`); } catch { /* exists */ }

db.exec(`
CREATE TABLE IF NOT EXISTS refresh_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  tokenHash TEXT NOT NULL UNIQUE,
  createdAt TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  revokedAt TEXT,
  userAgent TEXT,
  ip TEXT,
  FOREIGN KEY(userId) REFERENCES users(id)
);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS email_verification_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  tokenHash TEXT NOT NULL UNIQUE,
  createdAt TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  FOREIGN KEY(userId) REFERENCES users(id)
);
`);

db.exec(`
CREATE TABLE IF NOT EXISTS password_reset_tokens (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  userId INTEGER NOT NULL,
  tokenHash TEXT NOT NULL UNIQUE,
  createdAt TEXT NOT NULL,
  expiresAt TEXT NOT NULL,
  FOREIGN KEY(userId) REFERENCES users(id)
);
`);

/* -------------------------------------------------------------------------- */
/*                              COOKIE UTILITIES                              */
/* -------------------------------------------------------------------------- */

function setRefreshCookie(res, token) {
  res.cookie('refresh_token', token, {
    httpOnly: true,
    secure: true,            // true on HTTPS
    sameSite: 'lax',
    path: '/',
    maxAge: 30 * 24 * 60 * 60 * 1000,
  });
}
function clearRefreshCookie(res) {
  res.clearCookie('refresh_token', { path: '/' });
}

/* -------------------------------------------------------------------------- */
/*                                  MIDDLEWARE                                */
/* -------------------------------------------------------------------------- */

export function requireAuth(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing token' });

  try {
    const decoded = verifyAccess(token);
    req.user = { id: decoded.id, email: decoded.email };
    next();
  } catch {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

/* -------------------------------------------------------------------------- */
/*                                   HELPERS                                  */
/* -------------------------------------------------------------------------- */

function storeRefreshToken({ userId, token, userAgent, ip }) {
  const tokenHash = hashToken(token);
  const createdAt = nowISO();
  const expiresAt = addMs(30 * 24 * 60 * 60 * 1000); // 30d

  db.prepare(`
    INSERT INTO refresh_tokens (userId, tokenHash, createdAt, expiresAt, userAgent, ip)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(userId, tokenHash, createdAt, expiresAt, userAgent || null, ip || null);
}

function revokeRefreshByHash(tokenHash) {
  db.prepare(`UPDATE refresh_tokens SET revokedAt = ? WHERE tokenHash = ? AND revokedAt IS NULL`)
    .run(nowISO(), tokenHash);
}

function revokeAllRefreshForUser(userId) {
  db.prepare(`UPDATE refresh_tokens SET revokedAt = ? WHERE userId = ? AND revokedAt IS NULL`)
    .run(nowISO(), userId);
}

/* -------------------------------------------------------------------------- */
/*                                   ROUTES                                   */
/* -------------------------------------------------------------------------- */

// Register
router.post('/register', async (req, res) => {
  const { email, name, password } = req.body || {};
  if (!email || !name || !password) {
    return res.status(400).json({ error: 'email, name, password required' });
  }
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 10);
  const info = db.prepare(`
    INSERT INTO users (email, name, passwordHash, createdAt) VALUES (?, ?, ?, ?)
  `).run(email, name, passwordHash, nowISO());

  const user = { id: Number(info.lastInsertRowid), email, name };
  const access_token = signAccessToken({ id: user.id, email: user.email });
  const refresh_token = signRefreshToken({ id: user.id });

  storeRefreshToken({ userId: user.id, token: refresh_token, userAgent: req.headers['user-agent'], ip: req.ip });
  setRefreshCookie(res, refresh_token);

  // (Optional) إصدار توكن تحقق الإيميل
  const rawVerify = crypto.randomBytes(32).toString('hex');
  db.prepare(`
    INSERT INTO email_verification_tokens (userId, tokenHash, createdAt, expiresAt)
    VALUES (?, ?, ?, ?)
  `).run(user.id, hashToken(rawVerify), nowISO(), addMs(VERIFY_TTL_MS));

  // TODO: sendEmailVerification(email, rawVerify)

  res.status(201).json({ user: sanitizeUser(user), access_token, token_type: 'bearer', ...(isProd ? {} : { dev_verify_token: rawVerify }) });
});

// Login
router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row) return res.status(400).json({ error: 'Incorrect email or password' });

  const ok = await bcrypt.compare(password, row.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Incorrect email or password' });

  const user = { id: row.id, email: row.email, name: row.name, createdAt: row.createdAt, emailVerified: row.emailVerified };

  const access_token = signAccessToken({ id: user.id, email: user.email });
  const refresh_token = signRefreshToken({ id: user.id });

  storeRefreshToken({ userId: user.id, token: refresh_token, userAgent: req.headers['user-agent'], ip: req.ip });
  setRefreshCookie(res, refresh_token);

  res.json({ user: sanitizeUser(user), access_token, token_type: 'bearer' });
});

// Refresh (rotate)
router.post('/refresh', (req, res) => {
  const rt = req.cookies?.refresh_token;
  if (!rt) return res.status(401).json({ error: 'Missing refresh token' });

  const rtHash = hashToken(rt);
  const dbRow = db.prepare('SELECT * FROM refresh_tokens WHERE tokenHash = ?').get(rtHash);

  try {
    const payload = verifyRefresh(rt); // { id, iat, exp }
    // Reuse detection: token valid cryptographically but not found in DB
    if (!dbRow || dbRow.revokedAt) {
      // Compromised token → revoke all for that user
      revokeAllRefreshForUser(payload.id);
      clearRefreshCookie(res);
      return res.status(401).json({ error: 'Refresh token reuse detected' });
    }

    // Rotate: revoke old & issue new
    revokeRefreshByHash(rtHash);

    const newRt = signRefreshToken({ id: payload.id });
    storeRefreshToken({ userId: payload.id, token: newRt, userAgent: req.headers['user-agent'], ip: req.ip });
    setRefreshCookie(res, newRt);

    // Issue new access
    // If you want email in payload, fetch it:
    const u = db.prepare('SELECT email FROM users WHERE id = ?').get(payload.id);
    const newAccess = signAccessToken({ id: payload.id, email: u?.email });

    return res.json({ access_token: newAccess, token_type: 'bearer' });
  } catch {
    clearRefreshCookie(res);
    return res.status(401).json({ error: 'Invalid or expired refresh token' });
  }
});

// Logout (revoke current refresh cookie)
router.post('/logout', (req, res) => {
  const rt = req.cookies?.refresh_token;
  if (rt) revokeRefreshByHash(hashToken(rt));
  clearRefreshCookie(res);
  return res.json({ ok: true });
});

// Me
router.get('/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, email, name, createdAt, emailVerified FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'User not found' });
  res.json(sanitizeUser(row));
});

// Update profile (name / email)
router.patch('/me', requireAuth, (req, res) => {
  const { name, email } = req.body || {};
  const current = db.prepare('SELECT id, email FROM users WHERE id = ?').get(req.user.id);
  if (!current) return res.status(404).json({ error: 'User not found' });

  if (email && email !== current.email) {
    const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
    if (exists) return res.status(400).json({ error: 'Email already in use' });
    db.prepare('UPDATE users SET email = ?, emailVerified = 0 WHERE id = ?').run(email, req.user.id);

    // issue verify token
    const raw = crypto.randomBytes(32).toString('hex');
    db.prepare(`
      INSERT INTO email_verification_tokens (userId, tokenHash, createdAt, expiresAt)
      VALUES (?, ?, ?, ?)
    `).run(req.user.id, hashToken(raw), nowISO(), addMs(VERIFY_TTL_MS));
    // TODO send verification email
    return res.json({ ok: true, ...(isProd ? {} : { dev_verify_token: raw }) });
  }

  if (name) {
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(name, req.user.id);
  }
  const row = db.prepare('SELECT id, email, name, createdAt, emailVerified FROM users WHERE id = ?').get(req.user.id);
  return res.json(sanitizeUser(row));
});

// Change password (auth required)
router.post('/password/change', requireAuth, async (req, res) => {
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) {
    return res.status(400).json({ error: 'currentPassword and newPassword required' });
  }
  const row = db.prepare('SELECT passwordHash FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'User not found' });

  const ok = await bcrypt.compare(currentPassword, row.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Incorrect current password' });

  const newHash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(newHash, req.user.id);

  // revoke all sessions
  revokeAllRefreshForUser(req.user.id);
  clearRefreshCookie(res);
  return res.json({ ok: true });
});

// Forgot password (request reset link)
router.post('/password/forgot', (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'email required' });

  const user = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  // Always respond OK (don’t leak existence)
  if (user) {
    const raw = crypto.randomBytes(32).toString('hex');
    db.prepare(`
      INSERT INTO password_reset_tokens (userId, tokenHash, createdAt, expiresAt)
      VALUES (?, ?, ?, ?)
    `).run(user.id, hashToken(raw), nowISO(), addMs(RESET_TTL_MS));
    // TODO: sendResetEmail(email, raw)
    if (!isProd) console.log('[DEV] password reset token:', raw);
  }
  return res.json({ ok: true });
});

// Reset password (confirm)
router.post('/password/reset', async (req, res) => {
  const { token, newPassword } = req.body || {};
  if (!token || !newPassword) return res.status(400).json({ error: 'token and newPassword required' });

  const th = hashToken(token);
  const row = db.prepare('SELECT * FROM password_reset_tokens WHERE tokenHash = ?').get(th);
  if (!row) return res.status(400).json({ error: 'Invalid reset token' });
  if (row.expiresAt && new Date(row.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Reset token expired' });
  }

  const newHash = await bcrypt.hash(newPassword, 10);
  db.prepare('UPDATE users SET passwordHash = ? WHERE id = ?').run(newHash, row.userId);
  // cleanup + revoke sessions
  db.prepare('DELETE FROM password_reset_tokens WHERE userId = ?').run(row.userId);
  revokeAllRefreshForUser(row.userId);
  clearRefreshCookie(res);
  return res.json({ ok: true });
});

// Email verify: request (auth required)
router.post('/email/verify/request', requireAuth, (req, res) => {
  const raw = crypto.randomBytes(32).toString('hex');
  db.prepare(`
    INSERT INTO email_verification_tokens (userId, tokenHash, createdAt, expiresAt)
    VALUES (?, ?, ?, ?)
  `).run(req.user.id, hashToken(raw), nowISO(), addMs(VERIFY_TTL_MS));
  // TODO: sendEmailVerification(currentEmail, raw)
  return res.json({ ok: true, ...(isProd ? {} : { dev_verify_token: raw }) });
});

// Email verify: confirm
router.post('/email/verify/confirm', (req, res) => {
  const { token } = req.body || {};
  if (!token) return res.status(400).json({ error: 'token required' });

  const th = hashToken(token);
  const row = db.prepare('SELECT * FROM email_verification_tokens WHERE tokenHash = ?').get(th);
  if (!row) return res.status(400).json({ error: 'Invalid verify token' });
  if (row.expiresAt && new Date(row.expiresAt).getTime() < Date.now()) {
    return res.status(400).json({ error: 'Verify token expired' });
  }
  db.prepare('UPDATE users SET emailVerified = 1 WHERE id = ?').run(row.userId);
  db.prepare('DELETE FROM email_verification_tokens WHERE userId = ?').run(row.userId);
  return res.json({ ok: true });
});

// Sessions: list active refresh tokens (auth)
router.get('/sessions', requireAuth, (req, res) => {
  const list = db.prepare(`
    SELECT id, createdAt, expiresAt, revokedAt, userAgent, ip
    FROM refresh_tokens
    WHERE userId = ? AND revokedAt IS NULL
    ORDER BY createdAt DESC
  `).all(req.user.id);
  res.json({ sessions: list });
});

// Sessions: revoke by id (auth)
router.post('/sessions/revoke', requireAuth, (req, res) => {
  const { tokenId } = req.body || {};
  if (!tokenId) return res.status(400).json({ error: 'tokenId required' });
  db.prepare(`UPDATE refresh_tokens SET revokedAt = ? WHERE id = ? AND userId = ? AND revokedAt IS NULL`)
    .run(nowISO(), tokenId, req.user.id);
  return res.json({ ok: true });
});

export default router;
