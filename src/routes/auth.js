import express from 'express';
import bcrypt from 'bcrypt';
import { db } from '../db.js';
import { signToken, requireAuth } from '../middlewares/auth.js';

const router = express.Router();

router.post('/register', async (req, res) => {
  const { email, name, password } = req.body || {};
  if (!email || !name || !password) {
    return res.status(400).json({ error: 'email, name, password required' });
  }
  const exists = db.prepare('SELECT id FROM users WHERE email = ?').get(email);
  if (exists) return res.status(400).json({ error: 'Email already registered' });

  const passwordHash = await bcrypt.hash(password, 10);
  const now = new Date().toISOString();
  const info = db.prepare('INSERT INTO users (email, name, passwordHash, createdAt) VALUES (?, ?, ?, ?)')
    .run(email, name, passwordHash, now);

  const user = { id: Number(info.lastInsertRowid), email, name };
  const access_token = signToken({ id: user.id, email: user.email });
  res.status(201).json({ user, access_token, token_type: 'bearer' });
});

router.post('/login', async (req, res) => {
  const { email, password } = req.body || {};
  if (!email || !password) return res.status(400).json({ error: 'email and password required' });

  const row = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!row) return res.status(400).json({ error: 'Incorrect email or password' });

  const ok = await bcrypt.compare(password, row.passwordHash);
  if (!ok) return res.status(400).json({ error: 'Incorrect email or password' });

  const user = { id: row.id, email: row.email, name: row.name };
  const access_token = signToken({ id: user.id, email: user.email });
  res.json({ user, access_token, token_type: 'bearer' });
});

router.get('/me', requireAuth, (req, res) => {
  const row = db.prepare('SELECT id, email, name, createdAt FROM users WHERE id = ?').get(req.user.id);
  if (!row) return res.status(404).json({ error: 'User not found' });
  res.json(row);
});

export default router;
