import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../middlewares/auth.js';

const router = express.Router();

router.post('/', requireAuth, (req, res) => {
  const { meta, plan } = req.body || {};
  if (!meta || !plan) return res.status(400).json({ error: 'meta and plan required' });
  const now = new Date().toISOString();

  const info = db.prepare(`
    INSERT INTO itineraries (userId, meta, plan, createdAt)
    VALUES (?, ?, ?, ?)
  `).run(req.user.id, JSON.stringify(meta), JSON.stringify(plan), now);

  const r = db.prepare('SELECT * FROM itineraries WHERE id = ?').get(Number(info.lastInsertRowid));
  res.status(201).json({
    id: r.id, userId: r.userId,
    meta: JSON.parse(r.meta),
    plan: JSON.parse(r.plan),
    createdAt: r.createdAt,
  });
});

router.get('/', requireAuth, (req, res) => {
  const rows = db.prepare('SELECT * FROM itineraries WHERE userId = ? ORDER BY id DESC').all(req.user.id);
  res.json(rows.map(r => ({
    id: r.id, userId: r.userId,
    meta: JSON.parse(r.meta),
    plan: JSON.parse(r.plan),
    createdAt: r.createdAt,
  })));
});

router.get('/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const r = db.prepare('SELECT * FROM itineraries WHERE id = ? AND userId = ?').get(id, req.user.id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  res.json({
    id: r.id, userId: r.userId,
    meta: JSON.parse(r.meta),
    plan: JSON.parse(r.plan),
    createdAt: r.createdAt,
  });
});

router.delete('/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM itineraries WHERE id = ? AND userId = ?').run(id, req.user.id);
  if (!info.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

export default router;
