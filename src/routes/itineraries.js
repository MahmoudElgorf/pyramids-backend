// routes/itineraries.js
import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../middlewares/auth.js';

const router = express.Router();

router.post('/', requireAuth, async (req, res) => {
  const { meta, plan } = req.body || {};
  if (!meta || !plan) return res.status(400).json({ error: 'meta and plan required' });

  const row = await db.prepare(`
    INSERT INTO itineraries (userId, meta, plan)
    VALUES (?, ?, ?)
    RETURNING id, userId, meta, plan, createdAt
  `).get(req.user.id, JSON.stringify(meta), JSON.stringify(plan));

  return res.status(201).json({
    id: row.id,
    userId: row.userId,
    meta: JSON.parse(row.meta),
    plan: JSON.parse(row.plan),
    createdAt: row.createdAt,
  });
});

router.get('/', requireAuth, async (req, res) => {
  const rows = await db
    .prepare('SELECT * FROM itineraries WHERE userId = ? ORDER BY id DESC')
    .all(req.user.id);

  return res.json(rows.map(r => ({
    id: r.id,
    userId: r.userId,
    meta: JSON.parse(r.meta),
    plan: JSON.parse(r.plan),
    createdAt: r.createdAt,
  })));
});

router.get('/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const r = await db
    .prepare('SELECT * FROM itineraries WHERE id = ? AND userId = ?')
    .get(id, req.user.id);

  if (!r) return res.status(404).json({ error: 'Not found' });

  return res.json({
    id: r.id,
    userId: r.userId,
    meta: JSON.parse(r.meta),
    plan: JSON.parse(r.plan),
    createdAt: r.createdAt,
  });
});

router.delete('/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const info = await db
    .prepare('DELETE FROM itineraries WHERE id = ? AND userId = ?')
    .run(id, req.user.id);

  if (!info.changes) return res.status(404).json({ error: 'Not found' });
  return res.json({ ok: true });
});

export default router;
