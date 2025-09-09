// routes/pois.js
import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../middlewares/auth.js';

const router = express.Router();

router.get('/', async (req, res) => {
  const { city, q } = req.query;
  let sql = 'SELECT * FROM pois';
  const params = [];
  const where = [];

  if (city) { where.push('city ILIKE ?'); params.push(`%${city}%`); }
  if (q)    { where.push('(name ILIKE ? OR descriptionShort ILIKE ?)'); params.push(`%${q}%`, `%${q}%`); }
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY id DESC LIMIT 200';

  const rows = await db.prepare(sql).all(...params);
  res.json(rows.map(r => ({
    ...r,
    openHours: r.openHours ? JSON.parse(r.openHours) : null,
    tags: r.tags ? JSON.parse(r.tags) : [],
  })));
});

router.get('/:id', async (req, res) => {
  const id = Number(req.params.id);
  const r = await db.prepare('SELECT * FROM pois WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  r.openHours = r.openHours ? JSON.parse(r.openHours) : null;
  r.tags = r.tags ? JSON.parse(r.tags) : [];
  res.json(r);
});

router.post('/', requireAuth, async (req, res) => {
  const p = req.body || {};
  if (!p.name || !p.type || !p.city || !p.governorate || p.lat == null || p.lng == null) {
    return res.status(400).json({ error: 'name, type, city, governorate, lat, lng required' });
  }

  const openHours = p.openHours ? JSON.stringify(p.openHours) : null;
  const tags = p.tags ? JSON.stringify(p.tags) : JSON.stringify([]);

  const row = await db.prepare(`
    INSERT INTO pois
      (name, type, city, governorate, lat, lng, openHours, avgDurationMin, priceTier, tags, bestTimeOfDay, descriptionShort)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    RETURNING *
  `).get(
    p.name, p.type, p.city, p.governorate, p.lat, p.lng, openHours,
    p.avgDurationMin ?? 120, p.priceTier ?? 2, tags,
    p.bestTimeOfDay ?? 'morning', p.descriptionShort ?? ''
  );

  row.openHours = row.openHours ? JSON.parse(row.openHours) : null;
  row.tags = row.tags ? JSON.parse(row.tags) : [];
  res.status(201).json(row);
});

router.put('/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const exists = await db.prepare('SELECT id FROM pois WHERE id = ?').get(id);
  if (!exists) return res.status(404).json({ error: 'Not found' });

  const p = req.body || {};
  const openHours = p.openHours ? JSON.stringify(p.openHours) : null;
  const tags = p.tags ? JSON.stringify(p.tags) : JSON.stringify([]);

  await db.prepare(`
    UPDATE pois SET
      name = ?, type = ?, city = ?, governorate = ?,
      lat = ?, lng = ?, openHours = ?, avgDurationMin = ?,
      priceTier = ?, tags = ?, bestTimeOfDay = ?, descriptionShort = ?
    WHERE id = ?
  `).run(
    p.name, p.type, p.city, p.governorate,
    p.lat, p.lng, openHours, p.avgDurationMin ?? 120,
    p.priceTier ?? 2, tags, p.bestTimeOfDay ?? 'morning', p.descriptionShort ?? '',
    id
  );

  const row = await db.prepare('SELECT * FROM pois WHERE id = ?').get(id);
  row.openHours = row.openHours ? JSON.parse(row.openHours) : null;
  row.tags = row.tags ? JSON.parse(row.tags) : [];
  res.json(row);
});

router.delete('/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const info = await db.prepare('DELETE FROM pois WHERE id = ?').run(id);
  if (!info.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

export default router;
