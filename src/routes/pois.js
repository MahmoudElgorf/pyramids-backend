import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../middlewares/auth.js';

const router = express.Router();

router.get('/', (req, res) => {
  const { city, q } = req.query;
  let sql = 'SELECT * FROM pois';
  const params = [];
  const where = [];
  if (city) { where.push('city LIKE ?'); params.push(`%${city}%`); }
  if (q)    { where.push('(name LIKE ? OR descriptionShort LIKE ?)'); params.push(`%${q}%`, `%${q}%`); }
  if (where.length) sql += ' WHERE ' + where.join(' AND ');
  sql += ' ORDER BY id DESC LIMIT 200';

  const rows = db.prepare(sql).all(...params).map((r) => ({
    ...r,
    openHours: r.openHours ? JSON.parse(r.openHours) : null,
    tags: r.tags ? JSON.parse(r.tags) : [],
  }));
  res.json(rows);
});

router.get('/:id', (req, res) => {
  const id = Number(req.params.id);
  const r = db.prepare('SELECT * FROM pois WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  r.openHours = r.openHours ? JSON.parse(r.openHours) : null;
  r.tags = r.tags ? JSON.parse(r.tags) : [];
  res.json(r);
});

router.post('/', requireAuth, (req, res) => {
  const p = req.body || {};
  if (!p.name || !p.type || !p.city || !p.governorate || p.lat == null || p.lng == null) {
    return res.status(400).json({ error: 'name, type, city, governorate, lat, lng required' });
  }
  p.openHours = p.openHours ? JSON.stringify(p.openHours) : null;
  p.tags = p.tags ? JSON.stringify(p.tags) : JSON.stringify([]);
  const info = db.prepare(`
    INSERT INTO pois (name, type, city, governorate, lat, lng, openHours, avgDurationMin, priceTier, tags, bestTimeOfDay, descriptionShort)
    VALUES (@name, @type, @city, @governorate, @lat, @lng, @openHours, @avgDurationMin, @priceTier, @tags, @bestTimeOfDay, @descriptionShort)
  `).run({
    avgDurationMin: 120, priceTier: 2, bestTimeOfDay: 'morning', descriptionShort: '', ...p
  });
  const row = db.prepare('SELECT * FROM pois WHERE id = ?').get(Number(info.lastInsertRowid));
  row.openHours = row.openHours ? JSON.parse(row.openHours) : null;
  row.tags = row.tags ? JSON.parse(row.tags) : [];
  res.status(201).json(row);
});

router.put('/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const exists = db.prepare('SELECT id FROM pois WHERE id = ?').get(id);
  if (!exists) return res.status(404).json({ error: 'Not found' });

  const p = req.body || {};
  p.openHours = p.openHours ? JSON.stringify(p.openHours) : null;
  p.tags = p.tags ? JSON.stringify(p.tags) : JSON.stringify([]);

  db.prepare(`
    UPDATE pois SET
      name=@name, type=@type, city=@city, governorate=@governorate,
      lat=@lat, lng=@lng, openHours=@openHours, avgDurationMin=@avgDurationMin,
      priceTier=@priceTier, tags=@tags, bestTimeOfDay=@bestTimeOfDay, descriptionShort=@descriptionShort
    WHERE id=@id
  `).run({ id, ...p });

  const row = db.prepare('SELECT * FROM pois WHERE id = ?').get(id);
  row.openHours = row.openHours ? JSON.parse(row.openHours) : null;
  row.tags = row.tags ? JSON.parse(row.tags) : [];
  res.json(row);
});

router.delete('/:id', requireAuth, (req, res) => {
  const id = Number(req.params.id);
  const info = db.prepare('DELETE FROM pois WHERE id = ?').run(id);
  if (!info.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

export default router;
