// routes/pois.js
import express from 'express';
import { db } from '../db.js';
import { requireAuth } from '../middlewares/auth.js';

const router = express.Router();

/** Normalize a DB row (Postgres lower-cases unquoted identifiers) */
function normalizePoi(r) {
  if (!r) return null;

  // raw fields (handle both cases just in case)
  const openHoursRaw = r.openHours ?? r.openhours ?? null;
  const tagsRaw = r.tags ?? null;

  let openHours = null;
  if (openHoursRaw) {
    if (typeof openHoursRaw === 'string') {
      try { openHours = JSON.parse(openHoursRaw); } catch { openHours = null; }
    } else {
      openHours = openHoursRaw;
    }
  }

  let tags = [];
  if (tagsRaw != null) {
    if (Array.isArray(tagsRaw)) {
      tags = tagsRaw;
    } else if (typeof tagsRaw === 'string') {
      try { tags = JSON.parse(tagsRaw); } catch { tags = []; }
    }
  }

  return {
    id: r.id,
    name: r.name,
    type: r.type,
    city: r.city,
    governorate: r.governorate,
    lat: r.lat,
    lng: r.lng,
    openHours,
    avgDurationMin: r.avgDurationMin ?? r.avgdurationmin ?? null,
    priceTier: r.priceTier ?? r.pricetier ?? null,
    tags,
    bestTimeOfDay: r.bestTimeOfDay ?? r.besttimeofday ?? null,
    descriptionShort: r.descriptionShort ?? r.descriptionshort ?? '',
    createdAt: r.createdAt ?? r.createdat ?? null,
  };
}

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
  res.json(rows.map(normalizePoi));
});

router.get('/:id', async (req, res) => {
  const id = Number(req.params.id);
  const r = await db.prepare('SELECT * FROM pois WHERE id = ?').get(id);
  if (!r) return res.status(404).json({ error: 'Not found' });
  res.json(normalizePoi(r));
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

  res.status(201).json(normalizePoi(row));
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
  res.json(normalizePoi(row));
});

router.delete('/:id', requireAuth, async (req, res) => {
  const id = Number(req.params.id);
  const info = await db.prepare('DELETE FROM pois WHERE id = ?').run(id);
  if (!info.changes) return res.status(404).json({ error: 'Not found' });
  res.json({ ok: true });
});

export default router;
