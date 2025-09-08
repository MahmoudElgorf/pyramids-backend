// src/db.js
import 'dotenv/config';
import pg from 'pg';

const { Pool } = pg;

// لازم يكون DATABASE_URL متسجّل في خدمة Render (Environment)
if (!process.env.DATABASE_URL) {
  throw new Error('DATABASE_URL is missing. Add it in Render → Service → Environment.');
}

const useSSL = /render\.com|external/i.test(process.env.DATABASE_URL || '');
export const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: useSSL ? { rejectUnauthorized: false } : false,
});

// helpers شبه sqlite: prepare().run/get/all
function toPgParams(sql, args) {
  let i = 0;
  return { sql: sql.replace(/\?/g, () => `$${++i}`), params: args };
}
class Stmt {
  constructor(sql) { this.sql = sql; }
  async run(...args) {
    const { sql, params } = toPgParams(this.sql, args);
    const r = await pool.query(sql, params);
    return { changes: r.rowCount };
  }
  async get(...args) {
    const { sql, params } = toPgParams(this.sql, args);
    const r = await pool.query(sql, params);
    return r.rows[0] || null;
  }
  async all(...args) {
    const { sql, params } = toPgParams(this.sql, args);
    const r = await pool.query(sql, params);
    return r.rows;
  }
}

export const db = {
  prepare: (sql) => new Stmt(sql),
  exec: (sql) => pool.query(sql),
};

export async function ensureSchema() {
  console.log('[DB] Running Postgres schema');
  const steps = [
    `
    CREATE TABLE IF NOT EXISTS users (
      id SERIAL PRIMARY KEY,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      passwordHash TEXT NOT NULL,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      emailVerified BOOLEAN NOT NULL DEFAULT false
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS refresh_tokens (
      id SERIAL PRIMARY KEY,
      userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tokenHash TEXT NOT NULL UNIQUE,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expiresAt TIMESTAMPTZ NOT NULL,
      revokedAt TIMESTAMPTZ,
      userAgent TEXT,
      ip TEXT
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS email_verification_tokens (
      id SERIAL PRIMARY KEY,
      userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tokenHash TEXT NOT NULL UNIQUE,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expiresAt TIMESTAMPTZ NOT NULL
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id SERIAL PRIMARY KEY,
      userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      tokenHash TEXT NOT NULL UNIQUE,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      expiresAt TIMESTAMPTZ NOT NULL
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS pois (
      id SERIAL PRIMARY KEY,
      name TEXT NOT NULL,
      type TEXT NOT NULL,
      city TEXT NOT NULL,
      governorate TEXT NOT NULL,
      lat DOUBLE PRECISION NOT NULL,
      lng DOUBLE PRECISION NOT NULL,
      openHours TEXT,
      avgDurationMin INTEGER DEFAULT 120,
      priceTier INTEGER DEFAULT 2,
      tags TEXT,
      bestTimeOfDay TEXT DEFAULT 'morning',
      descriptionShort TEXT DEFAULT ''
    );
    `,
    `
    CREATE TABLE IF NOT EXISTS itineraries (
      id SERIAL PRIMARY KEY,
      userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
      meta TEXT NOT NULL,
      plan TEXT NOT NULL,
      createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW()
    );
    `,
  ];

  for (const sql of steps) {
    try { await db.exec(sql); }
    catch (e) {
      console.error('[DB] schema step failed:', e.message);
      console.error(sql);
      throw e;
    }
  }
}

export async function seedIfEmpty() {
  const row = await db.prepare('SELECT COUNT(*) AS c FROM pois').get();
  const count = Number(row?.c ?? 0);
  if (count > 0) return;

  const insert = db.prepare(`
    INSERT INTO pois
      (name, type, city, governorate, lat, lng, openHours, avgDurationMin, priceTier, tags, bestTimeOfDay, descriptionShort)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `);

  const seed = [
    {
      name: 'Giza Pyramids', type: 'Complex', city: 'Giza', governorate: 'Giza',
      lat: 29.9792, lng: 31.1342,
      openHours: JSON.stringify({ mon: { open: '08:00', close: '17:00' } }),
      avgDurationMin: 180, priceTier: 2,
      tags: JSON.stringify(['pyramids','history','photography']),
      bestTimeOfDay: 'morning',
      descriptionShort: 'Khufu, Khafre, Menkaure and the Great Sphinx.'
    },
    {
      name: 'Saqqara – Step Pyramid', type: 'Pyramid', city: 'Giza', governorate: 'Giza',
      lat: 29.8711, lng: 31.2166,
      openHours: JSON.stringify({ mon: { open: '08:00', close: '17:00' } }),
      avgDurationMin: 120, priceTier: 2,
      tags: JSON.stringify(['history']),
      bestTimeOfDay: 'morning',
      descriptionShort: 'Djoser step pyramid by Imhotep.'
    },
    {
      name: 'Karnak Temple', type: 'Temple', city: 'Luxor', governorate: 'Luxor',
      lat: 25.7188, lng: 32.6573,
      openHours: JSON.stringify({ mon: { open: '08:00', close: '17:00' } }),
      avgDurationMin: 150, priceTier: 2,
      tags: JSON.stringify(['temple','history']),
      bestTimeOfDay: 'afternoon',
      descriptionShort: 'Massive complex dedicated to Amun.'
    }
  ];

  for (const r of seed) {
    await insert.run(
      r.name, r.type, r.city, r.governorate, r.lat, r.lng, r.openHours,
      r.avgDurationMin, r.priceTier, r.tags, r.bestTimeOfDay, r.descriptionShort
    );
  }
  console.log('Seed data inserted (POIs).');
}
