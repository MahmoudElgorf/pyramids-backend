// src/db.js
import 'dotenv/config';

const USE_PG = !!process.env.DATABASE_URL;

let db;
let ensureSchema;
let seedIfEmpty;

if (USE_PG) {
  // ---------- PostgreSQL ----------
  const { default: pg } = await import('pg');
  const { Pool } = pg;

  // لو اللينك External يستلزم SSL، Internal لا
  const useSSL = /render\.com|external/i.test(process.env.DATABASE_URL || '');
  const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: useSSL ? { rejectUnauthorized: false } : false,
  });

  // يحوّل placeholders "?" إلى "$1, $2, ..."
  function toPgParams(sql, args) {
    let idx = 0;
    const out = sql.replace(/\?/g, () => `$${++idx}`);
    return { sql: out, params: args };
  }

  class PgStatement {
    constructor(pool, sql) { this.pool = pool; this.sql = sql; }
    async run(...args) {
      const { sql, params } = toPgParams(this.sql, args);
      const res = await this.pool.query(sql, params);
      return { changes: res.rowCount };
    }
    async get(...args) {
      const { sql, params } = toPgParams(this.sql, args);
      const res = await this.pool.query(sql, params);
      return res.rows[0] || null;
    }
    async all(...args) {
      const { sql, params } = toPgParams(this.sql, args);
      const res = await this.pool.query(sql, params);
      return res.rows;
    }
  }

  db = {
    prepare(sql) { return new PgStatement(pool, sql); },
    async exec(sql) { await pool.query(sql); },
    __pool: pool,
  };

  ensureSchema = async function ensureSchemaPg() {
    await db.exec(`
      CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        passwordHash TEXT NOT NULL,
        createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        emailVerified BOOLEAN NOT NULL DEFAULT false
      );
    `);

    await db.exec(`
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
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS email_verification_tokens (
        id SERIAL PRIMARY KEY,
        userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tokenHash TEXT NOT NULL UNIQUE,
        createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expiresAt TIMESTAMPTZ NOT NULL
      );
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id SERIAL PRIMARY KEY,
        userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        tokenHash TEXT NOT NULL UNIQUE,
        createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        expiresAt TIMESTAMPTZ NOT NULL
      );
    `);

    await db.exec(`
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
    `);

    await db.exec(`
      CREATE TABLE IF NOT EXISTS itineraries (
        id SERIAL PRIMARY KEY,
        userId INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
        meta TEXT NOT NULL,
        plan TEXT NOT NULL,
        createdAt TIMESTAMPTZ NOT NULL DEFAULT NOW()
      );
    `);
  };

  seedIfEmpty = async function seedIfEmptyPg() {
    const row = await db.prepare('SELECT COUNT(*) AS c FROM pois').get();
    const count = Number(row?.c ?? 0);
    if (count > 0) return;

    const insert = db.prepare(`
      INSERT INTO pois
        (name, type, city, governorate, lat, lng, openHours, avgDurationMin, priceTier, tags, bestTimeOfDay, descriptionShort)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);

    const seedData = [
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

    for (const r of seedData) {
      await insert.run(
        r.name, r.type, r.city, r.governorate, r.lat, r.lng, r.openHours,
        r.avgDurationMin, r.priceTier, r.tags, r.bestTimeOfDay, r.descriptionShort
      );
    }
    console.log('Seed data inserted (POIs) [Postgres].');
  };

} else {
  // ---------- SQLite (اختياري للمحلي) ----------
  const { default: Database } = await import('better-sqlite3');
  const DB_FILE = process.env.DB_FILE || './pyramids.db';
  const sqlite = new Database(DB_FILE);
  try { sqlite.pragma('journal_mode = WAL'); } catch {}

  db = {
    prepare: (sql) => sqlite.prepare(sql),
    exec: (sql) => sqlite.exec(sql),
    __sqlite: sqlite,
  };

  ensureSchema = function ensureSchemaSqlite() {
    sqlite.prepare(`
      CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE NOT NULL,
        name TEXT NOT NULL,
        passwordHash TEXT NOT NULL,
        createdAt TEXT NOT NULL,
        emailVerified INTEGER DEFAULT 0
      );
    `).run();

    sqlite.prepare(`
      CREATE TABLE IF NOT EXISTS refresh_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        tokenHash TEXT NOT NULL UNIQUE,
        createdAt TEXT NOT NULL,
        expiresAt TEXT NOT NULL,
        revokedAt TEXT,
        userAgent TEXT,
        ip TEXT
      );
    `).run();

    sqlite.prepare(`
      CREATE TABLE IF NOT EXISTS email_verification_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        tokenHash TEXT NOT NULL UNIQUE,
        createdAt TEXT NOT NULL,
        expiresAt TEXT NOT NULL
      );
    `).run();

    sqlite.prepare(`
      CREATE TABLE IF NOT EXISTS password_reset_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        tokenHash TEXT NOT NULL UNIQUE,
        createdAt TEXT NOT NULL,
        expiresAt TEXT NOT NULL
      );
    `).run();

    sqlite.prepare(`
      CREATE TABLE IF NOT EXISTS pois (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        type TEXT NOT NULL,
        city TEXT NOT NULL,
        governorate TEXT NOT NULL,
        lat REAL NOT NULL,
        lng REAL NOT NULL,
        openHours TEXT,
        avgDurationMin INTEGER DEFAULT 120,
        priceTier INTEGER DEFAULT 2,
        tags TEXT,
        bestTimeOfDay TEXT DEFAULT 'morning',
        descriptionShort TEXT DEFAULT ''
      );
    `).run();

    sqlite.prepare(`
      CREATE TABLE IF NOT EXISTS itineraries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        userId INTEGER NOT NULL,
        meta TEXT NOT NULL,
        plan TEXT NOT NULL,
        createdAt TEXT NOT NULL
      );
    `).run();
  };

  seedIfEmpty = function seedIfEmptySqlite() {
    const row = sqlite.prepare('SELECT COUNT(*) AS c FROM pois').get();
    if (Number(row.c) > 0) return;

    const insert = sqlite.prepare(`
      INSERT INTO pois
        (name, type, city, governorate, lat, lng, openHours, avgDurationMin, priceTier, tags, bestTimeOfDay, descriptionShort)
      VALUES (@name, @type, @city, @governorate, @lat, @lng, @openHours, @avgDurationMin, @priceTier, @tags, @bestTimeOfDay, @descriptionShort)
    `);

    const seedData = [
      { name:'Giza Pyramids', type:'Complex', city:'Giza', governorate:'Giza',
        lat:29.9792, lng:31.1342, openHours:JSON.stringify({mon:{open:'08:00',close:'17:00'}}),
        avgDurationMin:180, priceTier:2, tags:JSON.stringify(['pyramids','history','photography']),
        bestTimeOfDay:'morning', descriptionShort:'Khufu, Khafre, Menkaure and the Great Sphinx.'
      },
      { name:'Saqqara – Step Pyramid', type:'Pyramid', city:'Giza', governorate:'Giza',
        lat:29.8711, lng:31.2166, openHours:JSON.stringify({mon:{open:'08:00',close:'17:00'}}),
        avgDurationMin:120, priceTier:2, tags:JSON.stringify(['history']),
        bestTimeOfDay:'morning', descriptionShort:'Djoser step pyramid by Imhotep.'
      },
      { name:'Karnak Temple', type:'Temple', city:'Luxor', governorate:'Luxor',
        lat:25.7188, lng:32.6573, openHours:JSON.stringify({mon:{open:'08:00',close:'17:00'}}),
        avgDurationMin:150, priceTier:2, tags:JSON.stringify(['temple','history']),
        bestTimeOfDay:'afternoon', descriptionShort:'Massive complex dedicated to Amun.'
      }
    ];

    const tx = sqlite.transaction(rows => { for (const r of rows) insert.run(r); });
    tx(seedData);
    console.log('Seed data inserted (POIs) [SQLite].');
  };
}

// تصدير موحّد
export { db, ensureSchema, seedIfEmpty };
