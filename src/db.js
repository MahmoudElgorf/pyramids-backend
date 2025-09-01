import Database from 'better-sqlite3';
import 'dotenv/config';

const DB_FILE = process.env.DB_FILE || './pyramids.db';
export const db = new Database(DB_FILE);

export function ensureSchema() {
  db.prepare(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      email TEXT UNIQUE NOT NULL,
      name TEXT NOT NULL,
      passwordHash TEXT NOT NULL,
      createdAt TEXT NOT NULL
    );
  `).run();

  db.prepare(`
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

  db.prepare(`
    CREATE TABLE IF NOT EXISTS itineraries (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      userId INTEGER NOT NULL,
      meta TEXT NOT NULL,
      plan TEXT NOT NULL,
      createdAt TEXT NOT NULL,
      FOREIGN KEY(userId) REFERENCES users(id)
    );
  `).run();
}

export function seedIfEmpty() {
  const count = db.prepare('SELECT COUNT(*) AS c FROM pois').get().c;
  if (count > 0) return;

  const insert = db.prepare(`
    INSERT INTO pois
      (name, type, city, governorate, lat, lng, openHours, avgDurationMin, priceTier, tags, bestTimeOfDay, descriptionShort)
    VALUES (@name, @type, @city, @governorate, @lat, @lng, @openHours, @avgDurationMin, @priceTier, @tags, @bestTimeOfDay, @descriptionShort)
  `);

  const seedData = [
    {
      name: 'Giza Pyramids',
      type: 'Complex',
      city: 'Giza',
      governorate: 'Giza',
      lat: 29.9792, lng: 31.1342,
      openHours: JSON.stringify({ mon: { open: '08:00', close: '17:00' } }),
      avgDurationMin: 180,
      priceTier: 2,
      tags: JSON.stringify(['pyramids', 'history', 'photography']),
      bestTimeOfDay: 'morning',
      descriptionShort: 'Khufu, Khafre, Menkaure and the Great Sphinx.'
    },
    {
      name: 'Saqqara – Step Pyramid',
      type: 'Pyramid',
      city: 'Giza',
      governorate: 'Giza',
      lat: 29.8711, lng: 31.2166,
      openHours: JSON.stringify({ mon: { open: '08:00', close: '17:00' } }),
      avgDurationMin: 120,
      priceTier: 2,
      tags: JSON.stringify(['history']),
      bestTimeOfDay: 'morning',
      descriptionShort: 'Djoser step pyramid by Imhotep.'
    },
    {
      name: 'Karnak Temple',
      type: 'Temple',
      city: 'Luxor',
      governorate: 'Luxor',
      lat: 25.7188, lng: 32.6573,
      openHours: JSON.stringify({ mon: { open: '08:00', close: '17:00' } }),
      avgDurationMin: 150,
      priceTier: 2,
      tags: JSON.stringify(['temple', 'history']),
      bestTimeOfDay: 'afternoon',
      descriptionShort: 'Massive complex dedicated to Amun.'
    }
  ];

  const tx = db.transaction((rows) => { for (const r of rows) insert.run(r); });
  tx(seedData);

  console.log('Seed data inserted (POIs).');
}
