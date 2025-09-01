import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import { ensureSchema, seedIfEmpty } from './src/db.js';
import authRouter from './src/routes/auth.js';
import poisRouter from './src/routes/pois.js';
import itinerariesRouter from './src/routes/itineraries.js';

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 8000;

app.use(express.json());
app.use(cors({ origin: (process.env.CORS_ORIGINS || '*').split(',') }));

app.get('/', (_req, res) => res.json({ ok: true, service: 'pyramids-backend-basic' }));

app.use('/auth', authRouter);
app.use('/pois', poisRouter);
app.use('/itineraries', itinerariesRouter);

app.use((err, _req, res, _next) => {
  console.error('ERROR:', err);
  res.status(err?.status || 500).json({ error: err?.message || 'Server error' });
});

ensureSchema();
seedIfEmpty();
app.listen(PORT, () => console.log(`API running on http://127.0.0.1:${PORT}`));
