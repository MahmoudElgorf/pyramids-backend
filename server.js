import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { ensureSchema, seedIfEmpty } from './db.js';
import authRouter from './routes/auth.js';
import poisRouter from './routes/pois.js';
import itinerariesRouter from './routes/itineraries.js';

const app = express();
const PORT = Number(process.env.PORT) || 8000;

app.set('trust proxy', 1);
app.use(express.json({ limit: '1mb' }));

const origins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: origins.includes('*') ? true : origins,
  credentials: true,
  methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

app.use(cookieParser());

app.get('/', (_req, res) => res.json({ ok: true, service: 'pyramids-backend-basic' }));
app.get('/health', (_req, res) => res.send('ok'));

app.use('/api/auth', authRouter);
app.use('/auth', authRouter);
app.use('/pois', poisRouter);
app.use('/itineraries', itinerariesRouter);

app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl });
});

// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('ERROR:', err);
  res.status(err?.status || 500).json({ error: err?.message || 'Server error' });
});

try {
  await ensureSchema();
  await seedIfEmpty();
  console.log('[DB] schema ready.');
} catch (e) {
  console.error('[DB] init error:', e);
  process.exit(1);
}

app.listen(PORT, () => {
  console.log(`API running on :${PORT}`);
  if (origins.includes('*')) console.log('[CORS] echo Origin (credentials enabled).');
  else console.log('[CORS] allowed origins:', origins);
});

process.on('unhandledRejection', (err) => console.error('UNHANDLED REJECTION:', err));
process.on('uncaughtException', (err) => console.error('UNCAUGHT EXCEPTION:', err));
