import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { ensureSchema, seedIfEmpty } from './src/db.js';
import authRouter from './src/routes/auth.js';
import poisRouter from './src/routes/pois.js';
import itinerariesRouter from './src/routes/itineraries.js';

const app = express();
const PORT = Number(process.env.PORT) || 8000;

// خلف proxies عشان الكوكي secure يشتغل صح على Render
app.set('trust proxy', 1);

// JSON body
app.use(express.json({ limit: '1mb' }));

// CORS (من env: CORS_ORIGINS="https://frontend.com,https://other.com" أو "*")
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

// Cookies
app.use(cookieParser());

// Health check
app.get('/', (_req, res) => res.json({ ok: true, service: 'pyramids-backend-basic' }));
app.get('/health', (_req, res) => res.send('ok'));

// Routers
app.use('/api/auth', authRouter);
app.use('/auth', authRouter);
app.use('/pois', poisRouter);
app.use('/itineraries', itinerariesRouter);

// 404 JSON
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl });
});

// Error handler
// eslint-disable-next-line no-unused-vars
app.use((err, _req, res, _next) => {
  console.error('ERROR:', err);
  res.status(err?.status || 500).json({ error: err?.message || 'Server error' });
});

// ==== DB init ====
try {
  await ensureSchema();
  await seedIfEmpty();
  console.log('[DB] schema ready.');
} catch (e) {
  console.error('[DB] init error:', e);
  process.exit(1);
}

// Start server
app.listen(PORT, () => {
  console.log(`API running on :${PORT}`);
  if (origins.includes('*')) console.log('[CORS] echo Origin (credentials enabled).');
  else console.log('[CORS] allowed origins:', origins);
});

// سلامة عامة
process.on('unhandledRejection', (err) => console.error('UNHANDLED REJECTION:', err));
process.on('uncaughtException', (err) => console.error('UNCAUGHT EXCEPTION:', err));
