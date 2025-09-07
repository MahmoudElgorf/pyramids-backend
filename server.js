import 'dotenv/config';
import express from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';            // ← مهم للكوكي
import { ensureSchema, seedIfEmpty } from './src/db.js';
import authRouter from './src/routes/auth.js';
import poisRouter from './src/routes/pois.js';
import itinerariesRouter from './src/routes/itineraries.js';

const app = express();
const PORT = process.env.PORT ? Number(process.env.PORT) : 8000;

// خلف proxies (Render/Heroku/Nginx) عشان كوكي secure يشتغل صح
app.set('trust proxy', 1);

// JSON body
app.use(express.json());

// لو هتحتاج كوكي من الويب، فعل credentials + origins
// للموبايل مش ضروري credentials، بس مفيش ضرر
const origins = (process.env.CORS_ORIGINS || '*')
  .split(',')
  .map(s => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: origins.includes('*') ? true : origins,
  credentials: true,                                // ← مهم لو هتستخدم كوكي من المتصفح
  methods: ['GET','POST','PATCH','PUT','DELETE','OPTIONS'],
  allowedHeaders: ['Content-Type','Authorization'],
}));

// ضروري عشان req.cookies.refresh_token يشتغل
app.use(cookieParser());

// Health
app.get('/', (_req, res) => res.json({ ok: true, service: 'pyramids-backend-basic' }));

// Routers
app.use('/auth', authRouter);
app.use('/pois', poisRouter);
app.use('/itineraries', itinerariesRouter);

// 404 JSON بدل صفحة HTML
app.use((req, res) => {
  res.status(404).json({ error: 'Not Found', path: req.originalUrl });
});

// Error handler
app.use((err, _req, res, _next) => {
  console.error('ERROR:', err);
  res.status(err?.status || 500).json({ error: err?.message || 'Server error' });
});

// DB
ensureSchema();
seedIfEmpty();

app.listen(PORT, () => console.log(`API running on http://127.0.0.1:${PORT}`));
