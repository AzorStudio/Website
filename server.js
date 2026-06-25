require('dotenv').config();

const express = require('express');
const path = require('path');
const helmet = require('helmet');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');

const { initDatabase, ensurePasswordResetTable, seedAdmin } = require('./config/db');
const authRouter = require('./routes/auth');
const productsRouter = require('./routes/products');
const adminRouter = require('./routes/admin');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';
const ALLOWED_ORIGINS = FRONTEND_URL.split(',').map((origin) => origin.trim()).filter(Boolean);

const requiredEnv = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'SESSION_SECRET'];
if (isProduction && !process.env.FRONTEND_URL) {
  console.warn('[SECURITY WARNING] FRONTEND_URL is missing. Cross-domain login may fail.');
}

for (const key of requiredEnv) {
  if (!process.env[key] || process.env[key].includes('PUT_') || process.env[key].includes('CHANGE_THIS')) {
    console.warn(`[SECURITY WARNING] Missing or placeholder value for ${key}. Add it in .env before production.`);
  }
}

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(cors({
  origin(origin, callback) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) {
      return callback(null, true);
    }
    return callback(new Error(`CORS blocked origin: ${origin}`));
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type']
}));

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", 'data:', 'https://mc-heads.net'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"]
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(express.json({ limit: '64kb' }));
app.use(cookieParser());
app.use(rateLimit({ windowMs: 60 * 1000, limit: 180, standardHeaders: true, legacyHeaders: false }));

// Static files (public)
app.use(express.static(path.join(__dirname, '..', 'frontend'), {
  dotfiles: 'ignore',
  etag: true,
  maxAge: isProduction ? '1h' : 0
}));

// API Routes
app.use('/api/auth', authRouter);
app.use('/api/admin', adminRouter);
app.use('/', productsRouter); // Serves health, categories, filters, downloads, get products, files serving

// Admin page fallback check
app.get('/admin', (req, res) => {
  res.status(404).send('Admin page is on the frontend host. Use /api/admin/* for backend data.');
});

// Error handler
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: err.message || 'Server error.' });
});

// Database startup & listen
(async () => {
  await initDatabase();
  await ensurePasswordResetTable();
  await seedAdmin();
  app.listen(PORT, () => {
    console.log(`Azor Studios website running on http://localhost:${PORT}`);
  });
})().catch((error) => {
  console.error('Failed to start server:', error);
  process.exit(1);
});
