require('dotenv').config();

const express = require('express');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const argon2 = require('argon2');
const mysql = require('mysql2/promise');
const helmet = require('helmet');
const multer = require('multer');
const cors = require('cors');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const cookieParser = require('cookie-parser');

const app = express();
const PORT = Number(process.env.PORT || 3000);
const SESSION_COOKIE = 'obs_session';
const SESSION_DAYS = 7;
const isProduction = process.env.NODE_ENV === 'production';
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5500';
const ALLOWED_ORIGINS = FRONTEND_URL.split(',').map((origin) => origin.trim()).filter(Boolean);
const UPLOAD_DIR = path.join(__dirname, 'private_uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const requiredEnv = ['DB_HOST', 'DB_PORT', 'DB_NAME', 'DB_USER', 'DB_PASSWORD', 'SESSION_SECRET'];
if (isProduction && !process.env.FRONTEND_URL) {
  console.warn('[SECURITY WARNING] FRONTEND_URL is missing. Cross-domain login may fail.');
}

for (const key of requiredEnv) {
  if (!process.env[key] || process.env[key].includes('PUT_') || process.env[key].includes('CHANGE_THIS')) {
    console.warn(`[SECURITY WARNING] Missing or placeholder value for ${key}. Add it in .env before production.`);
  }
}

const pool = mysql.createPool({
  host: process.env.DB_HOST,
  port: Number(process.env.DB_PORT || 3306),
  database: process.env.DB_NAME,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  waitForConnections: true,
  connectionLimit: 10,
  queueLimit: 0,
  charset: 'utf8mb4'
});

function nowDate() {
  return new Date();
}

function sha256(value) {
  return crypto.createHash('sha256').update(value + process.env.SESSION_SECRET).digest('hex');
}

function avatarUrl(username) {
  return `https://mc-heads.net/avatar/${encodeURIComponent(username)}/128`;
}

function safeUser(user) {
  if (!user) return null;
  return {
    id: user.id,
    username: user.username,
    email: user.email,
    role: user.role,
    avatarUrl: user.avatar_url || avatarUrl(user.username),
    createdAt: user.created_at,
    lastLoginAt: user.last_login_at
  };
}

function validUsername(username) {
  return /^[A-Za-z0-9_]{3,16}$/.test(username);
}

function validEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

async function initDatabase() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id INT AUTO_INCREMENT PRIMARY KEY,
      username VARCHAR(16) NOT NULL UNIQUE,
      email VARCHAR(191) UNIQUE,
      password_hash TEXT NOT NULL,
      role ENUM('user','admin') NOT NULL DEFAULT 'user',
      avatar_url TEXT,
      created_at DATETIME NOT NULL,
      last_login_at DATETIME NULL,
      INDEX idx_users_role (role)
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS sessions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      token_hash CHAR(64) NOT NULL UNIQUE,
      ip VARCHAR(64),
      user_agent TEXT,
      created_at DATETIME NOT NULL,
      expires_at DATETIME NOT NULL,
      INDEX idx_sessions_user (user_id),
      INDEX idx_sessions_expires (expires_at),
      CONSTRAINT fk_sessions_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      action VARCHAR(64) NOT NULL,
      details TEXT,
      ip VARCHAR(64),
      user_agent TEXT,
      created_at DATETIME NOT NULL,
      INDEX idx_activity_user (user_id),
      INDEX idx_activity_created (created_at),
      CONSTRAINT fk_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS products (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(120) NOT NULL,
      slug VARCHAR(140) NOT NULL UNIQUE,
      category ENUM('plugins','setups','configs','skript','mods','resourcepacks') NOT NULL,
      version VARCHAR(40) NOT NULL,
      short_description VARCHAR(255) NOT NULL,
      description TEXT,
      file_name VARCHAR(255) NOT NULL,
      original_file_name VARCHAR(255) NOT NULL,
      file_size BIGINT NOT NULL,
      uploaded_by INT NULL,
      created_at DATETIME NOT NULL,
      INDEX idx_products_category (category),
      CONSTRAINT fk_products_user FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  try {
    await pool.query("ALTER TABLE products MODIFY category ENUM('plugins','setups','configs','skript','mods','resourcepacks') NOT NULL");
  } catch (error) {
    console.warn('Could not update products category enum:', error.code || error.message);
  }

  await pool.query(`
    CREATE TABLE IF NOT EXISTS downloads (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      item VARCHAR(120) NOT NULL,
      type VARCHAR(60) NOT NULL,
      product_id INT NULL,
      ip VARCHAR(64),
      user_agent TEXT,
      created_at DATETIME NOT NULL,
      INDEX idx_downloads_user (user_id),
      INDEX idx_downloads_created (created_at),
      INDEX idx_downloads_product (product_id),
      CONSTRAINT fk_downloads_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE SET NULL,
      CONSTRAINT fk_downloads_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}


async function ensurePasswordResetTable() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS password_resets (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NOT NULL,
      token_hash CHAR(64) NOT NULL UNIQUE,
      ip VARCHAR(64),
      user_agent TEXT,
      created_at DATETIME NOT NULL,
      expires_at DATETIME NOT NULL,
      used_at DATETIME NULL,
      INDEX idx_password_resets_user (user_id),
      INDEX idx_password_resets_expires (expires_at),
      CONSTRAINT fk_password_resets_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);
}

function getBaseUrl(req) {
  return process.env.PUBLIC_URL || `${req.protocol}://${req.get('host')}`;
}

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD && process.env.MAIL_FROM);
}

async function sendMail(to, subject, text) {
  if (!smtpConfigured()) {
    console.warn('[MAIL NOT CONFIGURED] Email not sent. Content below:');
    console.warn(`To: ${to}
Subject: ${subject}
${text}`);
    return false;
  }

  const transporter = nodemailer.createTransport({
    host: process.env.SMTP_HOST,
    port: Number(process.env.SMTP_PORT || 587),
    secure: String(process.env.SMTP_SECURE || 'false') === 'true',
    auth: {
      user: process.env.SMTP_USER,
      pass: process.env.SMTP_PASSWORD
    }
  });

  await transporter.sendMail({
    from: process.env.MAIL_FROM,
    to,
    subject,
    text
  });
  return true;
}

async function seedAdmin() {
  const username = process.env.ADMIN_USERNAME || 'Warrior_Playz';
  const password = process.env.ADMIN_PASSWORD || 'Admin123';
  const email = process.env.ADMIN_EMAIL || 'admin@obsidian.local';
  const forceReset = String(process.env.ADMIN_RESET_ON_START || 'false') === 'true';

  const passwordHash = await argon2.hash(password, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 4,
    parallelism: 2
  });

  const [rows] = await pool.execute('SELECT id, role FROM users WHERE username = ? LIMIT 1', [username]);
  if (rows.length) {
    const admin = rows[0];
    if (forceReset) {
      await pool.execute(
        "UPDATE users SET password_hash = ?, role = 'admin', email = ?, avatar_url = ? WHERE id = ?",
        [passwordHash, email, avatarUrl(username), admin.id]
      );
      await pool.execute('DELETE FROM sessions WHERE user_id = ?', [admin.id]);
      console.log(`Admin account reset from environment: ${username}`);
    } else if (admin.role !== 'admin') {
      await pool.execute("UPDATE users SET role = 'admin' WHERE id = ?", [admin.id]);
      console.log(`Promoted existing account to admin: ${username}`);
    }
    return;
  }

  await pool.execute(`
    INSERT INTO users (username, email, password_hash, role, avatar_url, created_at)
    VALUES (?, ?, ?, 'admin', ?, ?)
  `, [username, email, passwordHash, avatarUrl(username), nowDate()]);

  console.log(`Seeded admin account: ${username}`);
  if (password === 'Admin123') {
    console.warn('[SECURITY WARNING] Default admin password is Admin123. Change it before public launch.');
  }
}

async function logActivity(req, userId, action, details = '') {
  await pool.execute(`
    INSERT INTO activity (user_id, action, details, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [userId || null, action, String(details).slice(0, 1000), req.ip, req.get('user-agent') || '', nowDate()]);
}

async function createSession(req, res, user) {
  const raw = crypto.randomBytes(48).toString('base64url');
  const tokenHash = sha256(raw);
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);

  await pool.execute(`
    INSERT INTO sessions (user_id, token_hash, ip, user_agent, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [user.id, tokenHash, req.ip, req.get('user-agent') || '', nowDate(), expires]);

  res.cookie(SESSION_COOKIE, raw, {
    httpOnly: true,
    sameSite: isProduction ? 'none' : 'lax',
    secure: isProduction,
    maxAge: SESSION_DAYS * 24 * 60 * 60 * 1000
  });
}

async function getSessionUser(req) {
  const token = req.cookies[SESSION_COOKIE];
  if (!token) return null;
  const tokenHash = sha256(token);
  const [rows] = await pool.execute(`
    SELECT users.* FROM sessions
    JOIN users ON users.id = sessions.user_id
    WHERE sessions.token_hash = ? AND sessions.expires_at > NOW()
    LIMIT 1
  `, [tokenHash]);
  return rows[0] || null;
}

async function requireAuth(req, res, next) {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  req.user = user;
  next();
}

async function requireAdmin(req, res, next) {
  const user = await getSessionUser(req);
  if (!user) return res.status(401).json({ error: 'Not logged in' });
  if (user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  req.user = user;
  next();
}

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(cors({
  origin(origin, callback) {
    // Allow same-origin/server-to-server/no-origin requests and configured frontend domains.
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

const authLimiter = rateLimit({ windowMs: 15 * 60 * 1000, limit: 10, standardHeaders: true, legacyHeaders: false });

app.use(express.static(__dirname, {
  dotfiles: 'ignore',
  etag: true,
  maxAge: isProduction ? '1h' : 0
}));

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, UPLOAD_DIR),
    filename: (req, file, cb) => {
      const safe = file.originalname.replace(/[^a-zA-Z0-9._-]/g, '_');
      cb(null, Date.now() + '-' + crypto.randomBytes(8).toString('hex') + '-' + safe);
    }
  }),
  limits: { fileSize: 100 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    const allowed = ['.jar', '.zip', '.mcpack'];
    const ext = path.extname(file.originalname).toLowerCase();
    cb(null, allowed.includes(ext));
  }
});

function slugify(value) {
  return String(value).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120);
}

app.get('/api/health', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({ ok: true, database: true });
  } catch (error) {
    res.status(500).json({ ok: false, database: false, error: error.code || 'DB_ERROR' });
  }
});

app.post('/api/auth/signup', authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || '').trim();
    const email = String(req.body.email || '').trim().toLowerCase();
    const password = String(req.body.password || '');

    if (!validUsername(username)) return res.status(400).json({ error: 'Username must be 3-16 letters, numbers, or underscores.' });
    if (!validEmail(email)) return res.status(400).json({ error: 'Valid email required.' });
    if (password.length < 8) return res.status(400).json({ error: 'Password must be at least 8 characters.' });

    const passwordHash = await argon2.hash(password, {
      type: argon2.argon2id,
      memoryCost: 65536,
      timeCost: 4,
      parallelism: 2
    });

    const [result] = await pool.execute(`
      INSERT INTO users (username, email, password_hash, role, avatar_url, created_at)
      VALUES (?, ?, ?, 'user', ?, ?)
    `, [username, email, passwordHash, avatarUrl(username), nowDate()]);

    const [rows] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [result.insertId]);
    const user = rows[0];
    await createSession(req, res, user);
    await logActivity(req, user.id, 'signup', 'Created account');
    res.json({ user: safeUser(user) });
  } catch (error) {
    if (error && error.code === 'ER_DUP_ENTRY') return res.status(409).json({ error: 'Username or email already exists.' });
    console.error(error);
    res.status(500).json({ error: 'Signup failed.' });
  }
});

app.post('/api/auth/login', authLimiter, async (req, res) => {
  const username = String(req.body.username || '').trim();
  const password = String(req.body.password || '');
  const [rows] = await pool.execute('SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1', [username, username.toLowerCase()]);
  const user = rows[0];

  if (!user || !(await argon2.verify(user.password_hash, password))) {
    return res.status(401).json({ error: 'Invalid username or password.' });
  }

  await pool.execute('UPDATE users SET last_login_at = ? WHERE id = ?', [nowDate(), user.id]);
  await createSession(req, res, user);
  await logActivity(req, user.id, 'login', 'Logged in');
  const [fresh] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [user.id]);
  res.json({ user: safeUser(fresh[0]) });
});


app.post('/api/auth/change-password', authLimiter, requireAuth, async (req, res) => {
  const currentPassword = String(req.body.currentPassword || '');
  const newPassword = String(req.body.newPassword || '');

  if (newPassword.length < 8) {
    return res.status(400).json({ error: 'New password must be at least 8 characters.' });
  }

  const [rows] = await pool.execute('SELECT * FROM users WHERE id = ? LIMIT 1', [req.user.id]);
  const user = rows[0];
  if (!user || !(await argon2.verify(user.password_hash, currentPassword))) {
    return res.status(401).json({ error: 'Current password is incorrect.' });
  }

  const passwordHash = await argon2.hash(newPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 4,
    parallelism: 2
  });

  await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, user.id]);
  await pool.execute('DELETE FROM sessions WHERE user_id = ? AND token_hash != ?', [user.id, sha256(req.cookies[SESSION_COOKIE] || '')]);
  await logActivity(req, user.id, 'change_password', 'Changed account password');
  res.json({ ok: true });
});

app.post('/api/auth/forgot-password', authLimiter, async (req, res) => {
  const login = String(req.body.login || '').trim();
  const [rows] = await pool.execute('SELECT * FROM users WHERE username = ? OR email = ? LIMIT 1', [login, login.toLowerCase()]);
  const user = rows[0];

  // Always return ok so attackers cannot check which emails/usernames exist.
  if (!user || !user.email) {
    return res.json({ ok: true, message: 'If the account exists, a reset email was sent.' });
  }

  const rawToken = crypto.randomBytes(40).toString('base64url');
  const tokenHash = sha256(rawToken);
  const expires = new Date(Date.now() + 30 * 60 * 1000);

  await pool.execute(`
    INSERT INTO password_resets (user_id, token_hash, ip, user_agent, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [user.id, tokenHash, req.ip, req.get('user-agent') || '', nowDate(), expires]);

  const resetUrl = `${getBaseUrl(req)}/reset.html?token=${encodeURIComponent(rawToken)}`;
  const sent = await sendMail(
    user.email,
    'Reset your Azor Studios password',
    `Hello ${user.username},\n\nUse this link to reset your password. It expires in 30 minutes:\n\n${resetUrl}\n\nIf you did not request this, ignore this email.\n`
  );

  await logActivity(req, user.id, 'forgot_password', sent ? 'Reset email sent' : 'Reset generated but SMTP not configured');
  res.json({ ok: true, message: 'If the account exists, a reset email was sent.' });
});

app.post('/api/auth/reset-password', authLimiter, async (req, res) => {
  const token = String(req.body.token || '');
  const newPassword = String(req.body.newPassword || '');
  if (!token || newPassword.length < 8) {
    return res.status(400).json({ error: 'Invalid token or password too short.' });
  }

  const tokenHash = sha256(token);
  const [rows] = await pool.execute(`
    SELECT password_resets.*, users.username
    FROM password_resets
    JOIN users ON users.id = password_resets.user_id
    WHERE password_resets.token_hash = ?
      AND password_resets.expires_at > NOW()
      AND password_resets.used_at IS NULL
    LIMIT 1
  `, [tokenHash]);
  const reset = rows[0];
  if (!reset) {
    return res.status(400).json({ error: 'Reset link is invalid or expired.' });
  }

  const passwordHash = await argon2.hash(newPassword, {
    type: argon2.argon2id,
    memoryCost: 65536,
    timeCost: 4,
    parallelism: 2
  });

  await pool.execute('UPDATE users SET password_hash = ? WHERE id = ?', [passwordHash, reset.user_id]);
  await pool.execute('UPDATE password_resets SET used_at = ? WHERE id = ?', [nowDate(), reset.id]);
  await pool.execute('DELETE FROM sessions WHERE user_id = ?', [reset.user_id]);
  await logActivity(req, reset.user_id, 'reset_password', 'Password reset with email token');
  res.json({ ok: true });
});

app.post('/api/auth/logout', async (req, res) => {
  const token = req.cookies[SESSION_COOKIE];
  const user = await getSessionUser(req);
  if (token) await pool.execute('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
  if (user) await logActivity(req, user.id, 'logout', 'Logged out');
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
});

app.get('/api/me', async (req, res) => {
  res.json({ user: safeUser(await getSessionUser(req)) });
});

app.post('/api/downloads', async (req, res) => {
  const user = await getSessionUser(req);
  const item = String(req.body.item || 'unknown').slice(0, 80);
  const type = String(req.body.type || 'download').slice(0, 40);

  await pool.execute(`
    INSERT INTO downloads (user_id, item, type, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [user ? user.id : null, item, type, req.ip, req.get('user-agent') || '', nowDate()]);

  await logActivity(req, user ? user.id : null, 'download', `${type}: ${item}`);
  res.json({ ok: true });
});

app.get('/api/profile/:username', (req, res) => {
  const username = String(req.params.username || '').trim();
  res.json({ username, avatarUrl: avatarUrl(username) });
});


app.get('/api/products', async (req, res) => {
  const category = String(req.query.category || '').trim();
  const allowed = ['plugins', 'setups', 'configs', 'skript', 'mods', 'resourcepacks'];
  const params = [];
  let sql = `SELECT products.id,
                    products.title,
                    products.slug,
                    products.category,
                    products.version,
                    products.short_description,
                    products.description,
                    products.original_file_name,
                    products.file_size,
                    products.created_at,
                    users.username AS uploader
             FROM products LEFT JOIN users ON users.id = products.uploaded_by`;
  if (allowed.includes(category)) {
    sql += ' WHERE category = ?';
    params.push(category);
  }
  sql += ' ORDER BY products.created_at DESC';
  const [products] = await pool.execute(sql, params);
  res.json({ products });
});

app.post('/api/admin/products', requireAdmin, upload.single('file'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: 'File is required. Allowed: .jar, .zip, .mcpack up to 100MB.' });
  const title = String(req.body.title || '').trim().slice(0, 120);
  const category = String(req.body.category || '').trim();
  const version = String(req.body.version || '1.0.0').trim().slice(0, 40);
  const shortDescription = String(req.body.shortDescription || '').trim().slice(0, 255);
  const description = String(req.body.description || '').trim().slice(0, 5000);
  if (!title || !['plugins','setups','configs','skript','mods','resourcepacks'].includes(category) || !shortDescription) {
    return res.status(400).json({ error: 'Title, category, and short description are required.' });
  }
  const baseSlug = slugify(title);
  const slug = baseSlug + '-' + crypto.randomBytes(3).toString('hex');
  const [result] = await pool.execute(`
    INSERT INTO products (title, slug, category, version, short_description, description, file_name, original_file_name, file_size, uploaded_by, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [title, slug, category, version, shortDescription, description, req.file.filename, req.file.originalname, req.file.size, req.user.id, nowDate()]);
  await logActivity(req, req.user.id, 'upload', `${category}: ${title}`);
  res.json({ ok: true, id: result.insertId });
});


app.patch('/api/admin/products/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid product id.' });

  const title = String(req.body.title || '').trim().slice(0, 120);
  const category = String(req.body.category || '').trim();
  const version = String(req.body.version || '1.0.0').trim().slice(0, 40);
  const shortDescription = String(req.body.shortDescription || '').trim().slice(0, 255);
  const description = String(req.body.description || '').trim().slice(0, 5000);

  if (!title || !['plugins','setups','configs','skript','mods','resourcepacks'].includes(category) || !shortDescription) {
    return res.status(400).json({ error: 'Title, category, and short description are required.' });
  }

  const [result] = await pool.execute(`
    UPDATE products
    SET title = ?, category = ?, version = ?, short_description = ?, description = ?
    WHERE id = ?
  `, [title, category, version, shortDescription, description, id]);

  if (!result.affectedRows) return res.status(404).json({ error: 'Product not found.' });
  await logActivity(req, req.user.id, 'edit_product', `${category}: ${title}`);
  res.json({ ok: true });
});

app.delete('/api/admin/products/:id', requireAdmin, async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid product id.' });

  const [rows] = await pool.execute('SELECT * FROM products WHERE id = ? LIMIT 1', [id]);
  const product = rows[0];
  if (!product) return res.status(404).json({ error: 'Product not found.' });

  await pool.execute('DELETE FROM products WHERE id = ?', [id]);
  const filePath = path.join(UPLOAD_DIR, product.file_name);
  if (fs.existsSync(filePath)) {
    try { fs.unlinkSync(filePath); } catch (error) { console.warn('Could not delete uploaded file:', error.message); }
  }

  await logActivity(req, req.user.id, 'delete_product', `${product.category}: ${product.title}`);
  res.json({ ok: true });
});

app.get('/api/admin/products', requireAdmin, async (req, res) => {
  const [products] = await pool.execute(`
    SELECT products.*, users.username AS uploader
    FROM products LEFT JOIN users ON users.id = products.uploaded_by
    ORDER BY products.created_at DESC
  `);
  res.json({ products });
});

app.get('/download/:id', async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.execute('SELECT * FROM products WHERE id = ? LIMIT 1', [id]);
  const product = rows[0];
  if (!product) return res.status(404).send('File not found');

  const filePath = path.join(UPLOAD_DIR, product.file_name);
  if (!fs.existsSync(filePath)) {
    console.error(`Download file missing for product ${product.id}: ${filePath}`);
    return res.status(404).send('The uploaded file is missing on the server. Re-upload this project from the admin dashboard. For permanent storage on Railway, add a Volume or external storage.');
  }

  const user = await getSessionUser(req);
  await pool.execute(`
    INSERT INTO downloads (user_id, item, type, product_id, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [user ? user.id : null, product.title, product.category, product.id, req.ip, req.get('user-agent') || '', nowDate()]);
  await logActivity(req, user ? user.id : null, 'download', `${product.category}: ${product.title}`);

  res.download(filePath, product.original_file_name, (error) => {
    if (error && !res.headersSent) {
      console.error('Download failed:', error);
      res.status(500).send('Download failed.');
    }
  });
});

app.get('/api/admin/users', requireAdmin, async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT id, username, email, role, avatar_url, created_at, last_login_at
    FROM users
    ORDER BY created_at DESC
  `);
  res.json({ users: rows.map(safeUser) });
});

app.get('/api/admin/activity', requireAdmin, async (req, res) => {
  const [activity] = await pool.execute(`
    SELECT activity.*, users.username
    FROM activity
    LEFT JOIN users ON users.id = activity.user_id
    ORDER BY activity.created_at DESC
    LIMIT 200
  `);
  res.json({ activity });
});

app.get('/api/admin/downloads', requireAdmin, async (req, res) => {
  const [downloads] = await pool.execute(`
    SELECT downloads.*, users.username
    FROM downloads
    LEFT JOIN users ON users.id = downloads.user_id
    ORDER BY downloads.created_at DESC
    LIMIT 200
  `);
  res.json({ downloads });
});

app.get('/admin', (req, res) => {
  res.status(404).send('Admin page is on the frontend host. Use /api/admin/* for backend data.');
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'Server error.' });
});

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
