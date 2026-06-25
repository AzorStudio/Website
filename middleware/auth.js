const crypto = require('crypto');
const { pool } = require('../config/db');

const SESSION_COOKIE = 'obs_session';
const SESSION_DAYS = 7;
const isProduction = process.env.NODE_ENV === 'production';

function sha256(value) {
  return crypto.createHash('sha256').update(value + process.env.SESSION_SECRET).digest('hex');
}

async function createSession(req, res, user) {
  const raw = crypto.randomBytes(48).toString('base64url');
  const tokenHash = sha256(raw);
  const expires = new Date(Date.now() + SESSION_DAYS * 24 * 60 * 60 * 1000);

  await pool.execute(`
    INSERT INTO sessions (user_id, token_hash, ip, user_agent, created_at, expires_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [user.id, tokenHash, req.ip, req.get('user-agent') || '', new Date(), expires]);

  // GitHub Pages (azorstudio.github.io) -> Railway (website-production-d9c9.up.railway.app)
  // This is a TRUE cross-site / third-party context.
  // Modern Chrome/Firefox require partitioned cookies (CHIPS).
  const origin = req.get('origin') || '';
  const isCrossSite = origin && (
    !origin.includes('localhost') &&
    !origin.includes('127.0.0.1') &&
    !origin.includes(req.get('host'))
  );
  
  const useSecure = isProduction || isCrossSite || req.secure || req.get('x-forwarded-proto') === 'https';

  // CHIPS / Partitioned cookies required for third-party
  res.cookie(SESSION_COOKIE, raw, {
    httpOnly: true,
    sameSite: useSecure ? 'none' : 'lax',
    secure: useSecure,
    partitioned: useSecure, // <-- CRITICAL FIX: CHIPS
    path: '/',
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

module.exports = {
  SESSION_COOKIE,
  sha256,
  createSession,
  getSessionUser,
  requireAuth,
  requireAdmin
};
