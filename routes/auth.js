const express = require('express');
const router = express.Router();
const argon2 = require('argon2');
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const { pool } = require('../config/db');
const {
  nowDate,
  avatarUrl,
  safeUser,
  validUsername,
  validEmail,
  getBaseUrl,
  sendMail,
  logActivity
} = require('../utils/helpers');
const {
  SESSION_COOKIE,
  sha256,
  createSession,
  getSessionUser,
  requireAuth
} = require('../middleware/auth');

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: process.env.NODE_ENV === 'production' ? 10 : 1000,
  standardHeaders: true,
  legacyHeaders: false
});

router.post('/signup', authLimiter, async (req, res) => {
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

router.post('/login', authLimiter, async (req, res) => {
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

router.post('/change-password', authLimiter, requireAuth, async (req, res) => {
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

router.post('/forgot-password', authLimiter, async (req, res) => {
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

router.post('/reset-password', authLimiter, async (req, res) => {
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

router.post('/logout', async (req, res) => {
  const token = req.cookies[SESSION_COOKIE];
  const user = await getSessionUser(req);
  if (token) await pool.execute('DELETE FROM sessions WHERE token_hash = ?', [sha256(token)]);
  if (user) await logActivity(req, user.id, 'logout', 'Logged out');
  res.clearCookie(SESSION_COOKIE);
  res.json({ ok: true });
});

router.get('/me', async (req, res) => {
  res.json({ user: safeUser(await getSessionUser(req)) });
});

router.get('/profile/:username', (req, res) => {
  const username = String(req.params.username || '').trim();
  res.json({ username, avatarUrl: avatarUrl(username) });
});

module.exports = router;
