const nodemailer = require('nodemailer');
const crypto = require('crypto');
const { pool } = require('../config/db');

function nowDate() {
  return new Date();
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

function getBaseUrl(req) {
  if (process.env.PUBLIC_URL && !process.env.PUBLIC_URL.includes('your-backend')) {
    return process.env.PUBLIC_URL.replace(/\/$/, '');
  }
  return `${req.protocol}://${req.get('host')}`;
}

function smtpConfigured() {
  return Boolean(process.env.SMTP_HOST && process.env.SMTP_USER && process.env.SMTP_PASSWORD && process.env.MAIL_FROM);
}

async function sendMail(to, subject, text) {
  if (!smtpConfigured()) {
    console.warn('[MAIL NOT CONFIGURED] Email not sent. Content below:');
    console.warn(`To: ${to}\nSubject: ${subject}\n${text}`);
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

function slugify(value) {
  return String(value).toLowerCase().trim().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 120);
}

function csvList(value) {
  if (Array.isArray(value)) return value.map(String).map(v => v.trim()).filter(Boolean);
  return String(value || '').split(',').map(v => v.trim()).filter(Boolean);
}

function csvString(value) {
  return [...new Set(csvList(value))].join(',');
}

function splitCsv(value) {
  return csvList(value);
}

async function logActivity(req, userId, action, details = '') {
  await pool.execute(`
    INSERT INTO activity (user_id, action, details, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `, [userId || null, action, String(details).slice(0, 1000), req.ip, req.get('user-agent') || '', nowDate()]);
}

module.exports = {
  nowDate,
  avatarUrl,
  safeUser,
  validUsername,
  validEmail,
  getBaseUrl,
  smtpConfigured,
  sendMail,
  slugify,
  csvList,
  csvString,
  splitCsv,
  logActivity
};
