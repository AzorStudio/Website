const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/db');
const { requireAdmin } = require('../middleware/auth');
const { upload, UPLOAD_DIR } = require('../middleware/upload');
const {
  nowDate,
  slugify,
  csvString,
  logActivity,
  safeUser
} = require('../utils/helpers');

// Protect all admin routes
router.use(requireAdmin);

router.get('/products', async (req, res) => {
  const [products] = await pool.execute(`
    SELECT products.*, users.username AS uploader
    FROM products LEFT JOIN users ON users.id = products.uploaded_by
    ORDER BY products.created_at DESC
  `);
  res.json({ products });
});

router.post('/products', upload.fields([{ name: 'file', maxCount: 1 }, { name: 'icon', maxCount: 1 }]), async (req, res) => {
  const mainFile = req.files?.file?.[0];
  const iconFile = req.files?.icon?.[0];
  if (!mainFile) return res.status(400).json({ error: 'Version file is required. Allowed: .jar, .zip, .mcpack.' });
  if (!iconFile) return res.status(400).json({ error: 'Project icon is required.' });

  const title = String(req.body.title || '').trim().slice(0, 120);
  const type = String(req.body.category || 'plugins').trim();
  const categories = csvString(req.body.categories || '');
  const version = String(req.body.version || 'v1.0.0').trim().slice(0, 80);
  const minecraftVersions = csvString(req.body.minecraftVersions || req.body.minecraftVersion || '1.21.x');
  const loaders = csvString(req.body.loaders || '');
  const platforms = csvString(req.body.platforms || '');
  const environments = csvString(req.body.environments || 'server');
  const license = String(req.body.license || 'proprietary').trim() === 'open_source' ? 'open_source' : 'proprietary';
  const changelog = String(req.body.changelog || '').trim().slice(0, 5000);
  const shortDescription = String(req.body.shortDescription || '').trim().slice(0, 255);
  const description = String(req.body.description || '').trim().slice(0, 5000);

  const isPremium = Number(req.body.isPremium || 0) === 1 ? 1 : 0;
  const price = req.body.price ? Number(req.body.price) : null;
  const purchaseUrl = req.body.purchaseUrl ? String(req.body.purchaseUrl).trim() : null;

  if (!title || !['plugins','setups','configs','skript','mods','resourcepacks'].includes(type) || !shortDescription) {
    return res.status(400).json({ error: 'Title, project type, and short description are required.' });
  }
  if (!loaders) return res.status(400).json({ error: 'At least one loader is required for the uploaded version.' });
  if (!minecraftVersions) return res.status(400).json({ error: 'At least one Minecraft version is required.' });

  const slug = slugify(title) + '-' + crypto.randomBytes(3).toString('hex');
  const createdAt = nowDate();
  const [result] = await pool.execute(`
    INSERT INTO products (title, slug, category, categories, version, short_description, description, file_name, original_file_name, file_size, icon_file, author, license, is_premium, price, purchase_url, uploaded_by, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
  `, [title, slug, type, categories, version, shortDescription, description, mainFile.filename, mainFile.originalname, mainFile.size, iconFile.filename, req.user.username, license, isPremium, price, purchaseUrl, req.user.id, createdAt, createdAt]);

  await pool.execute(`
    INSERT INTO plugin_versions (product_id, version_name, minecraft_version, minecraft_versions, loaders, platforms, environments, file_name, original_file_name, file_size, downloads, changelog, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `, [result.insertId, version, minecraftVersions.split(',')[0] || '1.21.x', minecraftVersions, loaders, platforms, environments, mainFile.filename, mainFile.originalname, mainFile.size, changelog, createdAt]);

  await logActivity(req, req.user.id, 'create_project', `${type}: ${title}`);
  res.json({ ok: true, id: result.insertId });
});

router.patch('/products/:id', upload.single('icon'), async (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id) || id <= 0) return res.status(400).json({ error: 'Invalid product id.' });

  const title = String(req.body.title || '').trim().slice(0, 120);
  const category = String(req.body.category || '').trim();
  const shortDescription = String(req.body.shortDescription || '').trim().slice(0, 255);
  const description = String(req.body.description || '').trim().slice(0, 5000);
  const license = req.body.license !== undefined
    ? (String(req.body.license).trim() === 'open_source' ? 'open_source' : 'proprietary')
    : null;

  if (!title || !['plugins','setups','configs','skript','mods','resourcepacks'].includes(category) || !shortDescription) {
    return res.status(400).json({ error: 'Title, category, and short description are required.' });
  }

  let sql = `
    UPDATE products
    SET title = ?, category = ?, short_description = ?, description = ?, license = COALESCE(?, license)
  `;
  const params = [title, category, shortDescription, description, license];

  if (req.body.isPremium !== undefined) {
    sql += `, is_premium = ?`;
    params.push(Number(req.body.isPremium) === 1 ? 1 : 0);
  }
  if (req.body.price !== undefined) {
    sql += `, price = ?`;
    params.push(req.body.price ? Number(req.body.price) : null);
  }
  if (req.body.purchaseUrl !== undefined) {
    sql += `, purchase_url = ?`;
    params.push(req.body.purchaseUrl ? String(req.body.purchaseUrl).trim() : null);
  }

  if (req.file) {
    sql += `, icon_file = ?`;
    params.push(req.file.filename);
  }

  sql += ` WHERE id = ?`;
  params.push(id);

  const [result] = await pool.execute(sql, params);

  if (!result.affectedRows) return res.status(404).json({ error: 'Product not found.' });
  await logActivity(req, req.user.id, 'edit_product', `${category}: ${title}`);
  res.json({ ok: true });
});

router.delete('/products/:id', async (req, res) => {
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

router.post('/products/:id/versions', upload.single('file'), async (req, res) => {
  const productId = Number(req.params.id);
  if (!req.file) return res.status(400).json({ error: 'Version file is required.' });
  const versionName = String(req.body.versionName || req.body.version || 'v1.0.0').trim().slice(0, 80);
  const minecraftVersions = csvString(req.body.minecraftVersions || req.body.minecraftVersion || '1.21.x');
  const loaders = csvString(req.body.loaders || '');
  const platforms = csvString(req.body.platforms || '');
  const environments = csvString(req.body.environments || 'server');
  const changelog = String(req.body.changelog || '').trim().slice(0, 5000);
  if (!loaders) return res.status(400).json({ error: 'At least one loader is required.' });
  if (!minecraftVersions) return res.status(400).json({ error: 'At least one Minecraft version is required.' });
  const [productRows] = await pool.execute('SELECT id, title FROM products WHERE id = ? LIMIT 1', [productId]);
  if (!productRows[0]) return res.status(404).json({ error: 'Project not found.' });
  await pool.execute(`
    INSERT INTO plugin_versions (product_id, version_name, minecraft_version, minecraft_versions, loaders, platforms, environments, file_name, original_file_name, file_size, downloads, changelog, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, ?, ?)
  `, [productId, versionName, minecraftVersions.split(',')[0] || '1.21.x', minecraftVersions, loaders, platforms, environments, req.file.filename, req.file.originalname, req.file.size, changelog, nowDate()]);
  await pool.execute('UPDATE products SET version = ?, updated_at = ? WHERE id = ?', [versionName, nowDate(), productId]);
  await logActivity(req, req.user.id, 'add_version', `${productRows[0].title}: ${versionName}`);
  res.json({ ok: true });
});

router.patch('/versions/:id', async (req, res) => {
  const id = Number(req.params.id);
  const versionName = String(req.body.versionName || 'v1.0.0').trim().slice(0, 80);
  const minecraftVersions = csvString(req.body.minecraftVersions || '1.21.x');
  const loaders = csvString(req.body.loaders || '');
  const platforms = csvString(req.body.platforms || '');
  const environments = csvString(req.body.environments || 'server');
  const changelog = String(req.body.changelog || '').trim().slice(0, 5000);
  if (!loaders || !minecraftVersions) return res.status(400).json({ error: 'Loaders and Minecraft versions are required.' });
  const [result] = await pool.execute(`
    UPDATE plugin_versions SET version_name = ?, minecraft_version = ?, minecraft_versions = ?, loaders = ?, platforms = ?, environments = ?, changelog = ? WHERE id = ?
  `, [versionName, minecraftVersions.split(',')[0] || '1.21.x', minecraftVersions, loaders, platforms, environments, changelog, id]);
  if (!result.affectedRows) return res.status(404).json({ error: 'Version not found.' });
  await logActivity(req, req.user.id, 'edit_version', versionName);
  res.json({ ok: true });
});

router.post('/versions/:id/replace-file', upload.single('file'), async (req, res) => {
  const id = Number(req.params.id);
  if (!req.file) return res.status(400).json({ error: 'Replacement file is required.' });
  const [rows] = await pool.execute('SELECT * FROM plugin_versions WHERE id = ? LIMIT 1', [id]);
  const version = rows[0];
  if (!version) return res.status(404).json({ error: 'Version not found.' });
  const oldPath = path.join(UPLOAD_DIR, version.file_name);
  if (fs.existsSync(oldPath)) { try { fs.unlinkSync(oldPath); } catch {} }
  await pool.execute('UPDATE plugin_versions SET file_name = ?, original_file_name = ?, file_size = ? WHERE id = ?', [req.file.filename, req.file.originalname, req.file.size, id]);
  await logActivity(req, req.user.id, 'replace_version_file', version.version_name);
  res.json({ ok: true });
});

router.delete('/versions/:id', async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.execute('SELECT * FROM plugin_versions WHERE id = ? LIMIT 1', [id]);
  const version = rows[0];
  if (!version) return res.status(404).json({ error: 'Version not found.' });
  await pool.execute('DELETE FROM plugin_versions WHERE id = ?', [id]);
  const filePath = path.join(UPLOAD_DIR, version.file_name);
  if (fs.existsSync(filePath)) { try { fs.unlinkSync(filePath); } catch {} }
  await logActivity(req, req.user.id, 'delete_version', version.version_name);
  res.json({ ok: true });
});

router.get('/users', async (req, res) => {
  const [rows] = await pool.execute(`
    SELECT id, username, email, role, avatar_url, created_at, last_login_at
    FROM users
    ORDER BY created_at DESC
  `);
  res.json({ users: rows.map(safeUser) });
});

router.get('/activity', async (req, res) => {
  const [activity] = await pool.execute(`
    SELECT activity.*, users.username
    FROM activity
    LEFT JOIN users ON users.id = activity.user_id
    ORDER BY activity.created_at DESC
    LIMIT 200
  `);
  res.json({ activity });
});

router.get('/downloads', async (req, res) => {
  const [downloads] = await pool.execute(`
    SELECT downloads.*, users.username
    FROM downloads
    LEFT JOIN users ON users.id = downloads.user_id
    ORDER BY downloads.created_at DESC
    LIMIT 200
  `);
  res.json({ downloads });
});

module.exports = router;
