const express = require('express');
const router = express.Router();
const fs = require('fs');
const path = require('path');
const { pool } = require('../config/db');
const { UPLOAD_DIR } = require('../middleware/upload');
const { getSessionUser } = require('../middleware/auth');
const {
  nowDate,
  getBaseUrl,
  splitCsv,
  logActivity
} = require('../utils/helpers');

router.get('/api/health', async (req, res) => {
  try {
    await pool.execute('SELECT 1');
    res.json({ ok: true, database: true });
  } catch (error) {
    res.status(500).json({ ok: false, database: false, error: error.code || 'DB_ERROR' });
  }
});

router.get('/api/categories', async (req, res) => {
  const [rows] = await pool.execute(`SELECT category, COUNT(*) AS count FROM products GROUP BY category`);
  const counts = Object.fromEntries(rows.map((row) => [row.category, Number(row.count)]));
  res.json({ counts });
});

router.get('/api/filters', async (req, res) => {
  const [rows] = await pool.execute(`SELECT minecraft_versions FROM plugin_versions WHERE minecraft_versions IS NOT NULL AND minecraft_versions != ''`);
  const versionSet = new Set();
  for (const row of rows) {
    for (const v of splitCsv(row.minecraft_versions)) versionSet.add(v);
  }
  // Sort descending so newest versions show first, matching Modrinth's convention.
  const versions = [...versionSet].sort((a, b) => {
    const partsA = a.split('.').map(Number);
    const partsB = b.split('.').map(Number);
    for (let i = 0; i < Math.max(partsA.length, partsB.length); i++) {
      const diff = (partsB[i] || 0) - (partsA[i] || 0);
      if (diff) return diff;
    }
    return 0;
  });
  res.json({ versions });
});

router.get('/api/products', async (req, res) => {
  const type = String(req.query.category || '').trim();
  const allowed = ['plugins', 'setups', 'configs', 'skript', 'mods', 'resourcepacks'];
  const search = String(req.query.search || '').trim().slice(0, 120);
  const loaderFilter = String(req.query.loader || '').trim().toLowerCase();
  const platformFilter = String(req.query.platform || '').trim().toLowerCase();
  const environmentFilter = String(req.query.environment || '').trim().toLowerCase();
  const licenseFilter = String(req.query.license || '').trim().toLowerCase();
  const mcVersionFilter = String(req.query.mcVersion || '').trim();
  const sort = String(req.query.sort || 'newest').trim();
  const page = Math.max(1, Number(req.query.page) || 1);
  const perPage = Math.min(50, Math.max(1, Number(req.query.perPage) || 20));

  const params = [];
  const whereClauses = [];

  if (allowed.includes(type)) {
    whereClauses.push('products.category = ?');
    params.push(type);
  }
  if (search) {
    whereClauses.push('(products.title LIKE ? OR products.short_description LIKE ?)');
    params.push(`%${search}%`, `%${search}%`);
  }
  if (licenseFilter === 'open_source' || licenseFilter === 'proprietary') {
    whereClauses.push('products.license = ?');
    params.push(licenseFilter);
  }

  let sql = `SELECT products.id,
                    products.title,
                    products.slug,
                    products.category,
                    products.categories,
                    products.version,
                    products.short_description,
                    products.description,
                    products.icon_file,
                    products.author,
                    products.license,
                    products.created_at,
                    products.updated_at,
                    users.username AS uploader,
                    COALESCE(SUM(plugin_versions.downloads), 0) AS downloads,
                    COUNT(plugin_versions.id) AS versions,
                    GROUP_CONCAT(plugin_versions.loaders SEPARATOR ',') AS loaders_csv,
                    GROUP_CONCAT(plugin_versions.minecraft_versions SEPARATOR ',') AS minecraft_versions_csv,
                    GROUP_CONCAT(plugin_versions.platforms SEPARATOR ',') AS platforms_csv,
                    GROUP_CONCAT(plugin_versions.environments SEPARATOR ',') AS environments_csv
             FROM products
             LEFT JOIN users ON users.id = products.uploaded_by
             LEFT JOIN plugin_versions ON plugin_versions.product_id = products.id`;

  if (whereClauses.length) {
    sql += ' WHERE ' + whereClauses.join(' AND ');
  }

  sql += ' GROUP BY products.id';

  const havingClauses = [];
  if (loaderFilter) {
    havingClauses.push("CONCAT(',', LOWER(loaders_csv), ',') LIKE ?");
    params.push(`%,${loaderFilter},%`);
  }
  if (platformFilter) {
    havingClauses.push("CONCAT(',', LOWER(platforms_csv), ',') LIKE ?");
    params.push(`%,${platformFilter},%`);
  }
  if (environmentFilter === 'client' || environmentFilter === 'server') {
    havingClauses.push("CONCAT(',', LOWER(environments_csv), ',') LIKE ?");
    params.push(`%,${environmentFilter},%`);
  }
  if (mcVersionFilter) {
    havingClauses.push("CONCAT(',', minecraft_versions_csv, ',') LIKE ?");
    params.push(`%,${mcVersionFilter},%`);
  }
  if (havingClauses.length) {
    sql += ' HAVING ' + havingClauses.join(' AND ');
  }

  const sortMap = {
    newest: 'products.created_at DESC',
    oldest: 'products.created_at ASC',
    downloads: 'downloads DESC',
    name: 'products.title ASC'
  };
  sql += ` ORDER BY ${sortMap[sort] || sortMap.newest}`;

  const [allMatches] = await pool.execute(sql, params);
  const total = allMatches.length;
  const offset = (page - 1) * perPage;
  const pageRows = allMatches.slice(offset, offset + perPage);

  res.json({
    products: pageRows.map((product) => ({
      ...product,
      categories: splitCsv(product.categories),
      loaders: splitCsv(product.loaders_csv),
      minecraft_versions: splitCsv(product.minecraft_versions_csv),
      platforms: splitCsv(product.platforms_csv),
      environments: splitCsv(product.environments_csv),
      icon_url: product.icon_file ? `${getBaseUrl(req)}/files/${product.icon_file}` : null
    })),
    total,
    page,
    perPage,
    totalPages: Math.max(1, Math.ceil(total / perPage))
  });
});

router.get('/api/products/:id', async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.execute(`
    SELECT products.*, users.username AS uploader, COALESCE(SUM(plugin_versions.downloads), 0) AS downloads
    FROM products
    LEFT JOIN users ON users.id = products.uploaded_by
    LEFT JOIN plugin_versions ON plugin_versions.product_id = products.id
    WHERE products.id = ?
    GROUP BY products.id
    LIMIT 1
  `, [id]);
  const product = rows[0];
  if (!product) return res.status(404).json({ error: 'Project not found.' });
  const [versions] = await pool.execute(`
    SELECT id, version_name, minecraft_version, minecraft_versions, loaders, platforms, environments, original_file_name, file_size, downloads, changelog, created_at
    FROM plugin_versions
    WHERE product_id = ?
    ORDER BY created_at DESC
  `, [id]);
  res.json({
    product: {
      ...product,
      categories: splitCsv(product.categories),
      icon_url: product.icon_file ? `${getBaseUrl(req)}/files/${product.icon_file}` : null
    },
    versions: versions.map((version) => ({
      ...version,
      loaders: splitCsv(version.loaders),
      minecraft_versions: splitCsv(version.minecraft_versions || version.minecraft_version),
      platforms: splitCsv(version.platforms),
      environments: splitCsv(version.environments)
    }))
  });
});

router.post('/api/downloads', async (req, res) => {
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

router.get('/files/:name', (req, res) => {
  const safe = path.basename(req.params.name);
  const filePath = path.join(UPLOAD_DIR, safe);
  if (!fs.existsSync(filePath)) return res.status(404).send('File not found');
  res.sendFile(filePath);
});

router.get('/download/version/:id', async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.execute(`
    SELECT plugin_versions.*, products.title, products.category
    FROM plugin_versions
    JOIN products ON products.id = plugin_versions.product_id
    WHERE plugin_versions.id = ?
    LIMIT 1
  `, [id]);
  const version = rows[0];
  if (!version) return res.status(404).send('Version not found');
  const filePath = path.join(UPLOAD_DIR, version.file_name);
  if (!fs.existsSync(filePath)) return res.status(404).send('The uploaded version file is missing. Re-upload this version.');
  const user = await getSessionUser(req);
  await pool.execute('UPDATE plugin_versions SET downloads = downloads + 1 WHERE id = ?', [id]);
  await pool.execute(`
    INSERT INTO downloads (user_id, item, type, product_id, ip, user_agent, created_at)
    VALUES (?, ?, ?, ?, ?, ?, ?)
  `, [user ? user.id : null, version.title, version.category, version.product_id, req.ip, req.get('user-agent') || '', nowDate()]);
  await logActivity(req, user ? user.id : null, 'download_version', `${version.category}: ${version.title} ${version.version_name}`);
  res.download(filePath, version.original_file_name);
});

router.get('/download/:id', async (req, res) => {
  const id = Number(req.params.id);
  const [rows] = await pool.execute('SELECT * FROM products WHERE id = ? LIMIT 1', [id]);
  const product = rows[0];
  if (!product) return res.status(404).send('File not found');

  const [versions] = await pool.execute('SELECT id FROM plugin_versions WHERE product_id = ? ORDER BY created_at DESC LIMIT 1', [product.id]);
  if (versions[0]) return res.redirect(`/download/version/${versions[0].id}`);

  const filePath = path.join(UPLOAD_DIR, product.file_name);
  if (!fs.existsSync(filePath)) {
    console.error(`Download file missing for product ${product.id}: ${filePath}`);
    return res.status(404).send('The uploaded file is missing on the server.');
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

module.exports = router;
