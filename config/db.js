const mysql = require('mysql2/promise');
const argon2 = require('argon2');
const crypto = require('crypto');

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

function avatarUrl(username) {
  return `https://mc-heads.net/avatar/${encodeURIComponent(username)}/128`;
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
    CREATE TABLE IF NOT EXISTS products (
      id INT AUTO_INCREMENT PRIMARY KEY,
      title VARCHAR(120) NOT NULL,
      slug VARCHAR(120) NOT NULL UNIQUE,
      category VARCHAR(60) NOT NULL,
      categories TEXT,
      version VARCHAR(80),
      short_description VARCHAR(255) NOT NULL,
      description TEXT,
      file_name TEXT,
      original_file_name TEXT,
      file_size BIGINT,
      icon_file TEXT,
      author VARCHAR(80) NOT NULL DEFAULT 'Admin',
      license VARCHAR(60) NOT NULL DEFAULT 'proprietary',
      uploaded_by INT NULL,
      created_at DATETIME NOT NULL,
      updated_at DATETIME NOT NULL,
      INDEX idx_products_category (category),
      INDEX idx_products_slug (slug),
      CONSTRAINT fk_products_uploader FOREIGN KEY (uploaded_by) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS plugin_versions (
      id INT AUTO_INCREMENT PRIMARY KEY,
      product_id INT NOT NULL,
      version_name VARCHAR(80) NOT NULL,
      minecraft_version VARCHAR(80) NOT NULL DEFAULT '1.21.x',
      minecraft_versions TEXT,
      loaders VARCHAR(255),
      platforms VARCHAR(255),
      environments VARCHAR(255),
      file_name TEXT NOT NULL,
      original_file_name TEXT NOT NULL,
      file_size BIGINT NOT NULL,
      downloads INT NOT NULL DEFAULT 0,
      changelog TEXT,
      created_at DATETIME NOT NULL,
      INDEX idx_versions_product (product_id),
      CONSTRAINT fk_versions_product FOREIGN KEY (product_id) REFERENCES products(id) ON DELETE CASCADE
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  await pool.query(`
    CREATE TABLE IF NOT EXISTS activity (
      id INT AUTO_INCREMENT PRIMARY KEY,
      user_id INT NULL,
      action VARCHAR(120) NOT NULL,
      details TEXT,
      ip VARCHAR(64),
      user_agent TEXT,
      created_at DATETIME NOT NULL,
      INDEX idx_activity_user (user_id),
      INDEX idx_activity_created (created_at),
      CONSTRAINT fk_activity_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE SET NULL
    ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
  `);

  // Migrate legacy data if necessary (if files are defined on product itself but no version exists)
  try {
    const [products] = await pool.execute(`
      SELECT products.* FROM products
      LEFT JOIN plugin_versions ON plugin_versions.product_id = products.id
      WHERE plugin_versions.id IS NULL AND products.file_name IS NOT NULL
    `);
    for (const product of products) {
      await pool.execute(`
        INSERT INTO plugin_versions (product_id, version_name, minecraft_version, minecraft_versions, file_name, original_file_name, file_size, created_at)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
      `, [product.id, product.version || '1.0.0', '1.21.x', '1.21.x', product.file_name, product.original_file_name, product.file_size, product.created_at || nowDate()]);
    }
  } catch (error) {
    console.warn('Legacy version migration warning:', error.code || error.message);
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

  try {
    const [columns] = await pool.query('SHOW COLUMNS FROM products');
    const hasPremium = columns.some((col) => col.Field === 'is_premium');
    if (!hasPremium) {
      await pool.query('ALTER TABLE products ADD COLUMN is_premium TINYINT DEFAULT 0');
      await pool.query('ALTER TABLE products ADD COLUMN price DECIMAL(10,2) NULL');
      await pool.query('ALTER TABLE products ADD COLUMN purchase_url TEXT NULL');
      console.log('Successfully updated products table for premium columns.');
    }
  } catch (error) {
    console.error('Failed to run migration for premium columns:', error);
  }
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

module.exports = {
  pool,
  initDatabase,
  ensurePasswordResetTable,
  seedAdmin
};
