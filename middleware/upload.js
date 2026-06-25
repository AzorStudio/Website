const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const UPLOAD_DIR = path.join(__dirname, '..', 'private_uploads');
fs.mkdirSync(UPLOAD_DIR, { recursive: true });

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
    const ext = path.extname(file.originalname).toLowerCase();
    const fileAllowed = ['.jar', '.zip', '.mcpack'];
    const imageAllowed = ['.png', '.jpg', '.jpeg', '.webp', '.gif'];
    cb(null, fileAllowed.includes(ext) || imageAllowed.includes(ext));
  }
});

module.exports = {
  upload,
  UPLOAD_DIR
};
