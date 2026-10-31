const crypto = require('crypto');

// 32 byte の鍵 (hex 64 文字) を環境変数で渡す。本番は KMS / Secret Manager 推奨。
function getKey() {
  const hex = process.env.TOTP_ENC_KEY;
  if (!hex || hex.length !== 64) {
    throw new Error('TOTP_ENC_KEY must be 64 hex chars (32 bytes). Generate: openssl rand -hex 32');
  }
  return Buffer.from(hex, 'hex');
}

function encrypt(plain) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', getKey(), iv);
  const enc = Buffer.concat([cipher.update(plain, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return [iv, tag, enc].map((b) => b.toString('base64')).join('.');
}

function decrypt(payload) {
  const [iv, tag, enc] = payload.split('.').map((s) => Buffer.from(s, 'base64'));
  const decipher = crypto.createDecipheriv('aes-256-gcm', getKey(), iv);
  decipher.setAuthTag(tag);
  return Buffer.concat([decipher.update(enc), decipher.final()]).toString('utf8');
}

const sha256 = (s) => crypto.createHash('sha256').update(s).digest('hex');

// 例: "A1B2-C3D4-E5"
function generateRecoveryCodes(n = 8) {
  return Array.from({ length: n }, () => {
    const h = crypto.randomBytes(5).toString('hex').toUpperCase();
    return `${h.slice(0, 4)}-${h.slice(4, 8)}-${h.slice(8)}`;
  });
}

module.exports = { encrypt, decrypt, sha256, generateRecoveryCodes };
