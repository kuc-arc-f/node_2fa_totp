const { authenticator } = require('otplib');

// 前後 1 ステップ(±30 秒)の時刻ずれを許容
authenticator.options = { window: 1 };

const STEP_SEC = 30;

function generateSecret() {
  return authenticator.generateSecret();
}

function keyuri(account, issuer, secret) {
  return authenticator.keyuri(account, issuer, secret);
}

/**
 * 検証して「使われた時間ステップ」を返す。無効なら null。
 * delta は現在ステップからの差 (-1, 0, 1)。
 */
function verifyToken(token, secret) {
  if (!/^\d{6}$/.test(token)) return null;
  const delta = authenticator.checkDelta(token, secret);
  if (delta === null) return null;
  return Math.floor(Date.now() / 1000 / STEP_SEC) + delta;
}

module.exports = { generateSecret, keyuri, verifyToken };
