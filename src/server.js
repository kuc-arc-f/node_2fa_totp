const express = require('express');
const session = require('express-session');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const QRCode = require('qrcode');
const path = require('path');

const db = require('./db');
const { encrypt, decrypt, sha256, generateRecoveryCodes } = require('./crypto');
const totp = require('./totp');
const lock = require('./lock');

const ISSUER = process.env.TOTP_ISSUER || 'MyWebApp';
const DUMMY_HASH = bcrypt.hashSync('dummy-password', 12); // ユーザー列挙対策

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '..', 'public')));

app.use(session({
  name: 'sid',
  secret: process.env.SESSION_SECRET || 'dev-only-change-me',
  resave: false,
  saveUninitialized: false,
  // 本番は connect-sqlite3 / Redis などの永続ストアに変更すること
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    maxAge: 60 * 60 * 1000,
  },
}));

// ログイン系エンドポイント用のレート制限 (IP 単位)
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'リクエストが多すぎます。しばらくしてからお試しください。' },
});

// ---------- ミドルウェア ----------
// 完全にログイン済み (パスワード + OTP 通過)
function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: '未ログインです' });
  next();
}
// パスワード認証済み・OTP 待ちの仮状態
function requirePending(req, res, next) {
  const p = req.session.pending;
  if (!p || p.expires < Date.now()) {
    delete req.session.pending;
    return res.status(401).json({ error: 'パスワード認証からやり直してください' });
  }
  next();
}

// セッション固定攻撃対策: ログイン完了時に ID を再発行
function completeLogin(req, userId) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => {
      if (err) return reject(err);
      req.session.userId = userId;
      req.session.save((err2) => (err2 ? reject(err2) : resolve()));
    });
  });
}

const getUser = (id) => db.prepare('SELECT * FROM users WHERE id = ?').get(id);

// ---------- ユーザー登録 (サンプル) ----------
app.post('/api/register', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || username.length < 3 || username.length > 64) {
    return res.status(400).json({ error: 'username は 3〜64 文字です' });
  }
  if (typeof password !== 'string' || password.length < 6 || password.length > 128) {
    return res.status(400).json({ error: 'password は 6〜128 文字です' });
  }
  try {
    db.prepare('INSERT INTO users (username, password_hash) VALUES (?, ?)')
      .run(username, bcrypt.hashSync(password, 12));
    res.status(201).json({ ok: true });
  } catch (e) {
    if (String(e.message).includes('UNIQUE')) {
      return res.status(409).json({ error: 'そのユーザー名は使えません' });
    }
    throw e;
  }
});

// ---------- ログイン 第 1 要素: パスワード ----------
app.post('/api/login', authLimiter, async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: '入力が不正です' });
  }
  const user = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  const ok = await bcrypt.compare(password, user ? user.password_hash : DUMMY_HASH);

  if (!user || !ok) {
    if (user) lock.recordFailure(user.id);
    return res.status(401).json({ error: 'ID またはパスワードが違います' });
  }
  if (lock.isLocked(user)) {
    return res.status(423).json({ error: 'アカウントが一時的にロックされています' });
  }

  if (!user.totp_enabled) {
    lock.resetFailures(user.id);
    await completeLogin(req, user.id);
    return res.json({ status: 'logged_in', otpRequired: false });
  }

  // OTP 待ち: userId ではなく pending にだけ入れる (機能は使えない)
  await new Promise((r) => req.session.regenerate(r));
  req.session.pending = { userId: user.id, expires: Date.now() + 5 * 60 * 1000 };
  res.json({ status: 'otp_required' });
});

// ---------- ログイン 第 2 要素: OTP またはリカバリーコード ----------
app.post('/api/login/otp', authLimiter, requirePending, async (req, res) => {
  const { token, recoveryCode } = req.body || {};
  const user = getUser(req.session.pending.userId);

  if (!user) {
    delete req.session.pending;
    return res.status(401).json({ error: 'やり直してください' });
  }
  if (lock.isLocked(user)) {
    return res.status(423).json({ error: 'アカウントが一時的にロックされています' });
  }

  let success = false;

  if (typeof token === 'string') {
    const secret = decrypt(user.totp_secret_enc);
    const step = totp.verifyToken(token.trim(), secret);
    // step <= last_used_step なら再利用 (リプレイ) として拒否。
    // 条件付き UPDATE で並列リクエストによる二重使用も防ぐ。
    if (step !== null) {
      const r = db.prepare(
        'UPDATE users SET totp_last_used_step = ? WHERE id = ? AND totp_last_used_step < ?'
      ).run(step, user.id, step);
      success = r.changes === 1;
    }
  } else if (typeof recoveryCode === 'string') {
    const hash = sha256(recoveryCode.trim().toUpperCase());
    const r = db.prepare(
      'UPDATE recovery_codes SET used_at = ? WHERE user_id = ? AND code_hash = ? AND used_at IS NULL'
    ).run(Date.now(), user.id, hash);
    success = r.changes === 1;
  } else {
    return res.status(400).json({ error: 'token または recoveryCode が必要です' });
  }

  if (!success) {
    lock.recordFailure(user.id);
    return res.status(401).json({ error: 'コードが正しくありません' });
  }

  lock.resetFailures(user.id);
  await completeLogin(req, user.id);
  res.json({ status: 'logged_in' });
});

// ---------- ログアウト / 自分の情報 ----------
app.post('/api/logout', (req, res) => {
  req.session.destroy(() => {
    res.clearCookie('sid');
    res.json({ ok: true });
  });
});

app.get('/api/me', requireAuth, (req, res) => {
  const u = getUser(req.session.userId);
  res.json({ username: u.username, totpEnabled: !!u.totp_enabled });
});

// ---------- 2 段階認証 登録 ----------
// ① secret 生成 + QR 表示 (まだ有効化しない)
app.post('/api/2fa/setup', requireAuth, async (req, res) => {
  const user = getUser(req.session.userId);
  if (user.totp_enabled) return res.status(400).json({ error: 'すでに有効です' });

  const secret = totp.generateSecret();
  db.prepare('UPDATE users SET totp_secret_enc = ? WHERE id = ?')
    .run(encrypt(secret), user.id);

  const uri = totp.keyuri(user.username, ISSUER, secret);
  const qrDataUrl = await QRCode.toDataURL(uri);
  // 手入力用に secret も返す (この 1 回のみ)
  res.json({ qrDataUrl, manualKey: secret });
});

// ② ユーザーが入力したコードを検証できたら有効化 + リカバリーコード発行
app.post('/api/2fa/enable', authLimiter, requireAuth, (req, res) => {
  const user = getUser(req.session.userId);
  if (user.totp_enabled) return res.status(400).json({ error: 'すでに有効です' });
  if (!user.totp_secret_enc) return res.status(400).json({ error: '先に setup を実行してください' });

  const step = totp.verifyToken(String(req.body?.token || '').trim(), decrypt(user.totp_secret_enc));
  if (step === null) return res.status(400).json({ error: 'コードが正しくありません' });

  const codes = generateRecoveryCodes(8);
  const tx = db.transaction(() => {
    db.prepare('UPDATE users SET totp_enabled = 1, totp_last_used_step = ? WHERE id = ?')
      .run(step, user.id);
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(user.id);
    const ins = db.prepare('INSERT INTO recovery_codes (user_id, code_hash) VALUES (?, ?)');
    codes.forEach((c) => ins.run(user.id, sha256(c)));
  });
  tx();

  res.json({ ok: true, recoveryCodes: codes }); // 平文はこのレスポンスのみ
});

// ---------- 2 段階認証 無効化 (パスワード + OTP を再確認) ----------
app.post('/api/2fa/disable', authLimiter, requireAuth, async (req, res) => {
  const { password, token } = req.body || {};
  const user = getUser(req.session.userId);
  if (!user.totp_enabled) return res.status(400).json({ error: '有効化されていません' });

  const pwOk = typeof password === 'string' && await bcrypt.compare(password, user.password_hash);
  const step = totp.verifyToken(String(token || '').trim(), decrypt(user.totp_secret_enc));
  if (!pwOk || step === null || step <= user.totp_last_used_step) {
    return res.status(401).json({ error: 'パスワードまたはコードが正しくありません' });
  }

  db.transaction(() => {
    db.prepare(
      'UPDATE users SET totp_enabled = 0, totp_secret_enc = NULL, totp_last_used_step = 0 WHERE id = ?'
    ).run(user.id);
    db.prepare('DELETE FROM recovery_codes WHERE user_id = ?').run(user.id);
  })();
  res.json({ ok: true });
});

// ---------- エラーハンドラ ----------
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  console.error(err);
  res.status(500).json({ error: 'サーバーエラー' });
});

if (require.main === module) {
  const port = process.env.PORT || 3000;
  app.listen(port, () => console.log(`http://localhost:${port}`));
}

module.exports = app;
