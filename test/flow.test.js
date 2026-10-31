// 通しテスト: 登録 → 2FA 有効化 → ログイン → リプレイ拒否 → リカバリーコード → ロック
process.env.DB_PATH = ':memory:';
process.env.TOTP_ENC_KEY = 'a'.repeat(64);
process.env.SESSION_SECRET = 'test';

const assert = require('assert');
const { authenticator } = require('otplib');
const app = require('../src/server');

function client(base) {
  let cookie = '';
  return async (path, body, method = 'POST') => {
    const r = await fetch(base + path, {
      method,
      headers: { 'Content-Type': 'application/json', cookie },
      body: method === 'GET' ? undefined : JSON.stringify(body || {}),
    });
    const sc = r.headers.get('set-cookie');
    if (sc) cookie = sc.split(';')[0];
    return { status: r.status, data: await r.json().catch(() => ({})) };
  };
}

(async () => {
  const server = app.listen(0);
  const base = `http://127.0.0.1:${server.address().port}`;
  const c = client(base);
  const ok = (m) => console.log('  ✓', m);

  assert.equal((await c('/api/register', { username: 'alice', password: 'password123' })).status, 201);
  ok('register');

  assert.equal((await c('/api/login', { username: 'alice', password: 'password123' })).data.status, 'logged_in');
  assert.equal((await c('/api/me', null, 'GET')).status, 200);
  ok('login without 2FA');

  const setup = await c('/api/2fa/setup');
  assert.ok(setup.data.qrDataUrl.startsWith('data:image/png'));
  const secret = setup.data.manualKey;
  assert.equal((await c('/api/2fa/enable', { token: '000000' })).status, 400);
  const en = await c('/api/2fa/enable', { token: authenticator.generate(secret) });
  assert.equal(en.status, 200);
  assert.equal(en.data.recoveryCodes.length, 8);
  ok('2FA enable + recovery codes');

  // 2 回目のログイン: パスワードだけでは機能を使えない
  await c('/api/logout');
  const c2 = client(base);
  assert.equal((await c2('/api/login', { username: 'alice', password: 'password123' })).data.status, 'otp_required');
  assert.equal((await c2('/api/me', null, 'GET')).status, 401);
  ok('OTP-pending session cannot access /api/me');

  // 有効化で使ったステップは再利用不可 (リプレイ対策)
  assert.equal((await c2('/api/login/otp', { token: authenticator.generate(secret) })).status, 401);
  ok('replay of the enable-step code rejected');

  // 前のステップのコードは window=1 で有効、かつ last_used より新しい…ではないので拒否される。
  // 次のステップのコード (+1) は有効。
  const next = authenticator.generate(secret); // 同一ステップ → 拒否済み
  const future = (() => {
    const orig = Date.now; Date.now = () => orig() + 30000;
    const t = authenticator.generate(secret); Date.now = orig; return t;
  })();
  assert.equal((await c2('/api/login/otp', { token: future })).data.status, 'logged_in');
  assert.equal((await c2('/api/me', null, 'GET')).status, 200);
  ok('next-step code accepted, logged in');

  // 同じコードの再利用は拒否
  const c3 = client(base);
  await c3('/api/login', { username: 'alice', password: 'password123' });
  assert.equal((await c3('/api/login/otp', { token: future })).status, 401);
  ok('replay rejected');

  // リカバリーコード (1 回限り)
  const rc = en.data.recoveryCodes[0];
  assert.equal((await c3('/api/login/otp', { recoveryCode: rc })).data.status, 'logged_in');
  const c4 = client(base);
  await c4('/api/login', { username: 'alice', password: 'password123' });
  assert.equal((await c4('/api/login/otp', { recoveryCode: rc })).status, 401);
  ok('recovery code works once');

  // 連続失敗でロック
  const c5 = client(base);
  await c5('/api/login', { username: 'alice', password: 'password123' });
  for (let i = 0; i < 5; i++) await c5('/api/login/otp', { token: '111111' });
  assert.equal((await c5('/api/login/otp', { token: '111111' })).status, 423);
  ok('account locked after repeated failures');

  server.close();
  console.log('ALL PASSED');
  process.exit(0);
})().catch((e) => { console.error(e); process.exit(1); });
