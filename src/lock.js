const db = require('./db');

const MAX_FAILS = 5;
const LOCK_MS = 15 * 60 * 1000;

function isLocked(user) {
  return user.locked_until > Date.now();
}

function recordFailure(userId) {
  const u = db.prepare('SELECT failed_count FROM users WHERE id = ?').get(userId);
  const count = u.failed_count + 1;
  if (count >= MAX_FAILS) {
    db.prepare('UPDATE users SET failed_count = 0, locked_until = ? WHERE id = ?')
      .run(Date.now() + LOCK_MS, userId);
  } else {
    db.prepare('UPDATE users SET failed_count = ? WHERE id = ?').run(count, userId);
  }
}

function resetFailures(userId) {
  db.prepare('UPDATE users SET failed_count = 0, locked_until = 0 WHERE id = ?').run(userId);
}

module.exports = { isLocked, recordFailure, resetFailures };
