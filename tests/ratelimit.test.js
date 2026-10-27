import assert from 'node:assert/strict';
import test from 'node:test';

import { FixedWindowLimiter, LoginLimiter } from '../lib/ratelimit.js';

function clock(start = 1_000_000) {
  let now = start;
  return {
    now: () => now,
    advance(ms) {
      now += ms;
    }
  };
}

test('login limiter locks after 5 failures in the window', () => {
  const time = clock();
  const limiter = new LoginLimiter({ maxFailures: 5, windowMs: 15 * 60_000, lockMs: 15 * 60_000, now: time.now });
  for (let attempt = 1; attempt < 5; attempt += 1) {
    assert.deepEqual(limiter.fail('10.0.0.1', 'admin').locked, false, `attempt ${attempt}`);
    assert.equal(limiter.check('10.0.0.1', 'admin').allowed, true);
  }
  const locked = limiter.fail('10.0.0.1', 'admin');
  assert.equal(locked.locked, true);
  assert.ok(locked.retryAfterSeconds >= 899);
  const check = limiter.check('10.0.0.1', 'admin');
  assert.equal(check.allowed, false);
  assert.equal(check.locked, true);
});

test('login limiter unlocks after the lock window and clears the old failures', () => {
  const time = clock();
  const limiter = new LoginLimiter({ maxFailures: 1, windowMs: 60_000, lockMs: 60_000, now: time.now });
  assert.equal(limiter.fail('10.0.0.1', 'admin').locked, true);
  time.advance(60_001);
  assert.equal(limiter.check('10.0.0.1', 'admin').allowed, true);
  assert.equal(limiter.fail('10.0.0.1', 'admin').failures, 1);
});

test('login limiter is scoped by IP and username and resets on success', () => {
  const time = clock();
  const limiter = new LoginLimiter({ maxFailures: 2, windowMs: 60_000, lockMs: 60_000, now: time.now });
  limiter.fail('10.0.0.1', 'alice');
  limiter.fail('10.0.0.1', 'alice');
  assert.equal(limiter.check('10.0.0.2', 'alice').allowed, true);
  assert.equal(limiter.check('10.0.0.1', 'bob').allowed, true);
  limiter.succeed('10.0.0.1', 'alice');
  assert.equal(limiter.check('10.0.0.1', 'alice').allowed, true);
});

test('login failures outside the sliding window do not accumulate', () => {
  const time = clock();
  const limiter = new LoginLimiter({ maxFailures: 2, windowMs: 60_000, lockMs: 60_000, now: time.now });
  limiter.fail('10.0.0.1', 'admin');
  time.advance(60_001);
  assert.equal(limiter.fail('10.0.0.1', 'admin').locked, false);
  time.advance(1_000);
  assert.equal(limiter.fail('10.0.0.1', 'admin').locked, true);
});

test('login limiter bounds its key map under a username spray', () => {
  const time = clock();
  const limiter = new LoginLimiter({ maxFailures: 2, windowMs: 60_000, lockMs: 60_000, maxKeys: 25, now: time.now });
  for (let index = 0; index < 200; index += 1) limiter.fail(`10.0.0.${index % 5}`, `user-${index}`);
  assert.ok(limiter.entries.size <= 25);
  assert.equal(limiter.check('10.0.0.99', 'new-user').allowed, true);
});

test('fixed-window limiter allows exactly `limit` requests per window', () => {
  const time = clock();
  const limiter = new FixedWindowLimiter({ limit: 3, windowMs: 60_000, now: time.now });
  assert.equal(limiter.hit('pair:1').allowed, true);
  assert.equal(limiter.hit('pair:1').allowed, true);
  assert.equal(limiter.hit('pair:1').allowed, true);
  const fourth = limiter.hit('pair:1');
  assert.equal(fourth.allowed, false);
  assert.ok(fourth.retryAfterSeconds > 0);
  assert.equal(limiter.hit('pair:2').allowed, true);
  time.advance(60_001);
  assert.equal(limiter.hit('pair:1').allowed, true);
});

test('fixed-window limiter prunes unknown keys bounded', () => {
  const time = clock();
  const limiter = new FixedWindowLimiter({ limit: 1, windowMs: 1_000, maxKeys: 10, now: time.now });
  for (let index = 0; index < 100; index += 1) limiter.hit(`ip-${index}`);
  assert.ok(limiter.entries.size <= 10);
});
