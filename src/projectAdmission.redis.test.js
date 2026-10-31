'use strict';

const assert = require('node:assert/strict');
const { randomUUID } = require('node:crypto');
const { test } = require('node:test');
const { createClient } = require('redis');
const { createProjectAdmission } = require('./projectAdmission');

test('uses atomic Redis project-wide concurrency, request limits, and cooldowns', {
  skip: !process.env.KIARA_TEST_REDIS_URL
    || process.env.KIARA_TEST_REDIS_CONFIRM_ISOLATED !== 'true',
}, async () => {
  if (process.env.KIARA_TEST_REDIS_URL === process.env.REDIS_URL) {
    throw new Error('The Redis integration test must not use the gateway Redis URL.');
  }
  const redis = createClient({
    url: process.env.KIARA_TEST_REDIS_URL,
    socket: process.env.KIARA_TEST_REDIS_URL.startsWith('rediss://')
      ? { tls: true, rejectUnauthorized: true }
      : undefined,
  });
  redis.on('error', () => {});
  await redis.connect();

  try {
    const projectId = `redis-test-${randomUUID()}`;
    const firstInstance = createProjectAdmission({
      redis,
      projectId,
      maxConcurrent: 1,
      requestsPerMinute: 2,
    });
    const secondInstance = createProjectAdmission({
      redis,
      projectId,
      maxConcurrent: 1,
      requestsPerMinute: 2,
    });

    const firstPermit = await firstInstance.acquire(5000);
    assert.equal(firstPermit.acquired, true);
    assert.deepEqual(await secondInstance.acquire(5000), {
      acquired: false,
      reason: 'project_concurrency',
      retryAfterMs: 1000,
    });

    await firstInstance.release(firstPermit.requestId);
    const secondPermit = await secondInstance.acquire(5000);
    assert.equal(secondPermit.acquired, true);
    await secondInstance.release(secondPermit.requestId);

    const rateLimited = await firstInstance.acquire(5000);
    assert.equal(rateLimited.acquired, false);
    assert.equal(rateLimited.reason, 'project_rate_limit');

    await firstInstance.startQuotaCooldown(5000);
    const cooldown = await secondInstance.acquire(5000);
    assert.equal(cooldown.acquired, false);
    assert.equal(cooldown.reason, 'project_cooldown');
    assert.ok(cooldown.retryAfterMs > 0);

    await redis.disconnect();
    await redis.connect();
    assert.equal(await redis.ping(), 'PONG');

    const afterReconnect = await createProjectAdmission({
      redis,
      projectId: `${projectId}-reconnected`,
      maxConcurrent: 1,
      requestsPerMinute: 2,
    }).acquire(5000);
    assert.equal(afterReconnect.acquired, true);
  } finally {
    await redis.quit();
  }
});
