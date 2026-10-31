'use strict';

const { randomUUID } = require('node:crypto');
const { createHash } = require('node:crypto');

const ACQUIRE_PROJECT_CAPACITY_SCRIPT = `
local cooldownTtl = redis.call('PTTL', KEYS[1])
if cooldownTtl > 0 then
  return {-1, cooldownTtl}
end

local now = tonumber(ARGV[1])
local requestWindowMs = tonumber(ARGV[2])
local requestLimit = tonumber(ARGV[3])
local leaseTtlMs = tonumber(ARGV[4])
local concurrencyLimit = tonumber(ARGV[5])
local requestId = ARGV[6]

redis.call('ZREMRANGEBYSCORE', KEYS[2], '-inf', now - requestWindowMs)
local requestCount = redis.call('ZCARD', KEYS[2])
if requestCount >= requestLimit then
  local oldest = redis.call('ZRANGE', KEYS[2], 0, 0, 'WITHSCORES')
  local retryMs = math.max(1, tonumber(oldest[2]) + requestWindowMs - now)
  return {-2, retryMs}
end

redis.call('ZREMRANGEBYSCORE', KEYS[3], '-inf', now)
local activeCount = redis.call('ZCARD', KEYS[3])
if activeCount >= concurrencyLimit then
  return {-3, activeCount}
end

redis.call('ZADD', KEYS[2], now, requestId)
redis.call('PEXPIRE', KEYS[2], requestWindowMs * 2)
redis.call('ZADD', KEYS[3], now + leaseTtlMs, requestId)
redis.call('PEXPIRE', KEYS[3], leaseTtlMs * 2)
return {1, activeCount + 1}
`;

const RELEASE_PROJECT_CAPACITY_SCRIPT = `
redis.call('ZREM', KEYS[1], ARGV[1])
return 1
`;

function createProjectAdmission({
  redis,
  projectId,
  maxConcurrent,
  requestsPerMinute,
  now = Date.now,
}) {
  if (!redis || typeof redis.eval !== 'function') {
    throw new TypeError('A Redis client with EVAL support is required.');
  }
  if (typeof projectId !== 'string' || !projectId.trim()) {
    throw new Error('KIARA_GEMINI_PROJECT_ID is required.');
  }
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 100) {
    throw new Error('KIARA_GATEWAY_MAX_CONCURRENT must be between 1 and 100.');
  }
  if (!Number.isInteger(requestsPerMinute) || requestsPerMinute < 1 || requestsPerMinute > 100_000) {
    throw new Error('KIARA_PROJECT_REQUESTS_PER_MINUTE must be between 1 and 100000.');
  }

  const projectTag = createHash('sha256').update(projectId.trim()).digest('hex').slice(0, 24);
  const prefix = `kiara:live-gateway:{${projectTag}}`;
  const requestWindowMs = 60_000;

  return {
    async acquire(leaseTtlMs) {
      const requestId = randomUUID();
      const result = await redis.eval(ACQUIRE_PROJECT_CAPACITY_SCRIPT, {
        keys: [
          `${prefix}:quota-cooldown`,
          `${prefix}:project-requests`,
          `${prefix}:active-leases`,
        ],
        arguments: [
          String(now()),
          String(requestWindowMs),
          String(requestsPerMinute),
          String(leaseTtlMs),
          String(maxConcurrent),
          requestId,
        ],
      });

      const status = Number(result?.[0]);
      const value = Number(result?.[1]);
      if (status === 1) return { acquired: true, requestId };
      if (status === -1) return { acquired: false, reason: 'project_cooldown', retryAfterMs: Math.max(1, value) };
      if (status === -2) return { acquired: false, reason: 'project_rate_limit', retryAfterMs: Math.max(1, value) };
      if (status === -3) return { acquired: false, reason: 'project_concurrency', retryAfterMs: 1000 };
      throw new Error('Redis returned an invalid project-admission response.');
    },
    async release(requestId) {
      await redis.eval(RELEASE_PROJECT_CAPACITY_SCRIPT, {
        keys: [`${prefix}:active-leases`],
        arguments: [requestId],
      });
    },
    async startQuotaCooldown(cooldownMs) {
      await redis.set(`${prefix}:quota-cooldown`, '1', { PX: cooldownMs });
    },
  };
}

module.exports = {
  createProjectAdmission,
};
