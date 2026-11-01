'use strict';

const fs = require('node:fs');
const net = require('node:net');
const { createCredentialPool } = require('./credentials');

const PRODUCTION_REQUIRED_VARIABLES = [
  'HOST',
  'PORT',
  'REDIS_URL',
  'KIARA_GEMINI_PROJECT_ID',
  'KIARA_GATEWAY_HMAC_SECRET',
  'KIARA_LIVE_SYSTEM_INSTRUCTION_SHA256',
  'KIARA_GATEWAY_MAX_CONCURRENT',
  'KIARA_PROJECT_REQUESTS_PER_MINUTE',
  'KIARA_PROJECT_QUOTA_COOLDOWN_MS',
  'KIARA_GATEWAY_PROVIDER_TIMEOUT_MS',
];

function readInteger(environment, name, fallback, min, max, production) {
  const raw = environment[name];
  if (production && !raw) {
    throw new Error(`${name} is required in production.`);
  }
  const value = Number(raw || fallback);
  if (!Number.isInteger(value) || value < min || value > max) {
    throw new Error(`${name} must be an integer from ${min} to ${max}.`);
  }
  return value;
}

function isPrivateBindHost(host) {
  if (host === 'localhost' || host.endsWith('.localhost') || host.endsWith('.internal')) {
    return true;
  }
  if (net.isIP(host) === 6) {
    return host === '::1' || /^f[cd]/i.test(host);
  }
  if (net.isIP(host) !== 4) return false;
  const [first, second] = host.split('.').map(Number);
  return first === 10
    || first === 127
    || (first === 172 && second >= 16 && second <= 31)
    || (first === 192 && second === 168);
}

function loadGatewayConfig(environment = process.env) {
  const nodeEnv = environment.NODE_ENV;
  if (!['development', 'test', 'production'].includes(nodeEnv)) {
    throw new Error('NODE_ENV must be explicitly set to development, test, or production.');
  }
  const production = nodeEnv === 'production';
  if (production) {
    const missing = PRODUCTION_REQUIRED_VARIABLES.filter((name) => !environment[name]?.trim());
    if (missing.length) {
      throw new Error(`Missing required production environment variable: ${missing[0]}.`);
    }
  }

  const secret = environment.KIARA_GATEWAY_HMAC_SECRET || '';
  const previousSecret = environment.KIARA_GATEWAY_HMAC_PREVIOUS_SECRET || '';
  if (Buffer.byteLength(secret) < 32) {
    throw new Error('KIARA_GATEWAY_HMAC_SECRET must contain at least 32 bytes.');
  }
  if (previousSecret && Buffer.byteLength(previousSecret) < 32) {
    throw new Error('KIARA_GATEWAY_HMAC_PREVIOUS_SECRET must contain at least 32 bytes.');
  }

  const credentials = createCredentialPool(environment);
  const projectId = environment.KIARA_GEMINI_PROJECT_ID || '';
  if (!projectId.trim()) throw new Error('KIARA_GEMINI_PROJECT_ID is required.');

  const systemInstructionHashes = String(
    environment.KIARA_LIVE_SYSTEM_INSTRUCTION_SHA256 || ''
  ).split(',').map((hash) => hash.trim().toLowerCase()).filter(Boolean);
  if (
    !systemInstructionHashes.length
    || systemInstructionHashes.some((hash) => !/^[0-9a-f]{64}$/.test(hash))
  ) {
    throw new Error('KIARA_LIVE_SYSTEM_INSTRUCTION_SHA256 must contain one or more SHA-256 hashes.');
  }

  const redisUrl = environment.REDIS_URL || '';
  let parsedRedisUrl;
  try {
    parsedRedisUrl = new URL(redisUrl);
  } catch {
    throw new Error('REDIS_URL must be a valid Redis connection URL.');
  }
  if (!['redis:', 'rediss:'].includes(parsedRedisUrl.protocol)) {
    throw new Error('REDIS_URL must use redis:// or rediss://.');
  }
  if (production && parsedRedisUrl.protocol !== 'rediss:') {
    throw new Error('REDIS_URL must use TLS (rediss://) in production.');
  }

  const host = environment.HOST || (production ? '' : '127.0.0.1');
  if (!host) throw new Error('HOST is required in production.');
  if (production && host !== '0.0.0.0' && !isPrivateBindHost(host)) {
    throw new Error('HOST must be a private interface address, private hostname, or 0.0.0.0 in production.');
  }

  const port = readInteger(environment, 'PORT', 8080, 1, 65535, production);
  const maxConcurrent = readInteger(
    environment, 'KIARA_GATEWAY_MAX_CONCURRENT', 5, 1, 500, production
  );
  const requestsPerMinute = readInteger(
    environment, 'KIARA_PROJECT_REQUESTS_PER_MINUTE', 60, 1, 1_000_000, production
  );
  const quotaCooldownMs = readInteger(
    environment, 'KIARA_PROJECT_QUOTA_COOLDOWN_MS', 60_000, 1000, 24 * 60 * 60 * 1000, production
  );
  const providerTimeoutMs = readInteger(
    environment, 'KIARA_GATEWAY_PROVIDER_TIMEOUT_MS', 10_000, 1000, 30_000, production
  );

  const redisCaFile = environment.KIARA_REDIS_CA_CERT_FILE || '';
  if (redisCaFile) {
    try {
      if (!fs.statSync(redisCaFile).isFile()) {
        throw new Error('not a file');
      }
    } catch {
      throw new Error('KIARA_REDIS_CA_CERT_FILE must refer to a readable certificate file.');
    }
  }
  if (redisCaFile && parsedRedisUrl.protocol !== 'rediss:') {
    throw new Error('KIARA_REDIS_CA_CERT_FILE can only be used with a rediss:// URL.');
  }

  return {
    credentials,
    host,
    maxConcurrent,
    nodeEnv,
    port,
    previousSecret,
    projectId,
    providerTimeoutMs,
    quotaCooldownMs,
    redisCaFile,
    redisUrl,
    requestsPerMinute,
    secret,
    systemInstructionHashes,
  };
}

function createRedisClientOptions(config) {
  const options = { url: config.redisUrl };
  if (config.redisUrl.startsWith('rediss://')) {
    options.socket = {
      tls: true,
      rejectUnauthorized: true,
      reconnectStrategy: (retries) => Math.min(retries * 250, 5000),
      ...(config.redisCaFile ? { ca: fs.readFileSync(config.redisCaFile) } : {}),
    };
  } else {
    options.socket = {
      reconnectStrategy: (retries) => Math.min(retries * 250, 5000),
    };
  }
  return options;
}

module.exports = {
  createRedisClientOptions,
  loadGatewayConfig,
};
