'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const {
  createRedisClientOptions,
  loadGatewayConfig,
} = require('./config');

function productionEnvironment(overrides = {}) {
  const environment = {
    NODE_ENV: 'production',
    HOST: '127.0.0.1',
    PORT: '8080',
    REDIS_URL: 'rediss://gateway-user:gateway-password@redis.staging.internal:6380/0',
    KIARA_GEMINI_PROJECT_ID: 'kiara-staging-project',
    KIARA_GATEWAY_HMAC_SECRET: 'test-secret-with-more-than-thirty-two-bytes',
    KIARA_LIVE_SYSTEM_INSTRUCTION_SHA256: 'a'.repeat(64),
    KIARA_GATEWAY_MAX_CONCURRENT: '5',
    KIARA_PROJECT_REQUESTS_PER_MINUTE: '60',
    KIARA_PROJECT_QUOTA_COOLDOWN_MS: '60000',
    KIARA_GATEWAY_PROVIDER_TIMEOUT_MS: '10000',
    GEMINI_API_KEY_1: `AQ.${'A'.repeat(40)}`,
    GEMINI_CREDENTIAL_1_ENABLED: 'true',
  };
  return { ...environment, ...overrides };
}

test('requires an explicit supported NODE_ENV', () => {
  assert.throws(
    () => loadGatewayConfig({}),
    /NODE_ENV must be explicitly set/,
  );
  assert.throws(
    () => loadGatewayConfig({ NODE_ENV: 'staging' }),
    /NODE_ENV must be explicitly set/,
  );
});

test('fails production startup when a required setting is missing', () => {
  const required = [
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
  for (const name of required) {
    const environment = productionEnvironment();
    delete environment[name];
    assert.throws(
      () => loadGatewayConfig(environment),
      new RegExp(`Missing required production environment variable: ${name}`),
    );
  }
});

test('requires explicit production settings and rejects insecure Redis and wildcard binding', () => {
  assert.throws(
    () => loadGatewayConfig(productionEnvironment({ REDIS_URL: 'redis://redis.staging.internal:6379' })),
    /REDIS_URL must use TLS/,
  );
  assert.throws(
    () => loadGatewayConfig(productionEnvironment({ HOST: '0.0.0.0' })),
    /HOST must be a private interface address/,
  );
  assert.throws(
    () => loadGatewayConfig(productionEnvironment({ HOST: '203.0.113.10' })),
    /HOST must be a private interface address/,
  );
  assert.throws(
    () => loadGatewayConfig(productionEnvironment({ KIARA_PROJECT_REQUESTS_PER_MINUTE: undefined })),
    /Missing required production environment variable: KIARA_PROJECT_REQUESTS_PER_MINUTE/,
  );
});

test('accepts a Gemini authorization key without rewriting the secret', () => {
  const environment = productionEnvironment();
  const original = environment.GEMINI_API_KEY_1;
  const config = loadGatewayConfig(environment);
  assert.equal(config.credentials.count, 1);
  assert.equal(config.credentials.getNext().key, original);
});

test('rejects invalid HMAC configuration before opening Redis', () => {
  assert.throws(
    () => loadGatewayConfig(productionEnvironment({ KIARA_GATEWAY_HMAC_SECRET: 'too-short' })),
    /must contain at least 32 bytes/,
  );
});

test('enables certificate validation and bounded reconnects for Redis TLS', () => {
  const config = loadGatewayConfig(productionEnvironment());
  const options = createRedisClientOptions(config);
  assert.equal(options.url, config.redisUrl);
  assert.equal(options.socket.tls, true);
  assert.equal(options.socket.rejectUnauthorized, true);
  assert.equal(options.socket.reconnectStrategy(1), 250);
  assert.equal(options.socket.reconnectStrategy(100), 5000);
});
