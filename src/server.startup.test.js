'use strict';

const assert = require('node:assert/strict');
const { test } = require('node:test');
const { loadGatewayConfig } = require('./config');
const { getStartupChecks } = require('./server');

function createConfig(overrides = {}) {
  return loadGatewayConfig({
    NODE_ENV: 'development',
    HOST: '127.0.0.1',
    PORT: '8080',
    REDIS_URL: 'rediss://redis.internal:6380/0',
    KIARA_GEMINI_PROJECT_ID: 'test-project',
    KIARA_GATEWAY_HMAC_SECRET: 'test-hmac-secret-longer-than-thirty-two-bytes',
    KIARA_LIVE_SYSTEM_INSTRUCTION_SHA256: 'a'.repeat(64),
    GEMINI_API_KEY_1: `AQ.${'K'.repeat(40)}`,
    GEMINI_CREDENTIAL_1_ENABLED: 'true',
    ...overrides,
  });
}

test('reports startup readiness without exposing credentials or secrets', () => {
  const config = createConfig();
  const checks = getStartupChecks(config);
  const output = JSON.stringify(checks);

  assert.deepEqual(checks.map(({ check, status }) => ({ check, status })), [
    { check: 'configuration', status: 'passed' },
    { check: 'network_binding', status: 'configured' },
    { check: 'gemini_credentials', status: 'configured' },
    { check: 'backend_hmac_auth', status: 'configured' },
    { check: 'redis', status: 'pending' },
  ]);
  assert.deepEqual(checks[2].enabledSlots, [1]);
  assert.equal(checks[2].providerValidation, 'not_tested');
  assert.equal(checks[3].peerSecretMatch, 'not_tested');
  assert.equal(checks[4].tlsCertificateVerification, true);
  assert.equal(output.includes(config.secret), false);
  assert.equal(output.includes(config.credentials.getNext().key), false);
});

test('warns in startup diagnostics when binding to every network interface', () => {
  const [, networkBindingCheck] = getStartupChecks(createConfig({ HOST: '0.0.0.0' }));

  assert.equal(networkBindingCheck.status, 'warning');
  assert.equal(networkBindingCheck.host, '0.0.0.0');
});
