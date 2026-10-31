'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');
const { loadLocalEnvironment } = require('./environment');

test('loads local env values without overriding existing process values', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kiara-gateway-env-'));
  const envFile = path.join(directory, '.env');
  fs.writeFileSync(envFile, 'NODE_ENV=development\nPORT=8080\nHOST="127.0.0.1"\n');

  try {
    const environment = { PORT: '9090' };
    loadLocalEnvironment(environment, envFile);
    assert.deepEqual(environment, {
      NODE_ENV: 'development',
      PORT: '9090',
      HOST: '127.0.0.1',
    });
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('does not load a local env file in production', () => {
  const environment = { NODE_ENV: 'production' };
  loadLocalEnvironment(environment, path.join(os.tmpdir(), 'missing-gateway.env'));
  assert.deepEqual(environment, { NODE_ENV: 'production' });
});

test('does not load production settings from a local env file', () => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'kiara-gateway-env-'));
  const envFile = path.join(directory, '.env');
  fs.writeFileSync(envFile, 'NODE_ENV=production\nKIARA_GATEWAY_HMAC_SECRET=local-only\n');

  try {
    const environment = {};
    loadLocalEnvironment(environment, envFile);
    assert.deepEqual(environment, {});
  } finally {
    fs.rmSync(directory, { recursive: true, force: true });
  }
});

test('treats a missing local env file as optional', () => {
  const environment = {};
  loadLocalEnvironment(environment, path.join(os.tmpdir(), 'missing-gateway.env'));
  assert.deepEqual(environment, {});
});
