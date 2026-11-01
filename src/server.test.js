'use strict';

const assert = require('node:assert/strict');
const { createHash, randomUUID } = require('node:crypto');
const { after, test } = require('node:test');
const {
  createGatewayServer,
  signRequest,
} = require('./server');
const { createCredentialPool } = require('./credentials');
const {
  classifyProviderError,
  createGeminiTokenProvider,
} = require('./provider');

const secret = 'test-secret-with-more-than-thirty-two-bytes';
const servers = new Set();

class SharedMemoryRedis {
  constructor() {
    this.isReady = true;
    this.values = new Map();
    this.sortedSets = new Map();
    this.fail = false;
  }

  expireValues() {
    const now = Date.now();
    for (const [key, entry] of this.values) {
      if (entry.expiresAt !== null && entry.expiresAt <= now) this.values.delete(key);
    }
  }

  async set(key, value, options = {}) {
    if (this.fail) throw new Error('test Redis outage');
    this.expireValues();
    if (options.NX && this.values.has(key)) return null;
    const ttl = options.PX ? options.PX : options.EX ? options.EX * 1000 : null;
    this.values.set(key, {
      value,
      expiresAt: ttl === null ? null : Date.now() + ttl,
    });
    return 'OK';
  }

  async get(key) {
    if (this.fail) throw new Error('test Redis outage');
    this.expireValues();
    return this.values.get(key)?.value || null;
  }

  async eval(script, { keys, arguments: args }) {
    if (this.fail) throw new Error('test Redis outage');
    this.expireValues();
    if (script.includes("redis.call('PTTL'")) {
      const [cooldownKey, requestsKey, leasesKey] = keys;
      const now = Number(args[0]);
      const windowMs = Number(args[1]);
      const requestLimit = Number(args[2]);
      const leaseTtlMs = Number(args[3]);
      const concurrencyLimit = Number(args[4]);
      const requestId = args[5];
      const cooldown = this.values.get(cooldownKey);
      if (cooldown) return [-1, cooldown.expiresAt - Date.now()];

      const requests = this.sortedSets.get(requestsKey) || new Map();
      for (const [id, score] of requests) {
        if (score <= now - windowMs) requests.delete(id);
      }
      if (requests.size >= requestLimit) {
        const oldest = Math.min(...requests.values());
        return [-2, Math.max(1, oldest + windowMs - now)];
      }

      const leases = this.sortedSets.get(leasesKey) || new Map();
      for (const [id, score] of leases) {
        if (score <= now) leases.delete(id);
      }
      if (leases.size >= concurrencyLimit) return [-3, leases.size];

      requests.set(requestId, now);
      leases.set(requestId, now + leaseTtlMs);
      this.sortedSets.set(requestsKey, requests);
      this.sortedSets.set(leasesKey, leases);
      return [1, leases.size];
    }
    if (script.includes("redis.call('ZREM'")) {
      this.sortedSets.get(keys[0])?.delete(args[0]);
      return 1;
    }
    throw new Error('Unexpected Redis script.');
  }
}

after(async () => {
  await Promise.all([...servers].map(async (server) => {
    if (!server.listening) return;
    await new Promise((resolve) => server.close(resolve));
  }));
});

async function startTestServer(options = {}) {
  const redis = options.redis || new SharedMemoryRedis();
  const server = createGatewayServer({
    redis,
    secret,
    previousSecret: options.previousSecret || '',
    systemInstructionHashes: [
      createHash('sha256').update('test instruction', 'utf8').digest('hex'),
    ],
    projectId: 'kiara-staging-project',
    createToken: options.createToken || (async () => ({ name: 'test-token' })),
    maxConcurrent: options.maxConcurrent || 5,
    requestsPerMinute: options.requestsPerMinute || 60,
    quotaCooldownMs: options.quotaCooldownMs || 60_000,
    providerTimeoutMs: options.providerTimeoutMs || 10_000,
  });
  servers.add(server);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const address = server.address();
  return {
    server,
    redis,
    url: `http://127.0.0.1:${address.port}/internal/v1/live-token`,
  };
}

function makePayload() {
  return {
    expireTime: new Date(Date.now() + 30 * 60_000).toISOString(),
    newSessionExpireTime: new Date(Date.now() + 60_000).toISOString(),
    liveConnectConstraints: {
      model: 'gemini-3.1-flash-live-preview',
      config: {
        responseModalities: ['AUDIO'],
        systemInstruction: 'test instruction',
      },
    },
  };
}

function signedHeaders(body, nonce = randomUUID()) {
  const timestamp = String(Date.now());
  return {
    'content-type': 'application/json',
    'x-kiara-timestamp': timestamp,
    'x-kiara-nonce': nonce,
    'x-kiara-signature': signRequest(secret, timestamp, nonce, body),
  };
}

async function postToken(url, body = JSON.stringify(makePayload()), nonce) {
  return fetch(url, {
    method: 'POST',
    headers: signedHeaders(body, nonce),
    body,
  });
}

test('creates a Live token only for a valid signed request', async () => {
  let receivedPayload;
  let receivedSignal;
  const originalInfo = console.info;
  const logs = [];
  console.info = (...args) => logs.push(args);
  const { url } = await startTestServer({
    createToken: async (payload, signal) => {
      receivedPayload = payload;
      receivedSignal = signal;
      return { name: 'test-token' };
    },
  });
  const body = JSON.stringify(makePayload());
  const response = await postToken(url, body);

  try {
    assert.equal(response.status, 200);
    assert.equal(response.headers.get('cache-control'), 'no-store');
    assert.deepEqual(await response.json(), { token: 'test-token' });
    assert.deepEqual(receivedPayload, JSON.parse(body));
    assert.ok(receivedSignal instanceof AbortSignal);
    assert.equal(JSON.stringify(logs).includes('test-token'), false);
  } finally {
    console.info = originalInfo;
  }
});

test('rejects invalid HMACs, stale timestamps, and replayed nonces', async () => {
  let providerCalls = 0;
  const { url } = await startTestServer({
    createToken: async () => {
      providerCalls += 1;
      return { name: 'test-token' };
    },
  });
  const body = JSON.stringify(makePayload());
  const nonce = randomUUID();
  const invalidHeaders = signedHeaders(body, nonce);
  invalidHeaders['x-kiara-signature'] = '0'.repeat(64);
  assert.equal((await fetch(url, {
    method: 'POST',
    headers: invalidHeaders,
    body,
  })).status, 401);

  const staleHeaders = signedHeaders(body);
  staleHeaders['x-kiara-timestamp'] = String(Date.now() - 60_000);
  assert.equal((await fetch(url, {
    method: 'POST',
    headers: staleHeaders,
    body,
  })).status, 401);

  const validHeaders = signedHeaders(body, nonce);
  assert.equal((await fetch(url, {
    method: 'POST',
    headers: validHeaders,
    body,
  })).status, 200);
  assert.equal((await fetch(url, {
    method: 'POST',
    headers: validHeaders,
    body,
  })).status, 409);
  assert.equal(providerCalls, 1);
});

test('accepts a previous HMAC key during controlled secret rotation', async () => {
  const oldSecret = 'previous-test-secret-with-more-than-thirty-two-bytes';
  const { url } = await startTestServer({ previousSecret: oldSecret });
  const body = JSON.stringify(makePayload());
  const timestamp = String(Date.now());
  const nonce = randomUUID();
  const headers = {
    'content-type': 'application/json',
    'x-kiara-timestamp': timestamp,
    'x-kiara-nonce': nonce,
    'x-kiara-signature': signRequest(oldSecret, timestamp, nonce, body),
  };
  assert.equal((await fetch(url, { method: 'POST', headers, body })).status, 200);
});

test('rejects a retired HMAC key after the rotation overlap ends', async () => {
  const retiredSecret = 'retired-test-secret-with-more-than-thirty-two-bytes';
  const { url } = await startTestServer();
  const body = JSON.stringify(makePayload());
  const timestamp = String(Date.now());
  const retiredNonce = randomUUID();
  const retiredHeaders = {
    'content-type': 'application/json',
    'x-kiara-timestamp': timestamp,
    'x-kiara-nonce': retiredNonce,
    'x-kiara-signature': signRequest(retiredSecret, timestamp, retiredNonce, body),
  };
  assert.equal((await fetch(url, {
    method: 'POST',
    headers: retiredHeaders,
    body,
  })).status, 401);

  assert.equal((await postToken(url, body)).status, 200);
});

test('does not log a provider API key or provider error message', async () => {
  const apiKey = `AIza${'K'.repeat(30)}`;
  const providerError = `provider rejected ${apiKey}`;
  const credentials = createCredentialPool({
    GEMINI_API_KEY_1: apiKey,
    GEMINI_CREDENTIAL_1_ENABLED: 'true',
  });
  const redis = new SharedMemoryRedis();
  const createToken = createGeminiTokenProvider({
    credentials,
    redis,
    createClient: () => ({
      authTokens: {
        create: async () => {
          throw new Error(providerError);
        },
      },
    }),
  });
  const originalError = console.error;
  const logs = [];
  console.error = (...args) => logs.push(args);

  try {
    const { url } = await startTestServer({ createToken });
    assert.equal((await postToken(url)).status, 503);
    const output = JSON.stringify(logs);
    assert.equal(output.includes(apiKey), false);
    assert.equal(output.includes(providerError), false);
  } finally {
    console.error = originalError;
  }
});

test('enforces expiry, approved model, audio-only modality, and bounded instruction', async () => {
  let providerCalls = 0;
  const { url } = await startTestServer({
    createToken: async () => {
      providerCalls += 1;
      return { name: 'test-token' };
    },
  });
  const mutations = [
    (payload) => { payload.expireTime = new Date(Date.now() + 32 * 60_000).toISOString(); },
    (payload) => { payload.liveConnectConstraints.model = 'gemini-unapproved-model'; },
    (payload) => { payload.liveConnectConstraints.config.responseModalities.push('TEXT'); },
    (payload) => { payload.liveConnectConstraints.config.systemInstruction = ' '; },
    (payload) => { payload.liveConnectConstraints.config.systemInstruction = 'different signed prompt'; },
    (payload) => { payload.newSessionExpireTime = new Date(Date.now() + 120_000).toISOString(); },
  ];

  for (const mutate of mutations) {
    const payload = makePayload();
    mutate(payload);
    assert.equal((await postToken(url, JSON.stringify(payload))).status, 400);
  }
  assert.equal(providerCalls, 0);
});

test('fails closed when replay protection Redis is unavailable', async () => {
  const redis = new SharedMemoryRedis();
  redis.isReady = false;
  const { url } = await startTestServer({ redis });
  assert.equal((await postToken(url)).status, 503);
});

test('fails closed when a Redis operation errors', async () => {
  const redis = new SharedMemoryRedis();
  redis.fail = true;
  const { url } = await startTestServer({ redis });
  assert.equal((await postToken(url)).status, 503);
});

test('shares the project concurrency cap between gateway instances', async () => {
  const redis = new SharedMemoryRedis();
  let releaseProvider;
  let providerStarted;
  const providerStartedPromise = new Promise((resolve) => {
    providerStarted = resolve;
  });
  const options = {
    redis,
    maxConcurrent: 1,
    createToken: () => new Promise((resolve) => {
      releaseProvider = () => resolve({ name: 'test-token' });
      providerStarted();
    }),
  };
  const firstGateway = await startTestServer(options);
  const secondGateway = await startTestServer(options);
  const body = JSON.stringify(makePayload());
  const firstRequest = postToken(firstGateway.url, body);
  await providerStartedPromise;

  const secondResponse = await postToken(secondGateway.url, body);
  assert.equal(secondResponse.status, 503);
  releaseProvider();
  assert.equal((await firstRequest).status, 200);
});

test('shares project quota cooldown across gateway instances without credential retry', async () => {
  const redis = new SharedMemoryRedis();
  let providerCalls = 0;
  const firstGateway = await startTestServer({
    redis,
    createToken: async () => {
      providerCalls += 1;
      throw Object.assign(new Error('redacted provider response'), { status: 429 });
    },
  });
  const secondGateway = await startTestServer({
    redis,
    createToken: async () => {
      providerCalls += 1;
      return { name: 'unexpected-token' };
    },
  });
  const firstResponse = await postToken(firstGateway.url);
  assert.equal(firstResponse.status, 429);
  assert.equal((await postToken(secondGateway.url)).status, 429);
  assert.equal(providerCalls, 1);
});

test('applies one shared project request budget', async () => {
  const redis = new SharedMemoryRedis();
  let providerCalls = 0;
  const options = {
    redis,
    requestsPerMinute: 1,
    createToken: async () => {
      providerCalls += 1;
      return { name: 'test-token' };
    },
  };
  const first = await startTestServer(options);
  const second = await startTestServer(options);
  assert.equal((await postToken(first.url)).status, 200);
  const limited = await postToken(second.url);
  assert.equal(limited.status, 429);
  assert.equal(providerCalls, 1);
});

test('retains nonce replay protection after a gateway instance restarts', async () => {
  const redis = new SharedMemoryRedis();
  const first = await startTestServer({ redis });
  const body = JSON.stringify(makePayload());
  const nonce = randomUUID();
  const headers = signedHeaders(body, nonce);
  assert.equal((await fetch(first.url, { method: 'POST', headers, body })).status, 200);
  await new Promise((resolve) => first.server.close(resolve));

  const restarted = await startTestServer({ redis });
  assert.equal((await fetch(restarted.url, { method: 'POST', headers, body })).status, 409);
});

test('applies provider timeouts and aborts the provider request', async () => {
  let providerSignal;
  const { url } = await startTestServer({
    providerTimeoutMs: 1000,
    createToken: (_payload, signal) => {
      providerSignal = signal;
      return new Promise((_resolve, reject) => {
        signal.addEventListener('abort', () => {
          reject(Object.assign(new Error('request aborted'), { name: 'AbortError' }));
        }, { once: true });
      });
    },
  });
  const response = await postToken(url);
  assert.equal(response.status, 504);
  assert.equal((await response.json()).code, 'PROVIDER_TIMEOUT');
  assert.equal(providerSignal.aborted, true);
});

test('cancels provider work when the internal caller disconnects and frees capacity', async () => {
  let markStarted;
  let markAborted;
  const providerStarted = new Promise((resolve) => { markStarted = resolve; });
  const providerAborted = new Promise((resolve) => { markAborted = resolve; });
  const firstGateway = await startTestServer({
    maxConcurrent: 1,
    createToken: (_payload, signal) => new Promise((_resolve, reject) => {
      markStarted();
      signal.addEventListener('abort', () => {
        reject(Object.assign(new Error('aborted by caller'), { name: 'AbortError' }));
        markAborted();
      }, { once: true });
    }),
  });
  const controller = new AbortController();
  const body = JSON.stringify(makePayload());
  const pendingRequest = fetch(firstGateway.url, {
    method: 'POST',
    headers: signedHeaders(body),
    body,
    signal: controller.signal,
  });
  await providerStarted;
  controller.abort();
  await assert.rejects(pendingRequest, { name: 'AbortError' });
  await providerAborted;
  await new Promise((resolve) => setTimeout(resolve, 10));

  const recovered = await startTestServer({
    redis: firstGateway.redis,
    maxConcurrent: 1,
  });
  assert.equal((await postToken(recovered.url)).status, 200);
});

test('classifies Gemini HTTP errors without retrying transient or invalid requests', () => {
  const expected = new Map([
    [400, ['PROVIDER_INVALID_REQUEST', 502]],
    [401, ['PROVIDER_INVALID_CREDENTIAL', 502]],
    [403, ['PROVIDER_PERMISSION_DENIED', 502]],
    [404, ['PROVIDER_MODEL_NOT_FOUND', 502]],
    [429, ['PROJECT_QUOTA_EXCEEDED', 429]],
    [500, ['PROVIDER_UNAVAILABLE', 503]],
    [502, ['PROVIDER_UNAVAILABLE', 503]],
    [503, ['PROVIDER_UNAVAILABLE', 503]],
    [504, ['PROVIDER_TIMEOUT', 504]],
  ]);
  for (const [status, [code, statusCode]] of expected) {
    assert.deepEqual(
      classifyProviderError(Object.assign(new Error('secret response'), { status })),
      { code, statusCode },
    );
  }
  assert.equal(classifyProviderError(new TypeError('network failed')).code, 'PROVIDER_NETWORK_ERROR');
});

test('registers up to ten isolated credentials and supports explicit disable and rotation', () => {
  const environment = {};
  for (let slot = 1; slot <= 10; slot += 1) {
    environment[`GEMINI_API_KEY_${slot}`] = `AQ.${String(slot).padStart(2, '0')}${'A'.repeat(35)}`;
    environment[`GEMINI_CREDENTIAL_${slot}_ENABLED`] = 'true';
  }
  const pool = createCredentialPool(environment);
  assert.equal(pool.count, 10);
  const first = pool.getNext();
  const second = pool.getNext();
  assert.notEqual(first.key, second.key);
  assert.equal(pool.credentials.length, 10);

  environment.GEMINI_CREDENTIAL_2_ENABLED = 'false';
  const disabledPool = createCredentialPool(environment);
  assert.equal(disabledPool.credentials.some(({ slot }) => slot === 2), false);

  environment.GEMINI_API_KEY_2 = `AQ.${'B'.repeat(40)}`;
  environment.GEMINI_CREDENTIAL_2_ENABLED = 'true';
  assert.notEqual(createCredentialPool(environment).credentials[1].fingerprint, pool.credentials[1].fingerprint);
});

test('expires a local invalid-credential disable after its cooldown', async () => {
  const pool = createCredentialPool({
    GEMINI_API_KEY_1: `AIza01${'A'.repeat(30)}`,
  });
  const credential = pool.getNext();
  pool.disable(credential.fingerprint, 10);

  assert.equal(pool.getNext(), null);
  await new Promise((resolve) => setTimeout(resolve, 15));
  assert.equal(pool.getNext().fingerprint, credential.fingerprint);
});

test('requires a valid key in every enabled slot and rejects duplicate credentials', () => {
  assert.throws(
    () => createCredentialPool({ GEMINI_CREDENTIAL_1_ENABLED: 'true' }),
    /GEMINI_API_KEY_1 is not configured/,
  );
  assert.throws(
    () => createCredentialPool({ GEMINI_API_KEY_1: 'not-a-key' }),
    /invalid Google API key format/,
  );
  assert.equal(
    createCredentialPool({ GEMINI_API_KEY_1: `AQ.${'A'.repeat(40)}` }).count,
    1,
  );
  assert.throws(
    () => createCredentialPool({
      GEMINI_API_KEY_1: `AIza${'A'.repeat(30)}`,
      GEMINI_API_KEY_2: `AIza${'A'.repeat(30)}`,
    }),
    /unique API keys/,
  );
  assert.throws(
    () => createCredentialPool({ GEMINI_CREDENTIAL_1_ENABLED: 'false' }),
    /At least one enabled Gemini credential slot/,
  );
});

test('disables a rejected key and retries the next credential without switching on project quota errors', async () => {
  const credentials = createCredentialPool({
    GEMINI_API_KEY_1: `AIza${'A'.repeat(30)}`,
    GEMINI_API_KEY_2: `AIza${'B'.repeat(30)}`,
  });
  const redis = new SharedMemoryRedis();
  const attemptedKeys = [];
  const invalidKeyIssuer = createGeminiTokenProvider({
    credentials,
    redis,
    createClient: (key) => ({
      authTokens: {
        create: async () => {
          attemptedKeys.push(key);
          if (key.endsWith('A'.repeat(30))) {
            throw Object.assign(new Error('invalid key'), { status: 401 });
          }
          return { name: 'valid-token' };
        },
      },
    }),
  });
  const token = await invalidKeyIssuer(makePayload(), new AbortController().signal);
  assert.equal(token.name, 'valid-token');
  assert.equal(attemptedKeys.length, 2);
  assert.equal(attemptedKeys[0].endsWith('A'.repeat(30)), true);
  assert.equal(attemptedKeys[1].endsWith('B'.repeat(30)), true);

  const nextRequestIssuer = createGeminiTokenProvider({
    credentials: createCredentialPool({
      GEMINI_API_KEY_1: `AIza${'A'.repeat(30)}`,
      GEMINI_API_KEY_2: `AIza${'B'.repeat(30)}`,
    }),
    redis,
    createClient: (key) => ({
      authTokens: {
        create: async () => {
          attemptedKeys.push(key);
          return { name: 'valid-token' };
        },
      },
    }),
  });
  const nextToken = await nextRequestIssuer(makePayload(), new AbortController().signal);
  assert.equal(nextToken.name, 'valid-token');
  assert.equal(
    [...redis.values.keys()].some((key) => key.startsWith('kiara:live-gateway:credential-disabled:1:')),
    true,
  );

  const quotaCredentials = createCredentialPool({
    GEMINI_API_KEY_1: `AIza${'C'.repeat(30)}`,
    GEMINI_API_KEY_2: `AIza${'D'.repeat(30)}`,
  });
  let quotaAttempts = 0;
  const quotaIssuer = createGeminiTokenProvider({
    credentials: quotaCredentials,
    redis,
    createClient: () => ({
      authTokens: {
        create: async () => {
          quotaAttempts += 1;
          throw Object.assign(new Error('project quota'), { status: 429 });
        },
      },
    }),
  });
  await assert.rejects(quotaIssuer(makePayload(), new AbortController().signal), { status: 429 });
  assert.equal(quotaAttempts, 1);
});

test('does not rotate keys for project permission errors and marks all invalid keys unavailable', async () => {
  const credentials = createCredentialPool({
    GEMINI_API_KEY_1: `AIza${'E'.repeat(30)}`,
    GEMINI_API_KEY_2: `AIza${'F'.repeat(30)}`,
  });
  const redis = new SharedMemoryRedis();
  let forbiddenAttempts = 0;
  const forbiddenIssuer = createGeminiTokenProvider({
    credentials,
    redis,
    createClient: () => ({
      authTokens: {
        create: async () => {
          forbiddenAttempts += 1;
          throw Object.assign(new Error('permission denied'), { status: 403 });
        },
      },
    }),
  });
  await assert.rejects(forbiddenIssuer(makePayload(), new AbortController().signal), { status: 403 });
  assert.equal(forbiddenAttempts, 1);

  const invalidCredentials = createCredentialPool({
    GEMINI_API_KEY_1: `AIza${'G'.repeat(30)}`,
    GEMINI_API_KEY_2: `AIza${'H'.repeat(30)}`,
  });
  let invalidAttempts = 0;
  const invalidIssuer = createGeminiTokenProvider({
    credentials: invalidCredentials,
    redis,
    createClient: () => ({
      authTokens: {
        create: async () => {
          invalidAttempts += 1;
          throw Object.assign(new Error('invalid API key'), { status: 401 });
        },
      },
    }),
  });
  await assert.rejects(invalidIssuer(makePayload(), new AbortController().signal), {
    code: 'PROVIDER_INVALID_CREDENTIAL',
    statusCode: 502,
  });
  const secondInvalidIssuer = createGeminiTokenProvider({
    credentials: createCredentialPool({
      GEMINI_API_KEY_1: `AIza${'G'.repeat(30)}`,
      GEMINI_API_KEY_2: `AIza${'H'.repeat(30)}`,
    }),
    redis,
    createClient: () => ({
      authTokens: {
        create: async () => {
          invalidAttempts += 1;
          throw Object.assign(new Error('invalid API key'), { status: 401 });
        },
      },
    }),
  });
  await assert.rejects(secondInvalidIssuer(makePayload(), new AbortController().signal), {
    code: 'PROVIDER_INVALID_CREDENTIAL',
    statusCode: 502,
  });
  assert.equal(invalidAttempts, 2);
});

test('fails if all configured credential slots are disabled', () => {
  const environment = {};
  for (let slot = 1; slot <= 10; slot += 1) {
    environment[`GEMINI_CREDENTIAL_${slot}_ENABLED`] = 'false';
  }
  assert.throws(() => createCredentialPool(environment), /At least one enabled Gemini credential slot/);
});
