'use strict';

const http = require('node:http');
const {
  createHash,
  createHmac,
  timingSafeEqual,
} = require('node:crypto');
const { createClient } = require('redis');
const { loadLocalEnvironment } = require('./environment');
const {
  createRedisClientOptions,
  loadGatewayConfig,
} = require('./config');
const { createProjectAdmission } = require('./projectAdmission');
const {
  classifyProviderError,
  createGeminiTokenProvider,
} = require('./provider');

const MAX_BODY_BYTES = 64 * 1024;
const MAX_CLOCK_SKEW_MS = 30_000;
const NONCE_TTL_SECONDS = 60;
const PROVIDER_TIMEOUT_MS = 10_000;
const PROVIDER_LEASE_BUFFER_MS = 5_000;
const MAX_NEW_SESSION_WINDOW_MS = 90_000;
const APPROVED_LIVE_MODELS = new Set([
  'gemini-3.1-flash-live-preview',
  'gemini-2.5-flash-native-audio-preview-12-2025',
  'gemini-2.5-flash-preview-native-audio-dialog',
  'gemini-2.0-flash-live-001',
  'gemini-2.0-flash-live-preview-04-09',
]);

function signRequest(secret, timestamp, nonce, body) {
  const bodyHash = createHash('sha256').update(body).digest('hex');
  return createHmac('sha256', secret)
    .update(`${timestamp}.${nonce}.${bodyHash}`)
    .digest('hex');
}

function signatureIsValid(secret, timestamp, nonce, body, signature, now) {
  if (!/^\d{13}$/.test(timestamp || '')
    || Math.abs(now - Number(timestamp)) > MAX_CLOCK_SKEW_MS
    || !/^[0-9a-f-]{36}$/i.test(nonce || '')
    || !/^[0-9a-f]{64}$/i.test(signature || '')) {
    return false;
  }

  const received = Buffer.from(signature, 'hex');
  const secrets = Array.isArray(secret) ? secret : [secret];
  let valid = false;
  for (const candidate of secrets) {
    if (typeof candidate !== 'string' || Buffer.byteLength(candidate) < 32) continue;
    const expected = Buffer.from(signRequest(candidate, timestamp, nonce, body), 'hex');
    valid = (expected.length === received.length && timingSafeEqual(expected, received)) || valid;
  }
  return valid;
}

function sendJson(response, status, payload, headers = {}) {
  response.writeHead(status, {
    'cache-control': 'no-store',
    'content-type': 'application/json; charset=utf-8',
    ...headers,
  });
  response.end(JSON.stringify(payload));
}

function getStartupChecks(config) {
  const enabledCredentialSlots = config.credentials.credentials.map(({ slot }) => slot);
  const isWildcardBind = config.host === '0.0.0.0' || config.host === '::';
  return [
    {
      check: 'configuration',
      status: 'passed',
      environment: config.nodeEnv,
      bindHost: config.host,
      port: config.port,
      networkExposure: isWildcardBind ? 'all_interfaces' : 'configured_interface',
    },
    {
      check: 'network_binding',
      status: isWildcardBind ? 'warning' : 'configured',
      host: config.host,
      port: config.port,
    },
    {
      check: 'gemini_credentials',
      status: 'configured',
      enabledSlots: enabledCredentialSlots,
      providerValidation: 'not_tested',
    },
    {
      check: 'backend_hmac_auth',
      status: 'configured',
      peerSecretMatch: 'not_tested',
    },
    {
      check: 'redis',
      status: 'pending',
      protocol: config.redisUrl.startsWith('rediss://') ? 'rediss' : 'redis',
      tlsCertificateVerification: config.redisUrl.startsWith('rediss://'),
    },
  ];
}

function logStartupCheck(check) {
  console.info('[LIVE_GATEWAY_STARTUP_CHECK]', JSON.stringify(check));
}

async function readBody(request) {
  const contentLength = Number(request.headers['content-length'] || 0);
  if (contentLength > MAX_BODY_BYTES) {
    request.resume();
    const error = new Error('Request body is too large.');
    error.statusCode = 413;
    throw error;
  }

  const chunks = [];
  let size = 0;
  let tooLarge = false;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > MAX_BODY_BYTES) {
      tooLarge = true;
      chunks.length = 0;
    } else if (!tooLarge) {
      chunks.push(chunk);
    }
  }

  if (tooLarge) {
    const error = new Error('Request body is too large.');
    error.statusCode = 413;
    throw error;
  }
  return Buffer.concat(chunks).toString('utf8');
}

function validatePayload(payload, now, systemInstructionHashes) {
  const constraints = payload?.liveConnectConstraints;
  const config = constraints?.config;
  const expiration = Date.parse(payload?.expireTime);
  const newSessionExpiration = Date.parse(payload?.newSessionExpireTime);
  if (!Number.isFinite(expiration)
    || !Number.isFinite(newSessionExpiration)
    || typeof constraints?.model !== 'string'
    || !APPROVED_LIVE_MODELS.has(constraints.model)
    || !config
    || typeof config !== 'object'
    || Array.isArray(config)
    || !Array.isArray(config.responseModalities)
    || config.responseModalities.length !== 1
    || config.responseModalities[0] !== 'AUDIO'
    || typeof config.systemInstruction !== 'string'
    || !config.systemInstruction.trim()
    || config.systemInstruction.length > 48_000) {
    return false;
  }
  const instructionHash = createHash('sha256')
    .update(config.systemInstruction, 'utf8')
    .digest();
  const instructionIsApproved = systemInstructionHashes.some((hash) =>
    timingSafeEqual(Buffer.from(hash, 'hex'), instructionHash)
  );
  return instructionIsApproved
    && expiration > now
    && expiration <= now + 31 * 60_000
    && newSessionExpiration > now
    && newSessionExpiration <= now + MAX_NEW_SESSION_WINDOW_MS
    && newSessionExpiration <= expiration;
}

function createGatewayServer({
  redis,
  createToken,
  secret,
  previousSecret = '',
  systemInstructionHashes,
  projectId = 'test-project',
  maxConcurrent = 5,
  requestsPerMinute = 60,
  quotaCooldownMs = 60_000,
  providerTimeoutMs = PROVIDER_TIMEOUT_MS,
  now = Date.now,
}) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) {
    throw new Error('KIARA_GATEWAY_HMAC_SECRET must contain at least 32 bytes.');
  }
  if (previousSecret && Buffer.byteLength(previousSecret) < 32) {
    throw new Error('KIARA_GATEWAY_HMAC_PREVIOUS_SECRET must contain at least 32 bytes.');
  }
  if (!Number.isInteger(maxConcurrent) || maxConcurrent < 1 || maxConcurrent > 500) {
    throw new Error('KIARA_GATEWAY_MAX_CONCURRENT must be between 1 and 500.');
  }
  if (!Number.isInteger(requestsPerMinute) || requestsPerMinute < 1 || requestsPerMinute > 1_000_000) {
    throw new Error('KIARA_PROJECT_REQUESTS_PER_MINUTE must be between 1 and 1000000.');
  }
  if (!Number.isInteger(quotaCooldownMs) || quotaCooldownMs < 1000 || quotaCooldownMs > 24 * 60 * 60 * 1000) {
    throw new Error('KIARA_PROJECT_QUOTA_COOLDOWN_MS must be between 1000 and 86400000.');
  }
  if (!Number.isInteger(providerTimeoutMs) || providerTimeoutMs < 1000 || providerTimeoutMs > 30_000) {
    throw new Error('KIARA_GATEWAY_PROVIDER_TIMEOUT_MS must be between 1000 and 30000.');
  }
  if (!redis || typeof redis.set !== 'function' || typeof redis.eval !== 'function') {
    throw new TypeError('A connected Redis client with EVAL support is required.');
  }
  if (typeof createToken !== 'function') {
    throw new TypeError('A Live token provider function is required.');
  }
  if (
    !Array.isArray(systemInstructionHashes)
    || !systemInstructionHashes.length
    || systemInstructionHashes.some((hash) => !/^[0-9a-f]{64}$/i.test(hash))
  ) {
    throw new Error('At least one valid KIARA_LIVE_SYSTEM_INSTRUCTION_SHA256 hash is required.');
  }

  const admission = createProjectAdmission({
    redis,
    projectId,
    maxConcurrent,
    requestsPerMinute,
    now,
  });
  const providerLeaseTtlMs = providerTimeoutMs + PROVIDER_LEASE_BUFFER_MS;
  let activeRequests = 0;

  const server = http.createServer({ maxHeaderSize: 8 * 1024 }, async (request, response) => {
    const pathname = new URL(request.url, 'http://localhost').pathname;
    if (request.method === 'GET' && pathname === '/healthz') {
      sendJson(response, redis.isReady === false ? 503 : 200, {
        status: redis.isReady === false ? 'unavailable' : 'ok',
      });
      return;
    }

    if (request.method !== 'POST' || pathname !== '/internal/v1/live-token') {
      sendJson(response, 404, { error: 'Not found.' });
      return;
    }
    const requestStartedAt = performance.now();
    const controller = new AbortController();
    const abortWhenDisconnected = () => controller.abort();
    request.once('aborted', abortWhenDisconnected);
    response.once('close', () => {
      if (!response.writableEnded) abortWhenDisconnected();
    });
    if (redis.isReady === false) {
      sendJson(response, 503, { error: 'Gateway replay protection is unavailable.' });
      return;
    }
    if (!String(request.headers['content-type'] || '').toLowerCase().startsWith('application/json')) {
      sendJson(response, 415, { error: 'Content-Type must be application/json.' });
      return;
    }

    let rawBody;
    try {
      rawBody = await readBody(request);
    } catch (error) {
      sendJson(response, error.statusCode || 400, { error: error.message });
      return;
    }

    const timestamp = String(request.headers['x-kiara-timestamp'] || '');
    const nonce = String(request.headers['x-kiara-nonce'] || '');
    const signature = String(request.headers['x-kiara-signature'] || '');
    if (!signatureIsValid(
      [secret, previousSecret],
      timestamp,
      nonce,
      rawBody,
      signature,
      now(),
    )) {
      sendJson(response, 401, { error: 'Gateway request authentication failed.' });
      return;
    }

    try {
      const replayAccepted = await redis.set(
        `kiara:live-gateway:nonce:${nonce}`,
        '1',
        { NX: true, EX: NONCE_TTL_SECONDS }
      );
      if (replayAccepted !== 'OK') {
        sendJson(response, 409, { error: 'Gateway request has already been used.' });
        return;
      }
      if (controller.signal.aborted) return;
    } catch (error) {
      console.error('[LIVE_GATEWAY_REPLAY_STORE_FAILURE]', JSON.stringify({
        errorCode: String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80),
      }));
      sendJson(response, 503, { error: 'Gateway replay protection is unavailable.' });
      return;
    }

    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch {
      sendJson(response, 400, { error: 'Request body must be valid JSON.' });
      return;
    }
    if (!validatePayload(payload, now(), systemInstructionHashes)) {
      sendJson(response, 400, { error: 'Live token request is invalid.' });
      return;
    }
    if (activeRequests >= maxConcurrent) {
      sendJson(response, 503, { error: 'Live token gateway is at capacity.' }, {
        'retry-after': '1',
      });
      return;
    }

    let permit;
    try {
      permit = await admission.acquire(providerLeaseTtlMs);
    } catch (error) {
      console.error('[LIVE_GATEWAY_ADMISSION_FAILURE]', JSON.stringify({
        errorCode: String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80),
      }));
      sendJson(response, 503, { error: 'Live token gateway admission is unavailable.' });
      return;
    }
    if (!permit.acquired) {
      const rateLimited = permit.reason === 'project_cooldown'
        || permit.reason === 'project_rate_limit';
      sendJson(response, rateLimited ? 429 : 503, {
        error: permit.reason === 'project_cooldown'
          ? 'Gemini project quota is temporarily cooling down.'
          : permit.reason === 'project_rate_limit'
            ? 'Gemini project request capacity is temporarily exhausted.'
            : 'Live token gateway is at project concurrency capacity.',
        code: permit.reason,
      }, rateLimited ? {
        'retry-after': String(Math.max(1, Math.ceil(permit.retryAfterMs / 1000))),
      } : { 'retry-after': '1' });
      console.info('[LIVE_GATEWAY_ADMISSION_REJECTED]', JSON.stringify({
        reason: permit.reason,
        statusCode: rateLimited ? 429 : 503,
      }));
      return;
    }
    if (controller.signal.aborted) {
      try {
        await admission.release(permit.requestId);
      } catch (error) {
        console.error('[LIVE_GATEWAY_LEASE_RELEASE_FAILURE]', JSON.stringify({
          errorCode: String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80),
        }));
      }
      return;
    }

    activeRequests += 1;
    let timeout;
    let timedOut = false;
    try {
      const providerPromise = Promise.resolve().then(() =>
        createToken(payload, controller.signal)
      );
      const timeoutPromise = new Promise((resolve, reject) => {
        timeout = setTimeout(() => {
          const error = new Error('Gemini Live token provider timed out.');
          error.code = 'GATEWAY_PROVIDER_TIMEOUT';
          error.statusCode = 504;
          timedOut = true;
          controller.abort();
          reject(error);
        }, providerTimeoutMs);
      });
      const result = await Promise.race([providerPromise, timeoutPromise]);
      if ((!controller.signal.aborted || timedOut) && !response.destroyed) {
        if (typeof result?.name !== 'string' || !result.name) {
          sendJson(response, 502, { error: 'Live token provider returned an invalid response.' });
        } else {
          sendJson(response, 200, { token: result.name });
          console.info('[LIVE_GATEWAY_TOKEN_ISSUED]', JSON.stringify({
            durationMs: Math.round(performance.now() - requestStartedAt),
          }));
        }
      }
    } catch (error) {
      if ((!controller.signal.aborted || timedOut) && !response.destroyed) {
        const classified = classifyProviderError(error);
        let responseCode = classified.code;
        let statusCode = classified.statusCode;
        if (responseCode === 'PROJECT_QUOTA_EXCEEDED') {
          try {
            await admission.startQuotaCooldown(quotaCooldownMs);
          } catch (cooldownError) {
            console.error('[LIVE_GATEWAY_QUOTA_COOLDOWN_FAILURE]', JSON.stringify({
              errorCode: String(cooldownError?.code || cooldownError?.name || 'REDIS_ERROR').slice(0, 80),
            }));
            responseCode = 'PROJECT_QUOTA_STATE_UNAVAILABLE';
            statusCode = 503;
          }
        }
        console.error('[LIVE_GATEWAY_PROVIDER_FAILURE]', JSON.stringify({
          errorCode: responseCode,
          statusCode: classified.statusCode,
          providerErrorName: typeof error?.name === 'string'
            ? error.name.slice(0, 80)
            : null,
          providerErrorCode: typeof error?.code === 'string'
            ? error.code.slice(0, 80)
            : null,
          providerCauseName: typeof error?.cause?.name === 'string'
            ? error.cause.name.slice(0, 80)
            : null,
          providerCauseCode: typeof error?.cause?.code === 'string'
            ? error.cause.code.slice(0, 80)
            : null,
        }));
        if (!response.destroyed) {
          sendJson(response, statusCode, {
            error: responseCode === 'PROJECT_QUOTA_EXCEEDED'
              ? 'Gemini project quota is temporarily unavailable.'
              : responseCode === 'PROVIDER_TIMEOUT'
                ? 'Gemini Live token provider timed out.'
                : 'Live token provider could not create a token.',
            code: responseCode,
          }, responseCode === 'PROJECT_QUOTA_EXCEEDED' ? {
            'retry-after': String(Math.max(1, Math.ceil(quotaCooldownMs / 1000))),
          } : {});
        }
      }
    } finally {
      clearTimeout(timeout);
      activeRequests -= 1;
      request.removeListener('aborted', abortWhenDisconnected);
      try {
        await admission.release(permit.requestId);
      } catch (error) {
        console.error('[LIVE_GATEWAY_LEASE_RELEASE_FAILURE]', JSON.stringify({
          errorCode: String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80),
        }));
      }
    }
  });
  server.requestTimeout = 12_000;
  server.headersTimeout = 10_000;
  server.keepAliveTimeout = 5_000;
  return server;
}

async function start() {
  const config = loadGatewayConfig(process.env);
  const startupChecks = getStartupChecks(config);
  for (const check of startupChecks) logStartupCheck(check);

  const redis = createClient(createRedisClientOptions(config));
  redis.on('error', (error) => {
    console.error('[LIVE_GATEWAY_REDIS_ERROR]', JSON.stringify({
      errorCode: String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80),
    }));
  });
  try {
    await redis.connect();
    await redis.ping();
    logStartupCheck({
      check: 'redis',
      status: 'connected',
      protocol: config.redisUrl.startsWith('rediss://') ? 'rediss' : 'redis',
      tlsCertificateVerification: config.redisUrl.startsWith('rediss://'),
      ping: 'passed',
    });
  } catch (error) {
    logStartupCheck({
      check: 'redis',
      status: 'failed',
      errorCode: String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80),
    });
    throw new Error(
      `Could not connect to gateway Redis (${String(error?.code || error?.name || 'REDIS_ERROR').slice(0, 80)}).`,
    );
  }

  const server = createGatewayServer({
    redis,
    secret: config.secret,
    previousSecret: config.previousSecret,
    systemInstructionHashes: config.systemInstructionHashes,
    projectId: config.projectId,
    maxConcurrent: config.maxConcurrent,
    requestsPerMinute: config.requestsPerMinute,
    quotaCooldownMs: config.quotaCooldownMs,
    providerTimeoutMs: config.providerTimeoutMs,
    createToken: createGeminiTokenProvider({ credentials: config.credentials, redis }),
  });

  try {
    await new Promise((resolve, reject) => {
      server.once('error', reject);
      server.listen(config.port, config.host, () => {
        server.removeListener('error', reject);
        logStartupCheck({
          check: 'http_listener',
          status: 'listening',
          host: config.host,
          port: config.port,
        });
        console.info('[LIVE_GATEWAY_READY]', JSON.stringify({
          environment: config.nodeEnv,
          host: config.host,
          port: config.port,
        }));
        resolve();
      });
    });
  } catch (error) {
    await redis.quit();
    logStartupCheck({
      check: 'http_listener',
      status: 'failed',
      errorCode: String(error?.code || error?.name || 'LISTEN_ERROR').slice(0, 80),
    });
    throw new Error(
      `Could not listen on the configured gateway address (${String(error?.code || error?.name || 'LISTEN_ERROR').slice(0, 80)}).`,
    );
  }

  const shutdown = async () => {
    await new Promise((resolve, reject) => {
      server.close((error) => {
        if (error) reject(error);
        else resolve();
      });
    });
    await redis.quit();
  };
  for (const signal of ['SIGINT', 'SIGTERM']) {
    process.once(signal, () => {
      shutdown().catch((error) => {
        console.error('[LIVE_GATEWAY_SHUTDOWN_FAILED]', JSON.stringify({
          errorCode: String(error?.code || error?.name || 'SHUTDOWN_ERROR').slice(0, 80),
        }));
        process.exitCode = 1;
      });
    });
  }
}

if (require.main === module) {
  let environmentLoadFailed = false;
  try {
    loadLocalEnvironment();
  } catch (error) {
    environmentLoadFailed = true;
    console.error('[LIVE_GATEWAY_STARTUP_FAILED]', JSON.stringify({
      errorCode: String(error?.code || error?.name || 'ENV_FILE_ERROR').slice(0, 80),
      message: 'Could not load the local environment file.',
    }));
    process.exitCode = 1;
  }
  if (!environmentLoadFailed) {
    start().catch((error) => {
      console.error('[LIVE_GATEWAY_STARTUP_FAILED]', JSON.stringify({
        errorCode: String(error?.code || error?.name || 'STARTUP_ERROR').slice(0, 80),
        message: String(error?.message || 'Gateway startup failed.').slice(0, 200),
      }));
      process.exitCode = 1;
    });
  }
}

module.exports = {
  createGatewayServer,
  getStartupChecks,
  signRequest,
  signatureIsValid,
};
