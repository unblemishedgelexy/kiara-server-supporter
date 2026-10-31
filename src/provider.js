'use strict';

const { GoogleGenAI } = require('@google/genai');
const { CREDENTIAL_SLOT_COUNT } = require('./credentials');

const INVALID_CREDENTIAL_STATUS = 401;
const DISABLED_CREDENTIAL_TTL_SECONDS = 24 * 60 * 60;

function getProviderStatus(error) {
  const candidates = [
    error?.statusCode,
    error?.status,
    error?.response?.status,
    error?.error?.code,
  ];
  for (const candidate of candidates) {
    const status = Number(candidate);
    if (Number.isInteger(status) && status >= 100 && status <= 599) return status;
  }
  return null;
}

function classifyProviderError(error) {
  const status = getProviderStatus(error);
  if (status === 400) return { code: 'PROVIDER_INVALID_REQUEST', statusCode: 502 };
  if (status === 401) return { code: 'PROVIDER_INVALID_CREDENTIAL', statusCode: 502 };
  if (status === 403) return { code: 'PROVIDER_PERMISSION_DENIED', statusCode: 502 };
  if (status === 404) return { code: 'PROVIDER_MODEL_NOT_FOUND', statusCode: 502 };
  if (status === 429) return { code: 'PROJECT_QUOTA_EXCEEDED', statusCode: 429 };
  if ([500, 502, 503].includes(status)) {
    return { code: 'PROVIDER_UNAVAILABLE', statusCode: 503 };
  }
  if (status === 504 || error?.code === 'GATEWAY_PROVIDER_TIMEOUT') {
    return { code: 'PROVIDER_TIMEOUT', statusCode: 504 };
  }
  if (error?.name === 'AbortError') {
    return { code: 'PROVIDER_REQUEST_ABORTED', statusCode: 503 };
  }
  return { code: 'PROVIDER_NETWORK_ERROR', statusCode: 503 };
}

function createGeminiTokenProvider({
  credentials,
  redis,
  apiVersion = 'v1alpha',
  createClient = (apiKey) => new GoogleGenAI({
    apiKey,
    httpOptions: { apiVersion },
  }),
}) {
  if (!credentials || typeof credentials.getNext !== 'function') {
    throw new TypeError('A validated Gemini credential pool is required.');
  }
  if (!redis || typeof redis.get !== 'function' || typeof redis.set !== 'function') {
    throw new TypeError('A connected Redis client is required for credential state.');
  }

  const disabledKey = (credential) =>
    `kiara:live-gateway:credential-disabled:${credential.slot}:${credential.fingerprint}`;

  return async function createToken(payload, signal) {
    const skipped = new Set();
    const maxSlots = Math.min(credentials.count, CREDENTIAL_SLOT_COUNT);

    while (skipped.size < maxSlots) {
      const credential = credentials.getNext(skipped);
      if (!credential) break;

      const disabled = await redis.get(disabledKey(credential));
      if (disabled) {
        skipped.add(credential.fingerprint);
        continue;
      }

      try {
        const client = createClient(credential.key, credential.slot);
        return await client.authTokens.create({
          config: {
            uses: 1,
            expireTime: payload.expireTime,
            newSessionExpireTime: payload.newSessionExpireTime,
            abortSignal: signal,
            liveConnectConstraints: payload.liveConnectConstraints,
          },
        });
      } catch (error) {
        if (getProviderStatus(error) !== INVALID_CREDENTIAL_STATUS) throw error;

        credentials.disable(
          credential.fingerprint,
          DISABLED_CREDENTIAL_TTL_SECONDS * 1000,
        );
        await redis.set(disabledKey(credential), '1', {
          EX: DISABLED_CREDENTIAL_TTL_SECONDS,
        });
        const invalidCredentialError = new Error('Configured Gemini credential was rejected.');
        invalidCredentialError.code = 'PROVIDER_INVALID_CREDENTIAL';
        invalidCredentialError.statusCode = 502;
        throw invalidCredentialError;
      }
    }

    const error = new Error('No enabled Gemini credentials are available.');
    error.code = 'NO_VALID_GEMINI_CREDENTIALS';
    error.statusCode = 503;
    throw error;
  };
}

module.exports = {
  classifyProviderError,
  createGeminiTokenProvider,
  getProviderStatus,
};
