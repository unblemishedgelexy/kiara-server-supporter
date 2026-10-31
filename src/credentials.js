'use strict';

const { createHash } = require('node:crypto');

const CREDENTIAL_SLOT_COUNT = 10;
const GOOGLE_API_KEY_PATTERNS = [
  /^AIza[A-Za-z0-9_-]{20,}$/,
  /^AQ\.[A-Za-z0-9_-]{20,}$/,
];

function createCredentialPool(environment) {
  const credentials = [];
  const seenFingerprints = new Set();

  for (let slot = 1; slot <= CREDENTIAL_SLOT_COUNT; slot += 1) {
    const keyName = `GEMINI_API_KEY_${slot}`;
    const key = String(
      environment[keyName] || (slot === 1 ? environment.GEMINI_API_KEY : '') || ''
    ).trim();
    const enabledName = `GEMINI_CREDENTIAL_${slot}_ENABLED`;
    const enabledSetting = environment[enabledName];
    if (
      enabledSetting !== undefined
      && !['true', 'false'].includes(String(enabledSetting).toLowerCase())
    ) {
      throw new Error(`${enabledName} must be true or false.`);
    }
    const enabled = enabledSetting === undefined
      ? Boolean(key)
      : String(enabledSetting).toLowerCase() === 'true';

    if (!enabled) continue;
    if (!key) {
      throw new Error(`${enabledName} is true but ${keyName} is not configured.`);
    }
    if (!GOOGLE_API_KEY_PATTERNS.some((pattern) => pattern.test(key))) {
      throw new Error(`${keyName} has an invalid Google API key format.`);
    }

    const fingerprint = createHash('sha256').update(key).digest('hex');
    if (seenFingerprints.has(fingerprint)) {
      throw new Error('Gemini credential slots must contain unique API keys.');
    }
    seenFingerprints.add(fingerprint);
    credentials.push({ slot, key, fingerprint });
  }

  if (!credentials.length) {
    throw new Error('At least one enabled Gemini credential slot is required.');
  }

  let nextIndex = 0;
  const locallyDisabled = new Map();

  return {
    count: credentials.length,
    disable(fingerprint, ttlMs) {
      if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
        throw new Error('Credential disable duration must be positive.');
      }
      locallyDisabled.set(fingerprint, Date.now() + ttlMs);
    },
    getNext(disabledFingerprints = new Set()) {
      const currentTime = Date.now();
      for (const [fingerprint, disabledUntil] of locallyDisabled) {
        if (disabledUntil <= currentTime) locallyDisabled.delete(fingerprint);
      }

      for (let offset = 0; offset < credentials.length; offset += 1) {
        const index = (nextIndex + offset) % credentials.length;
        const credential = credentials[index];
        if (
          !locallyDisabled.has(credential.fingerprint)
          && !disabledFingerprints.has(credential.fingerprint)
        ) {
          nextIndex = (index + 1) % credentials.length;
          return credential;
        }
      }
      return null;
    },
    get credentials() {
      return credentials.map(({ slot, fingerprint }) => ({ slot, fingerprint }));
    },
  };
}

module.exports = {
  CREDENTIAL_SLOT_COUNT,
  createCredentialPool,
};
