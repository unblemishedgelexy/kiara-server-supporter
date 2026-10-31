'use strict';

const fs = require('node:fs');
const path = require('node:path');
const dotenv = require('dotenv');

const LOCAL_ENV_FILE = path.resolve(__dirname, '..', '.env');

function loadLocalEnvironment(environment = process.env, envFile = LOCAL_ENV_FILE) {
  if (environment.NODE_ENV === 'production') return;

  let parsed;
  try {
    parsed = dotenv.parse(fs.readFileSync(envFile));
  } catch (error) {
    if (error.code === 'ENOENT') return;
    throw error;
  }

  if (!environment.NODE_ENV && parsed.NODE_ENV === 'production') return;

  for (const [name, value] of Object.entries(parsed)) {
    if (environment[name] === undefined) environment[name] = value;
  }
}

module.exports = { loadLocalEnvironment };
