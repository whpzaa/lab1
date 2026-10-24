function parseInteger(value, name, fallback, minimum, maximum) {
  if (value === undefined || value === '') {
    return fallback;
  }

  const parsed = Number(value);
  if (!Number.isInteger(parsed) || parsed < minimum || parsed > maximum) {
    throw new Error(`${name} must be an integer between ${minimum} and ${maximum}`);
  }

  return parsed;
}

export function loadConfig(env = process.env) {
  const jwtSecret = env.JWT_SECRET;
  if (typeof jwtSecret !== 'string' || jwtSecret.length < 32) {
    throw new Error('JWT_SECRET must be set and contain at least 32 characters');
  }

  return {
    port: parseInteger(env.PORT, 'PORT', 3000, 1, 65535),
    databasePath: env.DATABASE_PATH || 'data/app.db',
    jwtSecret,
    jwtIssuer: 'hdu-is-lab1-secure-api',
    jwtAudience: 'hdu-is-lab1-client',
    jwtTtl: env.JWT_TTL || '15m',
    bcryptRounds: parseInteger(env.BCRYPT_ROUNDS, 'BCRYPT_ROUNDS', 12, 4, 15)
  };
}
