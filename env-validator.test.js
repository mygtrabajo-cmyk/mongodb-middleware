/**
 * env-validator.test.js
 * Jest — ejecutar con: npx jest env-validator.test.js
 */
const { validateEnv } = require('./env-validator');

// Helper: set env vars temporalmente
function withEnv(vars, fn) {
  const original = {};
  Object.keys(vars).forEach(k => {
    original[k] = process.env[k];
    if (vars[k] === undefined) delete process.env[k];
    else process.env[k] = vars[k];
  });
  try { return fn(); }
  finally {
    Object.keys(vars).forEach(k => {
      if (original[k] === undefined) delete process.env[k];
      else process.env[k] = original[k];
    });
  }
}

const VALID_ENV = {
  JWT_SECRET: 'super-secreto-de-al-menos-32-caracteres-ok!!',
  MONGODB_URI: 'mongodb+srv://user:pass@cluster.mongodb.net/iqu_telecom',
  NEBULA_AGENT_SECRET: 'nebula-secreto-real-de-al-menos-32-chars-xx'
};

describe('[SEC-001] env-validator', () => {
  test('✅ Pasa con todas las vars requeridas presentes', () => {
    withEnv(VALID_ENV, () => {
      const result = validateEnv({ exitOnError: false });
      expect(result.valid).toBe(true);
      expect(result.errors).toHaveLength(0);
    });
  });

  test('🚨 Falla si JWT_SECRET está ausente', () => {
    withEnv({ ...VALID_ENV, JWT_SECRET: undefined }, () => {
      expect(() => validateEnv({ exitOnError: false })).toThrow();
    });
  });

  test('🚨 Falla si JWT_SECRET es fallback conocido', () => {
    withEnv({ ...VALID_ENV, JWT_SECRET: 'dev-secret' }, () => {
      expect(() => validateEnv({ exitOnError: false })).toThrow(/VALOR INSEGURO/);
    });
  });

  test('🚨 Falla si NEBULA_AGENT_SECRET es fallback hardcodeado', () => {
    withEnv({ ...VALID_ENV, NEBULA_AGENT_SECRET: 'fallback-inseguro-hardcodeado' }, () => {
      expect(() => validateEnv({ exitOnError: false })).toThrow(/VALOR INSEGURO/);
    });
  });

  test('⚠️  Warn (no error) si PORT está ausente', () => {
    withEnv({ ...VALID_ENV, PORT: undefined }, () => {
      const result = validateEnv({ exitOnError: false });
      expect(result.valid).toBe(true);
      expect(result.warnings.some(w => w.includes('PORT'))).toBe(true);
    });
  });
});
