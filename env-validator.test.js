/**
 * env-validator.test.js
 * ─────────────────────────────────────────────────────────────────
 * Jest — [SEC-001] Validación de variables de entorno
 * Ejecutar: npx jest env-validator.test.js
 *
 * Cobertura:
 *  ✅ Happy path (todas las vars presentes y válidas)
 *  🚨 Vars requeridas ausentes
 *  🚨 Fallbacks peligrosos conocidos
 *  ⚠️  Vars opcionales ausentes (warn, no error)
 *  ⚠️  Secretos débiles (< 32 chars)
 */

'use strict';

const { validateEnv } = require('./env-validator');

// ─── Suprimir console durante tests ──────────────────────────────
// Sin esto Jest reporta el log de cada validación y ensucia la salida.
beforeAll(() => {
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterAll(() => {
  jest.restoreAllMocks();
});

// ─── Helper: set env vars temporalmente ──────────────────────────
/**
 * Ejecuta fn() con un conjunto de env vars sobreescritas.
 * Restaura el estado original (incluyendo vars que no existían) al terminar.
 *
 * @param {Object} vars - { VAR_NAME: 'value' | undefined }
 *   undefined = eliminar la var durante el test
 * @param {Function} fn - función a ejecutar con el env modificado
 */
function withEnv(vars, fn) {
  const original = {};

  // Guardar estado original
  Object.keys(vars).forEach(k => {
    // process.env[k] devuelve undefined si no existe — lo manejamos en finally
    original[k] = process.env[k];
    if (vars[k] === undefined) {
      delete process.env[k];
    } else {
      process.env[k] = vars[k];
    }
  });

  try {
    return fn();
  } finally {
    // Restaurar: si el original era undefined, eliminar la key en vez de poner "undefined"
    Object.keys(vars).forEach(k => {
      if (original[k] === undefined) {
        delete process.env[k];
      } else {
        process.env[k] = original[k];
      }
    });
  }
}

// ─── Entorno válido de referencia ────────────────────────────────
const VALID_ENV = {
  JWT_SECRET:          'super-secreto-de-al-menos-32-caracteres-ok!!',
  MONGODB_URI:         'mongodb+srv://user:pass@cluster.mongodb.net/iqu_telecom',
  NEBULA_AGENT_SECRET: 'nebula-secreto-real-de-al-menos-32-chars-xx',
};

// ─── Tests ───────────────────────────────────────────────────────
describe('[SEC-001] env-validator', () => {

  // ── Happy path ─────────────────────────────────────────────────
  describe('Happy path', () => {
    test('✅ Pasa con todas las vars requeridas presentes y válidas', () => {
      withEnv(VALID_ENV, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result.valid).toBe(true);
        expect(result.errors).toHaveLength(0);
      });
    });

    test('✅ Retorna { valid, errors, warnings } con la forma correcta', () => {
      withEnv(VALID_ENV, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result).toHaveProperty('valid');
        expect(result).toHaveProperty('errors');
        expect(result).toHaveProperty('warnings');
        expect(Array.isArray(result.errors)).toBe(true);
        expect(Array.isArray(result.warnings)).toBe(true);
      });
    });
  });

  // ── Vars requeridas ausentes ────────────────────────────────────
  describe('Vars requeridas — ausentes', () => {
    test('🚨 Falla si JWT_SECRET está ausente', () => {
      withEnv({ ...VALID_ENV, JWT_SECRET: undefined }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow();
      });
    });

    test('🚨 Falla si MONGODB_URI está ausente', () => {
      withEnv({ ...VALID_ENV, MONGODB_URI: undefined }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow();
      });
    });

    test('🚨 Falla si NEBULA_AGENT_SECRET está ausente', () => {
      withEnv({ ...VALID_ENV, NEBULA_AGENT_SECRET: undefined }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow();
      });
    });

    test('🚨 Falla si las 3 vars requeridas están ausentes', () => {
      withEnv({
        JWT_SECRET:          undefined,
        MONGODB_URI:         undefined,
        NEBULA_AGENT_SECRET: undefined,
      }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow();
      });
    });

    test('🚨 Falla si JWT_SECRET es string vacío', () => {
      withEnv({ ...VALID_ENV, JWT_SECRET: '' }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow();
      });
    });
  });

  // ── Fallbacks peligrosos ────────────────────────────────────────
  describe('Fallbacks peligrosos conocidos', () => {
    test('🚨 Falla si JWT_SECRET es el fallback "dev-secret"', () => {
      withEnv({ ...VALID_ENV, JWT_SECRET: 'dev-secret' }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow(/VALOR INSEGURO/);
      });
    });

    test('🚨 Falla si JWT_SECRET es "secret"', () => {
      withEnv({ ...VALID_ENV, JWT_SECRET: 'secret' }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow(/VALOR INSEGURO/);
      });
    });

    test('🚨 Falla si NEBULA_AGENT_SECRET es el fallback hardcodeado', () => {
      withEnv({ ...VALID_ENV, NEBULA_AGENT_SECRET: 'fallback-inseguro-hardcodeado' }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow(/VALOR INSEGURO/);
      });
    });

    test('🚨 Falla si NEBULA_AGENT_SECRET es "nebula-secret"', () => {
      withEnv({ ...VALID_ENV, NEBULA_AGENT_SECRET: 'nebula-secret' }, () => {
        expect(() => validateEnv({ exitOnError: false })).toThrow(/VALOR INSEGURO/);
      });
    });
  });

  // ── Vars opcionales ─────────────────────────────────────────────
  describe('Vars opcionales — warn pero no error', () => {
    test('⚠️  Warn (no error) si PORT está ausente', () => {
      withEnv({ ...VALID_ENV, PORT: undefined }, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result.valid).toBe(true);
        expect(result.warnings.some(w => w.includes('PORT'))).toBe(true);
      });
    });

    test('⚠️  Warn (no error) si GROQ_API_KEY está ausente', () => {
      withEnv({ ...VALID_ENV, GROQ_API_KEY: undefined }, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result.valid).toBe(true);
        // GROQ es opcional — debe aparecer en warnings o simplemente no bloquear
      });
    });
  });

  // ── Secretos débiles ────────────────────────────────────────────
  describe('Secretos débiles (< 32 chars)', () => {
    test('⚠️  Warn si JWT_SECRET tiene menos de 32 chars (no es error)', () => {
      withEnv({ ...VALID_ENV, JWT_SECRET: 'corto_menos_32_chars_aqui' }, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result.valid).toBe(true); // no es un error, solo advertencia
        expect(result.warnings.some(w => w.includes('SECRETO DÉBIL'))).toBe(true);
      });
    });

    test('⚠️  Warn si NEBULA_AGENT_SECRET tiene menos de 32 chars', () => {
      withEnv({ ...VALID_ENV, NEBULA_AGENT_SECRET: 'nebula-corto' }, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result.valid).toBe(true);
        expect(result.warnings.some(w => w.includes('SECRETO DÉBIL'))).toBe(true);
      });
    });

    test('✅ No warn si los secretos tienen exactamente 32 chars', () => {
      withEnv({
        ...VALID_ENV,
        JWT_SECRET:          '12345678901234567890123456789012', // exactamente 32
        NEBULA_AGENT_SECRET: '12345678901234567890123456789012',
      }, () => {
        const result = validateEnv({ exitOnError: false });
        expect(result.valid).toBe(true);
        expect(result.warnings.every(w => !w.includes('SECRETO DÉBIL'))).toBe(true);
      });
    });
  });

  // ── Modo exitOnError (default) ──────────────────────────────────
  describe('Modo exitOnError (comportamiento producción)', () => {
    test('🛑 exitOnError:true llama process.exit(1) si hay errores', () => {
      // Mockeamos process.exit para no terminar el proceso de Jest
      const mockExit = jest.spyOn(process, 'exit').mockImplementation(() => {
        throw new Error('process.exit llamado'); // para que Jest pueda capturarlo
      });

      withEnv({ ...VALID_ENV, JWT_SECRET: undefined }, () => {
        expect(() => validateEnv({ exitOnError: true })).toThrow('process.exit llamado');
      });

      mockExit.mockRestore();
    });
  });
});
