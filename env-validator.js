/**
 * env-validator.js
 * ─────────────────────────────────────────────────────────────────
 * Validación FAIL-FAST de variables de entorno al arranque.
 * Importar ANTES de cualquier otra lógica en server.js.
 *
 * Patrón:
 *   - REQUIRED: faltante → log de error explícito → process.exit(1)
 *   - OPTIONAL: faltante → WARN en log, usa default seguro
 *   - DANGEROUS_FALLBACK: si detecta valor de fallback conocido → exit(1)
 *
 * @module env-validator
 */

'use strict';

// ─── Definición de variables ──────────────────────────────────────

/**
 * Variables REQUERIDAS. Si alguna falta, el servidor NO arranca.
 * Cada entrada: { name, description, dangerousFallbacks? }
 */
const REQUIRED_VARS = [
  {
    name: 'JWT_SECRET',
    description: 'Clave secreta para firmar tokens JWT',
    // Si se detecta alguno de estos valores, se trata como ausente/inseguro
    dangerousFallbacks: ['dev-secret', 'secret', 'changeme', 'jwt-secret', 'mysecret']
  },
  {
    name: 'MONGODB_URI',
    description: 'URI de conexión a MongoDB Atlas'
  },
  {
    name: 'NEBULA_AGENT_SECRET',
    description: 'Secreto compartido para autenticación de agentes Nebula',
    dangerousFallbacks: [
      'nebula-secret',
      'fallback-inseguro-hardcodeado',
      'nebula-agent-secret',
      'secret123',
      'changeme'
    ]
  }
];

/**
 * Variables OPCIONALES con defaults seguros.
 * Faltantes generan WARN pero no detienen el arranque.
 */
const OPTIONAL_VARS = [
  { name: 'PORT',              default: '3000',  description: 'Puerto HTTP del servidor' },
  { name: 'NODE_ENV',          default: 'production', description: 'Entorno de ejecución' },
  { name: 'GOOGLE_SHEETS_KEY', default: null,    description: 'API key Google Sheets (algunas rutas degradadas sin ella)' },
  { name: 'GROQ_API_KEY',      default: null,    description: 'API key Groq para minuta IA (fallback local activo si falta)' },
  { name: 'GEMINI_API_KEY',    default: null,    description: 'API key Gemini fallback (opcional)' },
  { name: 'FRONTEND_URL',      default: '*',     description: 'URL permitida en CORS' },
  { name: 'RENDER_EXTERNAL_URL', default: null,  description: 'URL pública del servicio en Render' }
];

// ─── Validador principal ──────────────────────────────────────────

/**
 * Ejecuta la validación completa de entorno.
 * Llama a process.exit(1) si hay errores críticos.
 * Diseñado para ser idempotente (safe llamarlo múltiples veces en tests).
 *
 * @param {Object} options
 * @param {boolean} options.exitOnError - Si false, lanza Error en vez de exit (útil en tests)
 * @returns {{ valid: boolean, errors: string[], warnings: string[] }}
 */
function validateEnv({ exitOnError = true } = {}) {
  const errors = [];
  const warnings = [];
  const timestamp = new Date().toISOString();

  console.log(`\n[ENV-VALIDATOR] ${timestamp} — Iniciando validación de entorno...`);

  // ── 1. Validar variables requeridas ──────────────────────────────
  for (const varDef of REQUIRED_VARS) {
    const value = process.env[varDef.name];

    if (!value || value.trim() === '') {
      errors.push(`❌ REQUERIDA FALTANTE: ${varDef.name} — ${varDef.description}`);
      continue;
    }

    // Detectar fallbacks peligrosos conocidos
    if (varDef.dangerousFallbacks && varDef.dangerousFallbacks.includes(value.trim())) {
      errors.push(
        `🚨 VALOR INSEGURO DETECTADO: ${varDef.name} = "${value}" ` +
        `— Este valor es un fallback conocido. Configura un secreto real en Render.`
      );
      continue;
    }

    // Validación de longitud mínima para secretos
    if (['JWT_SECRET', 'NEBULA_AGENT_SECRET'].includes(varDef.name) && value.length < 32) {
      warnings.push(
        `⚠️  SECRETO DÉBIL: ${varDef.name} tiene ${value.length} caracteres. ` +
        `Recomendado: ≥ 32 caracteres aleatorios.`
      );
    }

    console.log(`   ✅ ${varDef.name} — OK`);
  }

  // ── 2. Validar variables opcionales ──────────────────────────────
  for (const varDef of OPTIONAL_VARS) {
    const value = process.env[varDef.name];

    if (!value || value.trim() === '') {
      if (varDef.default !== null) {
        // Aplicar default (sin mutación de process.env en producción real,
        // solo logging — el código consumidor debe usar el default explícito)
        warnings.push(
          `⚠️  OPCIONAL FALTANTE: ${varDef.name} — ${varDef.description} ` +
          `(default: "${varDef.default}")`
        );
      } else {
        warnings.push(
          `ℹ️  OPCIONAL AUSENTE: ${varDef.name} — ${varDef.description} ` +
          `(funcionalidad parcialmente degradada)`
        );
      }
    } else {
      console.log(`   ✅ ${varDef.name} — OK`);
    }
  }

  // ── 3. Reporte final ─────────────────────────────────────────────
  if (warnings.length > 0) {
    console.warn('\n[ENV-VALIDATOR] ⚠️  ADVERTENCIAS:');
    warnings.forEach(w => console.warn(`   ${w}`));
  }

  if (errors.length > 0) {
    console.error('\n[ENV-VALIDATOR] 🚨 ERRORES CRÍTICOS — EL SERVIDOR NO PUEDE ARRANCAR:');
    errors.forEach(e => console.error(`   ${e}`));
    console.error(
      '\n[ENV-VALIDATOR] ➡️  Solución: Configura las variables faltantes en el panel de ' +
      'Environment Variables de Render y haz redeploy.\n'
    );

    if (exitOnError) {
      process.exit(1); // Fail-fast: Render mostrará este log antes de marcar el deploy como fallido
    } else {
      throw new Error(`Validación de entorno fallida: ${errors.join(' | ')}`);
    }
  }

  console.log(`[ENV-VALIDATOR] ✅ Validación completada — ${errors.length} errores, ${warnings.length} advertencias.\n`);

  return { valid: errors.length === 0, errors, warnings };
}

// ─── Helpers de acceso seguro ─────────────────────────────────────

/**
 * Obtiene una variable de entorno requerida.
 * Lanza Error si no existe (para uso después de validateEnv()).
 *
 * @param {string} name
 * @returns {string}
 */
function getRequired(name) {
  const value = process.env[name];
  if (!value || value.trim() === '') {
    throw new Error(
      `[ENV] Variable requerida "${name}" no disponible. ` +
      `¿Se llamó validateEnv() al inicio?`
    );
  }
  return value.trim();
}

/**
 * Obtiene una variable de entorno opcional con fallback.
 *
 * @param {string} name
 * @param {string} defaultValue
 * @returns {string}
 */
function getOptional(name, defaultValue = '') {
  const value = process.env[name];
  return (value && value.trim() !== '') ? value.trim() : defaultValue;
}

module.exports = { validateEnv, getRequired, getOptional };
