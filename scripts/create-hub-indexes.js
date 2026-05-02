/**
 * create-hub-indexes.js
 * ─────────────────────────────────────────────────────────────
 * Script de migración — Índices compuestos para expansión Hub
 * ANALISIS_UNIFICADO v4.0 — SEM 1 · Capa 2 MongoDB
 *
 * Ejecución:
 *   node scripts/create-hub-indexes.js
 *
 * Requiere: MONGODB_URI en .env o variable de entorno
 * ─────────────────────────────────────────────────────────────
 */

require('dotenv').config();
const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;
if (!MONGODB_URI) {
    console.error('❌ MONGODB_URI no definida. Verifica tu .env');
    process.exit(1);
}

const DB_NAME = process.env.DB_NAME || 'myg_telecom';

/**
 * Índices a crear:
 * Estrategia: índices compuestos (area + campo de ordenamiento)
 * para que las queries ?area=X sean O(log n) en lugar de O(n).
 */
const INDEX_PLAN = [
    // ── Hub genérico (ya existentes → safe to create again) ──────────
    {
        col: 'hub_messages',
        index: { area: 1, createdAt: -1 },
        opts: { name: 'idx_area_createdAt', background: true },
    },
    {
        col: 'hub_tareas',
        index: { area: 1, status: 1, createdAt: -1 },
        opts: { name: 'idx_area_status_createdAt', background: true },
    },
    {
        col: 'hub_peticiones',
        index: { area: 1, status: 1, createdAt: -1 },
        opts: { name: 'idx_area_status_createdAt', background: true },
    },
    {
        col: 'hub_reuniones',
        index: { area: 1, startTime: -1 },
        opts: { name: 'idx_area_startTime', background: true },
    },
    {
        col: 'hub_anuncios',
        index: { area: 1, createdAt: -1 },
        opts: { name: 'idx_area_createdAt', background: true },
    },
    {
        col: 'hub_asistencia',
        index: { area: 1, fecha: -1 },
        opts: { name: 'idx_area_fecha', background: true },
    },
    {
        col: 'hub_minutas',
        index: { area: 1, createdAt: -1 },
        opts: { name: 'idx_area_createdAt', background: true },
    },
    {
        col: 'hub_recursos',
        index: { area: 1, categoria: 1 },
        opts: { name: 'idx_area_categoria', background: true },
    },
    // ── SEM 2: Mantenimiento ──────────────────────────────────────────
    {
        col: 'hub_mant_ordenes',
        index: { area: 1, status: 1, createdAt: -1 },
        opts: { name: 'idx_area_status_createdAt', background: true },
    },
    {
        col: 'hub_mant_bitacora',
        index: { area: 1, fecha: -1 },
        opts: { name: 'idx_area_fecha', background: true },
    },
    {
        col: 'hub_mant_bitacora',
        index: { equipoId: 1, fecha: -1 },
        opts: { name: 'idx_equipoId_fecha', background: true },
    },
    // ── SEM 3: Logística ─────────────────────────────────────────────
    {
        col: 'hub_log_guias',
        index: { area: 1, status: 1, createdAt: -1 },
        opts: { name: 'idx_area_status_createdAt', background: true },
    },
    {
        col: 'hub_log_inventario',
        index: { area: 1, status: 1, createdAt: -1 },
        opts: { name: 'idx_area_status_createdAt', background: true },
    },
    // ── SEM 4: Crédito ───────────────────────────────────────────────
    {
        col: 'hub_cred_solicitudes',
        index: { area: 1, status: 1, createdAt: -1 },
        opts: { name: 'idx_area_status_createdAt', background: true },
    },
    {
        col: 'hub_cred_casos',
        index: { area: 1, createdAt: -1 },
        opts: { name: 'idx_area_createdAt', background: true },
    },
    // ── Usuarios — para queries de rol/área ──────────────────────────
    {
        col: 'users',
        index: { rol: 1, area: 1 },
        opts: { name: 'idx_rol_area', background: true },
    },
];

async function run() {
    const client = new MongoClient(MONGODB_URI);
    try {
        await client.connect();
        const db = client.db(DB_NAME);
        console.log(`✅ Conectado a MongoDB: ${DB_NAME}`);
        console.log(`📋 Creando ${INDEX_PLAN.length} índices...\n`);

        let created = 0, skipped = 0, errors = 0;

        for (const { col, index, opts } of INDEX_PLAN) {
            try {
                await db.collection(col).createIndex(index, opts);
                console.log(`  ✅ ${col}.${opts.name}`);
                created++;
            } catch (err) {
                if (err.code === 85 || err.code === 86) {
                    // Índice ya existe con distinto nombre o conflicto → skip
                    console.log(`  ⏭️  ${col}.${opts.name} — ya existe (skip)`);
                    skipped++;
                } else {
                    console.error(`  ❌ ${col}.${opts.name} — ${err.message}`);
                    errors++;
                }
            }
        }

        console.log('\n─────────────────────────────────────────');
        console.log(`Creados: ${created} | Saltados: ${skipped} | Errores: ${errors}`);
        if (errors === 0) {
            console.log('✅ Todos los índices listos para la expansión de hubs.');
        } else {
            console.warn('⚠️  Algunos índices fallaron. Revisa los errores arriba.');
        }

    } finally {
        await client.close();
    }
}

run().catch(err => {
    console.error('❌ Error fatal:', err.message);
    process.exit(1);
});
