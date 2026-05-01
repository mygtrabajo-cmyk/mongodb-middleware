// ================================================================
// MYG TELECOM — API SERVER v4.7.0
// Render (Node.js) + MongoDB Atlas
//
// CHANGELOG:
//   v4.5.0: [CAN-1..4] CRUD canales dinámicos → hub_canales
//           [BOL-1..5] CRUD boletines semanales → hub_boletines
//           [BOL-6]   Índice hub_boletines / hub_canales
//   v4.5.2: [BUG-002] POST /api/formatos/generar → BLOB XLSX real (ExcelJS)
//                     GET  /api/formatos/sistemas → lista estática con cache
//                     POST /api/formatos/clear-cache → invalida cache
//                     Access-Control-Expose-Headers para Content-Disposition
//           [BUG-003] POST /api/hc/upload → transacción atómica (driver nativo)
//                     Elimina race condition deleteMany + insertMany sin sesión.
//                     Requiere: let mongoClient (global) + mongoClient = client en connectDB
//           [SEC-004] Helmet — HTTP Security Headers (una sola instancia, bien ordenado)
//   v4.5.3: [PERF-002] TTL index hub_notificaciones → borra docs > 30 días automáticamente
//                      Función crearIndicesTTL() llamada post-conexión en connectDB()
//           [BUG-004]  Email RH fresco desde MongoDB — evita email desactualizado del JWT
//                      POST /api/rh/movimientos consulta db.users para obtener email actual
//   v4.5.4: [BUG-005]  GET /api/rh/movimientos → paginación real con skip/limit/total
//                      Parámetros: page, limit (max 200), tipo, area, estado, desde, hasta
//                      Respuesta: { ok, data, paginacion: { total, page, limit, pages, hasNext, hasPrev } }
//                      Compatible hacia atrás — defaults: page=1, limit=50
//   v4.5.5: [FEAT-003] GET  /api/nebula/umbrales → leer umbrales CPU/RAM/Disco (autenticado)
//                      PATCH /api/nebula/umbrales → guardar umbrales (ADMIN/GERENTE_OPERACIONES)
//                      Colección: hub_nebula_config { _id: 'umbrales', umbrales, updatedBy, updatedAt }
//   v4.5.6: [MAINT-002] GET /api/config/sheets → Sheet IDs desde variables de entorno
//                       Mueve 13 IDs de config.js (cliente público) al servidor (.env)
//                       Merge servidor (prioridad) + config.js local (fallback zero-downtime)
//                       Nuevas env vars: SHEET_ID_RH, SHEET_ID_CORREOS, SHEET_ID_EQUIPOS_IQU,
//                         SHEET_ID_PDV_DETALLES, SHEET_ID_CORREOS_DETALLADOS, SHEET_ID_ACTIVOS,
//                         SHEET_ID_REPOSICIONES, SHEET_ID_TICKETS_DASHBOARD, SHEET_ID_TICKETS_CONTEO,
//                         SHEET_ID_RH_POC, SHEET_ID_RH_HISTORICO, SHEET_ID_SEGUIMIENTO_ALTAS,
//                         SHEET_ID_HEADCOUNT
//   v4.5.7: [FEAT-005] GET /api/hc/validar-consistencia
//   v4.7.0: [INN-002] Hub AI — POST /api/hub/ai/summarize-chat · extract-tasks · meeting-brief
//                      Helper _llamarIATexto (Groq→Gemini cascada, texto libre)
//           [INN-003] Dashboard Ejecutivo — GET /api/exec/alerts · /api/hub/activity/summary
//                      GET /api/kpi/summary · /api/headcount/summary
//                      requireEjecutivo middleware (ADMIN + GERENTE_OPERACIONES)
//   v4.6.0: [FEAT-004] Resumen semanal por email (scheduler nativo, sin deps)
//                      GET  /api/admin/weekly-report/status    → estado del scheduler
//                      POST /api/admin/weekly-report/enviar-ahora → disparo manual
//                      scheduleWeeklyReport() en connectDB() post-conexión
//                      Funciones: calcularResumenSemanal, _formatearHtmlResumenSemanal,
//                                 enviarResumenSemanal, scheduleWeeklyReport
//                      Nuevas env vars (todas opcionales, opt-in explícito):
//                        WEEKLY_REPORT_ENABLED=true
//                        WEEKLY_REPORT_RECIPIENTS=a@b.com,c@d.com
//                        WEEKLY_REPORT_DAY=1   (0=Dom…6=Sáb, default: 1=Lunes)
//                        WEEKLY_REPORT_HOUR=8  (hora MX 0-23, default: 8am)
//                        WEEKLY_REPORT_TZ_OFFSET=-6 (offset UTC, default: -6=MX)
// ================================================================

require('dotenv').config();
const { validateEnv, getRequired, getOptional } = require('./env-validator');
validateEnv();

const JWT_SECRET          = getRequired('JWT_SECRET');
const NEBULA_AGENT_SECRET = getRequired('NEBULA_AGENT_SECRET');
const MONGODB_URI         = getRequired('MONGODB_URI');

const PORT           = parseInt(getOptional('PORT', '3000'), 10);
const NODE_ENV       = getOptional('NODE_ENV', 'production');
const FRONTEND_URL   = getOptional('FRONTEND_URL', '*');
const GROQ_API_KEY   = getOptional('GROQ_API_KEY', '');
const GEMINI_API_KEY = getOptional('GEMINI_API_KEY', '');
const GOOGLE_SHEETS_KEY = getOptional('GOOGLE_SHEETS_KEY', '');

const express   = require('express');
const cors      = require('cors');
const helmet    = require('helmet');
const { MongoClient, ObjectId } = require('mongodb');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const Joi       = require('joi');
const rateLimit = require('express-rate-limit');
const morgan    = require('morgan');
const ExcelJS   = require('exceljs');
const nebulaRoutes = require('./routes/nebula_agents');

// ── [MAINT-002] Mapa de env vars → claves de Sheet ID ─────────
const SHEET_ENV_MAP = {
    rh:               'SHEET_ID_RH',
    correos:          'SHEET_ID_CORREOS',
    equiposIQU:       'SHEET_ID_EQUIPOS_IQU',
    pdvDetalles:      'SHEET_ID_PDV_DETALLES',
    correosDetallados:'SHEET_ID_CORREOS_DETALLADOS',
    activos:          'SHEET_ID_ACTIVOS',
    reposiciones:     'SHEET_ID_REPOSICIONES',
    dashboardTickets: 'SHEET_ID_TICKETS_DASHBOARD',
    ticketsConteo:    'SHEET_ID_TICKETS_CONTEO',
    rhPOC:            'SHEET_ID_RH_POC',
    rhHistorico:      'SHEET_ID_RH_HISTORICO',
    seguimientoAltas: 'SHEET_ID_SEGUIMIENTO_ALTAS',
    headcount:        'SHEET_ID_HEADCOUNT',
};

const _sheetIdsConfigured = Object.entries(SHEET_ENV_MAP)
    .filter(([, envVar]) => process.env[envVar]?.trim())
    .map(([key]) => key);
const _sheetIdsMissing = Object.entries(SHEET_ENV_MAP)
    .filter(([, envVar]) => !process.env[envVar]?.trim())
    .map(([key]) => key);

if (_sheetIdsMissing.length > 0) {
    console.warn(`[MAINT-002] ⚠️  Sheet IDs no en .env (usarán config.js local como fallback): ${_sheetIdsMissing.join(', ')}`);
}
if (_sheetIdsConfigured.length > 0) {
    console.log(`[MAINT-002] ✅ Sheet IDs configurados en .env: ${_sheetIdsConfigured.join(', ')}`);
}

// ── Nodemailer lazy-load ───────────────────────────────────────
let _nodemailer = null;
let _smtpTransporter = null;
function _getTransporter() {
    if (_smtpTransporter) return _smtpTransporter;
    try {
        if (!_nodemailer) _nodemailer = require('nodemailer');
        const host = process.env.SMTP_HOST;
        const port = parseInt(process.env.SMTP_PORT || '587', 10);
        const user = process.env.SMTP_USER;
        const pass = process.env.SMTP_PASS;
        if (!host || !user || !pass) {
            console.warn('[Email] SMTP_HOST/SMTP_USER/SMTP_PASS no configurados — emails desactivados');
            return null;
        }
        _smtpTransporter = _nodemailer.createTransport({
            host, port, secure: port === 465,
            auth: { user, pass },
            tls: { rejectUnauthorized: false },
        });
        console.log(`[Email] Transporter SMTP listo → ${host}:${port}`);
        return _smtpTransporter;
    } catch (err) {
        console.error('[Email] No se pudo inicializar Nodemailer:', err.message);
        return null;
    }
}

// ── Gemini SDK lazy-load ───────────────────────────────────────
let GoogleGenerativeAI;
try {
    ({ GoogleGenerativeAI } = require('@google/generative-ai'));
} catch (_) {
    console.warn('⚠️  @google/generative-ai no instalado — Gemini usará REST');
}

// ── Express app ────────────────────────────────────────────────
const app = express();

// ── [SEC-004] Helmet — HTTP Security Headers ───────────────────
app.use(
    helmet({
        contentSecurityPolicy: {
            directives: {
                defaultSrc:  ["'self'"],
                scriptSrc:   ["'self'", "'unsafe-inline'", "'unsafe-eval'"],
                styleSrc:    ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
                fontSrc:     ["'self'", "https://fonts.gstatic.com"],
                imgSrc:      ["'self'", "data:", "blob:", "https:"],
                connectSrc:  ["'self'", process.env.CLOUDFLARE_WORKER_URL || ""],
                frameSrc:    ["'none'"],
                objectSrc:   ["'none'"],
                upgradeInsecureRequests: process.env.NODE_ENV === 'production' ? [] : null,
            },
            reportOnly: process.env.CSP_REPORT_ONLY === 'true',
        },
        strictTransportSecurity: process.env.NODE_ENV === 'production'
            ? { maxAge: 31536000, includeSubDomains: true }
            : false,
        crossOriginEmbedderPolicy: false,
        hidePoweredBy: true,
    })
);

// ── CORS ───────────────────────────────────────────────────────
app.use(cors({
    origin: [
        'https://dashboard-myg-api.mygtrabajo.workers.dev',
        'https://myg-mongodb-api.onrender.com',
        'http://localhost:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500',
        'https://mygtelecom.netlify.app',
    ],
    methods:        ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
    allowedHeaders: ['Content-Type', 'Authorization'],
    exposedHeaders: ['Content-Disposition'],
}));

app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

// ── Rate limiters ──────────────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, max: 10,
    message: { error: 'Demasiados intentos. Espera 15 minutos.' }
});
const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000, max: 200,
    message: { error: 'Demasiadas peticiones.' }
});
app.use('/api/', apiLimiter);

// ── [BUG-003] Globals DB ───────────────────────────────────────
let db;
let mongoClient;

const MONGO_URI = MONGODB_URI;
const DB_NAME   = 'iqu_telecom';

// ================================================================
// EMAIL — Movimientos RH
// ================================================================
const RH_TIPO_LABELS = {
    ALTA:             '➕ Alta de Colaborador',
    ALTA_UDP:         '👪 Alta UDP (Beneficiario)',
    BAJA:             '➖ Baja de Colaborador',
    CAMBIO_PDV:       '🏪 Cambio de PDV',
    CAMBIO_PUESTO:    '📋 Cambio de Puesto',
    CAMBIO_COMBINADO: '🔀 Cambio Combinado (PDV + Puesto)',
};

async function enviarEmailMovimientoRH(movimiento, destinatario) {
    if (!destinatario) return;
    const transporter = _getTransporter();
    if (!transporter) return;

    try {
        const tipo       = movimiento.tipo || 'MOVIMIENTO';
        const tipoLabel  = RH_TIPO_LABELS[tipo] || tipo;
        const empleado   = movimiento.empleado         || {};
        const dm         = movimiento.datos_movimiento || {};
        const nombre     = [empleado.nombre, empleado.apellido_paterno, empleado.apellido_materno]
                             .filter(Boolean).join(' ') || '—';
        const attuid     = empleado.attuid || empleado.numero_empleado || '—';
        const puesto     = dm.puesto || empleado.puesto_actual || '—';
        const pdv        = dm.pdv   || '—';
        const ahora      = new Date().toLocaleString('es-MX', { timeZone: 'America/Mexico_City' });
        const id         = movimiento._id ? String(movimiento._id) : '—';

        const detallesExtra = [];
        if (tipo === 'BAJA') {
            if (dm.motivo)     detallesExtra.push(`<tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Motivo</td><td style="padding:4px;font-size:13px;font-weight:600;">${dm.motivo}</td></tr>`);
            if (dm.fecha_baja) detallesExtra.push(`<tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Fecha baja</td><td style="padding:4px;font-size:13px;">${dm.fecha_baja}</td></tr>`);
        }
        if (['CAMBIO_PDV','CAMBIO_COMBINADO'].includes(tipo) && pdv !== '—')
            detallesExtra.push(`<tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">PDV destino</td><td style="padding:4px;font-size:13px;">${pdv}</td></tr>`);
        if (['CAMBIO_PUESTO','CAMBIO_COMBINADO'].includes(tipo) && puesto !== '—')
            detallesExtra.push(`<tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Puesto nuevo</td><td style="padding:4px;font-size:13px;">${puesto}</td></tr>`);

        const colores = {
            ALTA:'#10B981', ALTA_UDP:'#14B8A6', BAJA:'#EF4444',
            CAMBIO_PDV:'#3B82F6', CAMBIO_PUESTO:'#6366F1', CAMBIO_COMBINADO:'#8B5CF6'
        };
        const colorTipo = colores[tipo] || '#3B82F6';

        const html = `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:Arial,sans-serif;">
  <table width="100%" cellpadding="0" cellspacing="0" style="background:#F3F4F6;padding:32px 16px;">
    <tr><td align="center">
      <table width="600" cellpadding="0" cellspacing="0" style="background:#FFFFFF;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,0.10);">
        <tr><td style="background:linear-gradient(135deg,#3B82F6,#8B5CF6);padding:28px 32px;">
          <h1 style="margin:0;color:#fff;font-size:22px;font-weight:700;">✅ Movimiento RH Registrado</h1>
          <p style="margin:6px 0 0;color:#BFDBFE;font-size:14px;">Dashboard MYG Telecom — Sistemas</p>
        </td></tr>
        <tr><td style="padding:24px 32px 8px;">
          <span style="display:inline-block;background:${colorTipo}18;color:${colorTipo};border:1px solid ${colorTipo}40;border-radius:999px;padding:6px 16px;font-size:14px;font-weight:700;">${tipoLabel}</span>
        </td></tr>
        <tr><td style="padding:16px 32px 24px;">
          <p style="margin:0 0 16px;color:#374151;font-size:14px;">Tu solicitud ha sido registrada correctamente. Resumen:</p>
          <table cellpadding="0" cellspacing="0" style="width:100%;border-top:1px solid #E5E7EB;">
            <tr><td style="padding:12px 12px 4px 0;color:#6B7280;font-size:13px;">Colaborador</td>
                <td style="padding:12px 0 4px;font-size:15px;font-weight:700;color:#111827;">${nombre}</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Puesto</td>
                <td style="padding:4px;font-size:13px;">${puesto}</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">PDV</td>
                <td style="padding:4px;font-size:13px;">${pdv}</td></tr>
            ${detallesExtra.join('')}
            <tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">ID Solicitud</td>
                <td style="padding:4px;font-size:11px;color:#9CA3AF;font-family:monospace;">${id}</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Registrado</td>
                <td style="padding:4px;font-size:13px;">${ahora} (MX)</td></tr>
            <tr><td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Estado</td>
                <td style="padding:4px;"><span style="background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px;">PENDIENTE</span></td></tr>
          </table>
        </td></tr>
        <tr><td style="padding:0 32px 24px;">
          <div style="background:#EFF6FF;border-left:4px solid #3B82F6;border-radius:4px;padding:12px 16px;">
            <p style="margin:0;color:#1E40AF;font-size:13px;">📌 Sigue el estado de esta solicitud en la pestaña <strong>RH</strong> del Dashboard MYG.</p>
          </div>
        </td></tr>
        <tr><td style="background:#F9FAFB;padding:16px 32px;border-top:1px solid #E5E7EB;">
          <p style="margin:0;color:#9CA3AF;font-size:12px;text-align:center;">Dashboard MYG Telecom · Correo automático, no responder.</p>
        </td></tr>
      </table>
    </td></tr>
  </table>
</body></html>`;

        await transporter.sendMail({
            from:    `"MYG Dashboard" <${process.env.SMTP_USER}>`,
            to:      destinatario,
            subject: `[MYG RH] ${tipoLabel} — ${nombre}`,
            html,
        });
        console.log(`[Email] ✅ Enviado a ${destinatario} — ${tipo} (${nombre})`);

    } catch (err) {
        console.error(`[Email] ❌ Error enviando a ${destinatario}:`, err.message);
    }
}

// ================================================================
// [FEAT-004] RESUMEN SEMANAL POR EMAIL — v4.6.0
// Scheduler nativo (setTimeout recursivo) — sin dependencias adicionales.
//
// ZERO DOWNTIME: si WEEKLY_REPORT_ENABLED != 'true' o SMTP no está
// configurado, NADA de este bloque se activa. Completamente inerte.
//
// Env vars (todas opcionales con defaults seguros):
//   WEEKLY_REPORT_ENABLED=true|false    (default: false — opt-in explícito)
//   WEEKLY_REPORT_RECIPIENTS=a@b.com,c  (vacío = auto-detect ADMIN+GERENTE con email)
//   WEEKLY_REPORT_DAY=1                 (0=Dom … 6=Sáb; default: 1=Lunes)
//   WEEKLY_REPORT_HOUR=8                (hora local MX 0–23; default: 8am)
//   WEEKLY_REPORT_TZ_OFFSET=-6          (offset UTC de la zona; default: -6 = MX)
// ================================================================

/**
 * Calcula los ms hasta la próxima ejecución programada.
 * @param {number} targetDay     - día UTC (0=Dom … 6=Sáb)
 * @param {number} targetHourUTC - hora en UTC ya ajustada por timezone
 * @returns {number} milisegundos hasta la próxima ejecución (mínimo 60 000 ms)
 */
function _getNextReportMs(targetDay, targetHourUTC) {
    const now  = new Date();
    const next = new Date(now);
    next.setUTCHours(targetHourUTC, 0, 0, 0);

    const curDay    = now.getUTCDay();
    let   daysAhead = (targetDay - curDay + 7) % 7;

    // Si hoy es el día pero la hora ya pasó → siguiente semana
    if (daysAhead === 0 && now.getTime() >= next.getTime()) daysAhead = 7;
    next.setUTCDate(next.getUTCDate() + daysAhead);

    return Math.max(next.getTime() - Date.now(), 60_000); // Mínimo 1 min
}

/**
 * Recoge datos de los últimos N días para armar el resumen semanal.
 * Usa Promise.allSettled → tolerante a fallos individuales de colección.
 * @param {number} diasAtras - ventana de análisis (default: 7)
 * @returns {object} resumen estructurado
 */
async function calcularResumenSemanal(diasAtras = 7) {
    const desde             = new Date(Date.now() - diasAtras * 24 * 3600 * 1000);
    const ahora             = new Date();
    const proximaSemanaFin  = new Date(ahora.getTime() + 7 * 24 * 3600 * 1000);

    const [
        rhMovsResult,
        hcMetaResult,
        hcEstatusResult,
        reunionesProxResult,
        reunionesRealizadasResult,
        activosResult,
        boletinesResult,
        minutasResult,
        notifResult,
        usuariosResult,
    ] = await Promise.allSettled([
        // RH: desglose por tipo + pendientes
        db.collection('rh_movimientos').aggregate([
            { $match: { createdAt: { $gte: desde } } },
            { $group: {
                _id:        '$tipo',
                count:      { $sum: 1 },
                pendientes: { $sum: { $cond: [{ $eq: ['$estado', 'pendiente'] }, 1, 0] } },
            }},
        ]).toArray(),

        // HC: última carga
        db.collection('hub_hc_meta').findOne({ _type: 'hc_usuarios' }),

        // HC: distribución por estatus
        db.collection('hub_hc_usuarios').aggregate([
            { $group: {
                _id:   { $toUpper: { $ifNull: ['$ESTATUS', 'DESCONOCIDO'] } },
                count: { $sum: 1 },
            }},
        ]).toArray(),

        // Reuniones programadas próxima semana (sin canceladas)
        db.collection('hub_reuniones').find({
            date:   {
                $gte: ahora.toISOString().split('T')[0],
                $lte: proximaSemanaFin.toISOString().split('T')[0],
            },
            status: { $ne: 'cancelada' },
        }).sort({ date: 1 }).limit(8)
          .project({ title: 1, date: 1, time: 1, organizer: 1 }).toArray(),

        // Reuniones completadas esta semana
        db.collection('hub_reuniones').countDocuments({
            date:   {
                $gte: desde.toISOString().split('T')[0],
                $lt:  ahora.toISOString().split('T')[0],
            },
            status: { $in: ['completada', 'realizada', 'finalizada'] },
        }),

        // Activos registrados esta semana
        db.collection('activos_movimientos').countDocuments({ createdAt: { $gte: desde } }),

        // Boletines subidos esta semana
        db.collection('hub_boletines').countDocuments({ createdAt: { $gte: desde } }),

        // Minutas generadas esta semana
        db.collection('hub_minutas').countDocuments({ createdAt: { $gte: desde } }),

        // Notificaciones no leídas (indicador de salud)
        db.collection('notificaciones').countDocuments({ leida: false }),

        // Usuarios activos en sistema
        db.collection('users').countDocuments({ activo: true }),
    ]);

    // Helper seguro para extraer valor de settled result
    const val = (r, fallback = null) => r.status === 'fulfilled' ? r.value : fallback;

    // ── Procesar RH ──────────────────────────────────────────────
    const rhMovs    = val(rhMovsResult, []);
    const rhPorTipo = {};
    let   rhPendientes = 0;
    for (const g of rhMovs) {
        rhPorTipo[g._id || 'OTRO'] = g.count;
        rhPendientes += g.pendientes || 0;
    }
    const rhTotal = Object.values(rhPorTipo).reduce((a, b) => a + b, 0);

    // ── Procesar HC ──────────────────────────────────────────────
    const hcMeta    = val(hcMetaResult);
    const hcEstatus = val(hcEstatusResult, []);
    const hcCounts  = {};
    for (const g of hcEstatus) hcCounts[g._id] = g.count;
    const hcActivos = hcCounts['ACTIVO'] || hcCounts['ALTA']     || 0;
    const hcBajas   = hcCounts['BAJA']   || hcCounts['INACTIVO'] || 0;
    const hcTotal   = Object.values(hcCounts).reduce((a, b) => a + b, 0);

    return {
        periodo: {
            desde:    desde.toLocaleDateString('es-MX', { timeZone: 'America/Mexico_City' }),
            hasta:    ahora.toLocaleDateString('es-MX',  { timeZone: 'America/Mexico_City' }),
            diasAtras,
        },
        rh:  { total: rhTotal, porTipo: rhPorTipo, pendientes: rhPendientes },
        hc:  {
            total: hcTotal, activos: hcActivos, bajas: hcBajas,
            ultimaCarga:   hcMeta?.uploadedAt || null,
            ultimaArchivo: hcMeta?.filename   || null,
            ultimaPor:     hcMeta?.uploadedBy || null,
        },
        reuniones: {
            programadasProximaSemana: val(reunionesProxResult,        []),
            realizadasEstaSemana:     val(reunionesRealizadasResult,   0),
        },
        activosRegistrados:    val(activosResult,   0),
        boletinesSubidos:      val(boletinesResult, 0),
        minutasGeneradas:      val(minutasResult,   0),
        notificacionesSinLeer: val(notifResult,     0),
        usuariosActivos:       val(usuariosResult,  0),
        generadoEn: ahora.toISOString(),
    };
}

/**
 * Genera el HTML del email de resumen semanal.
 * @param {object} resumen - salida de calcularResumenSemanal()
 * @returns {string} HTML completo del email
 */
function _formatearHtmlResumenSemanal(resumen) {
    const {
        periodo, rh, hc, reuniones,
        activosRegistrados, boletinesSubidos, minutasGeneradas,
        notificacionesSinLeer, usuariosActivos,
    } = resumen;

    const RH_LABELS = {
        ALTA:             '➕ Altas',
        ALTA_UDP:         '👪 Altas UDP',
        BAJA:             '➖ Bajas',
        CAMBIO_PDV:       '🏪 Cambios de PDV',
        CAMBIO_PUESTO:    '📋 Cambios de Puesto',
        CAMBIO_COMBINADO: '🔀 Cambios Combinados',
    };

    // ── Sección RH ───────────────────────────────────────────────
    const rhRowsHtml = Object.entries(rh.porTipo).length > 0
        ? Object.entries(rh.porTipo).map(([tipo, count]) => `
            <tr>
              <td style="padding:5px 12px 5px 0;color:#6B7280;font-size:13px;">${RH_LABELS[tipo] || tipo}</td>
              <td style="padding:5px 0;font-size:14px;font-weight:600;color:#111827;">${count}</td>
            </tr>`).join('') +
          `<tr style="border-top:1px solid #E5E7EB;">
             <td style="padding:8px 12px 4px 0;font-size:13px;font-weight:700;color:#374151;">Total</td>
             <td style="padding:8px 0 4px;font-size:15px;font-weight:700;color:#1D4ED8;">${rh.total}</td>
           </tr>` +
          (rh.pendientes > 0
            ? `<tr><td colspan="2" style="padding:6px 0 0;">
                 <span style="background:#FEF3C7;color:#92400E;padding:3px 10px;border-radius:4px;font-size:12px;font-weight:600;">
                   ⚠️ ${rh.pendientes} movimiento(s) pendiente(s) de aprobación
                 </span></td></tr>`
            : '')
        : '<tr><td colspan="2" style="padding:6px 0;color:#9CA3AF;font-size:13px;">Sin movimientos esta semana</td></tr>';

    // ── Sección Reuniones ────────────────────────────────────────
    const reunionesProxHtml = reuniones.programadasProximaSemana.length > 0
        ? reuniones.programadasProximaSemana.slice(0, 5).map(r => `
            <tr>
              <td style="padding:4px 10px 4px 0;color:#6B7280;font-size:12px;white-space:nowrap;">${r.date || ''}</td>
              <td style="padding:4px 0;font-size:12px;color:#374151;">${r.title || '(sin título)'}</td>
            </tr>`).join('')
        : '<tr><td colspan="2" style="padding:6px 0;color:#9CA3AF;font-size:13px;">Sin reuniones programadas para la próxima semana</td></tr>';

    // ── Badge notificaciones ─────────────────────────────────────
    const badgeNotif = notificacionesSinLeer > 10
        ? `<span style="background:#FEF3C7;color:#92400E;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px;">${notificacionesSinLeer} sin leer</span>`
        : `<span style="background:#D1FAE5;color:#065F46;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px;">${notificacionesSinLeer} sin leer</span>`;

    const hcUltimaCargaHtml = hc.ultimaCarga
        ? `<tr>
             <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Última carga HC</td>
             <td style="padding:4px 0;font-size:12px;color:#9CA3AF;">
               ${new Date(hc.ultimaCarga).toLocaleDateString('es-MX')}
               ${hc.ultimaPor ? `· por ${hc.ultimaPor}` : ''}
             </td>
           </tr>`
        : '<tr><td colspan="2" style="padding:4px 0;color:#F87171;font-size:12px;">⚠️ Sin datos de HC cargados</td></tr>';

    const ahoraStr = new Date().toLocaleString('es-MX', { timeZone: 'America/Mexico_City' });

    return `<!DOCTYPE html><html lang="es"><head><meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#F3F4F6;font-family:Arial,sans-serif;">
<table width="100%" cellpadding="0" cellspacing="0" style="background:#F3F4F6;padding:32px 16px;">
<tr><td align="center">
<table width="640" cellpadding="0" cellspacing="0"
       style="background:#FFFFFF;border-radius:16px;overflow:hidden;box-shadow:0 4px 24px rgba(0,0,0,.10);">

  <!-- HEADER -->
  <tr><td style="background:linear-gradient(135deg,#1E3A5F,#3B82F6);padding:28px 32px;">
    <h1 style="margin:0;color:#fff;font-size:22px;font-weight:700;">📊 Resumen Semanal — MYG Telecom</h1>
    <p style="margin:6px 0 0;color:#BFDBFE;font-size:14px;">
      Período: ${periodo.desde} → ${periodo.hasta} · Dashboard Sistemas IT
    </p>
  </td></tr>

  <!-- KPI CARDS -->
  <tr><td style="padding:24px 32px 8px;">
    <table width="100%" cellpadding="0" cellspacing="0"><tr>
      <td width="25%" style="text-align:center;padding:0 6px;">
        <div style="background:#EFF6FF;border-radius:12px;padding:16px 6px;">
          <p style="margin:0;font-size:30px;font-weight:700;color:#1D4ED8;">${rh.total}</p>
          <p style="margin:4px 0 0;font-size:11px;color:#6B7280;">Movimientos RH</p>
        </div>
      </td>
      <td width="25%" style="text-align:center;padding:0 6px;">
        <div style="background:#F0FDF4;border-radius:12px;padding:16px 6px;">
          <p style="margin:0;font-size:30px;font-weight:700;color:#15803D;">${hc.activos}</p>
          <p style="margin:4px 0 0;font-size:11px;color:#6B7280;">HC Activos</p>
        </div>
      </td>
      <td width="25%" style="text-align:center;padding:0 6px;">
        <div style="background:#FFF7ED;border-radius:12px;padding:16px 6px;">
          <p style="margin:0;font-size:30px;font-weight:700;color:#C2410C;">${activosRegistrados}</p>
          <p style="margin:4px 0 0;font-size:11px;color:#6B7280;">Activos Reg.</p>
        </div>
      </td>
      <td width="25%" style="text-align:center;padding:0 6px;">
        <div style="background:#FAF5FF;border-radius:12px;padding:16px 6px;">
          <p style="margin:0;font-size:30px;font-weight:700;color:#7C3AED;">${minutasGeneradas}</p>
          <p style="margin:4px 0 0;font-size:11px;color:#6B7280;">Minutas</p>
        </div>
      </td>
    </tr></table>
  </td></tr>

  <!-- RH DETALLE -->
  <tr><td style="padding:20px 32px 0;">
    <h3 style="margin:0 0 12px;color:#1E3A5F;font-size:15px;border-bottom:2px solid #EEF2FF;padding-bottom:8px;">
      👥 Movimientos RH — Últimos ${periodo.diasAtras} días
    </h3>
    <table cellpadding="0" cellspacing="0" style="width:100%;">${rhRowsHtml}</table>
  </td></tr>

  <!-- HC STATUS -->
  <tr><td style="padding:20px 32px 0;">
    <h3 style="margin:0 0 12px;color:#1E3A5F;font-size:15px;border-bottom:2px solid #EEF2FF;padding-bottom:8px;">
      🏢 Estado Headcount
    </h3>
    <table cellpadding="0" cellspacing="0" style="width:100%;">
      <tr>
        <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Total registros HC</td>
        <td style="padding:4px 0;font-size:13px;font-weight:600;color:#111827;">${hc.total}</td>
      </tr>
      <tr>
        <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Colaboradores activos</td>
        <td style="padding:4px 0;font-size:13px;font-weight:600;color:#15803D;">${hc.activos}</td>
      </tr>
      ${hc.bajas > 0 ? `
      <tr>
        <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Bajas registradas</td>
        <td style="padding:4px 0;font-size:13px;font-weight:600;color:#DC2626;">${hc.bajas}</td>
      </tr>` : ''}
      ${hcUltimaCargaHtml}
    </table>
  </td></tr>

  <!-- REUNIONES PRÓXIMA SEMANA -->
  <tr><td style="padding:20px 32px 0;">
    <h3 style="margin:0 0 12px;color:#1E3A5F;font-size:15px;border-bottom:2px solid #EEF2FF;padding-bottom:8px;">
      📅 Reuniones — Próxima Semana
    </h3>
    <table cellpadding="0" cellspacing="0" style="width:100%;">${reunionesProxHtml}</table>
    ${reuniones.realizadasEstaSemana > 0
      ? `<p style="margin:10px 0 0;font-size:12px;color:#6B7280;">
           ✅ ${reuniones.realizadasEstaSemana} reunión(es) realizada(s) esta semana
         </p>`
      : ''}
  </td></tr>

  <!-- OTROS INDICADORES -->
  <tr><td style="padding:20px 32px 24px;">
    <h3 style="margin:0 0 12px;color:#1E3A5F;font-size:15px;border-bottom:2px solid #EEF2FF;padding-bottom:8px;">
      📌 Otros Indicadores
    </h3>
    <table cellpadding="0" cellspacing="0" style="width:100%;">
      <tr>
        <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Boletines subidos</td>
        <td style="padding:4px 0;font-size:13px;font-weight:600;">${boletinesSubidos}</td>
      </tr>
      <tr>
        <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Usuarios activos en sistema</td>
        <td style="padding:4px 0;font-size:13px;font-weight:600;">${usuariosActivos}</td>
      </tr>
      <tr>
        <td style="padding:4px 12px 4px 0;color:#6B7280;font-size:13px;">Notificaciones sin leer</td>
        <td style="padding:4px 0;">${badgeNotif}</td>
      </tr>
    </table>
  </td></tr>

  <!-- CTA -->
  <tr><td style="padding:0 32px 24px;">
    <div style="background:#EFF6FF;border-left:4px solid #3B82F6;border-radius:4px;padding:12px 16px;">
      <p style="margin:0;color:#1E40AF;font-size:13px;">
        📌 Revisa los movimientos pendientes en la pestaña <strong>RH</strong> del Dashboard MYG.
      </p>
    </div>
  </td></tr>

  <!-- FOOTER -->
  <tr><td style="background:#F9FAFB;padding:16px 32px;border-top:1px solid #E5E7EB;">
    <p style="margin:0;color:#9CA3AF;font-size:11px;text-align:center;">
      Dashboard MYG Telecom · Reporte automático semanal · ${ahoraStr} (MX) · v4.6.0<br>
      Para desactivar: <code>WEEKLY_REPORT_ENABLED=false</code> en Render.
    </p>
  </td></tr>

</table></td></tr></table>
</body></html>`;
}

/**
 * Orquesta la recolección de datos y el envío del reporte semanal.
 * @param {string[]|null} recipientOverride - lista de emails para envío manual
 * @returns {object} { ok, enviados, total, resultados, resumen } | { ok:false, reason, error }
 */
async function enviarResumenSemanal(recipientOverride = null) {
    const transporter = _getTransporter();
    if (!transporter) {
        console.warn('[FEAT-004] enviarResumenSemanal: SMTP no configurado, skipping');
        return { ok: false, reason: 'smtp_not_configured' };
    }

    try {
        console.log('[FEAT-004] Generando resumen semanal...');
        const resumen = await calcularResumenSemanal(7);

        // ── Determinar destinatarios ─────────────────────────────
        let destinatarios = (recipientOverride || []).filter(Boolean);

        if (!destinatarios.length) {
            // Env var: lista fija separada por comas
            destinatarios = (process.env.WEEKLY_REPORT_RECIPIENTS || '')
                .split(',').map(s => s.trim()).filter(Boolean);
        }

        if (!destinatarios.length) {
            // Auto-detect: ADMIN y GERENTE_OPERACIONES activos con email
            const admins = await db.collection('users').find(
                { rol: { $in: ['ADMIN', 'GERENTE_OPERACIONES'] }, activo: true, email: { $exists: true, $ne: '' } },
                { projection: { email: 1 } }
            ).toArray();
            destinatarios = admins.map(u => u.email).filter(Boolean);
        }

        if (!destinatarios.length) {
            console.warn('[FEAT-004] Sin destinatarios. Configura WEEKLY_REPORT_RECIPIENTS o agrega email a usuarios ADMIN/GERENTE.');
            return { ok: false, reason: 'no_recipients' };
        }

        const html    = _formatearHtmlResumenSemanal(resumen);
        const subject = `[MYG] Resumen Semanal ${resumen.periodo.desde} – ${resumen.periodo.hasta}`;

        // Enviar individualmente (no exponer lista en To:)
        const resultados = [];
        for (const dest of destinatarios) {
            try {
                await transporter.sendMail({
                    from:    `"MYG Dashboard" <${process.env.SMTP_USER}>`,
                    to:      dest,
                    subject,
                    html,
                });
                console.log(`[FEAT-004] ✅ Enviado a ${dest}`);
                resultados.push({ dest, ok: true });
            } catch (mailErr) {
                console.error(`[FEAT-004] ❌ Error enviando a ${dest}:`, mailErr.message);
                resultados.push({ dest, ok: false, error: mailErr.message });
            }
        }

        const enviados = resultados.filter(r => r.ok).length;
        console.log(`[FEAT-004] Reporte: ${enviados}/${destinatarios.length} enviados`);
        return { ok: true, enviados, total: destinatarios.length, resultados, resumen };

    } catch (err) {
        console.error('[FEAT-004] Error generando resumen semanal:', err.message);
        return { ok: false, error: err.message };
    }
}

// Referencias al timer activo (permite inspección en endpoint de status)
let _weeklyReportTimer    = null;
let _weeklyReportNextDate = null; // ISO string de la próxima ejecución

/**
 * Programa el próximo envío usando setTimeout recursivo.
 * Tolerante a fallos — siempre se reprograma en el finally.
 * No hace nada si WEEKLY_REPORT_ENABLED != 'true' o SMTP no configurado.
 */
function scheduleWeeklyReport() {
    if (process.env.WEEKLY_REPORT_ENABLED !== 'true') {
        console.log('[FEAT-004] Reporte semanal desactivado (WEEKLY_REPORT_ENABLED != "true")');
        return;
    }
    if (!_getTransporter()) {
        console.warn('[FEAT-004] SMTP no configurado — reporte semanal no se programará');
        return;
    }

    const configDay    = Math.min(Math.max(parseInt(process.env.WEEKLY_REPORT_DAY  || '1', 10), 0), 6);
    const configHourMX = Math.min(Math.max(parseInt(process.env.WEEKLY_REPORT_HOUR || '8', 10), 0), 23);
    const tzOffset     = parseInt(process.env.WEEKLY_REPORT_TZ_OFFSET || '-6', 10);
    const hourUTC      = ((configHourMX - tzOffset) % 24 + 24) % 24;

    const delayMs  = _getNextReportMs(configDay, hourUTC);
    const nextDate = new Date(Date.now() + delayMs);
    _weeklyReportNextDate = nextDate.toISOString();

    const nextStr  = nextDate.toLocaleString('es-MX', { timeZone: 'America/Mexico_City' });
    const horasR   = Math.floor(delayMs / 3600000);
    const minsR    = Math.round((delayMs % 3600000) / 60000);

    console.log(`[FEAT-004] ✅ Próximo reporte semanal: ${nextStr} MX (en ${horasR}h ${minsR}m)`);

    if (_weeklyReportTimer) clearTimeout(_weeklyReportTimer);

    _weeklyReportTimer = setTimeout(async () => {
        try {
            console.log('[FEAT-004] ⏰ Ejecutando envío automático de reporte semanal...');
            await enviarResumenSemanal();
        } catch (err) {
            console.error('[FEAT-004] Error en envío automático:', err.message);
        } finally {
            scheduleWeeklyReport(); // Re-programar siempre, incluso si falló
        }
    }, delayMs);
}

// ================================================================
// [PERF-002] TTL index para hub_notificaciones — v4.5.3
// ================================================================
async function crearIndicesTTL() {
    try {
        await db.collection('notificaciones').createIndex(
            { createdAt: 1 },
            {
                expireAfterSeconds: 2592000,
                name:       'ttl_notificaciones_30d',
                background: true,
            }
        );
        console.log('[PERF-002] TTL index notificaciones: OK (30 días sobre createdAt)');
    } catch (err) {
        console.error('[PERF-002] Error creando TTL index notificaciones:', err.message);
    }
}

async function connectDB() {
    const client = new MongoClient(MONGO_URI, {
        serverSelectionTimeoutMS: 10000,
        socketTimeoutMS:          45000,
        heartbeatFrequencyMS:     10000,   // ping al servidor cada 10s para detectar caídas rápido
        minPoolSize:              2,        // mantener al menos 2 conexiones abiertas (evita cold-start)
        maxPoolSize:              10,
        connectTimeoutMS:         15000,
        retryWrites:              true,
        retryReads:               true,
    });

    client.on('serverHeartbeatFailed', (evt) => {
        console.error(`[MongoDB] ❌ Heartbeat falló → ${evt.connectionId} (${evt.failure?.message})`);
    });
    client.on('serverClosed', (evt) => {
        console.warn(`[MongoDB] ⚠️  Servidor cerrado: ${evt.address}`);
    });
    client.on('topologyOpening', () => {
        console.log('[MongoDB] Conectando...');
    });

    await client.connect();
    db          = client.db(DB_NAME);
    mongoClient = client;

    console.log(`MongoDB conectado: ${DB_NAME}`);

    await nebulaRoutes.init(app, db, ssePush, requireAuth, requireAdmin);
    nebulaRoutes.startOfflineWatcher(db, ssePush);
    console.log('[Nebula] Agente backend inicializado ✅');

    const idx = async (col, spec, opts = {}) => {
        try {
            await db.collection(col).createIndex(spec, opts);
        } catch (e) {
            console.warn(`Indice ${col}: ${e.message?.split('\n')[0]}`);
        }
    };

    await idx('users',               { username: 1 },                    { unique: true,   name: 'username_unique' });
    await idx('access_logs',         { timestamp: 1 },                   { expireAfterSeconds: 30*24*3600, name: 'ttl_30d' });
    await idx('notificaciones',      { username: 1, leida: 1 },          { name: 'notif_username_leida' });
    await idx('notificaciones',      { usuario_destino: 1, leida: 1 },   { name: 'notif_destino_leida' });
    await idx('hub_asistencia',      { username: 1, fecha: 1 },          { name: 'asistencia_user_fecha' });
    await idx('hub_asistencia',      { fecha: 1 },                       { name: 'asistencia_fecha' });
    await idx('hub_asistencia',      { area: 1, fecha: 1 },              { name: 'asistencia_area_fecha' });
    await idx('hub_mensajes',        { canal: 1, createdAt: -1 },        { name: 'mensajes_canal_fecha' });
    await idx('hub_tareas',          { area: 1, createdAt: -1 },         { name: 'tareas_area_fecha' });
    await idx('hub_minutas',         { area: 1, createdAt: -1 },         { name: 'minutas_area_fecha' });
    await idx('hub_minutas',         { invitadoUsernames: 1 },           { name: 'minutas_invitados' });
    await idx('hub_reuniones',       { invitadoUsernames: 1 },           { name: 'reuniones_invitados' });
    await idx('hub_reuniones',       { organizer: 1 },                   { name: 'reuniones_organizer' });
    await idx('hub_reuniones',       { date: -1 },                       { name: 'reuniones_fecha' });
    await idx('hub_anuncios',        { area: 1, createdAt: -1 },         { name: 'anuncios_area_fecha' });
    await idx('hub_recursos',        { area: 1, createdAt: -1 },         { name: 'recursos_area_fecha' });
    await idx('hub_guias',           { area: 1, createdAt: -1 },         { name: 'guias_area_fecha' });
    await idx('hub_plantillas',      { area: 1, createdAt: -1 },         { name: 'plantillas_area_fecha' });
    await idx('activos_movimientos', { createdAt: -1 },                  { name: 'activos_fecha' });
    await idx('activos_movimientos', { 'Almacen': 1 },                   { name: 'activos_almacen' });
    await idx('activos_movimientos', { 'Tipo de Movimiento': 1 },        { name: 'activos_tipo' });
    await idx('hub_reposiciones',    { createdAt: -1 },                  { name: 'repos_fecha' });
    await idx('hub_reposiciones',    { 'PDV': 1 },                       { name: 'repos_pdv' });
    await idx('hub_reposiciones',    { 'Estado': 1 },                    { name: 'repos_estado' });
    await idx('hub_boletines',       { area: 1, semana: 1 },             { name: 'boletines_area_semana' });
    await idx('hub_boletines',       { createdAt: -1 },                  { name: 'boletines_fecha' });
    await idx('hub_canales',         { area: 1 },                        { name: 'canales_area' });
    await idx('hub_canales',         { id: 1 },                          { unique: true, name: 'canales_id_unique' });
    await idx('rh_movimientos',      { createdAt: -1 },                  { name: 'rh_mov_fecha' });
    await idx('rh_movimientos',      { tipo: 1, createdAt: -1 },         { name: 'rh_mov_tipo_fecha' });
    await idx('hub_nebula_config',   { _id: 1 },                         { name: 'nebula_config_id' });

    await crearIndicesTTL();

    // [FEAT-004] Programar reporte semanal (opt-in via WEEKLY_REPORT_ENABLED=true)
    // Si la env var no está o es 'false', esta llamada es completamente inerte.
    scheduleWeeklyReport();

    return client;
}

// ================================================================
// ROLES / PERMISOS
// ================================================================
const ROLES_VALIDOS  = ['ADMIN','GERENTE_OPERACIONES','COORDINADOR','ANALISTA','GERENTE_COMERCIAL','EJECUTIVO_COMERCIAL','GERENTE_RH','ANALISTA_RH','USUARIO'];
const AREAS_VALIDAS  = ['Sistemas','Mantenimiento','Credito','Logistica','CoordinacionATT'];
const ROLES_CON_AREA = ['COORDINADOR','ANALISTA','GERENTE_RH','ANALISTA_RH'];
const LEGACY_ROLE_MAP = { 'RH':'ANALISTA_RH','SISTEMAS':'COORDINADOR','GERENTE':'GERENTE_OPERACIONES','USUARIO':'USUARIO','ADMIN':'ADMIN' };

const MODULOS_PERMISOS = [
    'dashboard.ver','dashboard.rh','dashboard.headcount','dashboard.activos',
    'dashboard.tickets','dashboard.dispositivos','dashboard.kpi_sistemas',
    'hub.acceso','hub.mensajes','hub.reuniones','hub.minutas','hub.tareas',
    'hub.anuncios','hub.recursos','hub.guias','hub.plantillas',
    'hub.capacitacion','hub.capacitacion.ver',
    'hub.asistencia','hub.vacaciones','hub.concentrado',
    'hub.asistencia.registrar','hub.asistencia.admin_registro',
    'hub.concentrado.ver','hub.concentrado.editar',
    'hub.peticiones.crear','hub.peticiones.aprobar',
    'hub.peticiones.ver_todas','formatos.generar',
    'rh.movimientos.crear','rh.movimientos.ver','rh.movimientos.gestionar',
    'activos.ver','activos.registrar','exportar_datos',
    'chatbot.usar','admin.panel','admin.usuarios','admin.permisos','admin.logs','admin.formularios',
    'hub.coordinacion.acceso',
    'hub.boletines','hub.boletines.subir','hub.boletines.ver','hub.canales.admin',
];

const ROL_PERMISOS_DEFAULT = {
    ADMIN: ['*'],
    GERENTE_OPERACIONES: [
        'dashboard.ver','dashboard.rh','dashboard.headcount','dashboard.activos',
        'dashboard.tickets','dashboard.dispositivos','dashboard.kpi_sistemas',
        'hub.acceso','hub.mensajes','hub.reuniones','hub.minutas','hub.tareas',
        'hub.anuncios','hub.concentrado','hub.concentrado.ver','hub.concentrado.editar',
        'hub.asistencia','hub.asistencia.registrar','hub.asistencia.admin_registro',
        'hub.peticiones.ver_todas','hub.peticiones.aprobar','hub.peticiones.crear',
        'hub.capacitacion','hub.capacitacion.ver',
        'exportar_datos','chatbot.usar','hub.coordinacion.acceso','hub.boletines',
        'hub.boletines.subir','hub.boletines.ver','hub.canales.admin',
    ],
    COORDINADOR: [
        'dashboard.ver','dashboard.rh','dashboard.headcount','dashboard.activos',
        'dashboard.tickets','dashboard.dispositivos','dashboard.kpi_sistemas',
        'hub.acceso','hub.mensajes','hub.reuniones','hub.minutas','hub.tareas',
        'hub.anuncios','hub.recursos','hub.guias','hub.plantillas',
        'hub.capacitacion','hub.capacitacion.ver',
        'hub.asistencia','hub.vacaciones','hub.concentrado',
        'hub.asistencia.registrar','hub.asistencia.admin_registro',
        'hub.concentrado.ver','hub.concentrado.editar',
        'hub.peticiones.crear','hub.peticiones.aprobar','hub.peticiones.ver_todas',
        'formatos.generar',
        'rh.movimientos.crear','rh.movimientos.ver','rh.movimientos.gestionar',
        'activos.ver','activos.registrar','exportar_datos','chatbot.usar',
        'hub.coordinacion.acceso','hub.boletines','hub.boletines.subir',
        'hub.boletines.ver','hub.canales.admin',
    ],
    ANALISTA: [
        'dashboard.ver','dashboard.rh','dashboard.headcount','dashboard.activos',
        'dashboard.tickets','dashboard.dispositivos','dashboard.kpi_sistemas',
        'hub.acceso','hub.mensajes','hub.tareas','hub.anuncios',
        'hub.recursos','hub.guias','hub.plantillas',
        'hub.asistencia','hub.asistencia.registrar',
        'hub.vacaciones','hub.peticiones.crear',
        'rh.movimientos.ver','activos.ver','exportar_datos','chatbot.usar',
    ],
    GERENTE_COMERCIAL:   ['dashboard.ver','chatbot.usar'],
    EJECUTIVO_COMERCIAL: ['dashboard.ver','chatbot.usar'],
    GERENTE_RH: [
        'dashboard.ver','dashboard.rh','dashboard.headcount',
        'rh.movimientos.crear','rh.movimientos.ver','rh.movimientos.gestionar',
        'hub.acceso','hub.asistencia','hub.asistencia.registrar',
        'hub.vacaciones','hub.peticiones.crear',
        'exportar_datos','chatbot.usar',
    ],
    ANALISTA_RH: [
        'dashboard.ver','dashboard.rh','dashboard.headcount',
        'rh.movimientos.crear','rh.movimientos.ver',
        'hub.acceso','hub.asistencia','hub.asistencia.registrar',
        'hub.peticiones.crear','exportar_datos','chatbot.usar',
    ],
    USUARIO: ['dashboard.ver','chatbot.usar'],
};

function normalizarRol(rol) {
    if (ROLES_VALIDOS.includes(rol)) return rol;
    return LEGACY_ROLE_MAP[rol] || 'USUARIO';
}

function calcularPermisos(usuario) {
    const rol = normalizarRol(usuario.rol);
    if (rol === 'ADMIN') return ['*'];
    const base    = ROL_PERMISOS_DEFAULT[rol] || [];
    const extra   = usuario.permisosExtra    || [];
    const revoked = usuario.permisosRevocados || [];
    const set = new Set([...base, ...extra]);
    revoked.forEach(p => set.delete(p));
    return Array.from(set);
}

function tienePermiso(user, permiso) {
    if (!user) return false;
    const permisos = user.permisos || user.permisosEfectivos || [];
    if (permisos.includes('*')) return true;
    if (user.rol === 'ADMIN') return true;
    return permisos.includes(permiso);
}

// ── Schemas Joi ────────────────────────────────────────────────
const schemaCrearUsuario = Joi.object({
    username:      Joi.string().min(3).max(50).required(),
    password:      Joi.string().min(6).required(),
    nombre:        Joi.string().min(2).max(100).required(),
    email:         Joi.string().email().optional().allow(''),
    rol:           Joi.string().valid(...ROLES_VALIDOS).required(),
    area:          Joi.string().valid(...AREAS_VALIDAS).when('rol', {
                       is: Joi.valid(...ROLES_CON_AREA), then: Joi.required(), otherwise: Joi.optional().allow(null,'')
                   }),
    rolSecundario: Joi.string().valid(...ROLES_VALIDOS).optional().allow(null,''),
    activo:        Joi.boolean().default(true),
});

const schemaActualizarUsuario = Joi.object({
    nombre:            Joi.string().min(2).max(100).optional(),
    email:             Joi.string().email().optional().allow(''),
    rol:               Joi.string().valid(...ROLES_VALIDOS).optional(),
    area:              Joi.string().valid(...AREAS_VALIDAS).optional().allow(null,''),
    rolSecundario:     Joi.string().valid(...ROLES_VALIDOS).optional().allow(null,''),
    password:          Joi.string().min(6).optional(),
    activo:            Joi.boolean().optional(),
    permisosExtra:     Joi.array().items(Joi.string()).optional(),
    permisosRevocados: Joi.array().items(Joi.string()).optional(),
});

const schemaActualizarPerfil = Joi.object({
    nombre:      Joi.string().min(2).max(100).optional(),
    email:       Joi.string().email().optional().allow(''),
    avatar:      Joi.string().optional().allow(''),
    preferencias: Joi.object({ tabsPinned: Joi.array().items(Joi.string()).optional() }).optional(),
});

const schemaCambiarPassword = Joi.object({
    passwordActual: Joi.string().required(),
    passwordNueva:  Joi.string().min(6).required(),
});

// ── Auth middlewares ───────────────────────────────────────────
function requireAuth(req, res, next) {
    try {
        const header = req.headers.authorization;
        if (!header?.startsWith('Bearer '))
            return res.status(401).json({ error: 'Token no proporcionado' });
        const token = header.slice(7);
        const payload = jwt.verify(token, JWT_SECRET);
        payload.rol = normalizarRol(payload.rol);
        req.usuario = payload;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError')
            return res.status(401).json({ error: 'Token expirado', code: 'TOKEN_EXPIRED' });
        return res.status(401).json({ error: 'Token invalido' });
    }
}

function requireAuthSSE(req, res, next) {
    try {
        let token;
        const header = req.headers.authorization;
        if (header?.startsWith('Bearer ')) {
            token = header.slice(7);
        } else if (req.query.token) {
            token = req.query.token;
        }
        if (!token)
            return res.status(401).json({ error: 'Token no proporcionado' });
        const payload = jwt.verify(token, JWT_SECRET);
        payload.rol = normalizarRol(payload.rol);
        req.usuario = payload;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError')
            return res.status(401).json({ error: 'Token expirado', code: 'TOKEN_EXPIRED' });
        return res.status(401).json({ error: 'Token invalido' });
    }
}

function requireAdmin(req, res, next) {
    if (req.usuario?.rol !== 'ADMIN')
        return res.status(403).json({ error: 'Acceso denegado. Se requiere rol ADMIN.' });
    next();
}

function requirePermiso(permiso) {
    return (req, res, next) => {
        const permisos = req.usuario?.permisos || [];
        if (permisos.includes('*') || permisos.includes(permiso)) return next();
        return res.status(403).json({ error: `Permiso requerido: ${permiso}` });
    };
}

async function logAccess(username, action, details = {}) {
    try {
        if (!db) return;
        await db.collection('access_logs').insertOne({
            username, action, details,
            timestamp: new Date(),
            ip: details.ip || 'unknown',
        });
    } catch (err) {
        console.error('Error logging:', err.message);
    }
}

// ── HEALTH ─────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
    status:    'ok',
    version:   '4.7.0',
    timestamp: new Date().toISOString(),
    db:        db ? 'connected' : 'disconnected',
    ia: {
        groq:   !!process.env.GROQ_API_KEY,
        gemini: !!process.env.GEMINI_API_KEY,
    }
}));

// ================================================================
// [MAINT-002] GET /api/config/sheets — Sheet IDs desde .env
// ================================================================
app.get('/api/config/sheets', requireAuth, (req, res) => {
    const sheets  = {};
    const missing = [];

    for (const [clientKey, envVar] of Object.entries(SHEET_ENV_MAP)) {
        const value = process.env[envVar];
        if (value && value.trim()) {
            sheets[clientKey] = value.trim();
        } else {
            missing.push(clientKey);
        }
    }

    const source = Object.keys(sheets).length > 0 ? 'env' : 'none';

    res.set('Cache-Control', 'private, max-age=300');
    res.json({ ok: true, sheets, source, missing });
});

// ── LOGIN ──────────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Usuario y contrasena requeridos' });
        const usuarioDoc = await db.collection('users').findOne({ username: username.toLowerCase().trim() });
        if (!usuarioDoc) {
            await logAccess(username, 'LOGIN_FAILED', { reason: 'user_not_found', ip: req.ip });
            return res.status(401).json({ error: 'Credenciales invalidas' });
        }
        if (!usuarioDoc.activo) {
            await logAccess(username, 'LOGIN_BLOCKED', { reason: 'account_disabled', ip: req.ip });
            return res.status(401).json({ error: 'Cuenta desactivada.' });
        }
        const validPassword = await bcrypt.compare(password, usuarioDoc.password);
        if (!validPassword) {
            await logAccess(username, 'LOGIN_FAILED', { reason: 'wrong_password', ip: req.ip });
            return res.status(401).json({ error: 'Credenciales invalidas' });
        }
        const rolNormalizado = normalizarRol(usuarioDoc.rol);
        const permisos = calcularPermisos({ ...usuarioDoc, rol: rolNormalizado });
        const tokenPayload = {
            username:    usuarioDoc.username,
            nombre:      usuarioDoc.nombre,
            email:       usuarioDoc.email || '',
            rol:         rolNormalizado,
            area:        usuarioDoc.area || null,
            rolSecundario: usuarioDoc.rolSecundario || null,
            permisos,
            preferencias: usuarioDoc.preferencias || {},
        };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });
        await db.collection('users').updateOne(
            { username: usuarioDoc.username },
            { $set: { ultimoLogin: new Date(), rol: rolNormalizado } }
        );
        await logAccess(usuarioDoc.username, 'LOGIN_SUCCESS', { ip: req.ip, rol: rolNormalizado });
        res.json({ success: true, token, user: { ...tokenPayload } });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno' });
    }
});

app.post('/api/auth/renew', requireAuth, async (req, res) => {
    try {
        const { username } = req.usuario;
        const usuarioDoc = await db.collection('users').findOne(
            { username },
            { projection: { password: 0 } }
        );
        if (!usuarioDoc)
            return res.status(401).json({ error: 'Usuario no encontrado', code: 'USER_NOT_FOUND' });
        if (!usuarioDoc.activo)
            return res.status(401).json({ error: 'Cuenta desactivada', code: 'ACCOUNT_DISABLED' });

        const rolNormalizado = normalizarRol(usuarioDoc.rol);
        const permisos       = calcularPermisos({ ...usuarioDoc, rol: rolNormalizado });
        const tokenPayload = {
            username:      usuarioDoc.username,
            nombre:        usuarioDoc.nombre,
            email:         usuarioDoc.email         || '',
            rol:           rolNormalizado,
            area:          usuarioDoc.area           || null,
            rolSecundario: usuarioDoc.rolSecundario  || null,
            permisos,
            preferencias:  usuarioDoc.preferencias   || {},
        };
        const token = jwt.sign(tokenPayload, JWT_SECRET, { expiresIn: '8h' });
        await logAccess(username, 'TOKEN_RENEWED', { ip: req.ip, rol: rolNormalizado });
        console.log(`[FEAT-001] Token renovado: ${username} (${rolNormalizado})`);
        return res.json({ success: true, token, user: { ...tokenPayload } });
    } catch (err) {
        console.error('[FEAT-001] Error en /api/auth/renew:', err.message);
        return res.status(500).json({ error: 'Error al renovar sesión' });
    }
});

// ── USUARIOS CRUD (solo ADMIN) ─────────────────────────────────
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const usuarios = await db.collection('users').find({}, { projection: { password: 0 } }).toArray();
        res.json(usuarios.map(u => ({ ...u, rol: normalizarRol(u.rol) })));
    } catch (e) { res.status(500).json({ error: 'Error obteniendo usuarios' }); }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { error, value } = schemaCrearUsuario.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });
        if (value.rolSecundario && value.rolSecundario === value.rol)
            return res.status(400).json({ error: 'El rol secundario no puede ser igual al rol principal' });
        const existente = await db.collection('users').findOne({ username: value.username.toLowerCase() });
        if (existente) return res.status(409).json({ error: 'El usuario ya existe' });
        const nuevoUsuario = {
            username: value.username.toLowerCase().trim(),
            password: await bcrypt.hash(value.password, 12),
            nombre: value.nombre.trim(), email: value.email || '',
            rol: value.rol, area: value.area || null,
            rolSecundario: value.rolSecundario || null,
            activo: value.activo !== false,
            permisosExtra: [], permisosRevocados: [],
            preferencias: { tabsPinned: [] },
            createdAt: new Date(), createdBy: req.usuario.username,
        };
        await db.collection('users').insertOne(nuevoUsuario);
        await logAccess(req.usuario.username, 'USER_CREATED', { targetUser: nuevoUsuario.username });
        const { password: _, ...sinPassword } = nuevoUsuario;
        res.status(201).json({ success: true, user: sinPassword });
    } catch (e) {
        console.error('Error creando usuario:', e);
        res.status(500).json({ error: 'Error creando usuario' });
    }
});

app.put('/api/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin' && req.body.rol && req.body.rol !== 'ADMIN')
            return res.status(403).json({ error: 'No se puede cambiar el rol del administrador principal' });
        const { error, value } = schemaActualizarUsuario.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });
        const updates = { updatedAt: new Date(), updatedBy: req.usuario.username };
        if (value.nombre)               updates.nombre        = value.nombre.trim();
        if (value.email !== undefined)  updates.email         = value.email || '';
        if (value.rol)                  updates.rol           = value.rol;
        if (value.area !== undefined)   updates.area          = value.area || null;
        if (value.rolSecundario !== undefined) updates.rolSecundario = value.rolSecundario || null;
        if (value.activo !== undefined) updates.activo        = value.activo;
        if (value.permisosExtra)        updates.permisosExtra = value.permisosExtra;
        if (value.permisosRevocados)    updates.permisosRevocados = value.permisosRevocados;
        if (value.password)             updates.password      = await bcrypt.hash(value.password, 12);
        const result = await db.collection('users').updateOne({ username }, { $set: updates });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        await logAccess(req.usuario.username, 'USER_UPDATED', { targetUser: username, changes: Object.keys(updates) });
        res.json({ success: true, message: 'Usuario actualizado' });
    } catch (e) {
        console.error('Error actualizando usuario:', e);
        res.status(500).json({ error: 'Error actualizando usuario' });
    }
});

app.delete('/api/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin') return res.status(403).json({ error: 'No se puede eliminar el admin principal' });
        if (username === req.usuario.username) return res.status(403).json({ error: 'No puedes eliminarte a ti mismo' });
        const result = await db.collection('users').deleteOne({ username });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        await logAccess(req.usuario.username, 'USER_DELETED', { targetUser: username });
        res.json({ success: true, message: 'Usuario eliminado' });
    } catch (e) { res.status(500).json({ error: 'Error eliminando usuario' }); }
});

// ── PERFIL ─────────────────────────────────────────────────────
app.get('/api/users/:username', requireAuth, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN')
            return res.status(403).json({ error: 'Acceso denegado' });
        const usuario = await db.collection('users').findOne({ username }, { projection: { password: 0 } });
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ ...usuario, rol: normalizarRol(usuario.rol) });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo usuario' }); }
});

app.patch('/api/users/:username/profile', requireAuth, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN')
            return res.status(403).json({ error: 'Sin permiso para modificar este perfil' });
        const { error, value } = schemaActualizarPerfil.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });
        const updates = { updatedAt: new Date() };
        if (value.nombre)               updates.nombre   = value.nombre.trim();
        if (value.email !== undefined)  updates.email    = value.email || '';
        if (value.avatar !== undefined) updates.avatar   = value.avatar;
        if (value.preferencias?.tabsPinned !== undefined)
            updates['preferencias.tabsPinned'] = value.preferencias.tabsPinned;
        const result = await db.collection('users').updateOne({ username }, { $set: updates });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        const actualizado = await db.collection('users').findOne({ username }, { projection: { password: 0 } });
        res.json({ success: true, message: 'Perfil actualizado', preferencias: actualizado.preferencias || {} });
    } catch (e) {
        console.error('Error perfil:', e);
        res.status(500).json({ error: 'Error actualizando perfil' });
    }
});

app.patch('/api/users/:username/password', requireAuth, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN')
            return res.status(403).json({ error: 'Sin permiso para cambiar esta contrasena' });
        const { error, value } = schemaCambiarPassword.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });
        const usuario = await db.collection('users').findOne({ username });
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });
        if (req.usuario.rol !== 'ADMIN') {
            const valid = await bcrypt.compare(value.passwordActual, usuario.password);
            if (!valid) return res.status(400).json({ error: 'Contrasena actual incorrecta' });
        }
        await db.collection('users').updateOne(
            { username },
            { $set: { password: await bcrypt.hash(value.passwordNueva, 12), passwordChangedAt: new Date() } }
        );
        await logAccess(req.usuario.username, 'PASSWORD_CHANGED', { targetUser: username });
        res.json({ success: true, message: 'Contrasena actualizada' });
    } catch (e) { res.status(500).json({ error: 'Error cambiando contrasena' }); }
});

// ── ADMIN ──────────────────────────────────────────────────────
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [totalUsuarios, usuariosActivos, registrosPorRol, ultimosLogins, formSubmissions] = await Promise.all([
            db.collection('users').countDocuments(),
            db.collection('users').countDocuments({ activo: true }),
            db.collection('users').aggregate([{ $group: { _id: '$rol', count: { $sum: 1 } } }, { $sort: { count: -1 } }]).toArray(),
            db.collection('access_logs').find({ action: 'LOGIN_SUCCESS' }).sort({ timestamp: -1 }).limit(10).toArray(),
            db.collection('form_submissions').countDocuments({ createdAt: { $gte: new Date(Date.now() - 7*24*3600*1000) } }).catch(() => 0)
        ]);
        const porArea = await db.collection('users').aggregate([
            { $match: { area: { $ne: null } } },
            { $group: { _id: '$area', count: { $sum: 1 } } }
        ]).toArray();
        res.json({
            resumen: { totalUsuarios, usuariosActivos, formSubmissionsUltima7Dias: formSubmissions },
            porRol:  registrosPorRol.reduce((acc, r) => { acc[normalizarRol(r._id)] = (acc[normalizarRol(r._id)] || 0) + r.count; return acc; }, {}),
            porArea: porArea.reduce((acc, r) => { acc[r._id] = r.count; return acc; }, {}),
            ultimosLogins,
        });
    } catch (e) {
        console.error('Error stats:', e);
        res.status(500).json({ error: 'Error obteniendo estadisticas' });
    }
});

app.get('/api/admin/access-logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 500);
        const page  = Math.max(parseInt(req.query.page)  || 1, 1);
        const skip  = (page - 1) * limit;
        const filter = {};
        if (req.query.username) filter.username = req.query.username;
        if (req.query.action)   filter.action   = req.query.action;
        const [logs, total] = await Promise.all([
            db.collection('access_logs').find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
            db.collection('access_logs').countDocuments(filter)
        ]);
        res.json({ logs, total, page, totalPages: Math.ceil(total / limit) });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo logs' }); }
});

app.patch('/api/admin/permissions/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const { permisosExtra, permisosRevocados } = req.body;
        if (!Array.isArray(permisosExtra) || !Array.isArray(permisosRevocados))
            return res.status(400).json({ error: 'permisosExtra y permisosRevocados deben ser arrays' });
        const invalidosE = permisosExtra.filter(p => !MODULOS_PERMISOS.includes(p));
        const invalidosR = permisosRevocados.filter(p => !MODULOS_PERMISOS.includes(p));
        if (invalidosE.length) return res.status(400).json({ error: `Permisos extra invalidos: ${invalidosE.join(', ')}` });
        if (invalidosR.length) return res.status(400).json({ error: `Permisos revocados invalidos: ${invalidosR.join(', ')}` });
        await db.collection('users').updateOne(
            { username },
            { $set: { permisosExtra, permisosRevocados, updatedAt: new Date(), updatedBy: req.usuario.username } }
        );
        await logAccess(req.usuario.username, 'PERMISSIONS_UPDATED', { targetUser: username });
        res.json({ success: true, message: `Permisos actualizados para ${username}` });
    } catch (e) { res.status(500).json({ error: 'Error actualizando permisos' }); }
});

app.get('/api/admin/permissions/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const usuario = await db.collection('users').findOne({ username }, { projection: { rol:1, area:1, permisosExtra:1, permisosRevocados:1 } });
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });
        const rolNorm = normalizarRol(usuario.rol);
        const base    = ROL_PERMISOS_DEFAULT[rolNorm] || [];
        res.json({
            username, rol: rolNorm, area: usuario.area || null,
            permisosBase:       base,
            permisosExtra:      usuario.permisosExtra    || [],
            permisosRevocados:  usuario.permisosRevocados || [],
            permisosEfectivos:  calcularPermisos(usuario),
            modulosDisponibles: MODULOS_PERMISOS,
        });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo permisos' }); }
});

app.get('/api/admin/permissions/roles', requireAuth, requireAdmin, (req, res) => {
    res.json({ roles: ROLES_VALIDOS, areasValidas: AREAS_VALIDAS, rolesConArea: ROLES_CON_AREA, modulosDisponibles: MODULOS_PERMISOS, permisosDefault: ROL_PERMISOS_DEFAULT });
});

app.get('/api/admin/form-submissions', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 500);
        const submissions = await db.collection('form_submissions').find({}).sort({ createdAt: -1 }).limit(limit).toArray();
        res.json(submissions);
    } catch (e) { res.status(500).json({ error: 'Error obteniendo formularios' }); }
});

// ================================================================
// [FEAT-004] ENDPOINTS Reporte Semanal — solo ADMIN
// ================================================================

/**
 * GET /api/admin/weekly-report/status
 * Retorna el estado actual del scheduler (solo lectura, no ejecuta nada).
 */
app.get('/api/admin/weekly-report/status', requireAuth, requireAdmin, (req, res) => {
    const enabled    = process.env.WEEKLY_REPORT_ENABLED === 'true';
    const smtpOk     = !!_getTransporter();
    const scheduled  = !!_weeklyReportTimer;
    const recipients = (process.env.WEEKLY_REPORT_RECIPIENTS || '')
        .split(',').map(s => s.trim()).filter(Boolean);

    res.json({
        ok: true,
        config: {
            enabled,
            smtpConfigured:  smtpOk,
            schedulerActive: scheduled && enabled,
            nextExecutionUtc: _weeklyReportNextDate || null,
            nextExecutionMx:  _weeklyReportNextDate
                ? new Date(_weeklyReportNextDate).toLocaleString('es-MX', { timeZone: 'America/Mexico_City' })
                : null,
            reportDay:        parseInt(process.env.WEEKLY_REPORT_DAY   || '1', 10),
            reportHourMx:     parseInt(process.env.WEEKLY_REPORT_HOUR  || '8', 10),
            recipientMode:    recipients.length > 0 ? 'env_list' : 'auto_detect',
            recipientCount:   recipients.length || '(auto-detect ADMIN+GERENTE)',
        },
        notes: [
            !enabled   && '⚠️  WEEKLY_REPORT_ENABLED != "true" — scheduler inactivo',
            !smtpOk    && '⚠️  SMTP no configurado (SMTP_HOST/USER/PASS)',
            !scheduled && enabled && smtpOk && '⚠️  Timer no programado — reiniciar servidor',
        ].filter(Boolean),
    });
});

/**
 * POST /api/admin/weekly-report/enviar-ahora
 * Disparo manual. Body opcional: { recipients: ["a@b.com"] }
 * Si no se pasa recipients, usa la lógica de auto-detect igual que el scheduler.
 */
app.post('/api/admin/weekly-report/enviar-ahora', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { recipients } = req.body || {};
        if (recipients !== undefined && !Array.isArray(recipients))
            return res.status(400).json({ ok: false, error: 'recipients debe ser un array de emails' });

        console.log(`[FEAT-004] Envío manual disparado por ${req.usuario.username}`);
        const resultado = await enviarResumenSemanal(recipients || null);

        if (!resultado.ok) {
            const statusCode = resultado.reason === 'smtp_not_configured' ? 503 : 400;
            return res.status(statusCode).json(resultado);
        }

        await logAccess(req.usuario.username, 'WEEKLY_REPORT_SENT', {
            ip:       req.ip,
            enviados: resultado.enviados,
            total:    resultado.total,
        });

        res.json({
            ok:        true,
            message:   `Reporte enviado a ${resultado.enviados} de ${resultado.total} destinatario(s)`,
            enviados:  resultado.enviados,
            total:     resultado.total,
            resultados: resultado.resultados,
            resumen: {
                periodo:            resultado.resumen?.periodo,
                rhMovimientos:      resultado.resumen?.rh?.total,
                hcActivos:          resultado.resumen?.hc?.activos,
                activosRegistrados: resultado.resumen?.activosRegistrados,
                minutasGeneradas:   resultado.resumen?.minutasGeneradas,
            },
        });
    } catch (err) {
        console.error('[FEAT-004] Error en /enviar-ahora:', err.message);
        res.status(500).json({ ok: false, error: 'Error enviando reporte semanal' });
    }
});

// ── Nebula Umbrales ─────────────────────────────────────────────
app.get('/api/nebula/umbrales', requireAuth, async (req, res) => {
    try {
        const doc = await db.collection('hub_nebula_config').findOne({ _id: 'umbrales' });
        if (!doc) {
            return res.json({
                ok: true,
                umbrales: {
                    cpu:   { warning: 70, danger: 90 },
                    ram:   { warning: 70, danger: 90 },
                    disco: { warning: 75, danger: 90 },
                },
                source: 'default',
            });
        }
        res.json({ ok: true, umbrales: doc.umbrales, source: 'db' });
    } catch (err) {
        console.error('[FEAT-003] GET /api/nebula/umbrales:', err.message);
        res.status(500).json({ ok: false, error: 'Error leyendo umbrales' });
    }
});

app.patch('/api/nebula/umbrales', requireAuth, async (req, res) => {
    const { rol } = req.usuario;
    if (!['ADMIN', 'GERENTE_OPERACIONES'].includes(rol))
        return res.status(403).json({ ok: false, error: 'Sin permiso para modificar umbrales' });
    try {
        const { umbrales } = req.body;
        const metricas = ['cpu', 'ram', 'disco'];
        for (const m of metricas) {
            if (!umbrales?.[m]) return res.status(400).json({ ok: false, error: `Falta métrica: ${m}` });
            const { warning, danger } = umbrales[m];
            if (typeof warning !== 'number' || typeof danger !== 'number')
                return res.status(400).json({ ok: false, error: `${m}: valores deben ser números` });
            if (warning < 0 || warning > 100 || danger < 0 || danger > 100)
                return res.status(400).json({ ok: false, error: `${m}: valores deben estar entre 0 y 100` });
            if (warning >= danger)
                return res.status(400).json({ ok: false, error: `${m}: warning debe ser menor que danger` });
        }
        await db.collection('hub_nebula_config').updateOne(
            { _id: 'umbrales' },
            { $set: { umbrales, updatedBy: req.usuario.username, updatedAt: new Date() } },
            { upsert: true }
        );
        res.json({ ok: true, message: 'Umbrales guardados' });
    } catch (err) {
        console.error('[FEAT-003] PATCH /api/nebula/umbrales:', err.message);
        res.status(500).json({ ok: false, error: 'Error guardando umbrales' });
    }
});

// ================================================================
// NOTIFICACIONES SSE
// ================================================================
const sseClients = new Map();
function sseAdd(username, res)    { if (!sseClients.has(username)) sseClients.set(username, new Set()); sseClients.get(username).add(res); }
function sseRemove(username, res) { const s = sseClients.get(username); if (!s) return; s.delete(res); if (s.size === 0) sseClients.delete(username); }
function ssePush(username, evento, datos) {
    const targets = new Set();
    if (username === '*') { sseClients.forEach(set => set.forEach(r => targets.add(r))); }
    else { sseClients.get(username)?.forEach(r => targets.add(r)); sseClients.get('*')?.forEach(r => targets.add(r)); }
    const payload = `event: notificacion\ndata: ${JSON.stringify({ ...datos, _ts: Date.now() })}\n\n`;
    targets.forEach(r => { try { r.write(payload); } catch { } });
}

app.get('/api/notificaciones/sse', requireAuthSSE, (req, res) => {
    res.setHeader('Content-Type',  'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache');
    res.setHeader('Connection',    'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.flushHeaders();
    const username = req.usuario.username;
    sseAdd(username, res);
    res.write(`event: connected\ndata: ${JSON.stringify({ status: 'ok', username })}\n\n`);
    const heartbeat = setInterval(() => { try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); } }, 25000);
    req.on('close', () => { clearInterval(heartbeat); sseRemove(username, res); });
});

app.get('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const { username } = req.usuario;
        const notifs = await db.collection('notificaciones').find({
            $or: [{ username }, { usuario_destino: username }, { usuario_destino: '*' }]
        }).sort({ createdAt: -1 }).limit(50).toArray();
        res.json({ notificaciones: notifs, total_no_leidas: notifs.filter(n => !n.leida).length });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo notificaciones' }); }
});

app.post('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const { titulo, mensaje, tipo = 'info', icono, tab_destino, subtab, usuario_destino } = req.body;
        if (!titulo || !mensaje) return res.status(400).json({ error: 'titulo y mensaje requeridos' });
        const notif = {
            titulo, mensaje, tipo, icono: icono || null,
            tab_destino: tab_destino || null, subtab: subtab || null,
            usuario_destino: usuario_destino || req.usuario.username,
            creadaPor: req.usuario.username, leida: false,
            createdAt: new Date()
        };
        const result = await db.collection('notificaciones').insertOne(notif);
        notif._id = result.insertedId;
        ssePush(notif.usuario_destino, 'notificacion', notif);
        res.status(201).json({ success: true, notificacion: notif });
    } catch (e) { res.status(500).json({ error: 'Error creando notificacion' }); }
});

app.patch('/api/notificaciones/leer-todas', requireAuth, async (req, res) => {
    try {
        await db.collection('notificaciones').updateMany(
            { $or: [{ username: req.usuario.username }, { usuario_destino: req.usuario.username }], leida: false },
            { $set: { leida: true, leidaEn: new Date() } }
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error marcando notificaciones' }); }
});

app.patch('/api/notificaciones/:id/leer', requireAuth, async (req, res) => {
    try {
        await db.collection('notificaciones').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { leida: true, leidaEn: new Date() } }
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error marcando notificacion' }); }
});

app.delete('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const result = await db.collection('notificaciones').deleteMany({
            $or: [{ username: req.usuario.username }, { usuario_destino: req.usuario.username }],
            leida: true
        });
        res.json({ success: true, eliminadas: result.deletedCount });
    } catch (e) { res.status(500).json({ error: 'Error eliminando notificaciones' }); }
});

// ================================================================
// RH — Movimientos
// ================================================================
app.get('/api/rh/movimientos', requireAuth, requirePermiso('rh.movimientos.ver'), async (req, res) => {
    try {
        const page  = Math.max(1, parseInt(req.query.page)  || 1);
        const limit = Math.min(200, Math.max(1, parseInt(req.query.limit) || 50));
        const skip  = (page - 1) * limit;
        const q = {};
        if (req.query.tipo)   q.tipo   = req.query.tipo;
        if (req.query.area)   q.area   = req.query.area;
        if (req.query.estado) q.estado = req.query.estado;
        if (req.query.desde || req.query.hasta) {
            q.createdAt = {};
            if (req.query.desde) { const d = new Date(req.query.desde); if (!isNaN(d)) q.createdAt.$gte = d; }
            if (req.query.hasta) { const h = new Date(req.query.hasta); if (!isNaN(h)) { h.setHours(23,59,59,999); q.createdAt.$lte = h; } }
            if (Object.keys(q.createdAt).length === 0) delete q.createdAt;
        }
        const [movimientos, total] = await Promise.all([
            db.collection('rh_movimientos').find(q).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
            db.collection('rh_movimientos').countDocuments(q)
        ]);
        res.json({
            ok: true, data: movimientos,
            paginacion: { total, page, limit, pages: Math.ceil(total / limit) || 1, hasNext: page * limit < total, hasPrev: page > 1 }
        });
    } catch (e) {
        console.error('[BUG-005] Error GET rh/movimientos:', e);
        res.status(500).json({ error: 'Error RH' });
    }
});

app.post('/api/rh/movimientos', requireAuth, requirePermiso('rh.movimientos.crear'), async (req, res) => {
    try {
        const m = { ...req.body, creadoPor: req.usuario.username, createdAt: new Date(), estado: 'pendiente' };
        await db.collection('rh_movimientos').insertOne(m);
        let emailDestino = req.usuario.email || '';
        try {
            const userDoc = await db.collection('users').findOne({ username: req.usuario.username }, { projection: { email: 1 } });
            if (userDoc?.email) emailDestino = userDoc.email;
        } catch (emailLookupErr) {
            console.warn(`[BUG-004] Error email lookup ${req.usuario.username}:`, emailLookupErr.message);
        }
        if (emailDestino) {
            enviarEmailMovimientoRH(m, emailDestino).catch(err => console.error('[Email] Error async:', err.message));
        }
        res.status(201).json({ success: true, movimiento: m });
    } catch (e) {
        console.error('Error POST rh/movimientos:', e);
        res.status(500).json({ error: 'Error RH' });
    }
});

app.put('/api/rh/movimientos/:id', requireAuth, requirePermiso('rh.movimientos.gestionar'), async (req, res) => {
    try {
        const r = await db.collection('rh_movimientos').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { ...req.body, updatedAt: new Date(), updatedBy: req.usuario.username } }
        );
        if (!r.matchedCount) return res.status(404).json({ error: 'No encontrado' });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error RH' }); }
});

app.patch('/api/rh/movimientos/:id/estado', requireAuth, requirePermiso('rh.movimientos.gestionar'), async (req, res) => {
    try {
        const { estado, comentario } = req.body;
        await db.collection('rh_movimientos').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { estado, comentario, updatedAt: new Date(), updatedBy: req.usuario.username } }
        );
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error RH' }); }
});

// ================================================================
// FORMATOS DE ACTIVACIÓN — XLSX real con ExcelJS [BUG-002]
// ================================================================
const _formatosCache = { sistemas: null, timestamp: 0, TTL: 5 * 60 * 1000 };
const SISTEMAS_ACTIVACION = [
    { id: 'SIEBEL',  nombre: 'Siebel CRM',            descripcion: 'Gestión de clientes y oportunidades',    status: 'available' },
    { id: 'CLARIFY', nombre: 'Clarify',                descripcion: 'Atención a clientes y casos de soporte', status: 'available' },
    { id: 'AMDOCS',  nombre: 'Amdocs',                 descripcion: 'Facturación y activaciones',             status: 'available' },
    { id: 'REMEDY',  nombre: 'Remedy / ITSM',          descripcion: 'Gestión de tickets internos',            status: 'available' },
    { id: 'GENESYS', nombre: 'Genesys Contact Center', descripcion: 'Plataforma de llamadas',                 status: 'available' },
];

app.get('/api/formatos/sistemas', requireAuth, requirePermiso('formatos.generar'), (req, res) => {
    try {
        const ahora = Date.now();
        if (_formatosCache.sistemas && (ahora - _formatosCache.timestamp) < _formatosCache.TTL)
            return res.json({ sistemas: _formatosCache.sistemas });
        const disponibles = SISTEMAS_ACTIVACION.filter(s => s.status === 'available');
        _formatosCache.sistemas = disponibles; _formatosCache.timestamp = ahora;
        return res.json({ sistemas: disponibles });
    } catch (error) {
        console.error('[formatos/sistemas] Error:', error);
        return res.status(500).json({ error: 'Error obteniendo lista de sistemas' });
    }
});

app.post('/api/formatos/generar', requireAuth, requirePermiso('formatos.generar'), async (req, res) => {
    try {
        const { sistema, userData } = req.body;
        if (!sistema || typeof sistema !== 'string') return res.status(400).json({ error: 'Campo requerido: sistema (string)' });
        if (!userData || typeof userData !== 'object') return res.status(400).json({ error: 'Campo requerido: userData (object)' });
        const sistemaInfo = SISTEMAS_ACTIVACION.find(s => s.id === sistema && s.status === 'available');
        if (!sistemaInfo) return res.status(404).json({ error: `Sistema "${sistema}" no encontrado o no disponible` });

        const workbook = new ExcelJS.Workbook();
        workbook.creator = 'WebApp Coordinación AT&T'; workbook.created = new Date(); workbook.modified = new Date();
        const sheet = workbook.addWorksheet('Formato Activación', { pageSetup: { paperSize: 9, orientation: 'portrait', fitToPage: true } });
        sheet.getColumn(1).width = 28; sheet.getColumn(2).width = 42;
        sheet.mergeCells('A1:B1');
        const titleCell = sheet.getCell('A1');
        titleCell.value = `FORMATO DE ACTIVACIÓN — ${sistemaInfo.nombre}`;
        titleCell.font = { name: 'Calibri', bold: true, size: 14, color: { argb: 'FFFFFFFF' } };
        titleCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FF00447C' } };
        titleCell.alignment = { horizontal: 'center', vertical: 'middle' };
        sheet.getRow(1).height = 32;
        sheet.mergeCells('A2:B2');
        const subCell = sheet.getCell('A2');
        subCell.value = `Generado: ${new Date().toLocaleString('es-MX')}   |   Sistema: ${sistema}`;
        subCell.font = { name: 'Calibri', italic: true, size: 10, color: { argb: 'FF555555' } };
        subCell.alignment = { horizontal: 'center', vertical: 'middle' };
        subCell.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: 'FFE8EEF5' } };
        sheet.getRow(2).height = 18;
        const campos = [
            { label: 'Nombre Completo',    value: userData.NOMBRE      || '' },
            { label: 'ATTUID',             value: userData.ATTUID       || '' },
            { label: 'Puesto',             value: userData.PUESTO       || '' },
            { label: 'Nombre PDV',         value: userData.PDV          || '' },
            { label: 'Clave PDV',          value: userData['CLAVE PDV'] || '' },
            { label: 'Organización',       value: userData.ORG          || '' },
            { label: 'Área',               value: userData.AREA         || '' },
            { label: 'Sistema Solicitado', value: sistemaInfo.nombre       },
            { label: 'Descripción',        value: sistemaInfo.descripcion  },
            { label: 'Fecha Solicitud',    value: new Date().toLocaleDateString('es-MX') },
        ];
        const borderStyle = {
            top: { style: 'thin', color: { argb: 'FFB0BEC5' } }, bottom: { style: 'thin', color: { argb: 'FFB0BEC5' } },
            left: { style: 'thin', color: { argb: 'FFB0BEC5' } }, right: { style: 'thin', color: { argb: 'FFB0BEC5' } },
        };
        campos.forEach((campo, idx) => {
            const rowNum = idx + 3; const row = sheet.getRow(rowNum); row.height = 22;
            const cellA = row.getCell(1);
            cellA.value = campo.label; cellA.font = { name: 'Calibri', bold: true, size: 11, color: { argb: 'FF00447C' } };
            cellA.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: idx % 2 === 0 ? 'FFEEF4FB' : 'FFFFFFFF' } };
            cellA.border = borderStyle; cellA.alignment = { vertical: 'middle' };
            const cellB = row.getCell(2);
            cellB.value = campo.value; cellB.font = { name: 'Calibri', size: 11 };
            cellB.fill = { type: 'pattern', pattern: 'solid', fgColor: { argb: idx % 2 === 0 ? 'FFEEF4FB' : 'FFFFFFFF' } };
            cellB.border = borderStyle; cellB.alignment = { vertical: 'middle', wrapText: true };
        });
        const firmaRow = campos.length + 3 + 2;
        sheet.mergeCells(`A${firmaRow}:B${firmaRow}`);
        const firmaCell = sheet.getCell(`A${firmaRow}`);
        firmaCell.value = '______________________________\nFirma de autorización';
        firmaCell.font = { name: 'Calibri', italic: true, size: 10, color: { argb: 'FF888888' } };
        firmaCell.alignment = { horizontal: 'center', vertical: 'middle', wrapText: true };
        sheet.getRow(firmaRow).height = 40;
        const safeAttuid = (userData.ATTUID || 'SIN_ATTUID').replace(/[^a-zA-Z0-9_-]/g, '_');
        const safeSistema = sistema.replace(/[^a-zA-Z0-9_-]/g, '_');
        const filename = `ACTIVACION_${safeSistema}_${safeAttuid}_${Date.now()}.xlsx`;
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        await workbook.xlsx.write(res); res.end();
        console.log(`[formatos/generar] ✅ Generado: ${filename}`);
    } catch (error) {
        console.error('[formatos/generar] ❌ Error:', error);
        if (!res.headersSent) return res.status(500).json({ error: 'Error generando formato: ' + error.message });
        res.end();
    }
});

app.post('/api/formatos/clear-cache', requireAuth, requirePermiso('formatos.generar'), (req, res) => {
    _formatosCache.sistemas = null; _formatosCache.timestamp = 0;
    console.log('[formatos/clear-cache] Cache limpiado por:', req.usuario?.username);
    return res.json({ success: true, message: 'Cache de formatos limpiado' });
});

// ── Dispositivos ───────────────────────────────────────────────
app.get('/api/devices', requireAuth, requirePermiso('dashboard.dispositivos'), async (req, res) => {
    try { res.json(await db.collection('dispositivos').find({}).toArray()); }
    catch (e) { res.status(500).json({ error: 'Error dispositivos' }); }
});

// ── Chat ───────────────────────────────────────────────────────
app.post('/api/chat', requireAuth, requirePermiso('chatbot.usar'), async (req, res) => {
    try {
        const { messages, system, max_tokens = 1000, temperature = 0.7 } = req.body;
        if (!messages || !Array.isArray(messages) || !messages.length)
            return res.status(400).json({ error: 'messages[] requerido' });
        db.collection('chat_logs').insertOne({ username: req.usuario.username, messages: messages.slice(-3), createdAt: new Date() }).catch(() => {});
        const anthropicKey = process.env.ANTHROPIC_API_KEY;
        if (anthropicKey) {
            try {
                const r = await fetch('https://api.anthropic.com/v1/messages', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json', 'x-api-key': anthropicKey, 'anthropic-version': '2023-06-01' },
                    body: JSON.stringify({
                        model: 'claude-3-haiku-20240307', max_tokens,
                        system: system || 'Eres un asistente del dashboard MYG Telecom. Responde en español conciso.',
                        messages: messages.map(m => ({ role: m.role, content: m.content }))
                    }),
                });
                if (r.ok) { const data = await r.json(); return res.json({ ...data, _provider: 'anthropic' }); }
            } catch (aiErr) { console.error('Anthropic error:', aiErr.message); }
        }
        res.status(503).json({ error: 'IA no configurada. Configura ANTHROPIC_API_KEY.' });
    } catch (e) { res.status(500).json({ error: 'Error en chat' }); }
});

// ================================================================
// HUB — Helpers CRUD genéricos v4.4
// ================================================================
const COLECCIONES_CON_AREA = new Set([
    'hub_tareas','hub_minutas','hub_anuncios','hub_recursos','hub_guias','hub_plantillas',
]);
const ROLES_GESTORES_HUB = new Set(['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR']);

// Elimina claves peligrosas del body antes de insertar en MongoDB.
// Previene prototype pollution y acceso a campos internos.
const _BLOCKED_KEYS = new Set(['__proto__', 'constructor', 'prototype', '_id', 'creadoPor', 'createdAt', 'updatedAt', 'updatedBy']);
function _sanitizeBody(body) {
    if (!body || typeof body !== 'object') return {};
    return Object.fromEntries(
        Object.entries(body).filter(([k]) => !_BLOCKED_KEYS.has(k))
    );
}

function hubGet(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const limit  = Math.min(parseInt(req.query.limit)  || 100, 500);
            const page   = Math.max(parseInt(req.query.page)   || 1,   1);
            const skip   = (page - 1) * limit;
            const filter = {};
            if (req.query.username) filter.username = req.query.username;
            if (req.query.mes)      filter.mes      = req.query.mes;
            if (req.query.estado)   filter.estado   = req.query.estado;
            if (COLECCIONES_CON_AREA.has(col) && req.query.area) {
                const area = req.query.area;
                if (area === 'Sistemas') {
                    filter.$or = [{ area: 'Sistemas' }, { area: { $exists: false } }, { area: null }];
                } else { filter.area = area; }
            }
            const [data, total] = await Promise.all([
                db.collection(col).find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit).toArray(),
                db.collection(col).countDocuments(filter),
            ]);
            res.json({ data, paginacion: { total, page, limit, pages: Math.ceil(total / limit), hasNext: skip + limit < total } });
        } catch (e) { res.status(500).json({ error: `Error ${col}` }); }
    }];
}

function hubPost(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const safe = _sanitizeBody(req.body);
            const areaDefault = COLECCIONES_CON_AREA.has(col) && !safe.area ? 'Sistemas' : undefined;
            const doc = { ...safe, ...(areaDefault !== undefined && { area: areaDefault }), creadoPor: req.usuario.username, createdAt: new Date() };
            const result = await db.collection(col).insertOne(doc);
            res.status(201).json({ success: true, id: result.insertedId, doc });
        } catch (e) { res.status(500).json({ error: `Error ${col}` }); }
    }];
}

function hubPatch(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ error: `ID inválido: "${id}"` });
            const doc = await db.collection(col).findOne({ _id: new ObjectId(id) }, { projection: { creadoPor: 1 } });
            if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
            if (!ROLES_GESTORES_HUB.has(req.usuario.rol) && doc.creadoPor !== req.usuario.username)
                return res.status(403).json({ error: 'No tienes permiso para editar registros de otros usuarios.' });
            const updates = _sanitizeBody(req.body);
            if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No se enviaron campos a actualizar' });
            await db.collection(col).updateOne({ _id: new ObjectId(id) }, { $set: { ...updates, updatedAt: new Date(), updatedBy: req.usuario.username } });
            res.json({ success: true });
        } catch (e) {
            console.error(`[hubPatch] ${col} — ${e.message}`);
            res.status(500).json({ error: `Error actualizando en ${col}` });
        }
    }];
}

function hubDelete(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ error: `ID inválido: "${id}"` });
            const doc = await db.collection(col).findOne({ _id: new ObjectId(id) }, { projection: { creadoPor: 1 } });
            if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
            if (!ROLES_GESTORES_HUB.has(req.usuario.rol) && doc.creadoPor !== req.usuario.username)
                return res.status(403).json({ error: 'No tienes permiso para eliminar registros de otros usuarios.' });
            await db.collection(col).deleteOne({ _id: new ObjectId(id) });
            console.log(`[${col}] Eliminado: ${id} por ${req.usuario.username}`);
            res.json({ success: true });
        } catch (e) {
            console.error(`[hubDelete] ${col} — ${e.message}`);
            res.status(500).json({ error: `Error eliminando en ${col}` });
        }
    }];
}

// ── Hub general ────────────────────────────────────────────────
app.get('/api/hub/general', requireAuth, requirePermiso('hub.acceso'), async (req, res) => {
    try {
        const [reuniones, tareas, minutas, anuncios, recursos, guias, plantillas, capacitacion] = await Promise.all([
            db.collection('hub_reuniones').countDocuments(), db.collection('hub_tareas').countDocuments(),
            db.collection('hub_minutas').countDocuments(), db.collection('hub_anuncios').countDocuments(),
            db.collection('hub_recursos').countDocuments(), db.collection('hub_guias').countDocuments(),
            db.collection('hub_plantillas').countDocuments(), db.collection('hub_capacitacion').countDocuments(),
        ]);
        const anunciosRecientes = await db.collection('hub_anuncios').find({}).sort({ createdAt: -1 }).limit(100).toArray();
        res.json({ conteos: { reuniones, tareas, minutas, anuncios, recursos, guias, plantillas, capacitacion }, anunciosRecientes });
    } catch (e) { res.status(500).json({ error: 'Error hub general' }); }
});

// ── Reuniones ──────────────────────────────────────────────────
app.get('/api/hub/reuniones', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { usuario } = req;
        const limit   = Math.min(parseInt(req.query.limit) || 200, 500);
        const verTodo = ['ADMIN', 'GERENTE_OPERACIONES'].includes(usuario.rol) || (usuario.permisos || []).includes('*');
        const filter  = verTodo ? {} : {
            $or: [{ organizer: usuario.username }, { creadoPor: usuario.username }, { invitadoUsernames: usuario.username }],
        };
        const docs = await db.collection('hub_reuniones').find(filter).sort({ date: -1, time: -1 }).limit(limit).toArray();
        res.json(docs);
    } catch (e) { console.error('Error GET hub_reuniones:', e); res.status(500).json({ error: 'Error obteniendo reuniones' }); }
});

app.post('/api/hub/reuniones/serie', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { reunionOrigenId, nuevaFecha, nuevaHora, recurrencia, cantidadOcurrencias, titulo, agenda } = req.body;
        if (!nuevaFecha || !nuevaHora) return res.status(400).json({ error: 'nuevaFecha y nuevaHora son requeridos' });
        const cantidad = Math.min(Math.max(parseInt(cantidadOcurrencias) || 1, 1), 52);
        let reunionOrigen = null;
        if (reunionOrigenId && ObjectId.isValid(reunionOrigenId))
            reunionOrigen = await db.collection('hub_reuniones').findOne({ _id: new ObjectId(reunionOrigenId) });
        const serieId = reunionOrigen?.serieId || `serie_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`;
        if (reunionOrigen && !reunionOrigen.serieId)
            await db.collection('hub_reuniones').updateOne({ _id: new ObjectId(reunionOrigenId) }, { $set: { serieId, esOrigenSerie: true, updatedAt: new Date() } });
        const { _id: _oid, grabandoPor: _gp, grabacionInicio: _gi, ...baseFields } = reunionOrigen || {};
        const docs = [];
        for (let i = 0; i < cantidad; i++) {
            const fecha = new Date(nuevaFecha + 'T00:00:00');
            const { tipo = 'semanal', intervalo = 1 } = recurrencia || {};
            if (i > 0) {
                if (tipo === 'semanal') fecha.setDate(fecha.getDate() + 7 * i);
                else if (tipo === 'mensual') fecha.setMonth(fecha.getMonth() + i);
                else if (tipo === 'dias') fecha.setDate(fecha.getDate() + intervalo * i);
            }
            docs.push({
                ...baseFields,
                title: titulo || `${baseFields.title || 'Reunión'} — Seguimiento ${i + 1}`,
                date: fecha.toISOString().split('T')[0], time: nuevaHora,
                agenda: agenda || baseFields.agenda || '', status: 'programada',
                serieId, reunionOrigenId: reunionOrigenId || null, recurrencia: recurrencia || null,
                numeracionSerie: i + 1, totalSerie: cantidad,
                organizer: req.usuario.username, creadoPor: req.usuario.username,
                organizerArea: req.usuario.area || baseFields.organizerArea || null,
                invitadoUsernames: baseFields.invitadoUsernames || [], attendees: baseFields.attendees || [],
                createdAt: new Date(),
            });
        }
        const result = await db.collection('hub_reuniones').insertMany(docs, { ordered: true });
        const todosInvitados = [...new Set((baseFields.invitadoUsernames || []))];
        todosInvitados.forEach(uname => {
            if (uname === req.usuario.username) return;
            ssePush(uname, 'notificacion', { titulo: '📅 Nueva serie de reuniones', mensaje: `${cantidad} reunión(es) de seguimiento programadas desde ${nuevaFecha}`, tipo: 'reunion', icono: '🔄', tab_destino: 'hub', subtab: 'meetings' });
        });
        console.log(`[Serie] Creada: ${serieId} — ${result.insertedCount} reuniones por ${req.usuario.username}`);
        res.status(201).json({ success: true, serieId, creadas: result.insertedCount, reuniones: docs.map((d, i) => ({ ...d, _id: result.insertedIds[i] })) });
    } catch (e) { console.error('Error POST reuniones/serie:', e); res.status(500).json({ error: 'Error creando serie de reuniones' }); }
});

app.get('/api/hub/reuniones/serie/:serieId', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { serieId } = req.params; const { usuario } = req;
        const verTodo = ['ADMIN', 'GERENTE_OPERACIONES'].includes(usuario.rol) || (usuario.permisos || []).includes('*');
        const filter = { serieId };
        if (!verTodo) filter.$or = [{ organizer: usuario.username }, { creadoPor: usuario.username }, { invitadoUsernames: usuario.username }];
        const reuniones = await db.collection('hub_reuniones').find(filter).sort({ date: 1, numeracionSerie: 1 }).toArray();
        res.json(reuniones);
    } catch (e) { console.error('Error GET serie:', e); res.status(500).json({ error: 'Error obteniendo serie de reuniones' }); }
});

app.post('/api/hub/reuniones',       ...hubPost  ('hub_reuniones', 'hub.reuniones'));
app.patch('/api/hub/reuniones/:id',  ...hubPatch ('hub_reuniones', 'hub.reuniones'));
app.delete('/api/hub/reuniones/:id', ...hubDelete('hub_reuniones', 'hub.reuniones'));

app.get('/api/hub/usuarios-reunion', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { usuario } = req; const rol = usuario.rol; const area = usuario.area;
        const todos = await db.collection('users').find({ activo: true }, { projection: { password: 0 } }).toArray();
        const toInfo = (u) => ({ username: u.username, nombre: u.nombre, rol: normalizarRol(u.rol), area: u.area || null });
        const miArea = todos.filter(u => u.username !== usuario.username && u.area === area).map(toInfo);
        const puedeInvitarCruzado = ['ADMIN','GERENTE_OPERACIONES','COORDINADOR'].includes(rol);
        let otrosCoordi = [], gerencia = [];
        if (puedeInvitarCruzado) {
            otrosCoordi = todos.filter(u => u.username !== usuario.username && u.area !== area && normalizarRol(u.rol) === 'COORDINADOR').map(toInfo);
            gerencia    = todos.filter(u => u.username !== usuario.username && ['ADMIN','GERENTE_OPERACIONES'].includes(normalizarRol(u.rol))).map(toInfo);
        }
        res.json({ miArea, otrosCoordi, gerencia });
    } catch (e) { console.error('Error usuarios-reunion:', e); res.status(500).json({ error: 'Error obteniendo usuarios para reunión' }); }
});

// ── IA Minutas ─────────────────────────────────────────────────
const buildMinutaPrompt = ({ transcript, meetingTitle, meetingDate, meetingTime, attendees, agenda, duracion, notasAdicionales, modoAudio }) => {
    const durMin = Math.ceil((duracion || 0) / 60);
    const asistentes = Array.isArray(attendees) ? attendees.join(', ') : (attendees || 'No especificados');
    const hasTranscript = transcript && transcript.trim().length > 5;
    const transcriptText = hasTranscript ? transcript.trim() : '(Sin transcripción de voz — usar contexto de la agenda y notas del organizador)';
    const notasText = notasAdicionales?.trim() ? `\nNOTAS DEL ORGANIZADOR:\n${notasAdicionales.trim()}` : '';
    const modoText  = modoAudio === 'sistema' ? ' (grabación de reunión virtual — todos los participantes)' : ' (micrófono local)';

    const systemPrompt = `Eres el secretario ejecutivo corporativo de MYG Telecom, empresa mexicana de telecomunicaciones.
Tu función es redactar minutas ejecutivas formales, precisas y accionables en español mexicano profesional para el área de Sistemas/IT.

REGLAS CRÍTICAS — DEBES SEGUIRLAS AL PIE DE LA LETRA:
1. Responde ÚNICAMENTE con JSON válido. Cero backticks, cero texto fuera del JSON.
2. Español mexicano formal. Sin anglicismos innecesarios.
3. "tipoReunion": clasifica el tipo usando SOLO uno de estos valores exactos: seguimiento, kickoff, retrospectiva, planificacion, revision, urgente, capacitacion, otro
4. "resumen": párrafo ejecutivo de 3-6 oraciones. Debe capturar: objetivo principal, temas clave tratados, y resultado o estado general. NO es una lista — es prosa ejecutiva fluida.
5. "temasTratados": array de strings, uno por tema identificado. Formato: "Nombre del tema: breve descripción de lo discutido". Mínimo 1, máximo 8.
6. "decisions": string con bullet points "•". Solo decisiones CONCRETAS y CONFIRMADAS. Si no hay, dejar vacío "".
7. "acciones": array de objetos con exactamente 3 campos: responsable (nombre o rol), accion (qué debe hacer), fechaLimite (cuándo, o "" si no se mencionó).
8. "proximaReunion": string con fecha, hora y objetivo de la siguiente reunión. Si no se mencionó, dejar vacío "".
9. "observaciones": notas adicionales, contexto importante, riesgos identificados. Si no hay, dejar vacío "".
10. NO inventes información que no esté en la transcripción o notas. Si un campo no tiene datos suficientes, escribe "".`;

    const userPrompt = `Genera la minuta ejecutiva para esta reunión de MYG Telecom:

METADATOS:
- Título: ${meetingTitle || 'Reunión de Sistemas MYG Telecom'}
- Fecha: ${meetingDate || 'No especificada'}${meetingTime ? ' a las ' + meetingTime : ''}
- Duración: ${durMin > 0 ? durMin + ' minutos' : 'No registrada'}
- Asistentes: ${asistentes}
- Agenda previa: ${agenda || 'No especificada'}
- Modo de grabación: ${modoText}${notasText}

TRANSCRIPCIÓN:
${transcriptText}

Responde con EXACTAMENTE este JSON (sin backticks, sin texto adicional):
{
  "title": "Minuta: ${meetingTitle || 'Reunión de Sistemas'}",
  "tipoReunion": "seguimiento",
  "resumen": "Párrafo ejecutivo de 3-6 oraciones sobre temas tratados, decisiones clave y resultado general",
  "temasTratados": ["Tema 1: descripción de lo discutido", "Tema 2: descripción"],
  "decisions": "• Primera decisión concreta\\n• Segunda decisión concreta",
  "acciones": [
    {"responsable": "Nombre o Rol", "accion": "Descripción clara de la acción", "fechaLimite": "fecha o plazo"},
    {"responsable": "Nombre o Rol", "accion": "Otra acción", "fechaLimite": ""}
  ],
  "proximaReunion": "Fecha, hora y objetivo de la siguiente reunión, o vacío",
  "observaciones": "Notas adicionales, riesgos, contexto relevante, o vacío"
}`;

    return { system: systemPrompt, user: userPrompt };
};

const generarConGroq = async (pd) => {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) throw new Error('GROQ_API_KEY no configurada');
    const p = buildMinutaPrompt(pd);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 22000);
    try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
            signal: controller.signal,
            body: JSON.stringify({ model: 'llama-3.3-70b-versatile', max_tokens: 2000, temperature: 0.25, messages: [{ role: 'system', content: p.system }, { role: 'user', content: p.user }], response_format: { type: 'json_object' } }),
        });
        clearTimeout(timeout);
        if (!response.ok) { const errBody = await response.text().catch(() => ''); throw new Error(`Groq HTTP ${response.status}: ${errBody.slice(0, 200)}`); }
        const data = await response.json();
        const content = data.choices?.[0]?.message?.content || '';
        if (!content) throw new Error('Groq devolvió respuesta vacía');
        const parsed = JSON.parse(content.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim());
        if (!parsed || typeof parsed !== 'object') throw new Error('JSON inválido de Groq');
        return parsed;
    } finally { clearTimeout(timeout); }
};

const generarConGemini = async (pd) => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error('GEMINI_API_KEY no configurada');
    const p = buildMinutaPrompt(pd);
    if (GoogleGenerativeAI) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 22000);
        try {
            const model = new GoogleGenerativeAI(apiKey).getGenerativeModel({ model: 'gemini-2.0-flash', generationConfig: { temperature: 0.25, maxOutputTokens: 2000, responseMimeType: 'application/json' }, systemInstruction: p.system });
            const result = await model.generateContent(p.user);
            clearTimeout(timeout);
            const text = result.response.text().replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim();
            const parsed = JSON.parse(text);
            if (!parsed || typeof parsed !== 'object') throw new Error('JSON inválido de Gemini');
            return parsed;
        } finally { clearTimeout(timeout); }
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 22000);
    try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
        const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal, body: JSON.stringify({ contents: [{ parts: [{ text: p.user }] }], systemInstruction: { parts: [{ text: p.system }] }, generationConfig: { temperature: 0.25, maxOutputTokens: 2000, responseMimeType: 'application/json' } }) });
        clearTimeout(timeout);
        if (!response.ok) throw new Error(`Gemini HTTP ${response.status}`);
        const data = await response.json();
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!text) throw new Error('Gemini devolvió respuesta vacía');
        return JSON.parse(text.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim());
    } finally { clearTimeout(timeout); }
};

const generarConReglasLocales = (pd) => {
    const { transcript = '', meetingTitle = 'Reunión', meetingDate = '', meetingTime = '', attendees = [], agenda = '', duracion = 0, notasAdicionales = '' } = pd;
    const durMin = Math.ceil(duracion / 60);
    const fuenteTexto = [transcript, notasAdicionales].filter(Boolean).join(' ').trim();
    const textoLimpio = fuenteTexto.replace(/\[\d{2}:\d{2}(:\d{2})?\]\s*/g, '');
    const oraciones   = textoLimpio.split(/[.!?;]\s+/).map(s => s.trim()).filter(s => s.length > 15);
    const stopwords   = new Set(['el','la','los','las','un','una','de','del','en','y','a','que','se','es','no','con','por','para','como','mas','pero','su','sus','al','lo','le','les','este','esta','estos','estas']);
    const score = s => new Set(s.toLowerCase().split(/\s+/).filter(w => !stopwords.has(w) && w.length > 3)).size;
    const mejoresOraciones = oraciones.map(o => ({ text: o, score: score(o) })).sort((a, b) => b.score - a.score).slice(0, 5).map(o => o.text + '.');
    const decisiones = oraciones.filter(o => /\b(se decide|se acuerda|se aprueba|quedamos|acordamos|decidimos|se autoriza)\b/i.test(o)).slice(0, 5).map(d => `• ${d.trim().replace(/\.$/, '')}.`);
    const accionesObjs = oraciones.filter(o => /\b(pendiente|entregar|revisar|enviar|actualizar|verificar|contactar|coordinar|preparar|elaborar|subir|bajar|migrar)\b/i.test(o)).slice(0, 6).map(a => ({ responsable: '', accion: a.trim().replace(/\.$/, ''), fechaLimite: '' }));
    const temasTratados = [];
    if (agenda) { agenda.split(/[,;]/).map(t => t.trim()).filter(Boolean).slice(0, 5).forEach(t => temasTratados.push(`${t}: discutido durante la reunión`)); }
    else if (mejoresOraciones.length > 0) { temasTratados.push(`Temas generales: ${mejoresOraciones[0]}`); }
    if (temasTratados.length === 0) temasTratados.push('Temas de la reunión: ver transcripción');
    const agendaTexto = agenda ? `Agenda: ${agenda}.` : '';
    const resumenBase = mejoresOraciones.length > 0 ? mejoresOraciones.slice(0, 3).join(' ') : `Reunión "${meetingTitle}" del ${meetingDate}${meetingTime ? ' a las ' + meetingTime : ''}. ${agendaTexto} Duración: ${durMin} min. Por favor complementa los detalles.`;
    return { title: `Minuta: ${meetingTitle}`, tipoReunion: 'seguimiento', resumen: resumenBase, temasTratados, decisions: decisiones.join('\n') || '', acciones: accionesObjs, proximaReunion: '', observaciones: `Reunión de ${durMin > 0 ? durMin + ' min' : 'duración no registrada'} con ${Array.isArray(attendees) ? attendees.length : 0} asistente(s).${notasAdicionales ? ' Notas: ' + notasAdicionales : ''}`.trim() };
};

app.post('/api/hub/reuniones/:id/transcribir-audio', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { audio, mimeType = 'audio/webm', duracion = 0, lang = 'es' } = req.body;
        const apiKey = process.env.GROQ_API_KEY;
        if (!apiKey) return res.status(503).json({ error: 'GROQ_API_KEY no configurada para Whisper' });
        if (!audio)  return res.status(400).json({ error: 'Campo audio (base64) requerido' });
        const audioBuffer = Buffer.from(audio, 'base64');
        if (audioBuffer.length < 1000) return res.status(400).json({ error: 'Audio demasiado corto para transcribir' });
        const extMap = { 'audio/webm': 'webm', 'audio/webm;codecs=opus': 'webm', 'audio/ogg': 'ogg', 'audio/ogg;codecs=opus': 'ogg', 'audio/mp4': 'm4a', 'audio/mpeg': 'mp3', 'audio/wav': 'wav' };
        const ext = extMap[mimeType] || extMap[mimeType.split(';')[0]] || 'webm';
        const formData = new FormData(); const blob = new Blob([audioBuffer], { type: mimeType });
        formData.append('file', blob, `reunion-${Date.now()}.${ext}`);
        formData.append('model', 'whisper-large-v3-turbo'); formData.append('language', lang || 'es');
        formData.append('response_format', 'verbose_json'); formData.append('temperature', '0');
        const controller = new AbortController(); const timeout = setTimeout(() => controller.abort(), 300000);
        try {
            const response = await fetch('https://api.groq.com/openai/v1/audio/transcriptions', { method: 'POST', headers: { 'Authorization': `Bearer ${apiKey}` }, body: formData, signal: controller.signal });
            clearTimeout(timeout);
            if (!response.ok) { const errText = await response.text().catch(() => ''); throw new Error(`Groq Whisper HTTP ${response.status}: ${errText.slice(0, 300)}`); }
            const data = await response.json();
            const transcript = data.text || '';
            const segments   = (data.segments || []).map(s => ({ start: s.start || 0, end: s.end || 0, text: (s.text || '').trim() }));
            console.log(`[Whisper] ${transcript.length} chars, ${segments.length} segmentos, ${Math.round(audioBuffer.length / 1024)}KB`);
            res.json({ transcript, segments, duracion, idioma: data.language || lang });
        } finally { clearTimeout(timeout); }
    } catch (err) {
        console.error('[Whisper] Error:', err.message);
        if (err.name === 'AbortError') return res.status(504).json({ error: 'Timeout transcribiendo audio — intenta con grabaciones más cortas' });
        res.status(500).json({ error: `Error en transcripción: ${err.message}` });
    }
});

app.post('/api/hub/reuniones/:id/generar-minuta', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { transcript = '', meetingTitle, meetingDate, meetingTime, attendees, agenda, duracion, notasAdicionales = '', modoAudio = 'microfono', usóWhisper = false } = req.body;
        const transcriptUtil = transcript.trim();
        const pd = { transcript: transcriptUtil, meetingTitle, meetingDate, meetingTime, attendees, agenda, duracion, notasAdicionales, modoAudio, usóWhisper };
        const sinContenido = !transcriptUtil && !notasAdicionales.trim() && !agenda;
        if (sinContenido) { const local = generarConReglasLocales(pd); return res.json({ ...local, _proveedor: 'local', _aviso: 'Sin transcripción. Completa los campos manualmente.' }); }
        const forced = process.env.AI_PROVIDER;
        const cadena = [
            { nombre: 'groq',   fn: generarConGroq,                       activo: !forced || forced === 'groq',   tiene_key: !!process.env.GROQ_API_KEY  },
            { nombre: 'gemini', fn: generarConGemini,                      activo: !forced || forced === 'gemini', tiene_key: !!process.env.GEMINI_API_KEY },
            { nombre: 'local',  fn: async d => generarConReglasLocales(d), activo: true,                           tiene_key: true                         },
        ];
        let resultado = null; let ultimoError = null;
        for (const proveedor of cadena) {
            if (!proveedor.activo || !proveedor.tiene_key) { console.log(`[MinutaIA] ${proveedor.nombre} omitido`); continue; }
            try {
                console.log(`[MinutaIA] Intentando ${proveedor.nombre}...`);
                const t0 = Date.now(); resultado = await proveedor.fn(pd); const ms = Date.now() - t0;
                if (!resultado || typeof resultado !== 'object') throw new Error('Respuesta inválida');
                if (!resultado.title && !resultado.resumen) throw new Error('Respuesta sin campos esperados');
                resultado._proveedor = proveedor.nombre; resultado._ms = ms;
                console.log(`[MinutaIA] ✅ ${proveedor.nombre} en ${ms}ms`); break;
            } catch (err) {
                console.warn(`[MinutaIA] ⚠️ ${proveedor.nombre} falló: ${err.message}`); ultimoError = err;
                if (err.message?.includes('429') || err.message?.includes('rate_limit')) await new Promise(r => setTimeout(r, 2000));
            }
        }
        if (!resultado) throw ultimoError || new Error('Todos los proveedores fallaron');
        const { _ms, ...respuesta } = resultado;
        console.log(`[MinutaIA] Enviado (proveedor=${respuesta._proveedor}, ${_ms}ms, ${transcriptUtil.length}chars)`);
        res.json(respuesta);
    } catch (err) { console.error('[MinutaIA] Error fatal:', err.message); res.status(500).json({ error: `Error generando minuta: ${err.message}` }); }
});

// ── Tareas / Minutas / Anuncios / Recursos / Guías / Plantillas ─
app.get('/api/hub/tareas',           ...hubGet   ('hub_tareas',     'hub.tareas'));
app.post('/api/hub/tareas',          ...hubPost  ('hub_tareas',     'hub.tareas'));
app.patch('/api/hub/tareas/:id',     ...hubPatch ('hub_tareas',     'hub.tareas'));
app.delete('/api/hub/tareas/:id',    ...hubDelete('hub_tareas',     'hub.tareas'));

app.get('/api/hub/minutas', requireAuth, requirePermiso('hub.minutas'), async (req, res) => {
    try {
        const { usuario } = req; const limit = Math.min(parseInt(req.query.limit) || 100, 500);
        const area = req.query.area || usuario.area || 'Sistemas';
        let areaFilter;
        if (area === 'Sistemas') { areaFilter = { $or: [{ area: 'Sistemas' }, { area: { $exists: false } }, { area: null }] }; }
        else { areaFilter = { area }; }
        const verTodo = ['ADMIN','GERENTE_OPERACIONES'].includes(usuario.rol) || (usuario.permisos || []).includes('*');
        let filter;
        if (verTodo) { filter = req.query.area ? areaFilter : {}; }
        else { filter = { $or: [areaFilter, { invitadoUsernames: usuario.username }] }; }
        if (req.query.estado) filter.estado = req.query.estado;
        const docs = await db.collection('hub_minutas').find(filter).sort({ createdAt: -1 }).limit(limit).toArray();
        res.json(docs);
    } catch (e) { res.status(500).json({ error: 'Error hub_minutas' }); }
});
app.post('/api/hub/minutas',         ...hubPost  ('hub_minutas',    'hub.minutas'));
app.patch('/api/hub/minutas/:id',    ...hubPatch ('hub_minutas',    'hub.minutas'));
app.delete('/api/hub/minutas/:id',   ...hubDelete('hub_minutas',    'hub.minutas'));

app.get('/api/hub/anuncios',         ...hubGet   ('hub_anuncios',   'hub.anuncios'));
app.post('/api/hub/anuncios',        ...hubPost  ('hub_anuncios',   'hub.anuncios'));
app.patch('/api/hub/anuncios/:id',   ...hubPatch ('hub_anuncios',   'hub.anuncios'));
app.delete('/api/hub/anuncios/:id',  ...hubDelete('hub_anuncios',   'hub.anuncios'));

app.get('/api/hub/recursos',         ...hubGet   ('hub_recursos',   'hub.recursos'));
app.post('/api/hub/recursos',        ...hubPost  ('hub_recursos',   'hub.recursos'));
app.patch('/api/hub/recursos/:id',   ...hubPatch ('hub_recursos',   'hub.recursos'));
app.delete('/api/hub/recursos/:id',  ...hubDelete('hub_recursos',   'hub.recursos'));

app.get('/api/hub/guias',            ...hubGet   ('hub_guias',      'hub.guias'));
app.post('/api/hub/guias',           ...hubPost  ('hub_guias',      'hub.guias'));
app.patch('/api/hub/guias/:id',      ...hubPatch ('hub_guias',      'hub.guias'));
app.delete('/api/hub/guias/:id',     ...hubDelete('hub_guias',      'hub.guias'));

app.get('/api/hub/plantillas',       ...hubGet   ('hub_plantillas', 'hub.plantillas'));
app.post('/api/hub/plantillas',      ...hubPost  ('hub_plantillas', 'hub.plantillas'));
app.patch('/api/hub/plantillas/:id', ...hubPatch ('hub_plantillas', 'hub.plantillas'));
app.delete('/api/hub/plantillas/:id',...hubDelete('hub_plantillas', 'hub.plantillas'));

app.get('/api/hub/capacitacion',         ...hubGet   ('hub_capacitacion', 'hub.capacitacion'));
app.post('/api/hub/capacitacion',        ...hubPost  ('hub_capacitacion', 'hub.capacitacion'));
app.patch('/api/hub/capacitacion/:id',   ...hubPatch ('hub_capacitacion', 'hub.capacitacion'));
app.delete('/api/hub/capacitacion/:id',  ...hubDelete('hub_capacitacion', 'hub.capacitacion'));

// ── Minutas comentarios/acciones ───────────────────────────────
app.post('/api/hub/minutas/:minutaId/comentarios', requireAuth, requirePermiso('hub.minutas'), async (req, res) => {
    try {
        const comentario = { ...req.body, autor: req.usuario.username, createdAt: new Date() };
        await db.collection('hub_minutas').updateOne({ _id: new ObjectId(req.params.minutaId) }, { $push: { comentarios: comentario } });
        res.status(201).json({ success: true, comentario });
    } catch (e) { res.status(500).json({ error: 'Error comentario' }); }
});

app.patch('/api/hub/minutas/:minutaId/acciones/:itemId', requireAuth, requirePermiso('hub.minutas'), async (req, res) => {
    try {
        const { minutaId, itemId } = req.params;
        if (!ObjectId.isValid(minutaId)) return res.status(400).json({ error: 'minutaId inválido' });
        const minuta = await db.collection('hub_minutas').findOne({ _id: new ObjectId(minutaId) });
        if (!minuta) return res.status(404).json({ error: 'Minuta no encontrada' });
        const useField = minuta.actionItems ? 'actionItems' : 'acciones';
        const items = (minuta.actionItems || minuta.acciones || []);
        let found = false;
        const updated = items.map(a => {
            const matchId = a.id === itemId || a._id?.toString() === itemId;
            if (!matchId) return a; found = true;
            const bodyKeys = Object.keys(req.body || {});
            if (bodyKeys.length > 0) return { ...a, ...req.body, updatedAt: new Date() };
            return { ...a, done: !a.done, updatedAt: new Date() };
        });
        if (!found) return res.status(404).json({ error: `Acción con id "${itemId}" no encontrada en esta minuta` });
        await db.collection('hub_minutas').updateOne({ _id: new ObjectId(minutaId) }, { $set: { [useField]: updated, updatedAt: new Date(), updatedBy: req.usuario.username } });
        console.log(`[Minutas] Acción ${itemId} actualizada en ${minutaId} por ${req.usuario.username}`);
        res.json({ success: true, updated: updated.find(a => a.id === itemId || a._id?.toString() === itemId) });
    } catch (e) { console.error('Error toggleAccion:', e); res.status(500).json({ error: 'Error actualizando acción de minuta' }); }
});

app.patch('/api/hub/reuniones/:id/grabacion', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { id } = req.params; const { accion } = req.body; const { username, rol } = req.usuario;
        if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'ID de reunión inválido' });
        if (!['iniciar', 'finalizar'].includes(accion)) return res.status(400).json({ error: 'accion debe ser "iniciar" o "finalizar"' });
        const reunion = await db.collection('hub_reuniones').findOne({ _id: new ObjectId(id) });
        if (!reunion) return res.status(404).json({ error: 'Reunión no encontrada' });
        const esParticipante = reunion.organizer === username || reunion.creadoPor === username || (reunion.invitadoUsernames || []).includes(username) || ['ADMIN', 'GERENTE_OPERACIONES'].includes(rol);
        if (!esParticipante) return res.status(403).json({ error: 'No eres participante de esta reunión' });
        if (accion === 'iniciar') {
            if (reunion.grabandoPor && reunion.grabandoPor !== username)
                return res.status(409).json({ error: `${reunion.grabandoPor} ya está grabando esta reunión. Espera a que finalice.`, grabandoPor: reunion.grabandoPor, grabacionInicio: reunion.grabacionInicio });
            await db.collection('hub_reuniones').updateOne({ _id: new ObjectId(id) }, { $set: { grabandoPor: username, grabacionInicio: new Date(), updatedAt: new Date() } });
            console.log(`[Reuniones] Grabación iniciada: reunión=${id} por ${username}`);
            return res.json({ success: true, grabandoPor: username, grabacionInicio: new Date() });
        }
        if (reunion.grabandoPor && reunion.grabandoPor !== username && rol !== 'ADMIN')
            return res.status(403).json({ error: `Solo ${reunion.grabandoPor} puede finalizar esta grabación` });
        await db.collection('hub_reuniones').updateOne({ _id: new ObjectId(id) }, { $unset: { grabandoPor: '', grabacionInicio: '' }, $set: { updatedAt: new Date() } });
        console.log(`[Reuniones] Grabación finalizada: reunión=${id} por ${username}`);
        return res.json({ success: true });
    } catch (e) { console.error('Error mutex grabacion:', e); res.status(500).json({ error: 'Error en mutex de grabación' }); }
});

// ================================================================
// ACTIVOS — CRUD + BULK v4.4.0
// ================================================================
app.get('/api/activos/movimientos', requireAuth, requirePermiso('activos.ver'), async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 200, 1000); const filter = {};
        if (req.query.almacen) filter['Almacen'] = req.query.almacen.toUpperCase();
        if (req.query.tipo_movimiento) filter['Tipo de Movimiento'] = req.query.tipo_movimiento.toUpperCase();
        if (req.query.confirmada !== undefined) filter['Entrega Confirmada'] = req.query.confirmada === 'true';
        const [movimientos, total] = await Promise.all([
            db.collection('activos_movimientos').find(filter).sort({ createdAt: -1 }).limit(limit).toArray(),
            db.collection('activos_movimientos').countDocuments(filter),
        ]);
        res.json({ movimientos, total });
    } catch (e) { console.error('Error GET activos:', e); res.status(500).json({ error: 'Error obteniendo activos' }); }
});

app.post('/api/activos/movimientos/bulk', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { movimientos } = req.body;
        if (!Array.isArray(movimientos) || movimientos.length === 0) return res.status(400).json({ error: 'Se requiere un array "movimientos" no vacío' });
        if (movimientos.length > 500) return res.status(400).json({ error: 'Máximo 500 registros por carga masiva' });
        const ahora = new Date(); const errores = []; const docs = [];
        movimientos.forEach((m, i) => {
            const serie = String(m['Número de Serie'] || m['Serie'] || '').trim();
            const tipo  = String(m['Tipo de Activo']  || m['Tipo']  || '').trim();
            if (!serie) { errores.push(`Fila ${i+1}: Número de serie requerido`); return; }
            if (!tipo)  { errores.push(`Fila ${i+1}: Tipo de activo requerido`);  return; }
            const { _id: _localId, ...rest } = m;
            docs.push({ ...rest, 'Número de Serie': serie.toUpperCase(), 'Tipo de Activo': tipo, 'Tipo de Movimiento': (rest['Tipo de Movimiento'] || '').toUpperCase(), 'Entrega Confirmada': rest['Entrega Confirmada'] ?? false, 'Fecha Confirmacion Entrega': rest['Fecha Confirmacion Entrega'] || null, 'Confirmado Por': rest['Confirmado Por'] || null, 'Carga Masiva': true, 'Fecha Carga Masiva': ahora.toISOString(), creadoPor: req.usuario.username, createdAt: ahora });
        });
        let insertados = 0;
        if (docs.length > 0) { const result = await db.collection('activos_movimientos').insertMany(docs, { ordered: false }); insertados = result.insertedCount; }
        console.log(`[Activos] Bulk: ${insertados} insertados, ${errores.length} errores — ${req.usuario.username}`);
        res.status(201).json({ success: true, insertados, errores: errores.length, detallesError: errores });
    } catch (e) {
        if (e.name === 'MongoBulkWriteError') return res.json({ success: true, insertados: e.result?.insertedCount || 0, errores: e.writeErrors?.length || 0 });
        console.error('Error POST activos/bulk:', e); res.status(500).json({ error: 'Error en carga masiva de activos' });
    }
});

app.post('/api/activos/movimientos', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { movimientos } = req.body;
        if (Array.isArray(movimientos) && movimientos.length > 0) {
            const docs = movimientos.map(m => { const { _id: _localId, ...rest } = m; return { ...rest, creadoPor: req.usuario.username, createdAt: new Date(), 'Tipo de Movimiento': (rest['Tipo de Movimiento'] || '').toUpperCase(), 'Entrega Confirmada': rest['Entrega Confirmada'] ?? false, 'Fecha Confirmacion Entrega': rest['Fecha Confirmacion Entrega'] || null, 'Confirmado Por': rest['Confirmado Por'] || null }; });
            const result = await db.collection('activos_movimientos').insertMany(docs, { ordered: false });
            console.log(`[Activos] insertMany: ${result.insertedCount} docs por ${req.usuario.username}`);
            return res.status(201).json({ success: true, insertedCount: result.insertedCount, insertedIds: result.insertedIds });
        }
        if (!movimientos && Object.keys(req.body).length > 0) {
            const doc = { ...req.body, creadoPor: req.usuario.username, createdAt: new Date(), 'Tipo de Movimiento': (req.body['Tipo de Movimiento'] || '').toUpperCase(), 'Entrega Confirmada': req.body['Entrega Confirmada'] ?? false, 'Fecha Confirmacion Entrega': req.body['Fecha Confirmacion Entrega'] || null, 'Confirmado Por': req.body['Confirmado Por'] || null };
            const result = await db.collection('activos_movimientos').insertOne(doc);
            return res.status(201).json({ success: true, insertedCount: 1, movimiento: { ...doc, _id: result.insertedId } });
        }
        return res.status(400).json({ error: 'El campo "movimientos" debe ser un array no vacío' });
    } catch (e) {
        console.error('Error POST activos:', e);
        if (e.code === 11000) return res.status(409).json({ error: 'Algunos registros ya existen (clave duplicada)' });
        res.status(500).json({ error: 'Error registrando activos' });
    }
});

app.patch('/api/activos/movimientos/:id', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ error: `ID inválido: "${id}". Debe ser ObjectId de 24 caracteres.` });
        const CAMPOS_PROTEGIDOS = ['_id', 'creadoPor', 'createdAt'];
        const updates = { ...req.body }; CAMPOS_PROTEGIDOS.forEach(c => delete updates[c]);
        if (Object.keys(updates).length === 0) return res.status(400).json({ error: 'No se enviaron campos a actualizar' });
        if (updates['Tipo de Movimiento']) updates['Tipo de Movimiento'] = updates['Tipo de Movimiento'].toUpperCase();
        updates.updatedAt = new Date(); updates.updatedBy = req.usuario.username;
        const esConfirmacion = updates['Entrega Confirmada'] === true;
        const result = await db.collection('activos_movimientos').updateOne({ _id: new ObjectId(id) }, { $set: updates });
        if (result.matchedCount === 0) return res.status(404).json({ error: `Movimiento con id "${id}" no encontrado` });
        if (esConfirmacion) console.log(`[Activos] Entrega confirmada: id=${id} por ${req.usuario.username}`);
        const docActualizado = await db.collection('activos_movimientos').findOne({ _id: new ObjectId(id) });
        res.json({ success: true, movimiento: docActualizado });
    } catch (e) { console.error('Error PATCH activos:', e); res.status(500).json({ error: `Error actualizando activo: ${e.message}` }); }
});

app.delete('/api/activos/movimientos/:id', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ error: `ID inválido: "${id}"` });
        const registro = await db.collection('activos_movimientos').findOne({ _id: new ObjectId(id) });
        if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
        const rolesPrivilegiados = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
        if (!rolesPrivilegiados.includes(req.usuario.rol) && registro.creadoPor !== req.usuario.username)
            return res.status(403).json({ error: 'Sin permisos para eliminar este registro. Solo puedes borrar tus propios registros.' });
        await db.collection('activos_movimientos').deleteOne({ _id: new ObjectId(id) });
        console.log(`[Activos] Eliminado: ${id} por ${req.usuario.username}`);
        res.json({ success: true, eliminado: id });
    } catch (e) { console.error('Error DELETE activos:', e); res.status(500).json({ error: 'Error eliminando activo' }); }
});

// ================================================================
// REPOSICIONES — CRUD completo v4.4.0
// ================================================================
app.get('/api/reposiciones/movimientos', requireAuth, requirePermiso('activos.ver'), async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 500, 1000); const filter = {};
        if (req.query.pdv)    filter['PDV']            = { $regex: req.query.pdv,    $options: 'i' };
        if (req.query.estado) filter['Estado']         = req.query.estado;
        if (req.query.equipo) filter['Tipo de Equipo'] = { $regex: req.query.equipo, $options: 'i' };
        const [registros, total] = await Promise.all([
            db.collection('hub_reposiciones').find(filter).sort({ createdAt: -1 }).limit(limit).toArray(),
            db.collection('hub_reposiciones').countDocuments(filter),
        ]);
        res.json({ registros, total });
    } catch (e) { console.error('Error GET reposiciones:', e); res.status(500).json({ error: 'Error obteniendo reposiciones' }); }
});

app.post('/api/reposiciones/movimientos/bulk', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { registros } = req.body;
        if (!Array.isArray(registros) || registros.length === 0) return res.status(400).json({ error: 'Se requiere un array "registros" no vacío' });
        if (registros.length > 500) return res.status(400).json({ error: 'Máximo 500 registros por carga masiva' });
        const ahora = new Date(); const errores = []; const docs = [];
        registros.forEach((r, i) => {
            const serie = String(r['Número de Serie'] || r['Serie'] || '').trim();
            const pdv   = String(r['PDV'] || '').trim();
            if (!serie) { errores.push(`Fila ${i+1}: Número de serie requerido`); return; }
            if (!pdv)   { errores.push(`Fila ${i+1}: PDV requerido`); return; }
            const { _id: _localId, ...rest } = r;
            docs.push({ ...rest, 'Número de Serie': serie.toUpperCase(), 'PDV': pdv, 'Registrado Por': rest['Registrado Por'] || req.usuario.username, 'Fecha Registro': rest['Fecha Registro'] || ahora.toISOString(), 'Carga Masiva': true, 'Fecha Carga Masiva': ahora.toISOString(), creadoPor: req.usuario.username, createdAt: ahora });
        });
        let insertados = 0;
        if (docs.length > 0) { const result = await db.collection('hub_reposiciones').insertMany(docs, { ordered: false }); insertados = result.insertedCount; }
        console.log(`[Reposiciones] Bulk: ${insertados} insertados, ${errores.length} errores — ${req.usuario.username}`);
        res.status(201).json({ success: true, insertados, errores: errores.length, detallesError: errores });
    } catch (e) {
        if (e.name === 'MongoBulkWriteError') return res.json({ success: true, insertados: e.result?.insertedCount || 0, errores: e.writeErrors?.length || 0 });
        console.error('Error POST reposiciones/bulk:', e); res.status(500).json({ error: 'Error en carga masiva de reposiciones' });
    }
});

app.post('/api/reposiciones/movimientos', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { registro } = req.body; const data = registro || req.body;
        const serie = String(data['Número de Serie'] || data['Serie'] || '').trim();
        const pdv   = String(data['PDV'] || '').trim();
        if (!serie) return res.status(400).json({ error: 'Número de serie requerido' });
        if (!pdv)   return res.status(400).json({ error: 'PDV requerido' });
        const { _id: _localId, ...rest } = data;
        const doc = { ...rest, 'Número de Serie': serie.toUpperCase(), 'PDV': pdv, 'Registrado Por': rest['Registrado Por'] || req.usuario.username, creadoPor: req.usuario.username, createdAt: new Date() };
        const result = await db.collection('hub_reposiciones').insertOne(doc);
        console.log(`[Reposiciones] Creada: ${result.insertedId} por ${req.usuario.username}`);
        res.status(201).json({ success: true, id: result.insertedId, registro: { ...doc, _id: result.insertedId } });
    } catch (e) { console.error('Error POST reposiciones:', e); res.status(500).json({ error: 'Error creando reposición' }); }
});

app.patch('/api/reposiciones/movimientos/:id', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ error: `ID inválido: "${id}"` });
        const registro = await db.collection('hub_reposiciones').findOne({ _id: new ObjectId(id) });
        if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
        const rolesPrivilegiados = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
        if (!rolesPrivilegiados.includes(req.usuario.rol) && registro.creadoPor !== req.usuario.username)
            return res.status(403).json({ error: 'Sin permisos para editar este registro' });
        const updates = {};
        Object.entries(req.body).forEach(([k, v]) => { if (v !== '' && v !== null && v !== undefined) updates[k] = v; });
        delete updates._id; delete updates.creadoPor; delete updates.createdAt;
        updates.updatedAt = new Date(); updates['Editado Por'] = req.usuario.username; updates['Fecha Edicion'] = new Date().toISOString();
        await db.collection('hub_reposiciones').updateOne({ _id: new ObjectId(id) }, { $set: updates });
        console.log(`[Reposiciones] Editada: ${id} por ${req.usuario.username}`);
        res.json({ success: true, id });
    } catch (e) { console.error('Error PATCH reposiciones:', e); res.status(500).json({ error: 'Error actualizando reposición' }); }
});

app.delete('/api/reposiciones/movimientos/:id', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) return res.status(400).json({ error: `ID inválido: "${id}"` });
        const registro = await db.collection('hub_reposiciones').findOne({ _id: new ObjectId(id) });
        if (!registro) return res.status(404).json({ error: 'Registro no encontrado' });
        const rolesPrivilegiados = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
        if (!rolesPrivilegiados.includes(req.usuario.rol) && registro.creadoPor !== req.usuario.username)
            return res.status(403).json({ error: 'Sin permisos para eliminar este registro' });
        await db.collection('hub_reposiciones').deleteOne({ _id: new ObjectId(id) });
        console.log(`[Reposiciones] Eliminada: ${id} por ${req.usuario.username}`);
        res.json({ success: true, eliminado: id });
    } catch (e) { console.error('Error DELETE reposiciones:', e); res.status(500).json({ error: 'Error eliminando reposición' }); }
});

// ── Mensajes ───────────────────────────────────────────────────
app.get('/api/hub/mensajes/:canal', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { canal } = req.params; const limit = Math.min(parseInt(req.query.limit) || 50, 200);
        const docs = await db.collection('hub_mensajes').find({ canal }).sort({ createdAt: -1 }).limit(limit).toArray();
        res.json({ mensajes: docs.reverse() });
    } catch (e) { res.status(500).json({ error: 'Error mensajes' }); }
});

app.post('/api/hub/mensajes/:canal', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const doc = { ...req.body, canal: req.params.canal, autor: req.usuario.username, autorNombre: req.usuario.nombre || req.usuario.username, reactions: [], createdAt: new Date() };
        const result = await db.collection('hub_mensajes').insertOne(doc);
        res.status(201).json({ success: true, id: result.insertedId, doc });
    } catch (e) { res.status(500).json({ error: 'Error mensaje' }); }
});

app.patch('/api/hub/mensajes/:id', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try { await db.collection('hub_mensajes').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { ...req.body, editadoEn: new Date() } }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: 'Error mensaje' }); }
});

app.delete('/api/hub/mensajes/:id', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try { await db.collection('hub_mensajes').deleteOne({ _id: new ObjectId(req.params.id) }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: 'Error mensaje' }); }
});

app.patch('/api/hub/mensajes/:id/reaction', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { emoji } = req.body; const username = req.usuario.username;
        const msg = await db.collection('hub_mensajes').findOne({ _id: new ObjectId(req.params.id) });
        if (!msg) return res.status(404).json({ error: 'Mensaje no encontrado' });
        const reactions = msg.reactions || [];
        const idx = reactions.findIndex(r => r.emoji === emoji && r.username === username);
        if (idx >= 0) reactions.splice(idx, 1); else reactions.push({ emoji, username, createdAt: new Date() });
        await db.collection('hub_mensajes').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { reactions } });
        res.json({ success: true, reactions });
    } catch (e) { res.status(500).json({ error: 'Error reaction' }); }
});

// ── Asistencia ─────────────────────────────────────────────────
app.get('/api/hub/asistencia', requireAuth, requirePermiso('hub.asistencia'), async (req, res) => {
    try {
        const { usuario } = req; const filter = {};
        if (req.query.username) {
            filter.username = req.query.username;
            if (usuario.rol === 'COORDINADOR' && !tienePermiso(usuario, 'hub.concentrado.ver')) {
                const targetUser = await db.collection('users').findOne({ username: req.query.username }, { projection: { area: 1 } });
                if (targetUser && targetUser.area !== usuario.area) return res.status(403).json({ error: 'Solo puedes ver asistencia de usuarios de tu area' });
            }
        } else if (tienePermiso(usuario, 'hub.concentrado.ver')) {
            if (usuario.rol === 'COORDINADOR') {
                const usuariosArea = await db.collection('users').find({ area: usuario.area, activo: true }, { projection: { username: 1 } }).toArray();
                filter.username = { $in: usuariosArea.map(u => u.username) };
            }
        } else { filter.username = usuario.username; }
        if (req.query.mes) filter.fecha = { $regex: `^${req.query.mes}` };
        const docs = await db.collection('hub_asistencia').find(filter).sort({ fecha: -1, username: 1 }).limit(500).toArray();
        res.json(docs);
    } catch (e) { console.error('Error GET asistencia:', e); res.status(500).json({ error: 'Error obteniendo asistencia' }); }
});

app.post('/api/hub/asistencia', requireAuth, async (req, res) => {
    const { targetUsername, fecha, tipo, horaEntrada, horaSalida, notas } = req.body;
    const { usuario } = req;
    const esAdminReg = targetUsername && targetUsername !== usuario.username;
    if (esAdminReg && !tienePermiso(usuario, 'hub.asistencia.admin_registro')) return res.status(403).json({ error: 'Permiso insuficiente: hub.asistencia.admin_registro' });
    if (!esAdminReg && !tienePermiso(usuario, 'hub.asistencia.registrar')) return res.status(403).json({ error: 'Permiso insuficiente: hub.asistencia.registrar' });
    if (!tipo) return res.status(400).json({ error: 'El campo tipo es requerido' });
    try {
        if (esAdminReg && usuario.rol === 'COORDINADOR') {
            const targetUser = await db.collection('users').findOne({ username: targetUsername }, { projection: { area: 1 } });
            if (targetUser && targetUser.area !== usuario.area) return res.status(403).json({ error: 'Solo puedes registrar asistencia para usuarios de tu area' });
        }
        const usernameDestino = esAdminReg ? targetUsername : usuario.username;
        const fechaRegistro = fecha || new Date().toISOString().split('T')[0];
        const existe = await db.collection('hub_asistencia').findOne({ username: usernameDestino, fecha: fechaRegistro });
        if (existe) return res.status(409).json({ error: `Ya existe un registro para ${usernameDestino} el ${fechaRegistro}`, existingId: existe._id });
        const userDoc = await db.collection('users').findOne({ username: usernameDestino }, { projection: { area: 1 } });
        const doc = { username: usernameDestino, fecha: fechaRegistro, tipo, horaEntrada: horaEntrada || '', horaSalida: horaSalida || '', notas: notas || '', registradoPor: usuario.username, area: userDoc?.area || null, createdAt: new Date() };
        await db.collection('hub_asistencia').insertOne(doc);
        res.status(201).json({ success: true, doc });
    } catch (e) { console.error('Error POST asistencia:', e); res.status(500).json({ error: 'Error registrando asistencia' }); }
});

app.patch('/api/hub/asistencia/:id', requireAuth, async (req, res) => {
    try {
        const doc = await db.collection('hub_asistencia').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
        const { usuario } = req;
        const esPropioUsuario = doc.username === usuario.username;
        const tieneAdmin = tienePermiso(usuario, 'hub.asistencia.admin_registro');
        const tieneRegistrar = tienePermiso(usuario, 'hub.asistencia.registrar');
        const tieneEditConc = tienePermiso(usuario, 'hub.concentrado.editar');
        const puedeEditar = tieneAdmin || (esPropioUsuario && tieneRegistrar) || tieneEditConc;
        if (!puedeEditar) return res.status(403).json({ error: 'Sin permiso para editar este registro' });
        if (usuario.rol === 'COORDINADOR' && !tienePermiso(usuario, 'admin.panel')) {
            const targetUser = await db.collection('users').findOne({ username: doc.username }, { projection: { area: 1 } });
            if (targetUser && targetUser.area !== usuario.area) return res.status(403).json({ error: 'Solo puedes editar registros de usuarios de tu area' });
        }
        const updates = { ...req.body };
        if (!tieneAdmin) delete updates.username;
        updates.updatedAt = new Date(); updates.updatedBy = usuario.username;
        await db.collection('hub_asistencia').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
        res.json({ success: true });
    } catch (e) { console.error('Error PATCH asistencia:', e); res.status(500).json({ error: 'Error actualizando asistencia' }); }
});

app.delete('/api/hub/asistencia/:id', requireAuth, async (req, res) => {
    try {
        const doc = await db.collection('hub_asistencia').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
        const { usuario } = req;
        const esPropioUsuario = doc.username === usuario.username;
        const tieneAdmin = tienePermiso(usuario, 'hub.asistencia.admin_registro');
        const tieneRegistrar = tienePermiso(usuario, 'hub.asistencia.registrar');
        if (!tieneAdmin && !(esPropioUsuario && tieneRegistrar)) return res.status(403).json({ error: 'Sin permiso para eliminar este registro' });
        if (usuario.rol === 'COORDINADOR' && !tieneAdmin) {
            const targetUser = await db.collection('users').findOne({ username: doc.username }, { projection: { area: 1 } });
            if (targetUser && targetUser.area !== usuario.area) return res.status(403).json({ error: 'Solo puedes eliminar registros de tu area' });
        }
        await db.collection('hub_asistencia').deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ success: true });
    } catch (e) { console.error('Error DELETE asistencia:', e); res.status(500).json({ error: 'Error eliminando asistencia' }); }
});

app.get('/api/hub/usuarios-activos', requireAuth, requirePermiso('hub.asistencia.admin_registro'), async (req, res) => {
    try {
        const { usuario } = req; const filter = { activo: true };
        if (usuario.rol === 'COORDINADOR') filter.area = usuario.area;
        const usuarios = await db.collection('users').find(filter, { projection: { password: 0 } }).toArray();
        res.json(usuarios.map(u => ({ username: u.username, nombre: u.nombre, rol: normalizarRol(u.rol), area: u.area || null, activo: u.activo })));
    } catch (e) { res.status(500).json({ error: 'Error obteniendo usuarios activos' }); }
});

// ── Concentrado ────────────────────────────────────────────────
app.get('/api/hub/concentrado', requireAuth, requirePermiso('hub.concentrado.ver'), async (req, res) => {
    try {
        const { usuario } = req; const filter = {};
        if (req.query.mes) filter.mes = req.query.mes;
        if (usuario.rol === 'COORDINADOR') {
            const usersArea = await db.collection('users').find({ area: usuario.area, activo: true }, { projection: { username: 1 } }).toArray();
            filter.username = { $in: usersArea.map(u => u.username) };
        }
        const docs = await db.collection('hub_concentrado').find(filter).sort({ createdAt: -1 }).limit(500).toArray();
        res.json(docs);
    } catch (e) { res.status(500).json({ error: 'Error obteniendo concentrado' }); }
});

// ── Vacaciones ─────────────────────────────────────────────────
app.get('/api/hub/vacaciones', requireAuth, requirePermiso('hub.vacaciones'), async (req, res) => {
    try {
        const filter = {};
        if (req.query.username) filter.username = req.query.username;
        else if (!tienePermiso(req.usuario, 'hub.peticiones.ver_todas')) filter.username = req.usuario.username;
        if (req.query.estado) filter.estado = req.query.estado;
        res.json(await db.collection('hub_vacaciones').find(filter).sort({ createdAt: -1 }).limit(200).toArray());
    } catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});

app.post('/api/hub/vacaciones', requireAuth, requirePermiso('hub.peticiones.crear'), async (req, res) => {
    try {
        const doc = { ...req.body, username: req.usuario.username, estado: 'pendiente', createdAt: new Date() };
        await db.collection('hub_vacaciones').insertOne(doc); res.status(201).json({ success: true, doc });
    } catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});

app.patch('/api/hub/vacaciones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_vacaciones').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { ...req.body, updatedAt: new Date(), aprobadoPor: req.usuario.username } }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});

app.delete('/api/hub/vacaciones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_vacaciones').deleteOne({ _id: new ObjectId(req.params.id) }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});

// ── Peticiones ─────────────────────────────────────────────────
app.get('/api/hub/peticiones', requireAuth, requirePermiso('hub.acceso'), async (req, res) => {
    try {
        const { usuario } = req; const filter = {};
        if (tienePermiso(usuario, 'hub.peticiones.ver_todas')) {
            if (usuario.rol === 'COORDINADOR') {
                const usersArea = await db.collection('users').find({ area: usuario.area }, { projection: { username: 1 } }).toArray();
                filter.username = { $in: usersArea.map(u => u.username) };
            }
        } else { filter.username = usuario.username; }
        if (req.query.estado) filter.estado = req.query.estado;
        if (req.query.tipo)   filter.tipo   = req.query.tipo;
        res.json(await db.collection('hub_peticiones').find(filter).sort({ createdAt: -1 }).limit(200).toArray());
    } catch (e) { res.status(500).json({ error: 'Error peticiones' }); }
});

app.post('/api/hub/peticiones', requireAuth, requirePermiso('hub.peticiones.crear'), async (req, res) => {
    try {
        const doc = { ...req.body, username: req.usuario.username, nombre: req.usuario.nombre, estado: 'pendiente', createdAt: new Date() };
        await db.collection('hub_peticiones').insertOne(doc); res.status(201).json({ success: true, doc });
    } catch (e) { res.status(500).json({ error: 'Error peticion' }); }
});

app.patch('/api/hub/peticiones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_peticiones').updateOne({ _id: new ObjectId(req.params.id) }, { $set: { ...req.body, updatedAt: new Date(), aprobadoPor: req.usuario.username } }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: 'Error peticion' }); }
});

app.delete('/api/hub/peticiones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_peticiones').deleteOne({ _id: new ObjectId(req.params.id) }); res.json({ success: true }); }
    catch (e) { res.status(500).json({ error: 'Error peticion' }); }
});

// ── Canales ────────────────────────────────────────────────────
app.get('/api/hub/canales', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { area } = req.query; const filter = area ? { area } : {};
        const docs = await db.collection('hub_canales').find(filter).sort({ pinned: -1, createdAt: 1 }).toArray();
        res.json(docs);
    } catch (e) { console.error('Error GET canales:', e); res.status(500).json({ error: 'Error obteniendo canales' }); }
});

app.post('/api/hub/canales', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { nombre, emoji, desc, area, pinned = false } = req.body;
        const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(req.usuario.rol)) return res.status(403).json({ error: 'Sin permisos para crear canales' });
        if (!nombre || !nombre.trim()) return res.status(400).json({ error: 'nombre requerido' });
        const areaSlug   = (area || 'hub').toLowerCase().replace(/[^a-z0-9]/g, '_');
        const nombreSlug = nombre.toLowerCase().replace(/[^a-z0-9]/g, '_');
        const id = `${areaSlug}_${nombreSlug}_${Date.now()}`;
        const existe = await db.collection('hub_canales').findOne({ area, nombre: nombre.trim() });
        if (existe) return res.status(409).json({ error: `Ya existe un canal "${nombre}" en esa área` });
        const doc = { id, nombre: nombre.trim(), emoji: emoji || '💬', desc: desc || '', area: area || 'general', pinned: !!pinned, creadoPor: req.usuario.username, createdAt: new Date() };
        await db.collection('hub_canales').insertOne(doc);
        console.log(`[Canales] Creado: ${id} por ${req.usuario.username}`);
        res.status(201).json({ success: true, canal: doc });
    } catch (e) {
        if (e.code === 11000) return res.status(409).json({ error: 'ID de canal duplicado, intenta de nuevo' });
        console.error('Error POST canales:', e); res.status(500).json({ error: 'Error creando canal' });
    }
});

app.patch('/api/hub/canales/:id', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { id } = req.params;
        const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(req.usuario.rol)) return res.status(403).json({ error: 'Sin permisos para editar canales' });
        const canal = await db.collection('hub_canales').findOne({ id });
        if (!canal) return res.json({ success: true, note: 'Canal no encontrado en DB (puede ser default)' });
        const { nombre, emoji, desc, pinned } = req.body;
        const updates = { updatedAt: new Date(), updatedBy: req.usuario.username };
        if (nombre !== undefined) updates.nombre = nombre.trim();
        if (emoji  !== undefined) updates.emoji  = emoji;
        if (desc   !== undefined) updates.desc   = desc;
        if (pinned !== undefined) updates.pinned = !!pinned;
        await db.collection('hub_canales').updateOne({ id }, { $set: updates });
        res.json({ success: true });
    } catch (e) { console.error('Error PATCH canales:', e); res.status(500).json({ error: 'Error actualizando canal' }); }
});

app.delete('/api/hub/canales/:id', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { id } = req.params;
        const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(req.usuario.rol)) return res.status(403).json({ error: 'Sin permisos para eliminar canales' });
        const canal = await db.collection('hub_canales').findOne({ id });
        if (!canal) return res.status(404).json({ error: 'Canal no encontrado' });
        if (canal.pinned) return res.status(400).json({ error: 'No se puede eliminar un canal anclado (pinned)' });
        const [mensajesResult] = await Promise.all([
            db.collection('hub_mensajes').deleteMany({ canal: id }),
            db.collection('hub_canales').deleteOne({ id }),
        ]);
        console.log(`[Canales] Eliminado: ${id} (${mensajesResult.deletedCount} mensajes) por ${req.usuario.username}`);
        res.json({ success: true, mensajesEliminados: mensajesResult.deletedCount });
    } catch (e) { console.error('Error DELETE canales:', e); res.status(500).json({ error: 'Error eliminando canal' }); }
});

// ── Boletines ──────────────────────────────────────────────────
app.get('/api/hub/boletines', requireAuth, async (req, res) => {
    try {
        const { usuario } = req; const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin acceso al módulo de boletines' });
        const limit = Math.min(parseInt(req.query.limit) || 100, 500); const filter = {};
        if (req.query.area) filter.area = req.query.area;
        if (usuario.rol === 'COORDINADOR') filter.area = usuario.area;
        if (req.query.semana) filter.semana = req.query.semana;
        const docs = await db.collection('hub_boletines').find(filter).sort({ createdAt: -1 }).limit(limit).project({ 'archivos.data': 0 }).toArray();
        res.json(docs);
    } catch (e) { console.error('Error GET boletines:', e); res.status(500).json({ error: 'Error obteniendo boletines' }); }
});

app.get('/api/hub/boletines/:id', requireAuth, async (req, res) => {
    try {
        const { usuario } = req; const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin acceso' });
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ID inválido' });
        const doc = await db.collection('hub_boletines').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Boletín no encontrado' });
        if (usuario.rol === 'COORDINADOR' && doc.area !== usuario.area) return res.status(403).json({ error: 'Sin acceso a este boletín' });
        res.json(doc);
    } catch (e) { console.error('Error GET boletín:', e); res.status(500).json({ error: 'Error obteniendo boletín' }); }
});

app.post('/api/hub/boletines', requireAuth, async (req, res) => {
    try {
        const { usuario } = req; const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin permisos para crear boletines' });
        const { area, semana, semanaLabel, titulo, descripcion, archivos, fechaLimiteSabado, lunesPublicacion } = req.body;
        if (!area || !titulo) return res.status(400).json({ error: 'area y titulo son requeridos' });
        if (usuario.rol === 'COORDINADOR' && usuario.area !== area) return res.status(403).json({ error: `Solo puedes subir boletines del área ${usuario.area}` });
        const privilegiados = ['ADMIN', 'GERENTE_OPERACIONES'];
        const hoy = new Date().toISOString().split('T')[0];
        if (!privilegiados.includes(usuario.rol) && fechaLimiteSabado && hoy > fechaLimiteSabado)
            return res.status(400).json({ error: `La fecha límite de entrega (${fechaLimiteSabado}) ya pasó. Solo ADMIN o Gerente pueden subir fuera de plazo.` });
        const MAX_FILE_BYTES = 3 * 1024 * 1024;
        for (const arch of (archivos || [])) {
            if (!arch.data) continue;
            const bytes = Buffer.from(arch.data, 'base64').length;
            if (bytes > MAX_FILE_BYTES) return res.status(400).json({ error: `Archivo "${arch.nombre}" excede el límite de 3 MB` });
        }
        const doc = { area, semana: semana || '', semanaLabel: semanaLabel || semana || '', titulo: titulo.trim(), descripcion: (descripcion || '').trim(), archivos: archivos || [], fechaLimiteSabado: fechaLimiteSabado || null, lunesPublicacion: lunesPublicacion || null, creadoPor: usuario.username, createdAt: new Date() };
        const result = await db.collection('hub_boletines').insertOne(doc);
        console.log(`[Boletines] Creado: ${result.insertedId} área=${area} semana=${semana} por ${usuario.username}`);
        const { archivos: _arch, ...sinArchivos } = doc;
        const archMetadata = (archivos || []).map(({ nombre, tipo, tamanio }) => ({ nombre, tipo, tamanio }));
        res.status(201).json({ success: true, id: result.insertedId, boletin: { ...sinArchivos, archivos: archMetadata, _id: result.insertedId } });
    } catch (e) { console.error('Error POST boletines:', e); res.status(500).json({ error: 'Error creando boletín' }); }
});

app.patch('/api/hub/boletines/:id', requireAuth, async (req, res) => {
    try {
        const { usuario } = req; const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin permisos' });
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ID inválido' });
        const doc = await db.collection('hub_boletines').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Boletín no encontrado' });
        if (usuario.rol === 'COORDINADOR') {
            if (doc.area !== usuario.area) return res.status(403).json({ error: 'Solo puedes editar boletines de tu área' });
            const hoy = new Date().toISOString().split('T')[0];
            if (doc.fechaLimiteSabado && hoy > doc.fechaLimiteSabado) return res.status(400).json({ error: 'La fecha límite de entrega ya pasó. No puedes editar este boletín.' });
        }
        const { titulo, descripcion, archivos } = req.body;
        const updates = { updatedAt: new Date(), updatedBy: usuario.username };
        if (titulo      !== undefined) updates.titulo      = titulo.trim();
        if (descripcion !== undefined) updates.descripcion = descripcion.trim();
        if (archivos    !== undefined) {
            const MAX_FILE_BYTES = 3 * 1024 * 1024;
            for (const arch of archivos) { if (!arch.data) continue; const bytes = Buffer.from(arch.data, 'base64').length; if (bytes > MAX_FILE_BYTES) return res.status(400).json({ error: `Archivo "${arch.nombre}" excede 3 MB` }); }
            updates.archivos = archivos;
        }
        await db.collection('hub_boletines').updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates });
        console.log(`[Boletines] Actualizado: ${req.params.id} por ${usuario.username}`);
        res.json({ success: true });
    } catch (e) { console.error('Error PATCH boletines:', e); res.status(500).json({ error: 'Error actualizando boletín' }); }
});

app.delete('/api/hub/boletines/:id', requireAuth, async (req, res) => {
    try {
        const { usuario } = req; const rolesPermitidos = ['ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin permisos' });
        if (!ObjectId.isValid(req.params.id)) return res.status(400).json({ error: 'ID inválido' });
        const doc = await db.collection('hub_boletines').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Boletín no encontrado' });
        if (usuario.rol === 'COORDINADOR' && doc.area !== usuario.area) return res.status(403).json({ error: 'Solo puedes eliminar boletines de tu área' });
        await db.collection('hub_boletines').deleteOne({ _id: new ObjectId(req.params.id) });
        console.log(`[Boletines] Eliminado: ${req.params.id} por ${usuario.username}`);
        res.json({ success: true });
    } catch (e) { console.error('Error DELETE boletines:', e); res.status(500).json({ error: 'Error eliminando boletín' }); }
});

// ================================================================
// HC — Headcount (hub_hc_usuarios / hub_hc_meta)
// ================================================================
app.get('/api/hc/usuarios', requireAuth, async (req, res) => {
    try {
        const meta = await db.collection('hub_hc_meta').findOne({ _type: 'hc_usuarios' });
        const rows = await db.collection('hub_hc_usuarios').find({}).toArray();
        const rowsLimpias = rows.map(({ _id, _type, ...rest }) => rest);
        res.json({ ok: true, meta: meta ? { filename: meta.filename, total: meta.total, uploadedAt: meta.uploadedAt, uploadedBy: meta.uploadedBy } : null, rows: rowsLimpias });
    } catch (err) { console.error('GET /api/hc/usuarios error:', err); res.status(500).json({ error: err.message }); }
});

app.post('/api/hc/upload', requireAuth, async (req, res) => {
    try {
        const usuario = req.usuario; const rolesPermitidos = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin permisos para cargar HC' });
        const { rows, filename } = req.body;
        if (!Array.isArray(rows) || rows.length === 0) return res.status(400).json({ error: 'rows debe ser un array no vacío' });
        const MAX_ROWS = 50_000;
        if (rows.length > MAX_ROWS) return res.status(413).json({ error: `El archivo supera el límite de ${MAX_ROWS} filas` });
        const session = mongoClient.startSession();
        try {
            await session.withTransaction(async () => {
                const col = db.collection('hub_hc_usuarios');
                await col.deleteMany({}, { session });
                const rowsConTipo = rows.map(r => ({ ...r, _type: 'hc_row' }));
                const BATCH_SIZE = 500;
                for (let i = 0; i < rowsConTipo.length; i += BATCH_SIZE) {
                    await col.insertMany(rowsConTipo.slice(i, i + BATCH_SIZE), { session });
                }
            }, { readConcern: { level: 'snapshot' }, writeConcern: { w: 'majority' } });
            const meta = { _type: 'hc_usuarios', filename: filename || 'desconocido', total: rows.length, uploadedAt: new Date().toISOString(), uploadedBy: usuario.username };
            await db.collection('hub_hc_meta').updateOne({ _type: 'hc_usuarios' }, { $set: meta }, { upsert: true });
            console.log(`✅ HC Upload (transacción): ${rows.length} registros por ${usuario.username}`);
            res.json({ ok: true, total: rows.length, meta });
        } finally { await session.endSession(); }
    } catch (err) {
        console.error('POST /api/hc/upload error:', err);
        res.status(500).json({ error: err.message, detail: 'Los datos anteriores del HC no fueron modificados (rollback automático).' });
    }
});

app.patch('/api/hc/usuarios/aplicar-movimiento', requireAuth, async (req, res) => {
    try {
        const usuario = req.usuario; const rolesPermitidos = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES', 'GERENTE_RH', 'ANALISTA_RH'];
        if (!rolesPermitidos.includes(usuario.rol)) return res.status(403).json({ error: 'Sin permisos para modificar HC' });
        const { tipo, attuid, nombre, pdv, puesto, motivo } = req.body;
        if (!tipo) return res.status(400).json({ error: 'tipo es requerido' });
        const col = db.collection('hub_hc_usuarios');
        const buildQuery = () => {
            if (attuid && attuid.trim()) return { $or: [{ ATTUID: attuid.trim() }, { attuid: attuid.trim() }] };
            if (nombre) { const nombreNorm = nombre.toUpperCase().trim(); return { $or: [{ NOMBRE: { $regex: nombreNorm, $options: 'i' } }, { 'Nombre Completo': { $regex: nombreNorm, $options: 'i' } }, { nombre: { $regex: nombreNorm, $options: 'i' } }] }; }
            return null;
        };
        const query = buildQuery();
        if (!query) return res.status(400).json({ error: 'Se requiere attuid o nombre para identificar al colaborador' });
        const historial = { tipo, fecha: new Date().toISOString(), aplicadoPor: usuario.username, ...(pdv ? { pdv } : {}), ...(puesto ? { puesto } : {}), ...(motivo ? { motivo } : {}) };
        let updateOp = {};
        switch (tipo) {
            case 'BAJA': updateOp = { $set: { ESTATUS: 'BAJA', estatus: 'BAJA', FECHA_BAJA: new Date().toISOString().slice(0, 10), MOTIVO_BAJA: motivo || '', _ultimaActualizacion: new Date().toISOString() }, $push: { _historialMovimientos: historial } }; break;
            case 'CAMBIO_PDV': updateOp = { $set: { PDV: pdv || '', 'NOMBRE PDV': pdv || '', _ultimaActualizacion: new Date().toISOString() }, $push: { _historialMovimientos: historial } }; break;
            case 'CAMBIO_PUESTO': updateOp = { $set: { PUESTO: puesto || '', Puesto: puesto || '', _ultimaActualizacion: new Date().toISOString() }, $push: { _historialMovimientos: historial } }; break;
            case 'CAMBIO_COMBINADO': updateOp = { $set: { PDV: pdv || '', 'NOMBRE PDV': pdv || '', PUESTO: puesto || '', Puesto: puesto || '', _ultimaActualizacion: new Date().toISOString() }, $push: { _historialMovimientos: historial } }; break;
            default: return res.status(400).json({ error: `Tipo de movimiento no soportado: ${tipo}` });
        }
        const result = await col.updateOne(query, updateOp);
        if (result.matchedCount === 0) {
            console.warn(`⚠️  HC aplicar-movimiento: ningún registro coincidió. tipo=${tipo} attuid=${attuid} nombre=${nombre}`);
            return res.json({ ok: false, warning: 'No se encontró el colaborador en el HC de la base de datos. El movimiento RH sí se guardó.', matched: 0, modified: 0 });
        }
        console.log(`✅ HC movimiento aplicado: ${tipo} → ${attuid || nombre} por ${usuario.username}`);
        res.json({ ok: true, matched: result.matchedCount, modified: result.modifiedCount });
    } catch (err) { console.error('PATCH /api/hc/usuarios/aplicar-movimiento error:', err); res.status(500).json({ error: err.message }); }
});

// ================================================================
// [FEAT-005] GET /api/hc/validar-consistencia — v4.5.7
// ================================================================
app.get('/api/hc/validar-consistencia', requireAuth, async (req, res) => {
    const ROLES_PERMITIDOS_FEAT005 = [
        'ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR', 'GERENTE_RH', 'ANALISTA_RH',
    ];
    if (!ROLES_PERMITIDOS_FEAT005.includes(req.usuario.rol))
        return res.status(403).json({ error: 'Sin permisos para ejecutar validación HC vs RH' });

    try {
        const diasAtras = Math.min(Math.max(parseInt(req.query.dias) || 90, 1), 365);
        const desde     = new Date(Date.now() - diasAtras * 24 * 3600 * 1000);

        const [hcRows, movimientos] = await Promise.all([
            db.collection('hub_hc_usuarios').find({}).toArray(),
            db.collection('rh_movimientos')
                .find({ createdAt: { $gte: desde } })
                .sort({ createdAt: -1 })
                .toArray(),
        ]);

        if (hcRows.length === 0) {
            return res.json({
                ok: true,
                resumen: {
                    hcTotalRegistros: 0,
                    rhMovimientosAnalizados: movimientos.length,
                    diasAnalizados: diasAtras,
                    totalInconsistencias: 0,
                    estadoGeneral: 'SIN_HC',
                    aviso: 'No hay datos de HC cargados. Sube el archivo HC primero.',
                },
                inconsistencias: { sinMatchEnHC: [], bajasPendientesEnRH: [], attuidsDuplicados: [], camposFaltantes: [] },
                timestamp: new Date().toISOString(),
            });
        }

        const hcByAttuid    = new Map();
        const hcAttuidCount = new Map();

        for (const row of hcRows) {
            const attuid = (row.ATTUID || row.attuid || '').trim().toUpperCase();
            if (!attuid) continue;
            hcAttuidCount.set(attuid, (hcAttuidCount.get(attuid) || 0) + 1);
            if (!hcByAttuid.has(attuid)) hcByAttuid.set(attuid, row);
        }

        const inconsistencias = {
            sinMatchEnHC:        [],
            bajasPendientesEnRH: [],
            attuidsDuplicados:   [],
            camposFaltantes:     [],
        };

        for (const [attuid, count] of hcAttuidCount.entries()) {
            if (count > 1) {
                inconsistencias.attuidsDuplicados.push({
                    attuid, ocurrencias: count, severidad: 'MEDIA',
                    mensaje: `ATTUID "${attuid}" aparece ${count} veces en el HC — posible duplicado de carga`,
                    accionRecomendada: 'Revisar y eliminar duplicados en el archivo HC antes del próximo upload',
                });
            }
        }

        const getCampo = (row, ...keys) => {
            for (const k of keys) {
                const v = row[k];
                if (v !== undefined && v !== null && String(v).trim() !== '') return String(v).trim();
            }
            return '';
        };

        for (const row of hcRows) {
            const attuid = getCampo(row, 'ATTUID', 'attuid');
            const nombre = getCampo(row, 'NOMBRE', 'Nombre Completo', 'nombre');
            const faltantes = [];
            if (!getCampo(row, 'PDV', 'NOMBRE PDV', 'pdv'))       faltantes.push('PDV');
            if (!getCampo(row, 'PUESTO', 'Puesto', 'puesto'))      faltantes.push('PUESTO');
            if (!getCampo(row, 'ESTATUS', 'estatus', 'Status'))    faltantes.push('ESTATUS');
            if (faltantes.length > 0) {
                inconsistencias.camposFaltantes.push({
                    attuid: attuid || '(sin ATTUID)', nombre: nombre || '(sin nombre)',
                    camposFaltantes: faltantes, severidad: faltantes.length >= 2 ? 'ALTA' : 'BAJA',
                    mensaje: `Faltan campos críticos: ${faltantes.join(', ')}`,
                    accionRecomendada: 'Actualizar el archivo HC con los campos faltantes y recargar',
                });
            }
        }

        for (const mov of movimientos) {
            const empleado = mov.empleado || {};
            const attuid   = (empleado.attuid || empleado.ATTUID || empleado.numero_empleado || '').trim().toUpperCase();
            const nombre   = [empleado.nombre, empleado.apellido_paterno, empleado.apellido_materno].filter(Boolean).join(' ') || '(sin nombre)';

            if (attuid && !hcByAttuid.has(attuid)) {
                inconsistencias.sinMatchEnHC.push({
                    movimientoId: String(mov._id), attuid, nombre,
                    tipo: mov.tipo, estado: mov.estado || 'desconocido',
                    fecha: mov.createdAt, creadoPor: mov.creadoPor || '',
                    severidad: 'ALTA',
                    mensaje: `Movimiento ${mov.tipo} referencia ATTUID "${attuid}" que no existe en el HC actual`,
                    accionRecomendada: 'Verificar ATTUID o recargar HC si el colaborador ya fue dado de alta',
                });
                continue;
            }

            if (mov.tipo === 'BAJA' && mov.estado === 'pendiente' && attuid) {
                const hcRow = hcByAttuid.get(attuid);
                if (hcRow) {
                    const estatus = getCampo(hcRow, 'ESTATUS', 'estatus', 'Status').toUpperCase();
                    if (estatus !== 'BAJA' && estatus !== 'INACTIVO') {
                        inconsistencias.bajasPendientesEnRH.push({
                            movimientoId: String(mov._id), attuid, nombre,
                            estatusHC: estatus || 'ACTIVO', fechaMovimiento: mov.createdAt,
                            diasPendiente: Math.floor((Date.now() - new Date(mov.createdAt).getTime()) / 86400000),
                            severidad: 'ALTA',
                            mensaje: `Baja RH pendiente desde hace ${Math.floor((Date.now() - new Date(mov.createdAt).getTime()) / 86400000)} días, HC sigue como "${estatus || 'ACTIVO'}"`,
                            accionRecomendada: 'Aprobar el movimiento RH o aplicar manualmente en el módulo HC',
                        });
                    }
                }
            }
        }

        const totalInconsistencias =
            inconsistencias.sinMatchEnHC.length        +
            inconsistencias.bajasPendientesEnRH.length +
            inconsistencias.attuidsDuplicados.length   +
            inconsistencias.camposFaltantes.length;

        const altasSeveridad =
            inconsistencias.sinMatchEnHC.filter(i => i.severidad === 'ALTA').length        +
            inconsistencias.bajasPendientesEnRH.filter(i => i.severidad === 'ALTA').length +
            inconsistencias.camposFaltantes.filter(i => i.severidad === 'ALTA').length;

        const estadoGeneral =
            altasSeveridad > 0       ? 'CRITICO'    :
            totalInconsistencias > 0 ? 'ADVERTENCIA' : 'OK';

        const resumen = {
            hcTotalRegistros:        hcRows.length,
            rhMovimientosAnalizados: movimientos.length,
            diasAnalizados:          diasAtras,
            totalInconsistencias,
            altaSeveridad:           altasSeveridad,
            sinMatchEnHC:            inconsistencias.sinMatchEnHC.length,
            bajasPendientesEnRH:     inconsistencias.bajasPendientesEnRH.length,
            attuidsDuplicados:       inconsistencias.attuidsDuplicados.length,
            camposFaltantes:         inconsistencias.camposFaltantes.length,
            estadoGeneral,
        };

        console.log(
            `[FEAT-005] Validación HC vs RH — estado=${estadoGeneral} | ` +
            `inconsistencias=${totalInconsistencias} | hc=${hcRows.length} | rh=${movimientos.length} | ` +
            `usuario=${req.usuario.username}`
        );

        res.set('Cache-Control', 'private, max-age=60');
        res.json({ ok: true, resumen, inconsistencias, timestamp: new Date().toISOString() });

    } catch (err) {
        console.error('[FEAT-005] Error en /api/hc/validar-consistencia:', err.message);
        res.status(500).json({ error: 'Error ejecutando validación de consistencia HC vs RH' });
    }
});

// ================================================================
// [INN-002] HUB AI — Asistente IA genérico (texto libre)
// ================================================================

// Helper genérico: llama Groq → Gemini en cascada, devuelve texto plano
const _llamarIATexto = async (systemPrompt, userPrompt) => {
    const forced = process.env.AI_PROVIDER;
    const tryGroq = async () => {
        const apiKey = process.env.GROQ_API_KEY;
        if (!apiKey) throw new Error('GROQ_API_KEY no configurada');
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 22000);
        try {
            const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${apiKey}` },
                signal: controller.signal,
                body: JSON.stringify({ model: 'llama-3.3-70b-versatile', max_tokens: 1500, temperature: 0.3, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: userPrompt }] }),
            });
            clearTimeout(timeout);
            if (!response.ok) { const t = await response.text().catch(() => ''); throw new Error(`Groq HTTP ${response.status}: ${t.slice(0, 120)}`); }
            const data = await response.json();
            const text = data.choices?.[0]?.message?.content || '';
            if (!text) throw new Error('Groq devolvió respuesta vacía');
            return text.trim();
        } finally { clearTimeout(timeout); }
    };
    const tryGemini = async () => {
        const apiKey = process.env.GEMINI_API_KEY;
        if (!apiKey) throw new Error('GEMINI_API_KEY no configurada');
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 22000);
        try {
            const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
            const response = await fetch(url, { method: 'POST', headers: { 'Content-Type': 'application/json' }, signal: controller.signal, body: JSON.stringify({ contents: [{ parts: [{ text: userPrompt }] }], systemInstruction: { parts: [{ text: systemPrompt }] }, generationConfig: { temperature: 0.3, maxOutputTokens: 1500 } }) });
            clearTimeout(timeout);
            if (!response.ok) throw new Error(`Gemini HTTP ${response.status}`);
            const data = await response.json();
            const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
            if (!text) throw new Error('Gemini devolvió respuesta vacía');
            return text.trim();
        } finally { clearTimeout(timeout); }
    };
    const cadena = [
        { nombre: 'groq',   fn: tryGroq,   activo: !forced || forced === 'groq',   tiene_key: !!process.env.GROQ_API_KEY },
        { nombre: 'gemini', fn: tryGemini, activo: !forced || forced === 'gemini', tiene_key: !!process.env.GEMINI_API_KEY },
    ].filter(p => p.activo && p.tiene_key);
    if (cadena.length === 0) throw new Error('No hay proveedor IA disponible (configura GROQ_API_KEY o GEMINI_API_KEY)');
    let lastError;
    for (const prov of cadena) {
        try { return await prov.fn(); } catch (e) { lastError = e; console.warn(`[HubAI] ${prov.nombre} falló: ${e.message} — próximo proveedor`); }
    }
    throw lastError;
};

// POST /api/hub/ai/summarize-chat
app.post('/api/hub/ai/summarize-chat', requireAuth, requirePermiso('hub.chat'), async (req, res) => {
    try {
        const { area = '', canal = '', messages = [] } = req.body;
        if (!Array.isArray(messages) || messages.length === 0)
            return res.status(400).json({ error: 'Se requiere el array messages[]' });
        const transcripcion = messages.slice(-60).map(m => {
            const autor = m.autor || m.author || m.username || '?';
            const texto = m.texto || m.content || m.text || '';
            const ts    = m.ts   || m.createdAt || '';
            const hora  = ts ? new Date(ts).toLocaleTimeString('es-MX', { hour: '2-digit', minute: '2-digit' }) : '??:??';
            return `[${hora}] ${autor}: ${texto}`;
        }).join('\n');
        const system = 'Eres un asistente corporativo. Resumir conversaciones de chat de equipos de trabajo en español de forma clara, objetiva y concisa.';
        const user = `Resume el chat del área "${area || 'N/A'}"${canal ? `, canal #${canal}` : ''} (${messages.length} mensajes):\n\n${transcripcion}\n\nProporciona:\n1. Resumen ejecutivo (3-5 líneas)\n2. Temas principales discutidos\n3. Conclusiones o próximos pasos mencionados\n\nTexto plano, sin markdown excesivo.`;
        const resumen = await _llamarIATexto(system, user);
        res.json({ resumen, _proveedor: 'ia', mensajesAnalizados: Math.min(messages.length, 60) });
    } catch (e) {
        console.error('[INN-002] summarize-chat:', e.message);
        res.status(e.message.includes('No hay proveedor') || e.message.includes('_KEY') ? 503 : 500).json({ error: e.message });
    }
});

// POST /api/hub/ai/extract-tasks
app.post('/api/hub/ai/extract-tasks', requireAuth, requirePermiso('hub.chat'), async (req, res) => {
    try {
        const { area = '', canal = '', messages = [] } = req.body;
        if (!Array.isArray(messages) || messages.length === 0)
            return res.status(400).json({ error: 'Se requiere el array messages[]' });
        const transcripcion = messages.slice(-60).map(m => {
            const autor = m.autor || m.author || m.username || '?';
            const texto = m.texto || m.content || m.text || '';
            return `${autor}: ${texto}`;
        }).join('\n');
        const system = 'Eres un extractor de tareas y compromisos en chats corporativos en español. Extrae ÚNICAMENTE tareas concretas, compromisos, pendientes o acciones mencionadas. Responde SOLO con JSON válido, sin texto adicional.';
        const user = `Del siguiente chat del área "${area || 'N/A'}"${canal ? `, canal #${canal}` : ''}, extrae todas las tareas y compromisos:\n\n${transcripcion}\n\nResponde con JSON:\n{"tareas":[{"tarea":"descripción concreta","responsable":"nombre si se menciona, si no vacío","fecha":"fecha límite si se menciona, si no vacío"}]}\n\nSi no hay tareas: {"tareas":[]}`;
        const texto = await _llamarIATexto(system, user);
        let parsed;
        try { const clean = texto.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim(); parsed = JSON.parse(clean); if (!parsed.tareas) parsed = { tareas: [] }; }
        catch (_) { parsed = { tareas: [], _raw: texto }; }
        res.json({ ...parsed, _proveedor: 'ia', mensajesAnalizados: Math.min(messages.length, 60) });
    } catch (e) {
        console.error('[INN-002] extract-tasks:', e.message);
        res.status(e.message.includes('No hay proveedor') || e.message.includes('_KEY') ? 503 : 500).json({ error: e.message });
    }
});

// POST /api/hub/ai/meeting-brief
app.post('/api/hub/ai/meeting-brief', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const { area = '', reunionId, titulo = '' } = req.body;
        if (!reunionId) return res.status(400).json({ error: 'Se requiere reunionId' });
        let rid;
        try { rid = new ObjectId(String(reunionId)); } catch (_) { return res.status(400).json({ error: 'reunionId inválido' }); }
        const reunion = await db.collection('hub_reuniones').findOne({ _id: rid });
        if (!reunion) return res.status(404).json({ error: 'Reunión no encontrada' });
        const tituloReunion = titulo || reunion.title || reunion.titulo || 'Reunión';
        const agenda     = reunion.agenda || '';
        const asistentes = Array.isArray(reunion.invitadoUsernames) ? reunion.invitadoUsernames.join(', ') : (reunion.invitados || '');
        const fecha      = reunion.startTime || reunion.fecha || reunion.date || '';
        const minuta     = reunion.minuta || reunion.acuerdos || '';
        const system = 'Eres un asistente corporativo experto en redacción de actas y minutas de reuniones en español. Redacta actas estructuradas y profesionales en texto plano.';
        const user = `Genera un acta de reunión para:\n\nTítulo: ${tituloReunion}\nÁrea: ${area}\nFecha: ${fecha ? new Date(fecha).toLocaleDateString('es-MX') : 'No especificada'}\nAsistentes: ${asistentes || 'No especificados'}\nAgenda: ${agenda || 'No especificada'}\n${minuta ? `\nMinuta/Notas previas:\n${minuta}` : ''}\n\nEstructura el acta con:\n1. Encabezado (título, fecha, área, asistentes)\n2. Objetivo de la reunión\n3. Temas tratados\n4. Acuerdos y decisiones\n5. Compromisos y responsables\n6. Próxima reunión (si aplica)\n\nUsa formato de texto claro y profesional.`;
        const acta = await _llamarIATexto(system, user);
        res.json({ acta, _proveedor: 'ia', reunionTitulo: tituloReunion });
    } catch (e) {
        console.error('[INN-002] meeting-brief:', e.message);
        res.status(e.message.includes('No hay proveedor') || e.message.includes('_KEY') ? 503 : 500).json({ error: e.message });
    }
});

// ================================================================
// [INN-003] DASHBOARD EJECUTIVO — Alertas y resúmenes cross-system
// ================================================================

function requireEjecutivo(req, res, next) {
    const rol = req.usuario?.rol;
    if (rol === 'ADMIN' || rol === 'GERENTE_OPERACIONES' || (req.usuario?.permisos || []).includes('*'))
        return next();
    return res.status(403).json({ error: 'Acceso denegado. Se requiere rol ADMIN o GERENTE_OPERACIONES.' });
}

// GET /api/exec/alerts
app.get('/api/exec/alerts', requireAuth, requireEjecutivo, async (req, res) => {
    try {
        const ahora = new Date();
        const alerts = [];
        // Agentes Nebula offline (sin heartbeat > 10 min)
        try {
            const agOffline = await db.collection('nebula_agents')
                .find({ lastSeen: { $lt: new Date(ahora - 10 * 60 * 1000) }, activo: { $ne: false } })
                .project({ agentId: 1, hostname: 1, lastSeen: 1 }).limit(10).toArray();
            for (const ag of agOffline) {
                const min = Math.floor((ahora - new Date(ag.lastSeen)) / 60000);
                alerts.push({ severity: min > 60 ? 'critical' : 'warning', categoria: 'nebula', titulo: `Agente offline: ${ag.hostname || ag.agentId}`, descripcion: `Sin heartbeat hace ${min} min` });
            }
        } catch (_) {}
        // Movimientos RH pendientes > 5 días
        try {
            const n = await db.collection('hub_movimientos_rh').countDocuments({ estado: 'pendiente', createdAt: { $lt: new Date(ahora - 5 * 24 * 60 * 60 * 1000) } });
            if (n > 0) alerts.push({ severity: n > 3 ? 'warning' : 'info', categoria: 'rh', titulo: `${n} movimiento(s) RH pendiente(s) > 5 días`, descripcion: 'Revisar y procesar en el módulo de RH' });
        } catch (_) {}
        // Peticiones hub sin atender > 3 días
        try {
            const n = await db.collection('hub_peticiones').countDocuments({ status: 'pendiente', createdAt: { $lt: new Date(ahora - 3 * 24 * 60 * 60 * 1000) } });
            if (n > 0) alerts.push({ severity: 'info', categoria: 'hub', titulo: `${n} petición(es) hub sin atender > 3 días`, descripcion: 'Revisar en el módulo de asistencia' });
        } catch (_) {}
        // Vacaciones pendientes de aprobación > 2 días
        try {
            const n = await db.collection('hub_vacaciones').countDocuments({ estado: 'pendiente', createdAt: { $lt: new Date(ahora - 2 * 24 * 60 * 60 * 1000) } });
            if (n > 0) alerts.push({ severity: 'info', categoria: 'rh', titulo: `${n} solicitud(es) de vacaciones pendiente(s)`, descripcion: 'Revisar en el módulo de asistencia' });
        } catch (_) {}
        res.set('Cache-Control', 'private, max-age=120');
        res.json({ ok: true, items: alerts, timestamp: ahora.toISOString() });
    } catch (e) {
        console.error('[INN-003] /api/exec/alerts:', e.message);
        res.status(500).json({ error: 'Error obteniendo alertas ejecutivas' });
    }
});

// GET /api/hub/activity/summary
app.get('/api/hub/activity/summary', requireAuth, async (req, res) => {
    try {
        const ahora  = new Date();
        const hace7d = new Date(ahora - 7 * 24 * 60 * 60 * 1000);
        const [msgs, mtgs, pets, bols] = await Promise.allSettled([
            db.collection('hub_messages').aggregate([{ $match: { createdAt: { $gte: hace7d } } }, { $group: { _id: '$area', count: { $sum: 1 }, lastMsg: { $max: '$createdAt' } } }, { $sort: { count: -1 } }]).toArray(),
            db.collection('hub_reuniones').aggregate([{ $match: { startTime: { $gte: hace7d } } }, { $group: { _id: '$area', count: { $sum: 1 } } }]).toArray(),
            db.collection('hub_peticiones').aggregate([{ $match: { createdAt: { $gte: hace7d } } }, { $group: { _id: '$area', count: { $sum: 1 } } }]).toArray(),
            db.collection('hub_boletines').find({ createdAt: { $gte: hace7d } }).sort({ createdAt: -1 }).limit(5).project({ titulo: 1, area: 1, createdAt: 1, autor: 1 }).toArray(),
        ]);
        const areas = {};
        const merge = (settled, key) => { if (settled.status === 'fulfilled') for (const r of settled.value) { if (!r._id) continue; if (!areas[r._id]) areas[r._id] = { mensajes: 0, reuniones: 0, peticiones: 0 }; areas[r._id][key] = r.count; } };
        merge(msgs, 'mensajes'); merge(mtgs, 'reuniones'); merge(pets, 'peticiones');
        res.set('Cache-Control', 'private, max-age=300');
        res.json({ ok: true, countsByArea: areas, boletinesRecientes: bols.status === 'fulfilled' ? bols.value : [], timestamp: ahora.toISOString() });
    } catch (e) {
        console.error('[INN-003] /api/hub/activity/summary:', e.message);
        res.status(500).json({ error: 'Error obteniendo resumen de actividad' });
    }
});

// GET /api/kpi/summary
app.get('/api/kpi/summary', requireAuth, async (req, res) => {
    try {
        const ahora = new Date();
        const [ticketsPend, rhMovsPend, vacPend, agTotal, agOk, hcTotal, usrActivos] = await Promise.allSettled([
            db.collection('hub_peticiones').countDocuments({ status: { $in: ['pendiente', 'en_proceso'] } }),
            db.collection('hub_movimientos_rh').countDocuments({ estado: 'pendiente' }),
            db.collection('hub_vacaciones').countDocuments({ estado: 'pendiente' }),
            db.collection('nebula_agents').countDocuments({ activo: { $ne: false } }),
            db.collection('nebula_agents').countDocuments({ activo: { $ne: false }, lastSeen: { $gte: new Date(ahora - 10 * 60 * 1000) } }),
            db.collection('headcount').countDocuments({}),
            db.collection('users').countDocuments({ activo: true }),
        ]);
        const g = (r, d = 0) => r.status === 'fulfilled' ? r.value : d;
        res.set('Cache-Control', 'private, max-age=180');
        res.json({ ok: true, kpis: { tickets: { pendientes: g(ticketsPend), label: 'Tickets/Peticiones pendientes' }, rh: { movimientosPendientes: g(rhMovsPend), vacacionesPendientes: g(vacPend), label: 'Movimientos RH' }, nebula: { total: g(agTotal), online: g(agOk), label: 'Agentes Nebula' }, headcount: { total: g(hcTotal), label: 'Headcount' }, usuarios: { activos: g(usrActivos), label: 'Usuarios del sistema' } }, timestamp: ahora.toISOString() });
    } catch (e) {
        console.error('[INN-003] /api/kpi/summary:', e.message);
        res.status(500).json({ error: 'Error obteniendo KPIs' });
    }
});

// GET /api/headcount/summary
app.get('/api/headcount/summary', requireAuth, async (req, res) => {
    try {
        const [result] = await db.collection('headcount').aggregate([{ $group: { _id: null, total: { $sum: 1 }, areas: { $push: '$area' } } }]).toArray();
        if (!result) return res.json({ ok: true, total: 0, porArea: {}, activos: 0, bajas: 0, timestamp: new Date().toISOString() });
        const porArea = {};
        for (const a of (result.areas || [])) { const k = a || 'Sin área'; porArea[k] = (porArea[k] || 0) + 1; }
        const [activos, bajas] = await Promise.allSettled([
            db.collection('headcount').countDocuments({ estatus: { $regex: /activo/i } }),
            db.collection('headcount').countDocuments({ estatus: { $regex: /baja/i } }),
        ]);
        res.set('Cache-Control', 'private, max-age=300');
        res.json({ ok: true, total: result.total, activos: activos.status === 'fulfilled' ? activos.value : null, bajas: bajas.status === 'fulfilled' ? bajas.value : null, porArea, timestamp: new Date().toISOString() });
    } catch (e) {
        console.error('[INN-003] /api/headcount/summary:', e.message);
        res.status(500).json({ error: 'Error obteniendo resumen de headcount' });
    }
});

// ================================================================
// START
// ================================================================
async function start() {
    try {
        await connectDB();

        app.use('*', (req, res) => res.status(404).json({ error: `Endpoint no encontrado: ${req.originalUrl}` }));
        app.use((err, req, res, next) => { console.error('Error no manejado:', err); res.status(500).json({ error: 'Error interno' }); });

        app.listen(PORT, () => {
            console.log(`MYG API v4.7.0 en puerto ${PORT}`);   // ← PASO 5: actualizado
            console.log(`IA Minutas: Groq=${!!process.env.GROQ_API_KEY ? '✅' : '❌'} | Gemini=${!!process.env.GEMINI_API_KEY ? '✅' : '❌'} | Local=✅`);
            console.log(`Activos:      GET(limit) POST(insertMany) PATCH(edit) DELETE(permisos) BULK(500max) ✅`);
            console.log(`Reposiciones: GET POST POST-bulk PATCH DELETE → hub_reposiciones ✅`);
            console.log(`Reuniones:    GET con filtro de privacidad por invitadoUsernames ✅`);
            console.log(`Nebula Agent: /api/nebula/* y /api/agents/* ✅`);
            console.log(`Email SMTP:   ${process.env.SMTP_HOST ? '✅ ' + process.env.SMTP_HOST : '❌ no configurado'}`);
            console.log(`HC Upload:    Transacción atómica ACID (BUG-003 ✅ v4.5.2)`);
            console.log(`Formatos:     XLSX real ExcelJS + cache + CORS header (BUG-002 ✅ v4.5.2)`);
            console.log(`Seguridad:    Helmet CSP/HSTS/hidePoweredBy (SEC-004 ✅ v4.5.2)`);
            console.log(`TTL Index:    hub_notificaciones 30d (PERF-002 ✅ v4.5.3)`);
            console.log(`Email RH:     Email fresco desde MongoDB (BUG-004 ✅ v4.5.3)`);
            console.log(`Paginación:   GET /api/rh/movimientos page+limit+filtros (BUG-005 ✅ v4.5.4)`);
            console.log(`Sheet IDs:    GET /api/config/sheets autenticado (MAINT-002 ✅ v4.5.6) — ${_sheetIdsConfigured.length}/${Object.keys(SHEET_ENV_MAP).length} configurados`);
            console.log(`HC Validación: GET /api/hc/validar-consistencia (FEAT-005 ✅ v4.5.7)`);
            // ← PASO 5: nueva línea de estado FEAT-004
            console.log(`Reporte Semanal: ${process.env.WEEKLY_REPORT_ENABLED === 'true' ? '✅ Activo (WEEKLY_REPORT_ENABLED=true)' : '❌ Inactivo — activa con WEEKLY_REPORT_ENABLED=true'}`);
            console.log(`Hub AI:          POST /api/hub/ai/summarize-chat · extract-tasks · meeting-brief (INN-002 ✅ v4.7.0)`);
            console.log(`Exec Alerts:     GET /api/exec/alerts (ADMIN/GERENTE_OPERACIONES) (INN-003 ✅ v4.7.0)`);
            console.log(`KPI Summary:     GET /api/kpi/summary · /api/hub/activity/summary · /api/headcount/summary (INN-003 ✅ v4.7.0)`);
        });
    } catch (err) {
        console.error('Error iniciando:', err);
        process.exit(1);
    }
}

start();
