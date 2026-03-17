/* ==================================================================
   MYG TELECOM - SERVIDOR UNIFICADO v3.6

   Cambios v3.6:
   - 6 nuevos permisos granulares (asistencia, concentrado, peticiones)
   - ROL_PERMISOS_DEFAULT actualizado (SISTEMAS y GERENTE)
   - Colección hub_peticiones con índices
   - canViewConcentrado usa permiso dinámico hub.concentrado.ver
   - Helper usuarioTienePermisoConOverride
   - Middleware requirePermisoHub
   - POST /api/hub/asistencia: admin puede registrar para otros (targetUsername)
   - POST /api/auth/login: devuelve permisosEfectivos calculados
   - Endpoints completos /api/hub/peticiones (GET/POST/PATCH/DELETE)
   ================================================================== */

import express    from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import ExcelJS    from 'exceljs';
import cors       from 'cors';
import crypto     from 'crypto';
import Joi        from 'joi';
import winston    from 'winston';
import path       from 'path';
import { fileURLToPath } from 'url';
import fs         from 'fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname  = path.dirname(__filename);

const app  = express();
const PORT = process.env.PORT || 3000;

const IS_VERCEL     = process.env.VERCEL === '1';
const IS_RENDER     = process.env.RENDER === 'true';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const IS_CLOUD      = IS_VERCEL || IS_RENDER || IS_PRODUCTION;
const TEMPLATES_DIR = path.join(__dirname, 'plantillas');
const templateCache = new Map();
const CACHE_TTL     = 60 * 60 * 1000;

const sseClients = new Map();

function sseEnviar(username, event, data) {
    const conns = sseClients.get(username);
    if (!conns || conns.size === 0) return;
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    const muertas = [];
    for (const res of conns) {
        try { res.write(payload); } catch { muertas.push(res); }
    }
    for (const res of muertas) { conns.delete(res); }
    if (conns.size === 0) sseClients.delete(username);
}

function sseBroadcast(event, data) {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const [username, conns] of sseClients) {
        const muertas = [];
        for (const res of conns) {
            try { res.write(payload); } catch { muertas.push(res); }
        }
        for (const res of muertas) { conns.delete(res); }
        if (conns.size === 0) sseClients.delete(username);
    }
}

function sseRegistrar(username, res) {
    if (!sseClients.has(username)) sseClients.set(username, new Set());
    sseClients.get(username).add(res);
    logger.info(`SSE conectado: ${username}`);
    return () => {
        const conns = sseClients.get(username);
        if (conns) { conns.delete(res); if (conns.size === 0) sseClients.delete(username); }
        logger.info(`SSE desconectado: ${username}`);
    };
}

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (IS_PRODUCTION ? 'info' : 'debug'),
    format: winston.format.combine(winston.format.timestamp(), winston.format.json()),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(winston.format.colorize(), winston.format.simple())
        })
    ]
});
if (!IS_CLOUD) {
    logger.add(new winston.transports.File({ filename: 'logs/error.log', level: 'error' }));
    logger.add(new winston.transports.File({ filename: 'logs/combined.log' }));
}

const MONGODB_URI = process.env.MONGODB_URI ||
    'mongodb+srv://iqu_api:UV1qiXyzk6Yducaz@cluster0.kb6nsgi.mongodb.net/?appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET ||
    'AKfycbwJ6NPiIrwGMXOfZYLjoo-TXI07O3pz94QA-M7yOOb-fiBmsXb3bmFljw_FnVsebTK4hw';
const DB_NAME = 'iqu_telecom';

const COLLECTIONS = {
    USERS:                  'users',
    DEVICES:                'devices',
    INVENTORY_HISTORY:      'inventory_history',
    COMMANDS:               'commands',
    AGENTS_LOG:             'agents_log',
    RH_MOVIMIENTOS:         'rh_movimientos',
    NOTIFICACIONES:         'notificaciones',
    HUB_MENSAJES:           'hub_mensajes',
    HUB_REUNIONES:          'hub_reuniones',
    HUB_MINUTAS:            'hub_minutas',
    HUB_TAREAS:             'hub_tareas',
    HUB_ANUNCIOS:           'hub_anuncios',
    HUB_RECURSOS:           'hub_recursos',
    HUB_GUIAS:              'hub_guias',
    HUB_PLANTILLAS:         'hub_plantillas',
    HUB_CAPACITACION:       'hub_capacitacion',
    HUB_ASISTENCIA:         'hub_asistencia',
    HUB_VACACIONES:         'hub_vacaciones',
    HUB_CONCENTRADO_CONFIG: 'hub_concentrado_config',
    HUB_PETICIONES:         'hub_peticiones',        // ← v3.6 NUEVO
    ADMIN_ACCESS_LOGS:      'admin_access_logs',
    ROLE_PERMISSIONS:       'role_permissions',
};

const ACTIVATION_TEMPLATES = {
    ACCWEB:     { file: 'ACTIVACION_ACCWEB.xlsx',     driveId: process.env.DRIVE_ID_ASCCWEB || process.env.DRIVE_ID_ACCWEB, label: 'AccWeb',     description: 'ACCWEB',     fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    ASCC:       { file: 'ACTIVACION_ASCC.xlsx',       driveId: process.env.DRIVE_ID_ASCC,       label: 'ASCC',       description: 'ASCC',       fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    ASD:        { file: 'ACTIVACION_ASD.xlsx',        driveId: process.env.DRIVE_ID_ASD,        label: 'ASD',        description: 'ASD',        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    AVS:        { file: 'ACTIVACION_AVS.xlsx',        driveId: process.env.DRIVE_ID_AVS,        label: 'AVS',        description: 'AVS',        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    DIGITAL:    { file: 'ACTIVACION_DIGITAL.xlsx',    driveId: process.env.DRIVE_ID_DIGITAL,    label: 'DIGITAL',    description: 'Digital',    fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    IC:         { file: 'ACTIVACION_IC.xlsx',         driveId: process.env.DRIVE_ID_IC,         label: 'IC',         description: 'Inventario Ciclico', fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    IDM:        { file: 'ACTIVACION_IDM.xlsx',        driveId: process.env.DRIVE_ID_IDM,        label: 'IDM',        description: 'IDM',        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    OFA:        { file: 'ACTIVACION_OFA.xlsx',        driveId: process.env.DRIVE_ID_OFA,        label: 'OFA',        description: 'Oracle',     fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    PAYMENTBOX: { file: 'ACTIVACION_PAYMENTBOX.xlsx', driveId: process.env.DRIVE_ID_PAYMENTBOX, label: 'PAYMENTBOX', description: 'Paymentbox', fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    RED:        { file: 'ACTIVACION_RED.xlsx',        driveId: process.env.DRIVE_ID_RED,        label: 'RED',        description: 'RED',        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    SALESFORCE: { file: 'ACTIVACION_SALESFORCE.xlsx', driveId: process.env.DRIVE_ID_SALESFORCE, label: 'SALESFORCE', description: 'Salesforce', fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
    VPN:        { file: 'ACTIVACION_VPN.xlsx',        driveId: process.env.DRIVE_ID_VPN,        label: 'VPN',        description: 'VPN',        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' } },
};

const userCreateSchema = Joi.object({
    username: Joi.string().min(3).max(50).required(),
    password: Joi.string().min(6).required(),
    nombre:   Joi.string().min(3).max(100).required(),
    email:    Joi.string().email().required(),
    rol:      Joi.string().valid('ADMIN','RH','SISTEMAS','GERENTE','USUARIO').required(),
    activo:   Joi.boolean().default(true)
});
const userUpdateSchema = Joi.object({
    password: Joi.string().min(6).optional(),
    nombre:   Joi.string().min(3).max(100).optional(),
    email:    Joi.string().email().optional(),
    rol:      Joi.string().valid('ADMIN','RH','SISTEMAS','GERENTE','USUARIO').optional(),
    activo:   Joi.boolean().optional(),
    telefono: Joi.string().max(20).optional().allow(''),
    puesto:   Joi.string().max(100).optional().allow(''),
});

app.use(cors());
app.use(express.json({ limit: '10mb' }));
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, { ip: req.ip, env: IS_CLOUD ? 'cloud' : 'local' });
    next();
});

const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Token requerido' });
        req.usuario = verifyJWT(token);
        next();
    } catch (error) {
        res.status(401).json({ error: 'Autenticación fallida' });
    }
};

const requireAdmin = (req, res, next) => {
    if (!req.usuario || req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Requiere rol ADMIN' });
    next();
};
const requireSistemas = (req, res, next) => {
    if (!req.usuario || !['SISTEMAS', 'ADMIN'].includes(req.usuario.rol)) return res.status(403).json({ error: 'Requiere rol SISTEMAS o ADMIN' });
    next();
};

function base64UrlEncode(str) { return Buffer.from(str).toString('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, ''); }
function base64UrlDecode(str) { str = str.replace(/-/g, '+').replace(/_/g, '/'); while (str.length % 4) str += '='; return Buffer.from(str, 'base64').toString('utf8'); }
function createJWT(payload) {
    const header  = { alg: 'HS256', typ: 'JWT' };
    const enc     = s => base64UrlEncode(JSON.stringify(s));
    const message = `${enc(header)}.${enc(payload)}`;
    const sig = crypto.createHmac('sha256', JWT_SECRET).update(message).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    return `${message}.${sig}`;
}
function verifyJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token');
    const [encodedHeader, encodedPayload, signature] = parts;
    const message = `${encodedHeader}.${encodedPayload}`;
    const expectedSig = crypto.createHmac('sha256', JWT_SECRET).update(message).digest('base64').replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
    if (signature !== expectedSig) throw new Error('Invalid signature');
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    if (payload.exp && Date.now() > payload.exp) throw new Error('Token expired');
    return payload;
}
function hashPassword(password) { return crypto.createHash('sha256').update(password).digest('hex'); }
function esDateValido(str) {
    if (!str || typeof str !== 'string') return false;
    if (!/^\d{4}-\d{2}-\d{2}$/.test(str)) return false;
    return !isNaN(new Date(str + 'T12:00:00').getTime());
}

// ============================================================
// MÓDULO DE PERMISOS v3.6
// ============================================================

const MODULOS_PERMISOS = {
    'dashboard.ver':           'Ver Dashboard principal',
    'dashboard.rh':            'Módulo RH (Movimientos)',
    'dashboard.headcount':     'Módulo Headcount',
    'dashboard.activos':       'Módulo Activos',
    'dashboard.tickets':       'Módulo Tickets',
    'dashboard.dispositivos':  'Módulo Dispositivos IQU',
    'dashboard.kpi_sistemas':  'KPI Sistemas',
    'hub.acceso':              'Acceder al Hub de Sistemas',
    'hub.mensajes':            'Mensajes del Hub',
    'hub.reuniones':           'Reuniones',
    'hub.minutas':             'Minutas',
    'hub.tareas':              'Kanban de Tareas',
    'hub.anuncios':            'Anuncios',
    'hub.recursos':            'Recursos compartidos',
    'hub.guias':               'Guías y procedimientos',
    'hub.plantillas':          'Plantillas del Hub',
    'hub.capacitacion':        'Tracker de Capacitación',
    'hub.asistencia':          'Asistencias (legacy)',
    'hub.vacaciones':          'Vacaciones',
    'hub.concentrado':         'Concentrado de Asistencia (legacy)',
    // ── v3.6: Permisos granulares ─────────────────────────
    'hub.asistencia.registrar':       'Registrar su propia asistencia',
    'hub.asistencia.admin_registro':  'Registrar asistencia de OTROS usuarios',
    'hub.concentrado.ver':            'Ver concentrado general de asistencia',
    'hub.peticiones.crear':           'Crear peticiones (HO, tardanza, permiso, etc.)',
    'hub.peticiones.aprobar':         'Aprobar o rechazar peticiones del equipo',
    'hub.peticiones.ver_todas':       'Ver todas las peticiones del equipo',
    // ─────────────────────────────────────────────────────
    'formatos.generar':        'Generar formatos de activación',
    'rh.movimientos.crear':    'Crear solicitudes RH',
    'rh.movimientos.ver':      'Ver movimientos RH',
    'rh.movimientos.gestionar':'Cambiar estado de movimientos',
    'activos.ver':             'Ver activos e inventario',
    'activos.registrar':       'Registrar movimientos de activos',
    'chatbot.usar':            'Usar chatbot IA',
    'admin.panel':             'Acceder al Panel de Administración',
    'admin.usuarios':          'Gestión de usuarios (CRUD)',
    'admin.permisos':          'Gestión de permisos y roles',
    'admin.logs':              'Ver logs de acceso',
    'admin.formularios':       'Ver entradas de formularios',
};

const ROL_PERMISOS_DEFAULT = {
    ADMIN: ['*'],
    SISTEMAS: [
        'dashboard.ver', 'dashboard.dispositivos',
        'hub.acceso', 'hub.mensajes', 'hub.reuniones', 'hub.minutas',
        'hub.tareas', 'hub.anuncios', 'hub.recursos', 'hub.guias',
        'hub.plantillas', 'hub.capacitacion', 'hub.asistencia', 'hub.vacaciones',
        'hub.concentrado',
        // ── v3.6 granulares ──────────────────────────────
        'hub.asistencia.registrar', 'hub.asistencia.admin_registro',
        'hub.concentrado.ver',
        'hub.peticiones.crear', 'hub.peticiones.aprobar', 'hub.peticiones.ver_todas',
        'formatos.generar', 'rh.movimientos.ver', 'rh.movimientos.gestionar',
        'activos.ver', 'activos.registrar', 'chatbot.usar',
    ],
    RH: [
        'dashboard.ver', 'dashboard.rh', 'dashboard.headcount',
        'rh.movimientos.crear', 'rh.movimientos.ver', 'chatbot.usar',
    ],
    GERENTE: [
        'dashboard.ver', 'dashboard.rh', 'dashboard.headcount',
        'dashboard.activos', 'dashboard.tickets', 'rh.movimientos.ver', 'chatbot.usar',
        // ── v3.6 ─────────────────────────────────────────
        'hub.acceso', 'hub.concentrado.ver',
        'hub.peticiones.aprobar', 'hub.peticiones.ver_todas',
    ],
    USUARIO: ['dashboard.ver', 'chatbot.usar'],
};

function usuarioTienePermiso(usuario, permiso, overrides = null) {
    if (!usuario) return false;
    if (usuario.rol === 'ADMIN') return true;
    const added   = overrides?.added   || usuario.permisosOverride?.added   || [];
    const removed = overrides?.removed || usuario.permisosOverride?.removed || [];
    if (removed.includes(permiso)) return false;
    if (added.includes(permiso))   return true;
    const rolPermisos = ROL_PERMISOS_DEFAULT[usuario.rol] || [];
    if (rolPermisos.includes('*')) return true;
    return rolPermisos.includes(permiso);
}

// ── v3.6: Helper que consulta overrides en BD ─────────────────
async function usuarioTienePermisoConOverride(req, permiso) {
    if (!req.usuario) return false;
    if (req.usuario.rol === 'ADMIN') return true;
    try {
        const col  = await getCollection(COLLECTIONS.USERS);
        const user = await col.findOne({ username: req.usuario.username }, { projection: { permisosOverride: 1 } });
        return usuarioTienePermiso(req.usuario, permiso, user?.permisosOverride);
    } catch { return false; }
}

const requirePermiso = (permiso) => async (req, res, next) => {
    try {
        if (!req.usuario) return res.status(401).json({ error: 'No autenticado' });
        if (req.usuario.rol === 'ADMIN') return next();
        const col  = await getCollection(COLLECTIONS.USERS);
        const user = await col.findOne({ username: req.usuario.username }, { projection: { permisosOverride: 1 } });
        if (usuarioTienePermiso(req.usuario, permiso, user?.permisosOverride)) return next();
        return res.status(403).json({ error: `Acceso denegado. Permiso requerido: ${permiso}`, permiso });
    } catch (err) { return res.status(500).json({ error: err.message }); }
};

// ── v3.6: Middleware granular para permisos del Hub ───────────
const requirePermisoHub = (permiso) => async (req, res, next) => {
    if (!req.usuario) return res.status(401).json({ error: 'No autenticado' });
    if (req.usuario.rol === 'ADMIN') return next();
    if (await usuarioTienePermisoConOverride(req, permiso)) return next();
    logger.warn(`Permiso hub denegado: ${req.usuario.username} → [${permiso}]`);
    return res.status(403).json({ error: `Permiso requerido: ${permiso}`, permiso });
};

// ── MongoDB ───────────────────────────────────────────────────
let cachedClient = null, cachedDb = null;
async function connectDB() {
    if (cachedClient && cachedDb) return { client: cachedClient, db: cachedDb };
    const client = new MongoClient(MONGODB_URI, { maxPoolSize: 10, minPoolSize: 2, serverSelectionTimeoutMS: 5000, socketTimeoutMS: 45000 });
    await client.connect();
    cachedClient = client; cachedDb = client.db(DB_NAME);
    logger.info('✅ Connected to MongoDB Atlas');
    return { client, db: cachedDb };
}
async function getCollection(collectionName) { const { db } = await connectDB(); return db.collection(collectionName); }

// ── Template utils ────────────────────────────────────────────
async function downloadTemplateFromDrive(driveId, filename) {
    const url = `https://drive.google.com/uc?export=download&id=${driveId}`;
    const response = await fetch(url, { headers: { 'User-Agent': 'Mozilla/5.0' }, signal: AbortSignal.timeout(30000) });
    if (!response.ok) throw new Error(`HTTP ${response.status}: ${response.statusText}`);
    return Buffer.from(await response.arrayBuffer());
}
async function loadTemplate(sistema, config) {
    const cacheKey = `template_${sistema}`;
    const templatePath = path.join(TEMPLATES_DIR, config.file);
    if (!IS_CLOUD) {
        try { await fs.access(templatePath); return await fs.readFile(templatePath); } catch {}
    }
    if (templateCache.has(cacheKey)) {
        const cached = templateCache.get(cacheKey);
        if (Date.now() - cached.timestamp < CACHE_TTL) return cached.buffer;
        templateCache.delete(cacheKey);
    }
    if (!config.driveId) throw new Error(`Plantilla ${config.file} no disponible: falta DRIVE_ID_${sistema}`);
    const buffer = await downloadTemplateFromDrive(config.driveId, config.file);
    templateCache.set(cacheKey, { buffer, timestamp: Date.now() });
    return buffer;
}
function getNormalizedFieldValue(obj, possibleNames) {
    if (!obj) return '';
    for (const name of possibleNames) {
        if (name in obj && obj[name] !== null && obj[name] !== undefined) {
            const value = String(obj[name]).trim();
            if (value && value !== '-' && value !== 'N/A') return value;
        }
    }
    return '';
}
function normalizePDVName(n) { return n ? n.toString().replace(/^(PUNTO DE VENTA|PDV|PV)\s*/i, '').trim() : ''; }
function mapUserDataForFormato(ud) {
    return {
        nombre:    getNormalizedFieldValue(ud, ['NOMBRE','nombre','Nombre Completo','NOMBRE COMPLETO','nombreCompleto','Nombre','NAME']),
        attuid:    getNormalizedFieldValue(ud, ['ATTUID','attuid','ATT UID','AttUID','att_uid']),
        puesto:    getNormalizedFieldValue(ud, ['PUESTO','puesto','Puesto','POSITION','Position','cargo']),
        pdv:       normalizePDVName(getNormalizedFieldValue(ud, ['PDV','pdv','nombrePDV','NOMBRE PDV','Nombre PDV','nombre_pdv'])),
        clave_pdv: getNormalizedFieldValue(ud, ['CLAVE PDV','clavePDV','clave_pdv','CLAVEPDV','Clave PDV']),
        correo:    getNormalizedFieldValue(ud, ['CORREO','correo','email','EMAIL','E-mail','mail']),
    };
}
function generateSafeFilename(sistema, nombre) {
    const safeName = (nombre || 'USUARIO').toUpperCase().replace(/\s+/g, '_').replace(/[^A-Z0-9_]/g, '').substring(0, 30);
    return `ACTIVACION_${sistema}_${safeName}.xlsx`;
}

async function verificarPlantillas() {
    const status = { filesystem: false, googleDrive: false, available: [], missing: [], mode: IS_CLOUD ? 'cloud' : 'local' };
    if (!IS_CLOUD) { try { await fs.access(TEMPLATES_DIR); status.filesystem = true; } catch {} }
    for (const [key, config] of Object.entries(ACTIVATION_TEMPLATES)) {
        let available = false;
        if (status.filesystem) {
            try { await fs.access(path.join(TEMPLATES_DIR, config.file)); available = true; status.available.push({ sistema: key, source: 'filesystem' }); } catch {}
        }
        if (!available && config.driveId) {
            status.googleDrive = true; available = true; status.available.push({ sistema: key, source: 'drive' });
        }
        if (!available) status.missing.push({ sistema: key, file: config.file, needsDriveId: `DRIVE_ID_${key}` });
    }
    return status;
}

// ── Hub middleware ─────────────────────────────────────────────
const requireHubAccess = (req, res, next) => {
    if (!req.usuario || !['SISTEMAS', 'ADMIN'].includes(req.usuario.rol)) {
        return res.status(403).json({ error: 'Acceso solo para roles SISTEMAS y ADMIN' });
    }
    next();
};

const HUB_CANALES = [
    { id: 'general',   name: 'general',    emoji: '💬', pinned: true  },
    { id: 'proyectos', name: 'proyectos',  emoji: '🚀', pinned: false },
    { id: 'soporte',   name: 'soporte',    emoji: '🛠️', pinned: false },
    { id: 'dev',       name: 'desarrollo', emoji: '💻', pinned: false },
    { id: 'anuncios',  name: 'anuncios',   emoji: '📣', pinned: true  },
];

const TIPOS_ASISTENCIA = ['asistencia','falta','retardo','incapacidad','permiso','homeoffice'];
const TIPOS_PETICION   = ['homeoffice','tardanza','vacaciones','permiso_personal','incapacidad','dia_personal','otro'];

// ============================================================
// DB INIT
// ============================================================
async function initializeDB() {
    try {
        const users = await getCollection(COLLECTIONS.USERS);
        const admin = await users.findOne({ username: 'admin' });
        if (!admin) {
            await users.insertOne({
                username: 'admin', password: hashPassword('myg2025'),
                nombre: 'Administrador', email: 'admin@mygtelecom.mx',
                rol: 'ADMIN', activo: true, permisos: ['*'],
                creadoEn: new Date().toISOString(), actualizadoEn: new Date().toISOString(), ultimoAcceso: null
            });
            logger.info('✅ Admin user created');
        }
        // Índices RH
        const rhMovimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        await rhMovimientos.createIndex({ fecha_creacion: -1 });
        await rhMovimientos.createIndex({ estado: 1 });
        // Índices notificaciones
        const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
        await notificaciones.createIndex({ usuario_destino: 1, leida: 1 });
        await notificaciones.createIndex({ fecha_creacion: -1 });
        // Índices Hub
        for (const [col, idx] of [
            [COLLECTIONS.HUB_MENSAJES,    [{ canal: 1, createdAt: -1 }]],
            [COLLECTIONS.HUB_REUNIONES,   [{ fecha: 1 }]],
            [COLLECTIONS.HUB_MINUTAS,     [{ createdAt: -1 }]],
            [COLLECTIONS.HUB_TAREAS,      [{ columna: 1, orden: 1 }]],
            [COLLECTIONS.HUB_ANUNCIOS,    [{ pinned: -1, createdAt: -1 }]],
            [COLLECTIONS.HUB_RECURSOS,    [{ categoria: 1, createdAt: -1 }]],
            [COLLECTIONS.HUB_GUIAS,       [{ categoria: 1, createdAt: -1 }, { titulo: 'text', descripcion: 'text' }]],
            [COLLECTIONS.HUB_PLANTILLAS,  [{ tipo: 1, nombre: 1 }]],
            [COLLECTIONS.HUB_CAPACITACION,[{ orden: 1 }, { progreso: 1 }]],
        ]) {
            const c = await getCollection(col);
            for (const i of idx) await c.createIndex(i);
        }
        // Asistencia
        const hubAsistencia = await getCollection(COLLECTIONS.HUB_ASISTENCIA);
        await hubAsistencia.createIndex({ username: 1, fecha: -1 });
        await hubAsistencia.createIndex({ fecha: -1 });
        await hubAsistencia.createIndex({ username: 1, fecha: 1 }, { unique: true, name: 'unique_user_date' });
        // Vacaciones
        const hubVacaciones = await getCollection(COLLECTIONS.HUB_VACACIONES);
        await hubVacaciones.createIndex({ username: 1, creadoEn: -1 });
        await hubVacaciones.createIndex({ status: 1 });
        // Peticiones v3.6
        const hubPeticiones = await getCollection(COLLECTIONS.HUB_PETICIONES);
        await hubPeticiones.createIndex({ username: 1, creadoEn: -1 });
        await hubPeticiones.createIndex({ status: 1, creadoEn: -1 });
        await hubPeticiones.createIndex({ tipo: 1 });
        logger.info('✅ hub_peticiones indexes created');
        // Admin logs
        const adminLogs = await getCollection(COLLECTIONS.ADMIN_ACCESS_LOGS);
        await adminLogs.createIndex({ timestamp: -1 });
        await adminLogs.createIndex({ username: 1, timestamp: -1 });
        // Role permissions seed
        const rolePermsCol  = await getCollection(COLLECTIONS.ROLE_PERMISSIONS);
        const existingPerms = await rolePermsCol.findOne({ type: 'role_defaults' });
        if (!existingPerms) {
            await rolePermsCol.insertOne({
                type: 'role_defaults', permisos: ROL_PERMISOS_DEFAULT,
                modulos: MODULOS_PERMISOS, version: '1.2',
                actualizadoEn: new Date().toISOString(), actualizadoPor: 'system-v3.6',
            });
            logger.info('✅ Role permissions seeded v1.2');
        } else {
            // Migración: asegurar nuevos permisos en SISTEMAS
            const newPerms = ['hub.asistencia.registrar','hub.asistencia.admin_registro','hub.concentrado.ver','hub.peticiones.crear','hub.peticiones.aprobar','hub.peticiones.ver_todas'];
            const sistPerms = existingPerms.permisos?.SISTEMAS || [];
            const toAdd = newPerms.filter(p => !sistPerms.includes(p));
            if (toAdd.length > 0) {
                await rolePermsCol.updateOne({ type: 'role_defaults' }, {
                    $addToSet: { 'permisos.SISTEMAS': { $each: toAdd } },
                    $set: { actualizadoEn: new Date().toISOString(), actualizadoPor: 'system-v3.6' }
                });
                logger.info(`✅ Migrados ${toAdd.length} permisos v3.6 a SISTEMAS`);
            }
        }
        logger.info('✅ Database indexes created v3.6');
    } catch (error) {
        logger.error('Error initializing DB:', error); throw error;
    }
}

// ============================================================
// ENDPOINTS — ROOT & HEALTH
// ============================================================
app.get('/', (req, res) => res.json({ name: 'MYG Telecom - Servidor Unificado', version: '3.6.0', status: 'running' }));

app.get('/health', async (req, res) => {
    try {
        await connectDB();
        const plantillasStatus = await verificarPlantillas();
        res.json({ status: 'ok', timestamp: new Date().toISOString(), version: '3.6.0', database: { status: 'connected' }, storage: { templates: plantillasStatus } });
    } catch (error) { res.status(500).json({ status: 'error', error: error.message }); }
});

// ============================================================
// ENDPOINTS — AUTENTICACIÓN
// ============================================================
app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        const users = await getCollection(COLLECTIONS.USERS);
        const user  = await users.findOne({ username });
        if (!user || !user.activo) return res.status(401).json({ error: 'Credenciales inválidas' });
        if (hashPassword(password) !== user.password) {
            try {
                const accessLogs = await getCollection(COLLECTIONS.ADMIN_ACCESS_LOGS);
                await accessLogs.insertOne({ username, nombre: user?.nombre || null, rol: user?.rol || null, ip: req.ip || req.headers['x-forwarded-for'] || 'unknown', userAgent: req.get('user-agent') || 'unknown', resultado: 'fallido', razon: 'password_incorrecto', timestamp: new Date().toISOString() });
            } catch {}
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }
        await users.updateOne({ username }, { $set: { ultimoAcceso: new Date().toISOString() } });
        const token = createJWT({ username: user.username, nombre: user.nombre, rol: user.rol, email: user.email, exp: Date.now() + (24 * 60 * 60 * 1000) });
        try {
            const accessLogs = await getCollection(COLLECTIONS.ADMIN_ACCESS_LOGS);
            await accessLogs.insertOne({ username, nombre: user.nombre, rol: user.rol, ip: req.ip || req.headers['x-forwarded-for'] || 'unknown', userAgent: req.get('user-agent') || 'unknown', resultado: 'exitoso', timestamp: new Date().toISOString() });
        } catch {}

        // v3.6: calcular permisosEfectivos para el cliente
        const rolPerms  = ROL_PERMISOS_DEFAULT[user.rol] || [];
        const overrides = user.permisosOverride || { added: [], removed: [] };
        const permisosEfectivos = user.rol === 'ADMIN'
            ? ['*']
            : [...rolPerms.filter(p => !overrides.removed.includes(p)), ...overrides.added.filter(p => !rolPerms.includes(p))];

        logger.info(`Login successful: ${username}`);
        res.json({
            success: true, token,
            user: { username: user.username, nombre: user.nombre, rol: user.rol, email: user.email, permisos: permisosEfectivos }
        });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// ENDPOINTS — USUARIOS
// ============================================================
app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        const collection = await getCollection(COLLECTIONS.USERS);
        const users = await collection.find({ activo: true }).project({ password: 0 }).toArray();
        res.json(users);
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.get('/api/users/:username', authMiddleware, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Solo puedes consultar tu propio perfil' });
        const col  = await getCollection(COLLECTIONS.USERS);
        const user = await col.findOne({ username }, { projection: { password: 0 } });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json(user);
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/users', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { error, value } = userCreateSchema.validate(req.body, { abortEarly: false });
        if (error) return res.status(400).json({ error: error.details.map(d => d.message).join('; ') });
        const collection = await getCollection(COLLECTIONS.USERS);
        if (await collection.findOne({ username: value.username })) return res.status(409).json({ error: 'Username ya existe' });
        value.password = hashPassword(value.password); value.creadoEn = new Date().toISOString(); value.actualizadoEn = new Date().toISOString(); value.ultimoAcceso = null; value.permisos = ['*'];
        const result = await collection.insertOne(value);
        delete value.password;
        res.status(201).json({ success: true, user: { ...value, _id: result.insertedId } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.put('/api/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { error, value } = userUpdateSchema.validate(req.body, { stripUnknown: true });
        if (error) return res.status(400).json({ error: error.details.map(d => d.message).join('; ') });
        const collection = await getCollection(COLLECTIONS.USERS);
        if (value.password) value.password = hashPassword(value.password);
        value.actualizadoEn = new Date().toISOString();
        const result = await collection.updateOne({ username: req.params.username }, { $set: value });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.delete('/api/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        if (req.params.username === 'admin') return res.status(403).json({ error: 'No se puede eliminar el usuario admin' });
        const collection = await getCollection(COLLECTIONS.USERS);
        const result = await collection.updateOne({ username: req.params.username }, { $set: { activo: false, eliminadoEn: new Date().toISOString() } });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.patch('/api/users/:username/profile', authMiddleware, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Solo puedes actualizar tu propio perfil' });
        const profileSchema = Joi.object({ nombre: Joi.string().min(3).max(100).optional(), email: Joi.string().email().optional().allow(''), telefono: Joi.string().max(20).optional().allow(''), puesto: Joi.string().max(100).optional().allow('') });
        const { error, value } = profileSchema.validate(req.body, { stripUnknown: true });
        if (error) return res.status(400).json({ error: error.details.map(d => d.message).join('; ') });
        const camposValidos = Object.fromEntries(Object.entries(value).filter(([, v]) => v !== '' && v !== null && v !== undefined));
        if (Object.keys(camposValidos).length === 0) return res.status(400).json({ error: 'No se enviaron campos válidos' });
        camposValidos.actualizadoEn = new Date().toISOString();
        const col = await getCollection(COLLECTIONS.USERS);
        const result = await col.updateOne({ username }, { $set: camposValidos });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        const updatedUser = await col.findOne({ username }, { projection: { password: 0 } });
        res.json({ success: true, updated: camposValidos, user: updatedUser });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.patch('/api/users/:username/password', authMiddleware, async (req, res) => {
    try {
        const { username } = req.params;
        const { passwordActual, passwordNueva } = req.body;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Solo puedes cambiar tu propia contraseña' });
        if (!passwordActual || !passwordNueva) return res.status(400).json({ error: 'Se requieren passwordActual y passwordNueva' });
        if (passwordNueva.length < 6) return res.status(400).json({ error: 'La contraseña nueva debe tener al menos 6 caracteres' });
        const col  = await getCollection(COLLECTIONS.USERS);
        const user = await col.findOne({ username });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        if (req.usuario.rol !== 'ADMIN' && user.password !== hashPassword(passwordActual)) return res.status(401).json({ error: 'La contraseña actual no es correcta' });
        await col.updateOne({ username }, { $set: { password: hashPassword(passwordNueva), actualizadoEn: new Date().toISOString() } });
        res.json({ success: true, message: 'Contraseña actualizada correctamente' });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// ENDPOINTS — FORMATOS DE ACTIVACIÓN
// ============================================================
app.get('/api/formatos/sistemas', authMiddleware, async (req, res) => {
    try {
        const plantillasStatus = await verificarPlantillas();
        const sistemas = Object.keys(ACTIVATION_TEMPLATES).map(key => {
            const config = ACTIVATION_TEMPLATES[key];
            const availableItem = plantillasStatus.available.find(i => i.sistema === key);
            return { id: key, label: config.label, description: config.description, file: config.file, status: availableItem ? 'available' : 'unavailable', source: availableItem?.source || null, driveConfigured: !!config.driveId };
        }).sort((a, b) => a.label.localeCompare(b.label));
        res.json({ total: sistemas.length, available: sistemas.filter(s => s.status === 'available').length, mode: IS_CLOUD ? 'cloud' : 'local', sistemas });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/formatos/generar', authMiddleware, async (req, res) => {
    const startTime = Date.now();
    try {
        const { sistema, userData } = req.body;
        if (!sistema || !userData) return res.status(400).json({ error: 'Campos "sistema" y "userData" son requeridos' });
        if (!ACTIVATION_TEMPLATES[sistema]) return res.status(400).json({ error: `Sistema no encontrado: ${sistema}` });
        const config = ACTIVATION_TEMPLATES[sistema];
        const fieldData = mapUserDataForFormato(userData);
        if (!fieldData.nombre || !fieldData.puesto) return res.status(400).json({ error: 'Faltan campos críticos: nombre y puesto son requeridos' });
        const templateBuffer = await loadTemplate(sistema, config);
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(templateBuffer);
        const worksheet = workbook.worksheets[0];
        Object.keys(config.fields).forEach(fieldName => { const value = fieldData[fieldName]; if (value) worksheet.getCell(config.fields[fieldName]).value = value; });
        const buffer = await workbook.xlsx.writeBuffer();
        const filename = generateSafeFilename(sistema, fieldData.nombre);
        try { const logs = await getCollection(COLLECTIONS.AGENTS_LOG); await logs.insertOne({ tipo: 'formato_activacion', sistema, usuario: req.usuario.username, nombre_empleado: fieldData.nombre, filename, size_bytes: buffer.length, duracion_ms: Date.now() - startTime, environment: IS_CLOUD ? 'cloud' : 'local', timestamp: new Date().toISOString() }); } catch {}
        res.setHeader('Content-Type', 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', `attachment; filename="${filename}"`);
        res.send(buffer);
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/formatos/clear-cache', authMiddleware, requireAdmin, (req, res) => {
    const beforeSize = templateCache.size; templateCache.clear();
    res.json({ success: true, itemsCleared: beforeSize });
});

// ============================================================
// ENDPOINTS — DISPOSITIVOS
// ============================================================
app.get('/api/devices', async (req, res) => {
    try {
        const devices = await getCollection(COLLECTIONS.DEVICES);
        const { location, status, search } = req.query;
        const filter = {};
        if (location) filter.location = location;
        if (status) filter.status = status;
        if (search) filter.$or = [{ hostname: { $regex: search, $options: 'i' } }, { logged_user: { $regex: search, $options: 'i' } }, { ip_address: { $regex: search, $options: 'i' } }];
        const twentyMinAgo = new Date(Date.now() - 20 * 60 * 1000);
        await devices.updateMany({ last_seen: { $lt: twentyMinAgo.toISOString() }, status: 'online' }, { $set: { status: 'offline' } });
        res.json(await devices.find(filter).sort({ last_seen: -1 }).limit(500).toArray());
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.get('/api/devices/:agentId', async (req, res) => {
    try {
        const devices = await getCollection(COLLECTIONS.DEVICES);
        const device  = await devices.findOne({ agent_id: req.params.agentId });
        if (!device) return res.status(404).json({ error: 'Dispositivo no encontrado' });
        res.json(device);
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/devices/:agentId', async (req, res) => {
    try {
        const devices = await getCollection(COLLECTIONS.DEVICES);
        await devices.updateOne({ agent_id: req.params.agentId }, { $set: { ...req.body, agent_id: req.params.agentId, updated_at: new Date().toISOString() }, $setOnInsert: { created_at: new Date().toISOString() } }, { upsert: true });
        res.json({ success: true });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// ENDPOINTS — RH MOVIMIENTOS
// ============================================================
app.post('/api/rh/movimientos', authMiddleware, async (req, res) => {
    try {
        const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const movimiento = { ...req.body, _id: new ObjectId(), creado_por: { username: req.usuario.username, nombre: req.usuario.nombre, email: req.usuario.email }, estado: 'PENDIENTE', fecha_creacion: new Date().toISOString(), fecha_modificacion: new Date().toISOString(), historial: [{ estado: 'PENDIENTE', fecha: new Date().toISOString(), usuario: req.usuario.username, comentario: 'Movimiento creado' }] };
        await movimientos.insertOne(movimiento);
        res.status(201).json(movimiento);
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.get('/api/rh/movimientos', authMiddleware, async (req, res) => {
    try {
        const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const { tipo, estado, usuario, fecha_desde, fecha_hasta } = req.query;
        const filter = {};
        if (tipo && tipo !== 'todos') filter.tipo = tipo;
        if (estado && estado !== 'todos') filter.estado = estado;
        if (req.usuario.rol === 'RH' || usuario) filter['creado_por.username'] = usuario || req.usuario.username;
        if (fecha_desde || fecha_hasta) { filter.fecha_creacion = {}; if (fecha_desde) filter.fecha_creacion.$gte = new Date(fecha_desde).toISOString(); if (fecha_hasta) filter.fecha_creacion.$lte = new Date(fecha_hasta).toISOString(); }
        else { const tresMesesAtras = new Date(); tresMesesAtras.setMonth(tresMesesAtras.getMonth() - 3); filter.fecha_creacion = { $gte: tresMesesAtras.toISOString() }; }
        res.json(await movimientos.find(filter).sort({ fecha_creacion: -1 }).toArray());
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.patch('/api/rh/movimientos/:id/estado', authMiddleware, requireSistemas, async (req, res) => {
    try {
        const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const { estado, comentario, correo_creado, procesado_por } = req.body;
        const estadosValidos = ['PENDIENTE','EN_PROCESO','COMPLETADO','RECHAZADO'];
        if (!estadosValidos.includes(estado)) return res.status(400).json({ error: 'Estado inválido' });
        const updates = { estado, fecha_modificacion: new Date().toISOString() };
        if (estado === 'COMPLETADO') { updates.fecha_completado = new Date().toISOString(); updates.procesado_por = procesado_por || { username: req.usuario.username, nombre: req.usuario.nombre }; if (correo_creado) updates.correo_creado = correo_creado; }
        await movimientos.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates, $push: { historial: { estado, fecha: new Date().toISOString(), usuario: req.usuario.username, comentario: comentario || `Estado cambiado a ${estado}` } } });
        res.json(await movimientos.findOne({ _id: new ObjectId(req.params.id) }));
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// ENDPOINTS — CHATBOT
// ============================================================
app.post('/api/chat', authMiddleware, async (req, res) => {
    try {
        const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;
        if (!ANTHROPIC_KEY) return res.status(503).json({ error: 'Servicio de IA no disponible.' });
        const { messages, system, max_tokens = 1000, temperature = 0.7 } = req.body;
        if (!messages || !Array.isArray(messages) || messages.length === 0) return res.status(400).json({ error: 'El campo "messages" es requerido.' });
        const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', { method: 'POST', headers: { 'Content-Type': 'application/json', 'x-api-key': ANTHROPIC_KEY, 'anthropic-version': '2023-06-01' }, body: JSON.stringify({ model: 'claude-sonnet-4-20250514', max_tokens, temperature, messages, ...(system && { system }) }) });
        const data = await anthropicRes.json();
        if (!anthropicRes.ok) return res.status(anthropicRes.status).json({ error: data.error?.message || 'Error en el servicio de IA' });
        res.json(data);
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// ENDPOINTS — SSE
// ============================================================
app.get('/api/notificaciones/sse', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(401).end();
    let usuario;
    try { usuario = verifyJWT(token); } catch { return res.status(401).end(); }
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();
    res.write(`event: connected\ndata: ${JSON.stringify({ username: usuario.username, ts: Date.now() })}\n\n`);
    const heartbeat = setInterval(() => { try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); } }, 25000);
    const cleanup = sseRegistrar(usuario.username, res);
    req.on('close', () => { clearInterval(heartbeat); cleanup(); });
});

// ============================================================
// ENDPOINTS — NOTIFICACIONES
// ============================================================
app.get('/api/notificaciones', authMiddleware, async (req, res) => {
    try {
        const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
        const filter = { usuario_destino: req.usuario.username };
        if (req.query.soloNoLeidas === 'true') filter.leida = false;
        const notificacionesList = await notificaciones.find(filter).sort({ fecha_creacion: -1 }).limit(50).toArray();
        const total_no_leidas = await notificaciones.countDocuments({ usuario_destino: req.usuario.username, leida: false });
        res.json({ notificaciones: notificacionesList, total_no_leidas });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.patch('/api/notificaciones/:id/leer', authMiddleware, async (req, res) => {
    try { const col = await getCollection(COLLECTIONS.NOTIFICACIONES); await col.updateOne({ _id: new ObjectId(req.params.id), usuario_destino: req.usuario.username }, { $set: { leida: true, fecha_lectura: new Date().toISOString() } }); res.json({ success: true }); }
    catch (error) { res.status(500).json({ error: error.message }); }
});
app.post('/api/notificaciones', authMiddleware, async (req, res) => {
    try {
        const { titulo, mensaje, tipo, icono, tab_destino, subtab, usuario_destino } = req.body;
        if (!titulo || !mensaje) return res.status(400).json({ error: 'titulo y mensaje son requeridos' });
        if (usuario_destino === '*' && !['ADMIN', 'SISTEMAS'].includes(req.usuario.rol)) return res.status(403).json({ error: 'Solo ADMIN o SISTEMAS pueden enviar notificaciones globales' });
        const col = await getCollection(COLLECTIONS.NOTIFICACIONES);
        let destinos;
        if (usuario_destino === '*') { const users = await getCollection(COLLECTIONS.USERS); destinos = await users.distinct('username', { activo: true }); }
        else destinos = [usuario_destino || req.usuario.username];
        const now = new Date().toISOString();
        const docs = destinos.map(dest => ({ titulo: titulo.trim(), mensaje: mensaje.trim(), tipo: tipo || 'info', icono: icono || null, tab_destino: tab_destino || null, subtab: subtab || null, usuario_destino: dest, autor: req.usuario.username, leida: false, fecha_creacion: now, fecha_lectura: null }));
        const result = await col.insertMany(docs);
        const insertedIds = Object.values(result.insertedIds);
        docs.forEach((doc, i) => sseEnviar(doc.usuario_destino, 'notificacion', { ...doc, _id: insertedIds[i] }));
        res.status(201).json({ success: true, creadas: docs.length });
    } catch (error) { res.status(500).json({ error: error.message }); }
});
app.patch('/api/notificaciones/leer-todas', authMiddleware, async (req, res) => {
    try { const col = await getCollection(COLLECTIONS.NOTIFICACIONES); const result = await col.updateMany({ usuario_destino: req.usuario.username, leida: false }, { $set: { leida: true, fecha_lectura: new Date().toISOString() } }); res.json({ success: true, actualizadas: result.modifiedCount }); }
    catch (error) { res.status(500).json({ error: error.message }); }
});
app.delete('/api/notificaciones/:id', authMiddleware, async (req, res) => {
    try { const col = await getCollection(COLLECTIONS.NOTIFICACIONES); await col.deleteOne({ _id: new ObjectId(req.params.id), usuario_destino: req.usuario.username }); res.json({ success: true }); }
    catch (error) { res.status(500).json({ error: error.message }); }
});
app.delete('/api/notificaciones', authMiddleware, async (req, res) => {
    try { const col = await getCollection(COLLECTIONS.NOTIFICACIONES); const result = await col.deleteMany({ usuario_destino: req.usuario.username, leida: true }); res.json({ success: true, eliminadas: result.deletedCount }); }
    catch (error) { res.status(500).json({ error: error.message }); }
});

// ============================================================
// ENDPOINTS — HUB (mensajes, reuniones, minutas, tareas,
//             anuncios, recursos, guías, plantillas, capacitación)
// (idénticos a v3.5 — omitidos por brevedad, incluidos completos abajo)
// ============================================================

// ── MENSAJES ──────────────────────────────────────────────────
app.get('/api/hub/mensajes/:canal', authMiddleware, requireHubAccess, async (req, res) => {
    try { const col = await getCollection(COLLECTIONS.HUB_MENSAJES); const mensajes = await col.find({ canal: req.params.canal }).sort({ createdAt: 1 }).limit(parseInt(req.query.limit) || 100).toArray(); res.json({ canal: req.params.canal, mensajes, canales: HUB_CANALES }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/hub/mensajes/:canal', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'El contenido del mensaje es requerido' });
        const col = await getCollection(COLLECTIONS.HUB_MENSAJES);
        const mensaje = { _id: new ObjectId(), canal: req.params.canal, userId: req.usuario.username, userName: req.usuario.nombre, avatar: req.usuario.nombre?.charAt(0).toUpperCase() || '?', content: content.trim(), reactions: {}, edited: false, createdAt: new Date() };
        await col.insertOne(mensaje); res.status(201).json(mensaje);
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/hub/mensajes/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try { const { content } = req.body; if (!content?.trim()) return res.status(400).json({ error: 'Contenido requerido' }); const col = await getCollection(COLLECTIONS.HUB_MENSAJES); const result = await col.updateOne({ _id: new ObjectId(req.params.id), userId: req.usuario.username }, { $set: { content: content.trim(), edited: true, editedAt: new Date() } }); if (result.matchedCount === 0) return res.status(404).json({ error: 'Mensaje no encontrado o no autorizado' }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/hub/mensajes/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try { const col = await getCollection(COLLECTIONS.HUB_MENSAJES); const filter = req.usuario.rol === 'ADMIN' ? { _id: new ObjectId(req.params.id) } : { _id: new ObjectId(req.params.id), userId: req.usuario.username }; const result = await col.deleteOne(filter); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrado o no autorizado' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/hub/mensajes/:id/reaction', authMiddleware, requireHubAccess, async (req, res) => {
    try { const { emoji } = req.body; if (!emoji) return res.status(400).json({ error: 'Emoji requerido' }); const col = await getCollection(COLLECTIONS.HUB_MENSAJES); const msg = await col.findOne({ _id: new ObjectId(req.params.id) }); if (!msg) return res.status(404).json({ error: 'Mensaje no encontrado' }); const current = msg.reactions?.[emoji] || []; const updated = current.includes(req.usuario.username) ? current.filter(u => u !== req.usuario.username) : [...current, req.usuario.username]; await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { [`reactions.${emoji}`]: updated } }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── REUNIONES ─────────────────────────────────────────────────
app.get('/api/hub/reuniones', authMiddleware, requireHubAccess, async (req, res) => { try { res.json(await (await getCollection(COLLECTIONS.HUB_REUNIONES)).find({}).sort({ fecha: 1, hora: 1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/reuniones', authMiddleware, requireHubAccess, async (req, res) => { try { const { title, desc, date, time, duration, location, attendees, agenda } = req.body; if (!title?.trim() || !date || !time) return res.status(400).json({ error: 'Título, fecha y hora son requeridos' }); const col = await getCollection(COLLECTIONS.HUB_REUNIONES); const reunion = { _id: new ObjectId(), title: title.trim(), desc: desc || '', date, time, duration: duration || 60, location: location || '', attendees: Array.isArray(attendees) ? attendees : (attendees || '').split(',').map(a => a.trim()).filter(Boolean), agenda: agenda || '', organizer: req.usuario.nombre, organizerUsername: req.usuario.username, status: 'scheduled', createdAt: new Date() }; await col.insertOne(reunion); res.status(201).json(reunion); } catch (e) { res.status(500).json({ error: e.message }); } });
app.patch('/api/hub/reuniones/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const allowed = ['title','desc','date','time','duration','location','attendees','agenda','status']; const updates = { updatedAt: new Date() }; allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; }); const col = await getCollection(COLLECTIONS.HUB_REUNIONES); const result = await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates }); if (result.matchedCount === 0) return res.status(404).json({ error: 'Reunión no encontrada' }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/reuniones/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const result = await (await getCollection(COLLECTIONS.HUB_REUNIONES)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── MINUTAS ───────────────────────────────────────────────────
app.get('/api/hub/minutas', authMiddleware, requireHubAccess, async (req, res) => { try { res.json(await (await getCollection(COLLECTIONS.HUB_MINUTAS)).find({}).sort({ createdAt: -1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/minutas', authMiddleware, requireHubAccess, async (req, res) => { try { const { title, date, summary, decisions, actionItems, attendees, meetingId } = req.body; if (!title?.trim() || !summary?.trim()) return res.status(400).json({ error: 'Título y resumen son requeridos' }); const parsedActions = (Array.isArray(actionItems) ? actionItems : (actionItems || '').split('\n')).map(t => t.trim()).filter(Boolean).map(text => ({ id: new ObjectId().toString(), text, done: false })); const col = await getCollection(COLLECTIONS.HUB_MINUTAS); const minuta = { _id: new ObjectId(), meetingId: meetingId || null, title: title.trim(), date: date || '', summary: summary.trim(), decisions: decisions || '', actionItems: parsedActions, attendees: attendees || '', author: req.usuario.nombre, authorUsername: req.usuario.username, comments: [], createdAt: new Date() }; await col.insertOne(minuta); res.status(201).json(minuta); } catch (e) { res.status(500).json({ error: e.message }); } });
app.patch('/api/hub/minutas/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const allowed = ['title','date','summary','decisions','actionItems','attendees']; const updates = { updatedAt: new Date() }; allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; }); if (updates.actionItems && Array.isArray(updates.actionItems)) updates.actionItems = updates.actionItems.map(a => typeof a === 'string' ? { id: new ObjectId().toString(), text: a.trim(), done: false } : a).filter(a => a.text?.trim()); const col = await getCollection(COLLECTIONS.HUB_MINUTAS); const result = await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates }); if (result.matchedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/minutas/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const col = await getCollection(COLLECTIONS.HUB_MINUTAS); const filter = req.usuario.rol === 'ADMIN' ? { _id: new ObjectId(req.params.id) } : { _id: new ObjectId(req.params.id), authorUsername: req.usuario.username }; const result = await col.deleteOne(filter); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrada o no autorizada' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/minutas/:id/comentarios', authMiddleware, requireHubAccess, async (req, res) => { try { const { content } = req.body; if (!content?.trim()) return res.status(400).json({ error: 'Contenido requerido' }); const comment = { id: new ObjectId().toString(), userId: req.usuario.username, userName: req.usuario.nombre, content: content.trim(), ts: Date.now() }; const col = await getCollection(COLLECTIONS.HUB_MINUTAS); const result = await col.updateOne({ _id: new ObjectId(req.params.id) }, { $push: { comments: comment } }); if (result.matchedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.status(201).json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.patch('/api/hub/minutas/:id/acciones/:itemId', authMiddleware, requireHubAccess, async (req, res) => { try { const col = await getCollection(COLLECTIONS.HUB_MINUTAS); const minuta = await col.findOne({ _id: new ObjectId(req.params.id) }); if (!minuta) return res.status(404).json({ error: 'No encontrada' }); const updatedActions = (minuta.actionItems || []).map(a => a.id === req.params.itemId ? { ...a, done: !a.done } : a); await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: { actionItems: updatedActions } }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── TAREAS ────────────────────────────────────────────────────
app.get('/api/hub/tareas', authMiddleware, requireHubAccess, async (req, res) => { try { res.json(await (await getCollection(COLLECTIONS.HUB_TAREAS)).find({}).sort({ columna: 1, orden: 1, createdAt: -1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/tareas', authMiddleware, requireHubAccess, async (req, res) => { try { const { title, desc, priority, assignee, dueDate, tags } = req.body; if (!title?.trim()) return res.status(400).json({ error: 'El título es requerido' }); const col = await getCollection(COLLECTIONS.HUB_TAREAS); const tarea = { _id: new ObjectId(), title: title.trim(), desc: desc || '', priority: priority || 'media', assignee: assignee || '', dueDate: dueDate || null, tags: Array.isArray(tags) ? tags : (tags || '').split(',').map(t => t.trim()).filter(Boolean), status: 'todo', orden: Date.now(), creadoPor: req.usuario.nombre, creadoPorUsername: req.usuario.username, createdAt: new Date() }; await col.insertOne(tarea); res.status(201).json(tarea); } catch (e) { res.status(500).json({ error: e.message }); } });
app.patch('/api/hub/tareas/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const allowed = ['title','desc','priority','assignee','dueDate','tags','status','orden']; const updates = { updatedAt: new Date() }; allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; }); const col = await getCollection(COLLECTIONS.HUB_TAREAS); const result = await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates }); if (result.matchedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/tareas/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const result = await (await getCollection(COLLECTIONS.HUB_TAREAS)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── ANUNCIOS ──────────────────────────────────────────────────
app.get('/api/hub/anuncios', authMiddleware, requireHubAccess, async (req, res) => { try { res.json(await (await getCollection(COLLECTIONS.HUB_ANUNCIOS)).find({}).sort({ pinned: -1, createdAt: -1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/anuncios', authMiddleware, requireHubAccess, async (req, res) => { try { const { title, content, priority, pinned } = req.body; if (!title?.trim() || !content?.trim()) return res.status(400).json({ error: 'Título y contenido son requeridos' }); const col = await getCollection(COLLECTIONS.HUB_ANUNCIOS); const anuncio = { _id: new ObjectId(), title: title.trim(), content: content.trim(), priority: priority || 'normal', pinned: !!pinned, author: req.usuario.nombre, authorUsername: req.usuario.username, createdAt: new Date() }; await col.insertOne(anuncio); res.status(201).json(anuncio); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/anuncios/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const result = await (await getCollection(COLLECTIONS.HUB_ANUNCIOS)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrado' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── RECURSOS ──────────────────────────────────────────────────
app.get('/api/hub/recursos', authMiddleware, requireHubAccess, async (req, res) => { try { const filter = req.query.categoria ? { categoria: req.query.categoria } : {}; res.json(await (await getCollection(COLLECTIONS.HUB_RECURSOS)).find(filter).sort({ createdAt: -1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/recursos', authMiddleware, requireHubAccess, async (req, res) => { try { const { nombre, descripcion, url, categoria, tipo } = req.body; if (!nombre?.trim()) return res.status(400).json({ error: 'El nombre es requerido' }); if (!url?.trim()) return res.status(400).json({ error: 'La URL es requerida' }); try { new URL(url.trim()); } catch { return res.status(400).json({ error: 'URL no válida' }); } const categoriasValidas = ['documentos','presentaciones','hojas','manuales','otros']; const col = await getCollection(COLLECTIONS.HUB_RECURSOS); await col.insertOne({ _id: new ObjectId(), nombre: nombre.trim(), descripcion: descripcion?.trim() || '', url: url.trim(), categoria: categoriasValidas.includes(categoria) ? categoria : 'otros', tipo: tipo || 'enlace', uploadedBy: req.usuario.nombre, uploadedByUsername: req.usuario.username, createdAt: new Date() }); res.status(201).json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/recursos/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const result = await (await getCollection(COLLECTIONS.HUB_RECURSOS)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrado' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── GUÍAS ─────────────────────────────────────────────────────
app.get('/api/hub/guias', authMiddleware, requireHubAccess, async (req, res) => { try { const { categoria, q } = req.query; const filter = {}; if (categoria) filter.categoria = categoria; if (q?.trim()) { const r = new RegExp(q.trim(), 'i'); filter.$or = [{ titulo: r }, { descripcion: r }, { contenido: r }]; } res.json(await (await getCollection(COLLECTIONS.HUB_GUIAS)).find(filter).sort({ createdAt: -1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/guias', authMiddleware, requireHubAccess, async (req, res) => { try { const { titulo, descripcion, categoria, url, contenido, version, autor } = req.body; if (!titulo?.trim()) return res.status(400).json({ error: 'El título es requerido' }); const categoriasValidas = ['accesos','hardware','correos','sistemas','soporte','procesos','otros']; const guia = { _id: new ObjectId(), titulo: titulo.trim(), descripcion: descripcion?.trim() || '', categoria: categoriasValidas.includes(categoria) ? categoria : 'otros', url: url?.trim() || '', contenido: contenido?.trim() || '', version: version?.trim() || '1.0', autor: autor?.trim() || req.usuario.nombre, autorUsername: req.usuario.username, createdAt: new Date(), updatedAt: new Date() }; await (await getCollection(COLLECTIONS.HUB_GUIAS)).insertOne(guia); res.status(201).json(guia); } catch (e) { res.status(500).json({ error: e.message }); } });
app.patch('/api/hub/guias/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const allowed = ['titulo','descripcion','categoria','url','contenido','version']; const updates = { updatedAt: new Date() }; allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; }); const col = await getCollection(COLLECTIONS.HUB_GUIAS); const result = await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates }); if (result.matchedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/guias/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const result = await (await getCollection(COLLECTIONS.HUB_GUIAS)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── PLANTILLAS ────────────────────────────────────────────────
app.get('/api/hub/plantillas', authMiddleware, requireHubAccess, async (req, res) => { try { const filter = req.query.tipo ? { tipo: req.query.tipo } : {}; res.json(await (await getCollection(COLLECTIONS.HUB_PLANTILLAS)).find(filter).sort({ tipo: 1, nombre: 1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/plantillas', authMiddleware, requireHubAccess, async (req, res) => { try { const { nombre, descripcion, tipo, url, instrucciones } = req.body; if (!nombre?.trim()) return res.status(400).json({ error: 'El nombre es requerido' }); if (!url?.trim()) return res.status(400).json({ error: 'La URL es requerida' }); try { new URL(url.trim()); } catch { return res.status(400).json({ error: 'URL no válida' }); } const tiposValidos = ['responsiva','alta_baja','inventario','incidencias','formatos','otros']; await (await getCollection(COLLECTIONS.HUB_PLANTILLAS)).insertOne({ _id: new ObjectId(), nombre: nombre.trim(), descripcion: descripcion?.trim() || '', tipo: tiposValidos.includes(tipo) ? tipo : 'otros', url: url.trim(), instrucciones: instrucciones?.trim() || '', uploadedBy: req.usuario.nombre, uploadedByUsername: req.usuario.username, createdAt: new Date() }); res.status(201).json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/plantillas/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const result = await (await getCollection(COLLECTIONS.HUB_PLANTILLAS)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ── CAPACITACIÓN ──────────────────────────────────────────────
app.get('/api/hub/capacitacion', authMiddleware, requireHubAccess, async (req, res) => { try { const filter = req.query.progreso ? { progreso: req.query.progreso } : {}; res.json(await (await getCollection(COLLECTIONS.HUB_CAPACITACION)).find(filter).sort({ orden: 1, createdAt: 1 }).toArray()); } catch (e) { res.status(500).json({ error: e.message }); } });
app.post('/api/hub/capacitacion', authMiddleware, requireHubAccess, async (req, res) => { try { const { funcion, frecuencia, herramienta, progreso, fecha, notas, confAnalista, confSupervisor } = req.body; if (!funcion?.trim()) return res.status(400).json({ error: 'La función es requerida' }); const progresoValidos = ['sin_asignar','en_curso','completado','pausado']; const supervisorValidos = ['pendiente','aprobado','rechazado']; const col = await getCollection(COLLECTIONS.HUB_CAPACITACION); const lastTask = await col.findOne({}, { sort: { orden: -1 } }); const tarea = { _id: new ObjectId(), orden: (lastTask?.orden || 0) + 1, funcion: funcion.trim(), frecuencia: frecuencia?.trim() || 'Según necesidad', herramienta: herramienta?.trim() || '', progreso: progresoValidos.includes(progreso) ? progreso : 'sin_asignar', fecha: fecha || null, notas: notas?.trim() || '', confAnalista: !!confAnalista, confSupervisor: supervisorValidos.includes(confSupervisor) ? confSupervisor : null, creadoPor: req.usuario.nombre, creadoPorUsername: req.usuario.username, createdAt: new Date(), updatedAt: new Date() }; await col.insertOne(tarea); res.status(201).json(tarea); } catch (e) { res.status(500).json({ error: e.message }); } });
app.patch('/api/hub/capacitacion/:id', authMiddleware, requireHubAccess, async (req, res) => { try { const allowed = ['funcion','frecuencia','herramienta','progreso','fecha','notas','confAnalista','confSupervisor','orden']; const updates = { updatedAt: new Date() }; allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; }); const col = await getCollection(COLLECTIONS.HUB_CAPACITACION); const result = await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: updates }); if (result.matchedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json(await col.findOne({ _id: new ObjectId(req.params.id) })); } catch (e) { res.status(500).json({ error: e.message }); } });
app.delete('/api/hub/capacitacion/:id', authMiddleware, requireHubAccess, async (req, res) => { try { if (req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Solo el administrador puede eliminar tareas' }); const result = await (await getCollection(COLLECTIONS.HUB_CAPACITACION)).deleteOne({ _id: new ObjectId(req.params.id) }); if (result.deletedCount === 0) return res.status(404).json({ error: 'No encontrada' }); res.json({ success: true }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ============================================================
// ENDPOINTS — HUB ASISTENCIA v3.6
// ============================================================
app.get('/api/hub/asistencia', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_ASISTENCIA);
        const query = {};
        if (req.query.username) {
            if (req.usuario.rol !== 'ADMIN' && req.usuario.rol !== 'SISTEMAS' && req.query.username !== req.usuario.username) return res.status(403).json({ error: 'Solo puedes consultar tu propia asistencia' });
            query.username = req.query.username;
        } else if (req.usuario.rol !== 'ADMIN' && req.usuario.rol !== 'SISTEMAS') {
            query.username = req.usuario.username;
        }
        if (req.query.mes)  query.fecha = { $regex: `^${req.query.mes}` };
        if (req.query.tipo) query.tipo  = req.query.tipo;
        res.json(await col.find(query).sort({ fecha: -1, username: 1 }).toArray());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── v3.6: POST soporta targetUsername (admin registra para otro) ──
app.post('/api/hub/asistencia', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_ASISTENCIA);
        const { fecha, tipo, horaEntrada, horaSalida, notas, targetUsername } = req.body;
        if (!fecha || !tipo) return res.status(400).json({ error: 'fecha y tipo son requeridos' });
        if (!esDateValido(fecha)) return res.status(400).json({ error: 'fecha debe tener formato YYYY-MM-DD válido' });
        if (!TIPOS_ASISTENCIA.includes(tipo)) return res.status(400).json({ error: `Tipo inválido. Valores permitidos: ${TIPOS_ASISTENCIA.join(', ')}` });

        let regUsername = req.usuario.username;
        let regNombre   = req.usuario.nombre || req.usuario.username;

        if (targetUsername && targetUsername !== req.usuario.username) {
            const puedeAdminReg = await usuarioTienePermisoConOverride(req, 'hub.asistencia.admin_registro');
            if (!puedeAdminReg) return res.status(403).json({ error: 'No tienes permiso para registrar asistencia de otros usuarios' });
            const usersCol   = await getCollection(COLLECTIONS.USERS);
            const targetUser = await usersCol.findOne({ username: targetUsername, activo: true });
            if (!targetUser) return res.status(404).json({ error: 'Usuario destino no encontrado o inactivo' });
            regUsername = targetUser.username;
            regNombre   = targetUser.nombre || targetUser.username;
        }

        const existe = await col.findOne({ username: regUsername, fecha });
        if (existe) return res.status(409).json({ error: 'Ya existe un registro para este día', existingId: existe._id });

        const doc = {
            _id: new ObjectId(), username: regUsername, nombre: regNombre, fecha, tipo,
            horaEntrada: horaEntrada || null, horaSalida: horaSalida || null,
            notas: (notas || '').trim(),
            registradoPor: req.usuario.username !== regUsername ? req.usuario.username : undefined,
            creadoEn: new Date().toISOString(),
        };
        await col.insertOne(doc);
        logger.info(`Asistencia: ${regUsername} — ${fecha} (${tipo}) por ${req.usuario.username}`);
        res.status(201).json(doc);
    } catch (e) {
        if (e.code === 11000) return res.status(409).json({ error: 'Ya existe un registro para este día' });
        res.status(500).json({ error: e.message });
    }
});

app.patch('/api/hub/asistencia/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_ASISTENCIA);
        const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
        if (doc.username !== req.usuario.username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Sin permiso para editar este registro' });
        const { tipo, horaEntrada, horaSalida, notas, fecha } = req.body;
        const upd = { actualizadoEn: new Date().toISOString() };
        if (tipo        !== undefined) { if (!TIPOS_ASISTENCIA.includes(tipo)) return res.status(400).json({ error: 'Tipo inválido' }); upd.tipo = tipo; }
        if (fecha       !== undefined) { if (!esDateValido(fecha)) return res.status(400).json({ error: 'fecha debe tener formato YYYY-MM-DD válido' }); upd.fecha = fecha; }
        if (horaEntrada !== undefined) upd.horaEntrada = horaEntrada;
        if (horaSalida  !== undefined) upd.horaSalida  = horaSalida;
        if (notas       !== undefined) upd.notas = (notas || '').trim();
        await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: upd });
        res.json(await col.findOne({ _id: new ObjectId(req.params.id) }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/hub/asistencia/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_ASISTENCIA);
        const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'No encontrado' });
        if (doc.username !== req.usuario.username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Sin permiso' });
        await col.deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── VACACIONES ────────────────────────────────────────────────
app.get('/api/hub/vacaciones', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_VACACIONES);
        const query = {};
        if (req.usuario.rol !== 'ADMIN') { query.username = req.usuario.username; }
        else if (req.query.username) { query.username = req.query.username; }
        if (req.query.status) query.status = req.query.status;
        res.json(await col.find(query).sort({ creadoEn: -1 }).toArray());
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.post('/api/hub/vacaciones', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_VACACIONES);
        const { fechaInicio, fechaFin, notas } = req.body;
        if (!fechaInicio || !fechaFin) return res.status(400).json({ error: 'fechaInicio y fechaFin son requeridos' });
        if (!esDateValido(fechaInicio) || !esDateValido(fechaFin)) return res.status(400).json({ error: 'Las fechas deben tener formato YYYY-MM-DD válido' });
        if (fechaInicio > fechaFin) return res.status(400).json({ error: 'fechaInicio debe ser anterior o igual a fechaFin' });
        const dias = Math.round((new Date(fechaFin + 'T12:00:00') - new Date(fechaInicio + 'T12:00:00')) / 86400000) + 1;
        const doc = { _id: new ObjectId(), username: req.usuario.username, nombre: req.usuario.nombre || req.usuario.username, fechaInicio, fechaFin, dias, notas: (notas || '').trim(), status: 'pendiente', comentarioAdmin: null, creadoEn: new Date().toISOString() };
        await col.insertOne(doc);
        res.status(201).json(doc);
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.patch('/api/hub/vacaciones/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_VACACIONES);
        const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'No encontrada' });
        const upd = { actualizadoEn: new Date().toISOString() };
        if (req.usuario.rol === 'ADMIN') {
            const statusValidos = ['pendiente','aprobada','rechazada'];
            if (req.body.status !== undefined) { if (!statusValidos.includes(req.body.status)) return res.status(400).json({ error: 'Status inválido' }); upd.status = req.body.status; }
            if (req.body.comentarioAdmin !== undefined) upd.comentarioAdmin = req.body.comentarioAdmin;
        } else if (doc.username === req.usuario.username) {
            if (doc.status !== 'pendiente') return res.status(403).json({ error: 'No puedes editar una solicitud ya procesada' });
            if (req.body.notas !== undefined) upd.notas = (req.body.notas || '').trim();
        } else return res.status(403).json({ error: 'Sin permiso' });
        await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: upd });
        res.json(await col.findOne({ _id: new ObjectId(req.params.id) }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.delete('/api/hub/vacaciones/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_VACACIONES);
        const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'No encontrada' });
        if (doc.username !== req.usuario.username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Sin permiso' });
        if (doc.status !== 'pendiente' && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'No puedes cancelar una solicitud ya procesada' });
        await col.deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ── CONCENTRADO ───────────────────────────────────────────────
async function canViewConcentrado(req) {
    if (!req.usuario) return false;
    if (req.usuario.rol === 'ADMIN') return true;
    return await usuarioTienePermisoConOverride(req, 'hub.concentrado.ver');
}

app.get('/api/hub/concentrado', authMiddleware, async (req, res) => {
    try {
        if (!(await canViewConcentrado(req))) return res.status(403).json({ error: 'Sin acceso al concentrado' });
        const asistCol = await getCollection(COLLECTIONS.HUB_ASISTENCIA);
        const vacCol   = await getCollection(COLLECTIONS.HUB_VACACIONES);
        const asistQ = {};
        if (req.query.mes)      asistQ.fecha    = { $regex: `^${req.query.mes}` };
        if (req.query.username) asistQ.username = req.query.username;
        if (req.query.tipo)     asistQ.tipo     = req.query.tipo;
        const vacQ = {};
        if (req.query.username) vacQ.username = req.query.username;
        const [asistencias, vacaciones] = await Promise.all([
            asistCol.find(asistQ).sort({ fecha: -1, username: 1 }).toArray(),
            vacCol.find(vacQ).sort({ creadoEn: -1 }).toArray(),
        ]);
        res.json({ asistencias, vacaciones });
    } catch (e) { res.status(500).json({ error: e.message }); }
});
app.get('/api/hub/concentrado/config', authMiddleware, requireAdmin, async (req, res) => { try { const col = await getCollection(COLLECTIONS.HUB_CONCENTRADO_CONFIG); res.json(await col.findOne({ _id: 'config' }) || { _id: 'config', allowedRoles: [], allowedUsers: [] }); } catch (e) { res.status(500).json({ error: e.message }); } });
app.put('/api/hub/concentrado/config', authMiddleware, requireAdmin, async (req, res) => { try { const col = await getCollection(COLLECTIONS.HUB_CONCENTRADO_CONFIG); const { allowedRoles = [], allowedUsers = [] } = req.body; await col.updateOne({ _id: 'config' }, { $set: { allowedRoles, allowedUsers, actualizadoEn: new Date().toISOString() } }, { upsert: true }); res.json({ ok: true, allowedRoles, allowedUsers }); } catch (e) { res.status(500).json({ error: e.message }); } });

// ============================================================
// ENDPOINTS — PETICIONES v3.6
// ============================================================
app.get('/api/hub/peticiones', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_PETICIONES);
        const puedeVerTodas = await usuarioTienePermisoConOverride(req, 'hub.peticiones.ver_todas');
        const puedeAprobar  = await usuarioTienePermisoConOverride(req, 'hub.peticiones.aprobar');
        const query = {};
        if (!puedeVerTodas && !puedeAprobar) query.username = req.usuario.username;
        if (req.query.username && (puedeVerTodas || puedeAprobar)) query.username = req.query.username;
        if (req.query.status) query.status = req.query.status;
        if (req.query.tipo)   query.tipo   = req.query.tipo;
        res.json(await col.find(query).sort({ creadoEn: -1 }).limit(300).toArray());
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/hub/peticiones', authMiddleware, requirePermisoHub('hub.peticiones.crear'), async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_PETICIONES);
        const { tipo, fechaInicio, fechaFin, motivo, notas } = req.body;
        if (!tipo || !fechaInicio || !motivo?.trim()) return res.status(400).json({ error: 'tipo, fechaInicio y motivo son requeridos' });
        if (!TIPOS_PETICION.includes(tipo)) return res.status(400).json({ error: `Tipo inválido. Permitidos: ${TIPOS_PETICION.join(', ')}` });
        if (!esDateValido(fechaInicio)) return res.status(400).json({ error: 'fechaInicio debe tener formato YYYY-MM-DD válido' });
        if (fechaFin && !esDateValido(fechaFin)) return res.status(400).json({ error: 'fechaFin debe tener formato YYYY-MM-DD válido' });
        if (fechaFin && fechaFin < fechaInicio) return res.status(400).json({ error: 'fechaFin debe ser igual o posterior a fechaInicio' });
        const doc = {
            _id: new ObjectId(), username: req.usuario.username, nombre: req.usuario.nombre || req.usuario.username,
            tipo, fechaInicio, fechaFin: fechaFin || fechaInicio, motivo: motivo.trim(), notas: (notas || '').trim(),
            status: 'pendiente', revisadoPor: null, revisadoEn: null, comentarioRevisor: null,
            creadoEn: new Date().toISOString(),
        };
        await col.insertOne(doc);
        logger.info(`Petición creada: ${req.usuario.username} — ${tipo} ${fechaInicio}`);
        res.status(201).json(doc);
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.patch('/api/hub/peticiones/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col  = await getCollection(COLLECTIONS.HUB_PETICIONES);
        const doc  = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Petición no encontrada' });
        const puedeAprobar = await usuarioTienePermisoConOverride(req, 'hub.peticiones.aprobar');
        const esPropia     = doc.username === req.usuario.username;
        if (!puedeAprobar && !esPropia) return res.status(403).json({ error: 'Sin permiso para modificar esta petición' });
        const upd = { actualizadoEn: new Date().toISOString() };
        if (req.body.status !== undefined) {
            if (!puedeAprobar) return res.status(403).json({ error: 'No tienes permiso para aprobar/rechazar peticiones' });
            const statusValidos = ['pendiente','aprobada','rechazada'];
            if (!statusValidos.includes(req.body.status)) return res.status(400).json({ error: `Status inválido. Valores: ${statusValidos.join(', ')}` });
            upd.status      = req.body.status;
            upd.revisadoPor = req.usuario.nombre || req.usuario.username;
            upd.revisadoEn  = new Date().toISOString();
        }
        if (req.body.comentarioRevisor !== undefined && puedeAprobar) upd.comentarioRevisor = (req.body.comentarioRevisor || '').trim();
        if (esPropia && doc.status === 'pendiente') {
            if (req.body.notas  !== undefined) upd.notas  = (req.body.notas  || '').trim();
            if (req.body.motivo !== undefined) upd.motivo = (req.body.motivo || '').trim();
        }
        await col.updateOne({ _id: new ObjectId(req.params.id) }, { $set: upd });
        res.json(await col.findOne({ _id: new ObjectId(req.params.id) }));
    } catch (e) { res.status(500).json({ error: e.message }); }
});

app.delete('/api/hub/peticiones/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_PETICIONES);
        const doc = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'No encontrada' });
        if (doc.username !== req.usuario.username && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'Sin permiso' });
        if (doc.status !== 'pendiente' && req.usuario.rol !== 'ADMIN') return res.status(403).json({ error: 'No puedes cancelar una petición ya procesada' });
        await col.deleteOne({ _id: new ObjectId(req.params.id) });
        res.json({ ok: true });
    } catch (e) { res.status(500).json({ error: e.message }); }
});

// ============================================================
// ENDPOINTS — ADMIN PANEL
// ============================================================
app.get('/api/admin/stats', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const colUsers = await getCollection(COLLECTIONS.USERS);
        const colLogs  = await getCollection(COLLECTIONS.ADMIN_ACCESS_LOGS);
        const colRH    = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const colFmt   = await getCollection(COLLECTIONS.AGENTS_LOG);
        const hoy = new Date(); hoy.setHours(0, 0, 0, 0);
        const [totalUsers, usersActivos, usersPorRol, accesosHoy, fallidosHoy, movimientosTotal, movimientosPendientes, formatosTotal] = await Promise.all([
            colUsers.countDocuments(), colUsers.countDocuments({ activo: true }),
            colUsers.aggregate([{ $group: { _id: '$rol', count: { $sum: 1 } } }]).toArray(),
            colLogs.countDocuments({ timestamp: { $gte: hoy.toISOString() } }),
            colLogs.countDocuments({ resultado: 'fallido', timestamp: { $gte: hoy.toISOString() } }),
            colRH.countDocuments(), colRH.countDocuments({ estado: 'PENDIENTE' }),
            colFmt.countDocuments({ tipo: 'formato_activacion' }),
        ]);
        res.json({ usuarios: { total: totalUsers, activos: usersActivos, porRol: usersPorRol }, accesos: { hoy: accesosHoy, fallidosHoy }, formularios: { rhTotal: movimientosTotal, rhPendientes: movimientosPendientes, formatosTotal } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/access-logs', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { username, resultado, desde, hasta, limit = 100, page = 1 } = req.query;
        const filter = {};
        if (username)  filter.username  = { $regex: username, $options: 'i' };
        if (resultado) filter.resultado = resultado;
        if (desde || hasta) { filter.timestamp = {}; if (desde) filter.timestamp.$gte = new Date(desde).toISOString(); if (hasta) filter.timestamp.$lte = new Date(hasta).toISOString(); }
        const col  = await getCollection(COLLECTIONS.ADMIN_ACCESS_LOGS);
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const total = await col.countDocuments(filter);
        const logs  = await col.find(filter).sort({ timestamp: -1 }).skip(skip).limit(parseInt(limit)).toArray();
        const hoy = new Date(); hoy.setHours(0, 0, 0, 0);
        const accesosHoy  = await col.countDocuments({ timestamp: { $gte: hoy.toISOString() } });
        const fallidosHoy = await col.countDocuments({ timestamp: { $gte: hoy.toISOString() }, resultado: 'fallido' });
        res.json({ logs, total, page: parseInt(page), limit: parseInt(limit), stats: { accesosHoy, fallidosHoy } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/form-submissions', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { tipo, desde, hasta, limit = 50, page = 1 } = req.query;
        const skip = (parseInt(page) - 1) * parseInt(limit);
        const dateFilter = {};
        if (desde) dateFilter.$gte = new Date(desde).toISOString();
        if (hasta) dateFilter.$lte = new Date(hasta).toISOString();
        const results = {};
        if (!tipo || tipo === 'rh') { const colRH = await getCollection(COLLECTIONS.RH_MOVIMIENTOS); const filterRH = {}; if (Object.keys(dateFilter).length) filterRH.fecha_creacion = dateFilter; results.rh = await colRH.find(filterRH).sort({ fecha_creacion: -1 }).skip(tipo === 'rh' ? skip : 0).limit(tipo === 'rh' ? parseInt(limit) : 20).project({ historial: 0 }).toArray(); }
        if (!tipo || tipo === 'formatos') { const colLog = await getCollection(COLLECTIONS.AGENTS_LOG); const filterLog = { tipo: 'formato_activacion' }; if (Object.keys(dateFilter).length) filterLog.timestamp = dateFilter; results.formatos = await colLog.find(filterLog).sort({ timestamp: -1 }).skip(tipo === 'formatos' ? skip : 0).limit(tipo === 'formatos' ? parseInt(limit) : 20).toArray(); }
        if (!tipo || tipo === 'activos') { try { const colActivos = await getCollection('activos_movimientos'); results.activos = await colActivos.find({}).sort({ fecha: -1 }).limit(20).toArray(); } catch { results.activos = []; } }
        const colRH2 = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const colLog2 = await getCollection(COLLECTIONS.AGENTS_LOG);
        res.json({ ...results, totales: { rh: await colRH2.countDocuments(), formatos: await colLog2.countDocuments({ tipo: 'formato_activacion' }) } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/permissions/roles', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.ROLE_PERMISSIONS);
        const doc = await col.findOne({ type: 'role_defaults' });
        res.json({ permisos: doc?.permisos || ROL_PERMISOS_DEFAULT, modulos: MODULOS_PERMISOS, version: doc?.version || '1.2', actualizadoEn: doc?.actualizadoEn, actualizadoPor: doc?.actualizadoPor });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/admin/permissions/roles/:rol', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { rol } = req.params;
        const rolesValidos = ['ADMIN','RH','SISTEMAS','GERENTE','USUARIO'];
        if (!rolesValidos.includes(rol)) return res.status(400).json({ error: `Rol inválido: ${rol}` });
        if (rol === 'ADMIN') return res.status(403).json({ error: 'Los permisos de ADMIN no se pueden modificar' });
        const { permisos } = req.body;
        if (!Array.isArray(permisos)) return res.status(400).json({ error: 'permisos debe ser un array' });
        const permisosLimpios = permisos.filter(p => Object.keys(MODULOS_PERMISOS).includes(p));
        const col = await getCollection(COLLECTIONS.ROLE_PERMISSIONS);
        await col.updateOne({ type: 'role_defaults' }, { $set: { [`permisos.${rol}`]: permisosLimpios, actualizadoEn: new Date().toISOString(), actualizadoPor: req.usuario.username } }, { upsert: true });
        res.json({ success: true, rol, permisos: permisosLimpios });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.get('/api/admin/permissions/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const colU  = await getCollection(COLLECTIONS.USERS);
        const user  = await colU.findOne({ username: req.params.username }, { projection: { password: 0 } });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        const col2     = await getCollection(COLLECTIONS.ROLE_PERMISSIONS);
        const roleDoc  = await col2.findOne({ type: 'role_defaults' });
        const rolPerms = roleDoc?.permisos?.[user.rol] || ROL_PERMISOS_DEFAULT[user.rol] || [];
        const overrides = user.permisosOverride || { added: [], removed: [] };
        const efectivos = user.rol === 'ADMIN' ? Object.keys(MODULOS_PERMISOS) : [...rolPerms.filter(p => !overrides.removed.includes(p)), ...overrides.added.filter(p => !rolPerms.includes(p))];
        res.json({ user: { username: user.username, nombre: user.nombre, rol: user.rol, email: user.email }, rolPermisos: rolPerms, overrides, efectivos, modulos: MODULOS_PERMISOS });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

app.put('/api/admin/permissions/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin') return res.status(403).json({ error: 'Los permisos del admin no se pueden modificar' });
        const { added = [], removed = [] } = req.body;
        if (!Array.isArray(added) || !Array.isArray(removed)) return res.status(400).json({ error: 'added y removed deben ser arrays' });
        const validos      = Object.keys(MODULOS_PERMISOS);
        const addedFinal   = added.filter(p => validos.includes(p) && !removed.includes(p));
        const removedFinal = removed.filter(p => validos.includes(p) && !added.includes(p));
        const col = await getCollection(COLLECTIONS.USERS);
        const result = await col.updateOne({ username }, { $set: { permisosOverride: { added: addedFinal, removed: removedFinal }, actualizadoEn: new Date().toISOString() } });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        res.json({ success: true, username, overrides: { added: addedFinal, removed: removedFinal } });
    } catch (error) { res.status(500).json({ error: error.message }); }
});

// ── Error handlers ────────────────────────────────────────────
app.use((req, res) => res.status(404).json({ error: 'Endpoint no encontrado', path: req.path }));
app.use((err, req, res, next) => { logger.error('Unhandled error:', err); res.status(500).json({ error: IS_PRODUCTION ? 'An error occurred' : err.message }); });

// ── Start ─────────────────────────────────────────────────────
async function startServer() {
    try {
        if (!IS_CLOUD) await fs.mkdir('logs', { recursive: true });
        await connectDB();
        await initializeDB();
        app.listen(PORT, () => {
            console.log('\n' + '='.repeat(60));
            console.log('🚀 SERVIDOR UNIFICADO v3.6 - MYG TELECOM');
            console.log('='.repeat(60));
            console.log(`✅ Puerto: ${PORT} | Modo: ${IS_CLOUD ? 'CLOUD' : 'LOCAL'}`);
            console.log('\n🔧 Novedades v3.6:');
            console.log('   ✅ 6 permisos granulares (asistencia, concentrado, peticiones)');
            console.log('   ✅ Admin puede registrar asistencia de otros (targetUsername)');
            console.log('   ✅ Login devuelve permisosEfectivos calculados');
            console.log('   ✅ Endpoints /api/hub/peticiones (GET/POST/PATCH/DELETE)');
            console.log('   ✅ Colección hub_peticiones con índices');
            console.log('='.repeat(60) + '\n');
        });
    } catch (error) { logger.error('❌ Fatal error:', error); process.exit(1); }
}

startServer();

process.on('SIGINT',  async () => { templateCache.clear(); if (cachedClient) await cachedClient.close(); process.exit(0); });
process.on('SIGTERM', async () => { templateCache.clear(); if (cachedClient) await cachedClient.close(); process.exit(0); });

export default app;
