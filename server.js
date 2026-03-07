/* ==================================================================
   MYG TELECOM - SERVIDOR UNIFICADO v3.3 (HÍBRIDO)
   
   Características:
   - Detección automática de entorno (local/cloud)
   - Plantillas: filesystem (local) + Google Drive (cloud/fallback)
   - Caché en memoria para templates descargados
   - Sistema completo: MongoDB + RH + Formatos + Notificaciones
   - Compatible: Node.js local + Vercel serverless
   - v3.3: Endpoint /api/chat (Proxy seguro Anthropic Claude)
   
   Autor: luis oliva - MYG Telecom
   ================================================================== */

import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import ExcelJS from 'exceljs';
import cors from 'cors';
import crypto from 'crypto';
import Joi from 'joi';
import winston from 'winston';
import path from 'path';
import { fileURLToPath } from 'url';
import fs from 'fs/promises';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURACIÓN DE ENTORNO
// ============================================================

const IS_VERCEL = process.env.VERCEL === '1';
const IS_RENDER = process.env.RENDER === 'true';
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
// IS_CLOUD: true en cualquier entorno cloud (Vercel, Render, Railway, etc.)
// En cloud no existe filesystem local → siempre usar Google Drive
const IS_CLOUD = IS_VERCEL || IS_RENDER || IS_PRODUCTION;
const TEMPLATES_DIR = path.join(__dirname, 'plantillas');

// Cache de plantillas en memoria (para cloud)
const templateCache = new Map();
const CACHE_TTL = 60 * 60 * 1000; // 1 hora

// ============================================================
// SSE — REGISTRO DE CONEXIONES EN TIEMPO REAL
// Mapa: username → Set de objetos Response (múltiples tabs)
// ============================================================
const sseClients = new Map(); // username → Set<res>

/**
 * Envía un evento SSE a todas las tabs abiertas de un usuario.
 * FIX: elimina del Set las conexiones muertas detectadas en el write.
 * @param {string} username
 * @param {string} event  - nombre del evento (ej: 'notificacion')
 * @param {object} data   - payload JSON
 */
function sseEnviar(username, event, data) {
    const conns = sseClients.get(username);
    if (!conns || conns.size === 0) return;
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    const muertas = [];
    for (const res of conns) {
        try { res.write(payload); }
        catch { muertas.push(res); }   // FIX: registrar para limpiar después del loop
    }
    // Limpiar conexiones muertas fuera del loop para no mutar el Set mientras se itera
    for (const res of muertas) {
        conns.delete(res);
        logger.warn(`SSE: conexión muerta eliminada para ${username}`);
    }
    if (conns.size === 0) sseClients.delete(username);
}

/**
 * Broadcast a todos los usuarios conectados.
 * FIX: elimina conexiones muertas detectadas en el write.
 * Útil para notificaciones globales (usuario_destino: '*')
 */
function sseBroadcast(event, data) {
    const payload = `event: ${event}\ndata: ${JSON.stringify(data)}\n\n`;
    for (const [username, conns] of sseClients) {
        const muertas = [];
        for (const res of conns) {
            try { res.write(payload); }
            catch { muertas.push(res); }
        }
        for (const res of muertas) {
            conns.delete(res);
            logger.warn(`SSE broadcast: conexión muerta eliminada para ${username}`);
        }
        if (conns.size === 0) sseClients.delete(username);
    }
}

/**
 * Registra una conexión SSE y devuelve la función de limpieza.
 */
function sseRegistrar(username, res) {
    if (!sseClients.has(username)) sseClients.set(username, new Set());
    sseClients.get(username).add(res);
    logger.info(`SSE conectado: ${username} (tabs abiertas: ${sseClients.get(username).size})`);

    return () => {
        const conns = sseClients.get(username);
        if (conns) {
            conns.delete(res);
            if (conns.size === 0) sseClients.delete(username);
        }
        logger.info(`SSE desconectado: ${username}`);
    };
}


// ============================================================
// LOGGER HÍBRIDO
// ============================================================

const logger = winston.createLogger({
    level: process.env.LOG_LEVEL || (IS_PRODUCTION ? 'info' : 'debug'),
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console({
            format: winston.format.combine(
                winston.format.colorize(),
                winston.format.simple()
            )
        })
    ]
});

// Solo agregar file transport si NO estamos en Vercel
if (!IS_CLOUD) {
    logger.add(new winston.transports.File({ 
        filename: 'logs/error.log', 
        level: 'error' 
    }));
    logger.add(new winston.transports.File({ 
        filename: 'logs/combined.log' 
    }));
}

// ============================================================
// CONFIGURACIÓN
// ============================================================

const MONGODB_URI = process.env.MONGODB_URI || 
    'mongodb+srv://iqu_api:UV1qiXyzk6Yducaz@cluster0.kb6nsgi.mongodb.net/?appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 
    'AKfycbwJ6NPiIrwGMXOfZYLjoo-TXI07O3pz94QA-M7yOOb-fiBmsXb3bmFljw_FnVsebTK4hw';
const DB_NAME = 'iqu_telecom';

const COLLECTIONS = {
    USERS: 'users',
    DEVICES: 'devices',
    INVENTORY_HISTORY: 'inventory_history',
    COMMANDS: 'commands',
    AGENTS_LOG: 'agents_log',
    RH_MOVIMIENTOS: 'rh_movimientos',
    NOTIFICACIONES: 'notificaciones',
    HUB_MENSAJES:     'hub_mensajes',
    HUB_REUNIONES:    'hub_reuniones',
    HUB_MINUTAS:      'hub_minutas',
    HUB_TAREAS:       'hub_tareas',
    HUB_ANUNCIOS:     'hub_anuncios',
    // Hub v3.0 — nuevos módulos
    HUB_RECURSOS:     'hub_recursos',
    HUB_GUIAS:        'hub_guias',
    HUB_PLANTILLAS:   'hub_plantillas',
    HUB_CAPACITACION: 'hub_capacitacion',
};

// Configuración HÍBRIDA de plantillas (filesystem + Google Drive)
const ACTIVATION_TEMPLATES = {
    ACCWEB: {
        file: 'ACTIVACION_ACCWEB.xlsx',
        driveId: process.env.DRIVE_ID_ASCCWEB || process.env.DRIVE_ID_ACCWEB, // soporta ambos nombres
        label: 'AccWeb',
        description: 'ACCWEB',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    ASCC: {
        file: 'ACTIVACION_ASCC.xlsx',
        driveId: process.env.DRIVE_ID_ASCC,
        label: 'ASCC',
        description: 'ASCC',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    ASD: {
        file: 'ACTIVACION_ASD.xlsx',
        driveId: process.env.DRIVE_ID_ASD,
        label: 'ASD',
        description: 'ASD',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    AVS: {
        file: 'ACTIVACION_AVS.xlsx',
        driveId: process.env.DRIVE_ID_AVS,
        label: 'AVS',
        description: 'AVS',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    DIGITAL: {
        file: 'ACTIVACION_DIGITAL.xlsx',
        driveId: process.env.DRIVE_ID_DIGITAL,
        label: 'DIGITAL',
        description: 'Digital',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    IC: {
        file: 'ACTIVACION_IC.xlsx',
        driveId: process.env.DRIVE_ID_IC,
        label: 'IC',
        description: 'Inventario Ciclico',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    IDM: {
        file: 'ACTIVACION_IDM.xlsx',
        driveId: process.env.DRIVE_ID_IDM,
        label: 'IDM',
        description: 'IDM',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    OFA: {
        file: 'ACTIVACION_OFA.xlsx',
        driveId: process.env.DRIVE_ID_OFA,
        label: 'OFA',
        description: 'Oracle',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    PAYMENTBOX: {
        file: 'ACTIVACION_PAYMENTBOX.xlsx',
        driveId: process.env.DRIVE_ID_PAYMENTBOX,
        label: 'PAYMENTBOX',
        description: 'Paymentbox',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    RED: {
        file: 'ACTIVACION_RED.xlsx',
        driveId: process.env.DRIVE_ID_RED,
        label: 'RED',
        description: 'RED',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6'}
    },
    SALESFORCE: {
        file: 'ACTIVACION_SALESFORCE.xlsx',
        driveId: process.env.DRIVE_ID_SALESFORCE,
        label: 'SALESFORCE',
        description: 'Salesforce',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' }
    },
    VPN: {
        file: 'ACTIVACION_VPN.xlsx',
        driveId: process.env.DRIVE_ID_VPN,
        label: 'VPN',
        description: 'VPN',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6' }
    }
};

// ============================================================
// SCHEMAS DE VALIDACIÓN
// ============================================================

const userCreateSchema = Joi.object({
    username: Joi.string().min(3).max(50).required(),
    password: Joi.string().min(6).required(),
    nombre: Joi.string().min(3).max(100).required(),
    email: Joi.string().email().required(),
    rol: Joi.string().valid('ADMIN', 'RH', 'SISTEMAS', 'GERENTE', 'USUARIO').required(),
    activo: Joi.boolean().default(true)
});

const userUpdateSchema = Joi.object({
    password: Joi.string().min(6).optional(),
    nombre: Joi.string().min(3).max(100).optional(),
    email: Joi.string().email().optional(),
    rol: Joi.string().valid('ADMIN', 'RH', 'SISTEMAS', 'GERENTE', 'USUARIO').optional(),
    activo: Joi.boolean().optional(),
    // Campos de perfil personal (actualizables por el propio usuario)
    telefono: Joi.string().max(20).optional().allow(''),
    puesto: Joi.string().max(100).optional().allow(''),
});

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Request logger
app.use((req, res, next) => {
    logger.info(`${req.method} ${req.path}`, { 
        ip: req.ip,
        userAgent: req.get('user-agent'),
        env: IS_CLOUD ? 'cloud' : 'local'
    });
    next();
});

// Auth middleware
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) {
            return res.status(401).json({ error: 'Token requerido' });
        }

        const payload = verifyJWT(token);
        req.usuario = payload;
        next();
    } catch (error) {
        logger.error(`Auth error: ${error.message}`);
        res.status(401).json({ error: 'Autenticación fallida' });
    }
};

// Admin middleware
const requireAdmin = (req, res, next) => {
    if (!req.usuario || req.usuario.rol !== 'ADMIN') {
        logger.warn(`Access denied: ${req.usuario?.username || 'unknown'} tried admin operation`);
        return res.status(403).json({ error: 'Requiere rol ADMIN' });
    }
    next();
};

// Sistemas middleware
const requireSistemas = (req, res, next) => {
    if (!req.usuario || !['SISTEMAS', 'ADMIN'].includes(req.usuario.rol)) {
        return res.status(403).json({ error: 'Requiere rol SISTEMAS o ADMIN' });
    }
    next();
};

// ============================================================
// JWT UTILS
// ============================================================

function base64UrlEncode(str) {
    return Buffer.from(str)
        .toString('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
}

function base64UrlDecode(str) {
    str = str.replace(/-/g, '+').replace(/_/g, '/');
    while (str.length % 4) str += '=';
    return Buffer.from(str, 'base64').toString('utf8');
}

function createJWT(payload) {
    const header = { alg: 'HS256', typ: 'JWT' };
    const encodedHeader = base64UrlEncode(JSON.stringify(header));
    const encodedPayload = base64UrlEncode(JSON.stringify(payload));
    const message = `${encodedHeader}.${encodedPayload}`;
    
    const signature = crypto
        .createHmac('sha256', JWT_SECRET)
        .update(message)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    return `${message}.${signature}`;
}

function verifyJWT(token) {
    const parts = token.split('.');
    if (parts.length !== 3) throw new Error('Invalid token');
    
    const [encodedHeader, encodedPayload, signature] = parts;
    const message = `${encodedHeader}.${encodedPayload}`;
    
    const expectedSignature = crypto
        .createHmac('sha256', JWT_SECRET)
        .update(message)
        .digest('base64')
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=/g, '');
    
    if (signature !== expectedSignature) {
        throw new Error('Invalid signature');
    }
    
    const payload = JSON.parse(base64UrlDecode(encodedPayload));
    
    if (payload.exp && Date.now() > payload.exp) {
        throw new Error('Token expired');
    }
    
    return payload;
}

function hashPassword(password) {
    return crypto.createHash('sha256').update(password).digest('hex');
}

// ============================================================
// MONGODB CONNECTION
// ============================================================

let cachedClient = null;
let cachedDb = null;

async function connectDB() {
    if (cachedClient && cachedDb) {
        return { client: cachedClient, db: cachedDb };
    }

    const client = new MongoClient(MONGODB_URI, {
        maxPoolSize: 10,
        minPoolSize: 2,
        serverSelectionTimeoutMS: 5000,
        socketTimeoutMS: 45000,
    });

    await client.connect();
    const db = client.db(DB_NAME);

    cachedClient = client;
    cachedDb = db;

    logger.info('✅ Connected to MongoDB Atlas');
    return { client, db };
}

async function getCollection(collectionName) {
    const { db } = await connectDB();
    return db.collection(collectionName);
}

// ============================================================
// TEMPLATE LOADING - SISTEMA HÍBRIDO
// ============================================================

/**
 * Descarga plantilla desde Google Drive
 * @param {string} driveId - ID del archivo en Google Drive
 * @param {string} filename - Nombre del archivo (para logs)
 * @returns {Promise<Buffer>} Buffer del archivo
 */
async function downloadTemplateFromDrive(driveId, filename) {
    try {
        const url = `https://drive.google.com/uc?export=download&id=${driveId}`;
        logger.info(`📥 Downloading from Drive: ${filename}`);
        
        const response = await fetch(url, { 
            headers: { 'User-Agent': 'Mozilla/5.0' },
            signal: AbortSignal.timeout(30000) // 30s timeout
        });
        
        if (!response.ok) {
            throw new Error(`HTTP ${response.status}: ${response.statusText}`);
        }
        
        const arrayBuffer = await response.arrayBuffer();
        const buffer = Buffer.from(arrayBuffer);
        
        logger.info(`✅ Downloaded: ${buffer.length} bytes`);
        return buffer;
        
    } catch (error) {
        logger.error(`❌ Drive download failed (${filename}):`, error.message);
        throw new Error(`No se pudo descargar plantilla desde Drive: ${error.message}`);
    }
}

/**
 * Carga plantilla desde filesystem local
 * @param {string} templatePath - Ruta completa del archivo
 * @param {string} filename - Nombre del archivo (para logs)
 * @returns {Promise<Buffer>} Buffer del archivo
 */
async function loadTemplateFromFilesystem(templatePath, filename) {
    try {
        logger.info(`📂 Loading from filesystem: ${filename}`);
        const buffer = await fs.readFile(templatePath);
        logger.info(`✅ Loaded: ${buffer.length} bytes`);
        return buffer;
    } catch (error) {
        logger.error(`❌ Filesystem load failed (${filename}):`, error.message);
        throw new Error(`No se pudo cargar plantilla del filesystem: ${error.message}`);
    }
}

/**
 * CARGA HÍBRIDA DE PLANTILLAS
 * Estrategia: filesystem → cache → Google Drive
 * 
 * @param {string} sistema - Nombre del sistema (ACCWEB, ASCC, etc)
 * @param {object} config - Configuración del template
 * @returns {Promise<Buffer>} Buffer del archivo Excel
 */
async function loadTemplate(sistema, config) {
    const cacheKey = `template_${sistema}`;
    const templatePath = path.join(TEMPLATES_DIR, config.file);
    
    // 1. INTENTAR FILESYSTEM (solo si no estamos en cloud)
    if (!IS_CLOUD) {
        try {
            await fs.access(templatePath);
            return await loadTemplateFromFilesystem(templatePath, config.file);
        } catch (error) {
            logger.warn(`⚠️  Filesystem unavailable for ${config.file}, trying alternatives...`);
        }
    }
    
    // 2. VERIFICAR CACHE (para entornos cloud)
    if (templateCache.has(cacheKey)) {
        const cached = templateCache.get(cacheKey);
        const age = Date.now() - cached.timestamp;
        
        if (age < CACHE_TTL) {
            logger.info(`♻️  Using cached template: ${config.file} (age: ${Math.round(age/1000)}s)`);
            return cached.buffer;
        } else {
            logger.debug(`⏰ Cache expired for ${config.file}, refreshing...`);
            templateCache.delete(cacheKey);
        }
    }
    
    // 3. DESCARGAR DESDE GOOGLE DRIVE
    if (!config.driveId) {
        throw new Error(
            `Plantilla ${config.file} no disponible: ` +
            `falta filesystem Y variable DRIVE_ID_${sistema}`
        );
    }
    
    const buffer = await downloadTemplateFromDrive(config.driveId, config.file);
    
    // Guardar en cache
    templateCache.set(cacheKey, {
        buffer,
        timestamp: Date.now()
    });
    
    return buffer;
}

// ============================================================
// FORMATOS UTILS
// ============================================================

function getNormalizedFieldValue(obj, possibleNames) {
    if (!obj) return '';

    for (const name of possibleNames) {
        if (name in obj && obj[name] !== null && obj[name] !== undefined) {
            const value = String(obj[name]).trim();
            if (value && value !== '-' && value !== 'N/A') {
                return value;
            }
        }
    }
    return '';
}

function normalizePDVName(nombrePDV) {
    if (!nombrePDV) return '';
    return nombrePDV
        .toString()
        .replace(/^(PUNTO DE VENTA|PDV|PV)\s*/i, '')
        .trim();
}

function mapUserDataForFormato(userData) {
    return {
        nombre: getNormalizedFieldValue(userData, [
            'NOMBRE', 'nombre', 'Nombre Completo', 'NOMBRE COMPLETO',
            'nombreCompleto', 'Nombre', 'NAME'
        ]),
        attuid: getNormalizedFieldValue(userData, [
            'ATTUID', 'attuid', 'ATT UID', 'AttUID', 'att_uid'
        ]),
        puesto: getNormalizedFieldValue(userData, [
            'PUESTO', 'puesto', 'Puesto', 'POSITION', 'Position', 'cargo'
        ]),
        pdv: normalizePDVName(getNormalizedFieldValue(userData, [
            'PDV', 'pdv', 'nombrePDV', 'NOMBRE PDV', 'Nombre PDV', 'nombre_pdv'
        ])),
        clave_pdv: getNormalizedFieldValue(userData, [
            'CLAVE PDV', 'clavePDV', 'clave_pdv', 'CLAVEPDV', 'Clave PDV'
        ]),
        correo: getNormalizedFieldValue(userData, [
            'CORREO', 'correo', 'email', 'EMAIL', 'E-mail', 'mail'
        ])
    };
}

function generateSafeFilename(sistema, nombre) {
    const safeName = (nombre || 'USUARIO')
        .toUpperCase()
        .replace(/\s+/g, '_')
        .replace(/[^A-Z0-9_]/g, '')
        .substring(0, 30);
    
    return `ACTIVACION_${sistema}_${safeName}.xlsx`;
}

// ============================================================
// INICIALIZACIÓN
// ============================================================

async function initializeDB() {
    try {
        // Crear usuario admin por defecto
        const users = await getCollection(COLLECTIONS.USERS);
        const admin = await users.findOne({ username: 'admin' });

        if (!admin) {
            const passwordHash = hashPassword('myg2025');
            await users.insertOne({
                username: 'admin',
                password: passwordHash,
                nombre: 'Administrador',
                email: 'admin@mygtelecom.mx',
                rol: 'ADMIN',
                activo: true,
                permisos: ['*'],
                creadoEn: new Date().toISOString(),
                actualizadoEn: new Date().toISOString(),
                ultimoAcceso: null
            });
            logger.info('✅ Admin user created (username: admin, password: myg2025)');
        }
        
        // Crear índices
        const rhMovimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        await rhMovimientos.createIndex({ fecha_creacion: -1 });
        await rhMovimientos.createIndex({ estado: 1 });
        await rhMovimientos.createIndex({ 'creado_por.username': 1 });
        
        const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
        await notificaciones.createIndex({ usuario_destino: 1, leida: 1 });
        await notificaciones.createIndex({ fecha_creacion: -1 });
        // Índices Hub Sistemas
         const hubMensajes  = await getCollection(COLLECTIONS.HUB_MENSAJES);
         await hubMensajes.createIndex({ canal: 1, createdAt: -1 });
         
         const hubReuniones = await getCollection(COLLECTIONS.HUB_REUNIONES);
         await hubReuniones.createIndex({ fecha: 1 });
         
         const hubMinutas   = await getCollection(COLLECTIONS.HUB_MINUTAS);
         await hubMinutas.createIndex({ createdAt: -1 });
         
         const hubTareas    = await getCollection(COLLECTIONS.HUB_TAREAS);
         await hubTareas.createIndex({ columna: 1, orden: 1 });
         
         const hubAnuncios  = await getCollection(COLLECTIONS.HUB_ANUNCIOS);
         await hubAnuncios.createIndex({ pinned: -1, createdAt: -1 });

         // Hub v3.0 — nuevos módulos
         const hubRecursos     = await getCollection(COLLECTIONS.HUB_RECURSOS);
         await hubRecursos.createIndex({ categoria: 1, createdAt: -1 });

         const hubGuias        = await getCollection(COLLECTIONS.HUB_GUIAS);
         await hubGuias.createIndex({ categoria: 1, createdAt: -1 });
         await hubGuias.createIndex({ titulo: 'text', descripcion: 'text' });

         const hubPlantillas   = await getCollection(COLLECTIONS.HUB_PLANTILLAS);
         await hubPlantillas.createIndex({ tipo: 1, nombre: 1 });

         const hubCapacitacion = await getCollection(COLLECTIONS.HUB_CAPACITACION);
         await hubCapacitacion.createIndex({ orden: 1 });
         await hubCapacitacion.createIndex({ progreso: 1 });

         logger.info('✅ Hub Sistemas indexes created (v3.0: recursos, guías, plantillas, capacitación)');
        logger.info('✅ Database indexes created');
    } catch (error) {
        logger.error('Error initializing DB:', error);
        throw error;
    }
}

// Verificar disponibilidad de plantillas
async function verificarPlantillas() {
    const status = {
        filesystem: false,
        googleDrive: false,
        available: [],
        missing: [],
        mode: IS_CLOUD ? 'cloud' : 'local'
    };

    // Verificar filesystem (solo si no estamos en cloud)
    if (!IS_CLOUD) {
        try {
            await fs.access(TEMPLATES_DIR);
            status.filesystem = true;
            logger.info(`✅ Templates directory found: ${TEMPLATES_DIR}`);
        } catch {
            logger.warn(`⚠️  Templates directory not found: ${TEMPLATES_DIR}`);
        }
    }

    // Verificar cada plantilla
    for (const [key, config] of Object.entries(ACTIVATION_TEMPLATES)) {
        let available = false;
        
        // Verificar filesystem
        if (status.filesystem) {
            const templatePath = path.join(TEMPLATES_DIR, config.file);
            try {
                await fs.access(templatePath);
                available = true;
                status.available.push({ sistema: key, source: 'filesystem' });
            } catch {}
        }
        
        // Verificar Google Drive
        if (!available && config.driveId) {
            status.googleDrive = true;
            available = true;
            status.available.push({ sistema: key, source: 'drive' });
        }
        
        if (!available) {
            status.missing.push({ 
                sistema: key, 
                file: config.file,
                needsDriveId: `DRIVE_ID_${key}`
            });
        }
    }

    // Log resumen
    logger.info(`📊 Templates status:`);
    logger.info(`   Mode: ${status.mode}`);
    logger.info(`   Filesystem: ${status.filesystem ? '✅' : '❌'}`);
    logger.info(`   Google Drive: ${status.googleDrive ? '✅' : '❌'}`);
    logger.info(`   Available: ${status.available.length}/${Object.keys(ACTIVATION_TEMPLATES).length}`);
    
    if (status.missing.length > 0) {
        logger.warn(`⚠️  Missing ${status.missing.length} templates:`);
        status.missing.forEach(item => {
            logger.warn(`   - ${item.file} (set ${item.needsDriveId})`);
        });
    }

    return status;
}

// ============================================================
// ENDPOINTS - ROOT & HEALTH
// ============================================================

app.get('/', (req, res) => {
    res.json({
        name: 'MYG Telecom - Servidor Unificado',
        version: '3.2.0',
        mode: IS_CLOUD ? 'cloud (Render/Vercel)' : 'local',
        status: 'running',
        modules: [
            'MongoDB Middleware (IQU Agents)',
            'Sistema RH (Movimientos + Notificaciones)',
            'Generador de Formatos de Activación (Híbrido)'
        ],
        storage: {
            templates: IS_CLOUD ? 'Google Drive' : 'Filesystem + Google Drive (fallback)',
            cache: `In-memory (TTL: ${CACHE_TTL/1000}s)`
        },
        endpoints: {
            auth: '/api/auth/login',
            users: '/api/users',
            devices: '/api/devices',
            rh: '/api/rh/movimientos',
            notifications: '/api/notificaciones',
            formats: '/api/formatos/*'
        },
        documentation: '/health'
    });
});

app.get('/health', async (req, res) => {
    try {
        await connectDB();
        const plantillasStatus = await verificarPlantillas();
        
        res.json({
            status: 'ok',
            timestamp: new Date().toISOString(),
            environment: {
                mode: IS_CLOUD ? 'cloud' : 'local',
                isProduction: IS_PRODUCTION,
                nodeVersion: process.version
            },
            database: {
                type: 'mongodb',
                status: 'connected'
            },
            storage: {
                templates: plantillasStatus,
                cacheSize: templateCache.size
            },
            version: '3.2.0',
            modules: {
                mongodb: 'ok',
                rh: 'ok',
                formatos: plantillasStatus.available.length > 0 ? 'ok' : 'degraded'
            }
        });
    } catch (error) {
        logger.error('Health check failed:', error);
        res.status(500).json({
            status: 'error',
            error: error.message,
            timestamp: new Date().toISOString()
        });
    }
});

// ============================================================
// ENDPOINTS - AUTENTICACIÓN
// ============================================================

app.post('/api/auth/login', async (req, res) => {
    try {
        const { username, password } = req.body;

        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }

        const users = await getCollection(COLLECTIONS.USERS);
        const user = await users.findOne({ username });

        if (!user || !user.activo) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        const passwordHash = hashPassword(password);
        if (passwordHash !== user.password) {
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Actualizar último acceso
        await users.updateOne(
            { username },
            { $set: { ultimoAcceso: new Date().toISOString() } }
        );

        // Crear JWT
        const payload = {
            username: user.username,
            nombre: user.nombre,
            rol: user.rol,
            email: user.email,
            exp: Date.now() + (24 * 60 * 60 * 1000) // 24h
        };

        const token = createJWT(payload);

        logger.info(`Login successful: ${username}`);

        res.json({
            success: true,
            token,
            user: {
                username: user.username,
                nombre: user.nombre,
                rol: user.rol,
                email: user.email,
                permisos: user.permisos
            }
        });
    } catch (error) {
        logger.error('Login error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// ENDPOINTS - USUARIOS
// ============================================================

app.get('/api/users', authMiddleware, async (req, res) => {
    try {
        const collection = await getCollection(COLLECTIONS.USERS);
        const users = await collection
            .find({ activo: true })
            .project({ password: 0 })
            .toArray();
        res.json(users);
    } catch (error) {
        logger.error('Error getting users:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// GET /api/users/:username — perfil completo de un usuario
// El propio usuario siempre puede leer su perfil (necesario para
// mostrar telefono y puesto que no están en el JWT).
// ADMIN puede leer cualquier perfil.
// ─────────────────────────────────────────────────────────────
app.get('/api/users/:username', authMiddleware, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN') {
            return res.status(403).json({ error: 'Solo puedes consultar tu propio perfil' });
        }
        const col = await getCollection(COLLECTIONS.USERS);
        const user = await col.findOne({ username }, { projection: { password: 0 } });
        if (!user) return res.status(404).json({ error: 'Usuario no encontrado' });
        logger.info(`Profile GET: ${username} (por: ${req.usuario.username})`);
        res.json(user);
    } catch (error) {
        logger.error('Error getting user profile:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/users', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { error, value } = userCreateSchema.validate(req.body, { abortEarly: false });
        if (error) {
            return res.status(400).json({ error: error.details.map(d => d.message).join('; ') });
        }

        const collection = await getCollection(COLLECTIONS.USERS);
        const existing = await collection.findOne({ username: value.username });
        if (existing) {
            return res.status(409).json({ error: 'Username ya existe' });
        }

        value.password = hashPassword(value.password);
        value.creadoEn = new Date().toISOString();
        value.actualizadoEn = new Date().toISOString();
        value.ultimoAcceso = null;
        value.permisos = ['*'];

        const result = await collection.insertOne(value);
        logger.info(`User created: ${value.username} by ${req.usuario.username}`);
        
        delete value.password;
        res.status(201).json({ success: true, user: { ...value, _id: result.insertedId } });
    } catch (error) {
        logger.error('Error creating user:', error);
        res.status(500).json({ error: error.message });
    }
});

app.put('/api/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        const { error, value } = userUpdateSchema.validate(req.body, { stripUnknown: true });
        if (error) {
            return res.status(400).json({ error: error.details.map(d => d.message).join('; ') });
        }

        const collection = await getCollection(COLLECTIONS.USERS);

        if (value.password) {
            value.password = hashPassword(value.password);
        }
        value.actualizadoEn = new Date().toISOString();

        const result = await collection.updateOne(
            { username: req.params.username },
            { $set: value }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        logger.info(`User updated: ${req.params.username} by ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error updating user:', error);
        res.status(500).json({ error: error.message });
    }
});

app.delete('/api/users/:username', authMiddleware, requireAdmin, async (req, res) => {
    try {
        if (req.params.username === 'admin') {
            return res.status(403).json({ error: 'No se puede eliminar el usuario admin' });
        }

        const collection = await getCollection(COLLECTIONS.USERS);
        const result = await collection.updateOne(
            { username: req.params.username },
            { $set: { activo: false, eliminadoEn: new Date().toISOString() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        logger.info(`User deleted: ${req.params.username} by ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Error deleting user:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// PATCH /api/users/:username/profile — el propio usuario actualiza su perfil
// Campos permitidos: nombre, email, telefono, puesto  (ROL no se puede cambiar)
// ─────────────────────────────────────────────────────────────
app.patch('/api/users/:username/profile', authMiddleware, async (req, res) => {
    try {
        const { username } = req.params;

        // Solo el propio usuario o ADMIN pueden actualizar el perfil
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN') {
            return res.status(403).json({ error: 'Solo puedes actualizar tu propio perfil' });
        }

        const profileSchema = Joi.object({
            nombre:   Joi.string().min(3).max(100).optional(),
            email:    Joi.string().email().optional().allow(''),
            telefono: Joi.string().max(20).optional().allow(''),
            puesto:   Joi.string().max(100).optional().allow(''),
        });

        const { error, value } = profileSchema.validate(req.body, { stripUnknown: true });
        if (error) {
            return res.status(400).json({ error: error.details.map(d => d.message).join('; ') });
        }

        // FIX CRÍTICO: descartar strings vacíos.
        // telefono y puesto no viajan en el JWT, así que el frontend
        // los inicializa como ''. Sin este filtro, MongoDB los sobreescribiría
        // con '' borrando los valores reales.
        const camposValidos = Object.fromEntries(
            Object.entries(value).filter(([, v]) => v !== '' && v !== null && v !== undefined)
        );

        if (Object.keys(camposValidos).length === 0) {
            return res.status(400).json({ error: 'No se enviaron campos válidos para actualizar' });
        }

        camposValidos.actualizadoEn = new Date().toISOString();

        const col = await getCollection(COLLECTIONS.USERS);
        const result = await col.updateOne(
            { username },
            { $set: camposValidos }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Devolver perfil completo actualizado para que el frontend sincronice estado
        const updatedUser = await col.findOne({ username }, { projection: { password: 0 } });

        logger.info(`Profile updated: ${username} → [${Object.keys(camposValidos).join(', ')}] (por: ${req.usuario.username})`);
        res.json({ success: true, updated: camposValidos, user: updatedUser });
    } catch (error) {
        logger.error('Profile update error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// PATCH /api/users/:username/password — el propio usuario cambia su contraseña
// El usuario debe confirmar su contraseña actual. ADMIN puede cambiar sin verificarla.
// ─────────────────────────────────────────────────────────────
app.patch('/api/users/:username/password', authMiddleware, async (req, res) => {
    try {
        const { username } = req.params;
        const { passwordActual, passwordNueva } = req.body;

        // Solo el propio usuario o ADMIN pueden operar sobre este endpoint
        if (req.usuario.username !== username && req.usuario.rol !== 'ADMIN') {
            return res.status(403).json({ error: 'Solo puedes cambiar tu propia contraseña' });
        }

        if (!passwordActual || !passwordNueva) {
            return res.status(400).json({ error: 'Se requieren passwordActual y passwordNueva' });
        }

        if (passwordNueva.length < 6) {
            return res.status(400).json({ error: 'La contraseña nueva debe tener al menos 6 caracteres' });
        }

        const col = await getCollection(COLLECTIONS.USERS);
        const user = await col.findOne({ username });

        if (!user) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        // Si no es ADMIN, verificar que la contraseña actual sea correcta
        if (req.usuario.rol !== 'ADMIN') {
            const hashActual = hashPassword(passwordActual);
            if (user.password !== hashActual) {
                return res.status(401).json({ error: 'La contraseña actual no es correcta' });
            }
        }

        await col.updateOne(
            { username },
            { $set: { password: hashPassword(passwordNueva), actualizadoEn: new Date().toISOString() } }
        );

        logger.info(`Password changed: ${username} (solicitado por: ${req.usuario.username})`);
        res.json({ success: true, message: 'Contraseña actualizada correctamente' });
    } catch (error) {
        logger.error('Password change error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// ENDPOINTS - FORMATOS DE ACTIVACIÓN
// ============================================================

// Listar sistemas disponibles
app.get('/api/formatos/sistemas', authMiddleware, async (req, res) => {
    try {
        const plantillasStatus = await verificarPlantillas();
        
        const sistemas = Object.keys(ACTIVATION_TEMPLATES).map(key => {
            const config = ACTIVATION_TEMPLATES[key];
            const availableItem = plantillasStatus.available.find(item => item.sistema === key);
            const missingItem = plantillasStatus.missing.find(item => item.sistema === key);
            
            return {
                id: key,
                label: config.label,
                description: config.description,
                file: config.file,
                status: availableItem ? 'available' : 'unavailable',
                source: availableItem?.source || null,
                driveConfigured: !!config.driveId,
                missingEnvVar: missingItem?.needsDriveId || null
            };
        }).sort((a, b) => a.label.localeCompare(b.label));

        res.json({
            total: sistemas.length,
            available: sistemas.filter(s => s.status === 'available').length,
            mode: IS_CLOUD ? 'cloud' : 'local',
            storage: plantillasStatus,
            sistemas
        });
    } catch (error) {
        logger.error('Error listing systems:', error);
        res.status(500).json({ error: error.message });
    }
});

// Generar formato (requiere autenticación)
app.post('/api/formatos/generar', authMiddleware, async (req, res) => {
    const startTime = Date.now();
    
    try {
        const { sistema, userData } = req.body;

        if (!sistema || !userData) {
            return res.status(400).json({ 
                error: 'Campos "sistema" y "userData" son requeridos' 
            });
        }

        if (!ACTIVATION_TEMPLATES[sistema]) {
            return res.status(400).json({ 
                error: `Sistema no encontrado: ${sistema}`,
                sistemasDisponibles: Object.keys(ACTIVATION_TEMPLATES)
            });
        }

        const config = ACTIVATION_TEMPLATES[sistema];

        // Mapear datos
        const fieldData = mapUserDataForFormato(userData);

        // Validar campos críticos
        if (!fieldData.nombre || !fieldData.puesto) {
            return res.status(400).json({
                error: 'Faltan campos críticos: nombre y puesto son requeridos',
                datosRecibidos: fieldData
            });
        }

        logger.info(`Generating format: ${sistema} for ${fieldData.nombre}`);

        // CARGA HÍBRIDA DE PLANTILLA
        const templateBuffer = await loadTemplate(sistema, config);

        // Cargar plantilla con ExcelJS
        const workbook = new ExcelJS.Workbook();
        await workbook.xlsx.load(templateBuffer);

        const worksheet = workbook.worksheets[0];

        // Escribir datos PRESERVANDO estilos
        let cellsWritten = 0;
        Object.keys(config.fields).forEach(fieldName => {
            const cellAddress = config.fields[fieldName];
            const value = fieldData[fieldName];
            
            if (value) {
                const cell = worksheet.getCell(cellAddress);
                cell.value = value; // Solo cambiar valor, NO estilos
                cellsWritten++;
                logger.debug(`${cellAddress} = "${value}"`);
            }
        });

        logger.info(`Cells written: ${cellsWritten}`);

        // Generar buffer
        const buffer = await workbook.xlsx.writeBuffer();

        // Nombre de archivo
        const filename = generateSafeFilename(sistema, fieldData.nombre);

        const elapsedTime = Date.now() - startTime;
        logger.info(`Format generated: ${filename} (${buffer.length} bytes, ${elapsedTime}ms)`);

        // Log en MongoDB (opcional - auditoría)
        try {
            const logs = await getCollection(COLLECTIONS.AGENTS_LOG);
            await logs.insertOne({
                tipo: 'formato_activacion',
                sistema,
                usuario: req.usuario.username,
                nombre_empleado: fieldData.nombre,
                filename,
                size_bytes: buffer.length,
                duracion_ms: elapsedTime,
                environment: IS_CLOUD ? 'cloud' : 'local',
                timestamp: new Date().toISOString()
            });
        } catch (logError) {
            logger.warn('Error logging format generation:', logError);
        }

        // Enviar archivo
        res.setHeader('Content-Type', 
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet');
        res.setHeader('Content-Disposition', 
            `attachment; filename="${filename}"`);
        res.setHeader('X-Generated-In-Ms', elapsedTime.toString());
        res.setHeader('X-Source', IS_CLOUD ? 'drive' : 'filesystem');
        res.send(buffer);

    } catch (error) {
        const elapsedTime = Date.now() - startTime;
        logger.error('Error generating format:', error);
        res.status(500).json({ 
            error: error.message,
            elapsedTime,
            sistema: req.body.sistema
        });
    }
});

// Limpiar cache (solo ADMIN)
app.post('/api/formatos/clear-cache', authMiddleware, requireAdmin, (req, res) => {
    const beforeSize = templateCache.size;
    templateCache.clear();
    logger.info(`Cache cleared by ${req.usuario.username} (${beforeSize} items)`);
    res.json({
        success: true,
        itemsCleared: beforeSize,
        message: `Cache cleared: ${beforeSize} templates removed`
    });
});

// ============================================================
// ENDPOINTS - DISPOSITIVOS (IQU)
// ============================================================

app.get('/api/devices', async (req, res) => {
    try {
        const devices = await getCollection(COLLECTIONS.DEVICES);
        
        const { location, status, search } = req.query;
        const filter = {};
        
        if (location) filter.location = location;
        if (status) filter.status = status;
        if (search) {
            filter.$or = [
                { hostname: { $regex: search, $options: 'i' } },
                { logged_user: { $regex: search, $options: 'i' } },
                { ip_address: { $regex: search, $options: 'i' } }
            ];
        }
        
        // Actualizar offline
        const twentyMinAgo = new Date(Date.now() - 20 * 60 * 1000);
        await devices.updateMany(
            { last_seen: { $lt: twentyMinAgo.toISOString() }, status: 'online' },
            { $set: { status: 'offline' } }
        );
        
        const deviceList = await devices
            .find(filter)
            .sort({ last_seen: -1 })
            .limit(500)
            .toArray();
        
        res.json(deviceList);
    } catch (error) {
        logger.error('Error getting devices:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/devices/:agentId', async (req, res) => {
    try {
        const devices = await getCollection(COLLECTIONS.DEVICES);
        const device = await devices.findOne({ agent_id: req.params.agentId });
        
        if (!device) {
            return res.status(404).json({ error: 'Dispositivo no encontrado' });
        }
        
        res.json(device);
    } catch (error) {
        logger.error('Error getting device:', error);
        res.status(500).json({ error: error.message });
    }
});

app.post('/api/devices/:agentId', async (req, res) => {
    try {
        const devices = await getCollection(COLLECTIONS.DEVICES);
        
        const deviceData = {
            ...req.body,
            agent_id: req.params.agentId,
            updated_at: new Date().toISOString()
        };
        
        const result = await devices.updateOne(
            { agent_id: req.params.agentId },
            { 
                $set: deviceData,
                $setOnInsert: { created_at: new Date().toISOString() }
            },
            { upsert: true }
        );
        
        res.json({ success: true });
    } catch (error) {
        logger.error('Error upserting device:', error);
        res.status(500).json({ error: error.message });
    }
});

// ============================================================
// ENDPOINTS - RH MOVIMIENTOS
// ============================================================

app.post('/api/rh/movimientos', authMiddleware, async (req, res) => {
    try {
        const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        
        const movimiento = {
            ...req.body,
            _id: new ObjectId(),
            creado_por: {
                username: req.usuario.username,
                nombre: req.usuario.nombre,
                email: req.usuario.email
            },
            estado: 'PENDIENTE',
            fecha_creacion: new Date().toISOString(),
            fecha_modificacion: new Date().toISOString(),
            historial: [{
                estado: 'PENDIENTE',
                fecha: new Date().toISOString(),
                usuario: req.usuario.username,
                comentario: 'Movimiento creado'
            }]
        };
        
        await movimientos.insertOne(movimiento);
        
        logger.info(`RH movement created: ${movimiento._id} (${movimiento.tipo}) by ${req.usuario.username}`);
        res.status(201).json(movimiento);
    } catch (error) {
        logger.error('Error creating movement:', error);
        res.status(500).json({ error: error.message });
    }
});

app.get('/api/rh/movimientos', authMiddleware, async (req, res) => {
    try {
        const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const { tipo, estado, usuario, fecha_desde, fecha_hasta } = req.query;
        
        const filter = {};
        
        if (tipo && tipo !== 'todos') filter.tipo = tipo;
        if (estado && estado !== 'todos') filter.estado = estado;
        
        if (req.usuario.rol === 'RH' || usuario) {
            filter['creado_por.username'] = usuario || req.usuario.username;
        }
        
        if (fecha_desde || fecha_hasta) {
            filter.fecha_creacion = {};
            if (fecha_desde) filter.fecha_creacion.$gte = new Date(fecha_desde).toISOString();
            if (fecha_hasta) filter.fecha_creacion.$lte = new Date(fecha_hasta).toISOString();
        } else {
            const tresMesesAtras = new Date();
            tresMesesAtras.setMonth(tresMesesAtras.getMonth() - 3);
            filter.fecha_creacion = { $gte: tresMesesAtras.toISOString() };
        }
        
        const movimientosList = await movimientos
            .find(filter)
            .sort({ fecha_creacion: -1 })
            .toArray();
        
        res.json(movimientosList);
    } catch (error) {
        logger.error('Error getting movements:', error);
        res.status(500).json({ error: error.message });
    }
});

app.patch('/api/rh/movimientos/:id/estado', authMiddleware, requireSistemas, async (req, res) => {
    try {
        const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
        const { estado, comentario, correo_creado, procesado_por } = req.body;
        
        const estadosValidos = ['PENDIENTE', 'EN_PROCESO', 'COMPLETADO', 'RECHAZADO'];
        if (!estadosValidos.includes(estado)) {
            return res.status(400).json({ error: 'Estado inválido' });
        }
        
        const updates = {
            estado,
            fecha_modificacion: new Date().toISOString()
        };
        
        if (estado === 'COMPLETADO') {
            updates.fecha_completado = new Date().toISOString();
            updates.procesado_por = procesado_por || {
                username: req.usuario.username,
                nombre: req.usuario.nombre
            };
            if (correo_creado) updates.correo_creado = correo_creado;
        }
        
        await movimientos.updateOne(
            { _id: new ObjectId(req.params.id) },
            { 
                $set: updates,
                $push: {
                    historial: {
                        estado,
                        fecha: new Date().toISOString(),
                        usuario: req.usuario.username,
                        comentario: comentario || `Estado cambiado a ${estado}`
                    }
                }
            }
        );
        
        const movimiento = await movimientos.findOne({ _id: new ObjectId(req.params.id) });
        
        logger.info(`Status changed: ${req.params.id} -> ${estado} by ${req.usuario.username}`);
        res.json(movimiento);
    } catch (error) {
        logger.error('Error changing status:', error);
        res.status(500).json({ error: error.message });
    }
});


// ============================================================
// ENDPOINT - CHATBOT IA (Proxy seguro → Anthropic Claude)
// La API key NUNCA se expone al cliente — vive solo en Render.
// Requiere variable de entorno: ANTHROPIC_API_KEY
// ============================================================
app.post('/api/chat', authMiddleware, async (req, res) => {
    try {
        const ANTHROPIC_KEY = process.env.ANTHROPIC_API_KEY;

        if (!ANTHROPIC_KEY) {
            logger.error('/api/chat: ANTHROPIC_API_KEY no configurada en Render');
            return res.status(503).json({
                error: 'Servicio de IA no disponible. Configura ANTHROPIC_API_KEY en las variables de entorno de Render.'
            });
        }

        const { messages, system, max_tokens = 1000, temperature = 0.7 } = req.body;

        if (!messages || !Array.isArray(messages) || messages.length === 0) {
            return res.status(400).json({ error: 'El campo "messages" es requerido y debe ser un array.' });
        }

        const anthropicBody = {
            model: 'claude-sonnet-4-20250514',
            max_tokens,
            temperature,
            messages,
            ...(system && { system }),
        };

        const anthropicRes = await fetch('https://api.anthropic.com/v1/messages', {
            method: 'POST',
            headers: {
                'Content-Type':      'application/json',
                'x-api-key':         ANTHROPIC_KEY,
                'anthropic-version': '2023-06-01',
            },
            body: JSON.stringify(anthropicBody),
        });

        const data = await anthropicRes.json();

        if (!anthropicRes.ok) {
            logger.error(`Anthropic API error ${anthropicRes.status}:`, data);
            return res.status(anthropicRes.status).json({
                error: data.error?.message || 'Error en el servicio de IA'
            });
        }

        logger.info(`/api/chat OK — usuario: ${req.usuario.username}, tokens: ${data.usage?.output_tokens ?? '?'}`);
        res.json(data);

    } catch (error) {
        logger.error('/api/chat error:', error);
        res.status(500).json({ error: error.message });
    }
});

// GET /api/notificaciones/sse — canal en tiempo real (Server-Sent Events)
// El token se pasa por query string porque EventSource no soporta headers custom
app.get('/api/notificaciones/sse', async (req, res) => {
    const { token } = req.query;
    if (!token) return res.status(401).end();

    let usuario;
    try {
        usuario = verifyJWT(token);
    } catch {
        return res.status(401).end();
    }

    // Cabeceras SSE — críticas para Cloudflare y proxies
    res.setHeader('Content-Type', 'text/event-stream; charset=utf-8');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');   // Nginx/Cloudflare: no buffering
    res.setHeader('Access-Control-Allow-Origin', '*');
    res.flushHeaders();

    // Evento inicial: confirmación de conexión
    res.write(`event: connected\ndata: ${JSON.stringify({ username: usuario.username, ts: Date.now() })}\n\n`);

    // Heartbeat cada 25s para mantener la conexión viva a través del proxy
    const heartbeat = setInterval(() => {
        try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); }
    }, 25000);

    // Registrar y obtener función de cleanup
    const cleanup = sseRegistrar(usuario.username, res);

    // Cleanup cuando el cliente cierra la tab o pierde conexión
    req.on('close', () => {
        clearInterval(heartbeat);
        cleanup();
    });
});

// ============================================================
// ENDPOINTS - NOTIFICACIONES
// ============================================================

app.get('/api/notificaciones', authMiddleware, async (req, res) => {
    try {
        const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
        const { soloNoLeidas } = req.query;

        // FIX SEGURIDAD: siempre usar el usuario del JWT — nunca aceptar
        // ?username= como parámetro (cualquier usuario autenticado podría
        // leer notificaciones ajenas pasando ?username=otrousuario)
        const filter = { usuario_destino: req.usuario.username };
        if (soloNoLeidas === 'true') filter.leida = false;

        const notificacionesList = await notificaciones
            .find(filter)
            .sort({ fecha_creacion: -1 })
            .limit(50)
            .toArray();

        const total_no_leidas = await notificaciones.countDocuments({
            usuario_destino: req.usuario.username,
            leida: false
        });

        res.json({ notificaciones: notificacionesList, total_no_leidas });
    } catch (error) {
        logger.error('Error getting notifications:', error);
        res.status(500).json({ error: error.message });
    }
});

app.patch('/api/notificaciones/:id/leer', authMiddleware, async (req, res) => {
    try {
        const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
        
        await notificaciones.updateOne(
            { _id: new ObjectId(req.params.id), usuario_destino: req.usuario.username },
            { $set: { leida: true, fecha_lectura: new Date().toISOString() } }
        );
        
        res.json({ success: true });
    } catch (error) {
        logger.error('Error marking notification:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/notificaciones — crear notificación con push SSE en tiempo real
app.post('/api/notificaciones', authMiddleware, async (req, res) => {
    try {
        const { titulo, mensaje, tipo, icono, tab_destino, subtab, usuario_destino } = req.body;
        if (!titulo || !mensaje) {
            return res.status(400).json({ error: 'titulo y mensaje son requeridos' });
        }

        // FIX SEGURIDAD: broadcast '*' solo para roles privilegiados.
        // Un usuario normal no debería poder enviar notificaciones a toda la empresa.
        if (usuario_destino === '*' && !['ADMIN', 'SISTEMAS'].includes(req.usuario.rol)) {
            return res.status(403).json({ error: 'Solo ADMIN o SISTEMAS pueden enviar notificaciones globales' });
        }

        const col = await getCollection(COLLECTIONS.NOTIFICACIONES);

        // usuario_destino '*' → broadcast a todos los usuarios activos en DB
        let destinos;
        if (usuario_destino === '*') {
            const users = await getCollection(COLLECTIONS.USERS);
            destinos = await users.distinct('username', { activo: true });
        } else {
            destinos = [usuario_destino || req.usuario.username];
        }

        const now = new Date().toISOString();
        const docs = destinos.map(dest => ({
            titulo:          titulo.trim(),
            mensaje:         mensaje.trim(),
            tipo:            tipo        || 'info',
            icono:           icono       || null,
            tab_destino:     tab_destino || null,
            subtab:          subtab      || null,
            usuario_destino: dest,
            autor:           req.usuario.username,
            leida:           false,
            fecha_creacion:  now,
            fecha_lectura:   null
        }));

        const result = await col.insertMany(docs);
        const insertedIds = Object.values(result.insertedIds);

        // ── Push en tiempo real via SSE ──────────────────────────
        docs.forEach((doc, i) => {
            const notifConId = { ...doc, _id: insertedIds[i] };
            sseEnviar(doc.usuario_destino, 'notificacion', notifConId);
        });

        logger.info(`Notif creada por ${req.usuario.username} → SSE push a: ${destinos.join(', ')}`);
        res.status(201).json({ success: true, creadas: docs.length });
    } catch (error) {
        logger.error('Error creating notification:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/notificaciones/leer-todas — marcar todas como leídas
app.patch('/api/notificaciones/leer-todas', authMiddleware, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.NOTIFICACIONES);
        const result = await col.updateMany(
            { usuario_destino: req.usuario.username, leida: false },
            { $set: { leida: true, fecha_lectura: new Date().toISOString() } }
        );
        res.json({ success: true, actualizadas: result.modifiedCount });
    } catch (error) {
        logger.error('Error marking all read:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/notificaciones/:id — eliminar notificación propia
app.delete('/api/notificaciones/:id', authMiddleware, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.NOTIFICACIONES);
        await col.deleteOne({
            _id: new ObjectId(req.params.id),
            usuario_destino: req.usuario.username
        });
        res.json({ success: true });
    } catch (error) {
        logger.error('Error deleting notification:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/notificaciones — eliminar todas las leídas del usuario
app.delete('/api/notificaciones', authMiddleware, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.NOTIFICACIONES);
        const result = await col.deleteMany({
            usuario_destino: req.usuario.username,
            leida: true
        });
        res.json({ success: true, eliminadas: result.deletedCount });
    } catch (error) {
        logger.error('Error clearing notifications:', error);
        res.status(500).json({ error: error.message });
    }
});


// ============================================================
// ENDPOINTS - HUB DE SISTEMAS
// ============================================================

const requireHubAccess = (req, res, next) => {
    if (!req.usuario || !['SISTEMAS', 'ADMIN'].includes(req.usuario.rol)) {
        return res.status(403).json({ error: 'Acceso solo para roles SISTEMAS y ADMIN' });
    }
    next();
};

// ── Canales estáticos del Hub ──────────────────────────────
const HUB_CANALES = [
    { id: 'general',   name: 'general',    emoji: '💬', desc: 'Canal general del área de sistemas', pinned: true  },
    { id: 'proyectos', name: 'proyectos',  emoji: '🚀', desc: 'Seguimiento y avances de proyectos',  pinned: false },
    { id: 'soporte',   name: 'soporte',    emoji: '🛠️', desc: 'Tickets, incidencias y soporte',      pinned: false },
    { id: 'dev',       name: 'desarrollo', emoji: '💻', desc: 'Desarrollo y actualizaciones',         pinned: false },
    { id: 'anuncios',  name: 'anuncios',   emoji: '📣', desc: 'Comunicados oficiales (solo admin)',   pinned: true  },
];

// ─────────────────────────────────────────────────────────────
// MENSAJES
// ─────────────────────────────────────────────────────────────

// GET /api/hub/mensajes/:canal — obtener mensajes del canal
app.get('/api/hub/mensajes/:canal', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { canal } = req.params;
        const limit = parseInt(req.query.limit) || 100;

        const col = await getCollection(COLLECTIONS.HUB_MENSAJES);
        const mensajes = await col
            .find({ canal })
            .sort({ createdAt: 1 })
            .limit(limit)
            .toArray();

        res.json({ canal, mensajes, canales: HUB_CANALES });
    } catch (error) {
        logger.error('Hub mensajes GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/mensajes/:canal — enviar mensaje
app.post('/api/hub/mensajes/:canal', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { canal } = req.params;
        const { content } = req.body;

        if (!content?.trim()) {
            return res.status(400).json({ error: 'El contenido del mensaje es requerido' });
        }

        const col = await getCollection(COLLECTIONS.HUB_MENSAJES);
        const mensaje = {
            _id: new ObjectId(),
            canal,
            userId: req.usuario.username,
            userName: req.usuario.nombre,
            avatar: req.usuario.nombre?.charAt(0).toUpperCase() || '?',
            content: content.trim(),
            reactions: {},
            edited: false,
            createdAt: new Date(),
        };

        await col.insertOne(mensaje);
        logger.info(`Hub mensaje en #${canal} por ${req.usuario.username}`);
        res.status(201).json(mensaje);
    } catch (error) {
        logger.error('Hub mensaje POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/mensajes/:id — editar mensaje (solo autor)
app.patch('/api/hub/mensajes/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'Contenido requerido' });

        const col = await getCollection(COLLECTIONS.HUB_MENSAJES);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id), userId: req.usuario.username },
            { $set: { content: content.trim(), edited: true, editedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Mensaje no encontrado o no autorizado' });
        }

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updated);
    } catch (error) {
        logger.error('Hub mensaje PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/mensajes/:id — eliminar mensaje (autor o ADMIN)
app.delete('/api/hub/mensajes/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_MENSAJES);

        // Admin puede borrar cualquiera; usuario solo los suyos
        const filter = req.usuario.rol === 'ADMIN'
            ? { _id: new ObjectId(req.params.id) }
            : { _id: new ObjectId(req.params.id), userId: req.usuario.username };

        const result = await col.deleteOne(filter);
        if (result.deletedCount === 0) {
            return res.status(404).json({ error: 'Mensaje no encontrado o no autorizado' });
        }

        res.json({ success: true });
    } catch (error) {
        logger.error('Hub mensaje DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/mensajes/:id/reaction — toggle reacción
app.patch('/api/hub/mensajes/:id/reaction', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { emoji } = req.body;
        if (!emoji) return res.status(400).json({ error: 'Emoji requerido' });

        const col = await getCollection(COLLECTIONS.HUB_MENSAJES);
        const msg = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!msg) return res.status(404).json({ error: 'Mensaje no encontrado' });

        const userId = req.usuario.username;
        const current = msg.reactions?.[emoji] || [];
        const updated = current.includes(userId)
            ? current.filter(u => u !== userId)
            : [...current, userId];

        await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { [`reactions.${emoji}`]: updated } }
        );

        const updatedMsg = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updatedMsg);
    } catch (error) {
        logger.error('Hub reaction error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// REUNIONES
// ─────────────────────────────────────────────────────────────

// GET /api/hub/reuniones
app.get('/api/hub/reuniones', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_REUNIONES);
        const reuniones = await col.find({}).sort({ fecha: 1, hora: 1 }).toArray();
        res.json(reuniones);
    } catch (error) {
        logger.error('Hub reuniones GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/reuniones
app.post('/api/hub/reuniones', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { title, desc, date, time, duration, location, attendees, agenda } = req.body;
        if (!title?.trim() || !date || !time) {
            return res.status(400).json({ error: 'Título, fecha y hora son requeridos' });
        }

        const col = await getCollection(COLLECTIONS.HUB_REUNIONES);
        const reunion = {
            _id: new ObjectId(),
            title: title.trim(),
            desc: desc || '',
            date,
            time,
            duration: duration || 60,
            location: location || '',
            attendees: Array.isArray(attendees) ? attendees : (attendees || '').split(',').map(a => a.trim()).filter(Boolean),
            agenda: agenda || '',
            organizer: req.usuario.nombre,
            organizerUsername: req.usuario.username,
            status: 'scheduled',
            createdAt: new Date(),
        };

        await col.insertOne(reunion);
        logger.info(`Hub reunión creada: "${title}" por ${req.usuario.username}`);
        res.status(201).json(reunion);
    } catch (error) {
        logger.error('Hub reunión POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/reuniones/:id
app.patch('/api/hub/reuniones/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const allowed = ['title', 'desc', 'date', 'time', 'duration', 'location', 'attendees', 'agenda', 'status'];
        const updates = {};
        allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });
        updates.updatedAt = new Date();

        const col = await getCollection(COLLECTIONS.HUB_REUNIONES);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updates }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: 'Reunión no encontrada' });

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updated);
    } catch (error) {
        logger.error('Hub reunión PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/reuniones/:id
app.delete('/api/hub/reuniones/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_REUNIONES);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Reunión no encontrada' });
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub reunión DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// MINUTAS
// ─────────────────────────────────────────────────────────────

// GET /api/hub/minutas
app.get('/api/hub/minutas', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_MINUTAS);
        const minutas = await col.find({}).sort({ createdAt: -1 }).toArray();
        res.json(minutas);
    } catch (error) {
        logger.error('Hub minutas GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/minutas/:id — editar minuta completa
app.patch('/api/hub/minutas/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const allowed = ['title', 'date', 'summary', 'decisions', 'actionItems', 'attendees'];
        const updates = { updatedAt: new Date() };
        allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

        // Re-parsear actionItems si vienen como strings
        if (updates.actionItems && Array.isArray(updates.actionItems)) {
            updates.actionItems = updates.actionItems.map(a =>
                typeof a === 'string'
                    ? { id: new ObjectId().toString(), text: a.trim(), done: false }
                    : a
            ).filter(a => a.text?.trim());
        }

        const col = await getCollection(COLLECTIONS.HUB_MINUTAS);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updates }
        );

        if (result.matchedCount === 0)
            return res.status(404).json({ error: 'Minuta no encontrada' });

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        logger.info(`Hub minuta actualizada: ${req.params.id} por ${req.usuario.username}`);
        res.json(updated);
    } catch (error) {
        logger.error('Hub minuta PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/minutas/:id — eliminar minuta (autor o ADMIN)
app.delete('/api/hub/minutas/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_MINUTAS);

        // ADMIN puede borrar cualquiera; el autor solo las suyas
        const filter = req.usuario.rol === 'ADMIN'
            ? { _id: new ObjectId(req.params.id) }
            : { _id: new ObjectId(req.params.id), authorUsername: req.usuario.username };

        const result = await col.deleteOne(filter);
        if (result.deletedCount === 0)
            return res.status(404).json({ error: 'Minuta no encontrada o no autorizada' });

        logger.info(`Hub minuta eliminada: ${req.params.id} por ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub minuta DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});
// POST /api/hub/minutas
app.post('/api/hub/minutas', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { title, date, summary, decisions, actionItems, attendees, meetingId } = req.body;
        if (!title?.trim() || !summary?.trim()) {
            return res.status(400).json({ error: 'Título y resumen son requeridos' });
        }

        const parsedActions = (Array.isArray(actionItems) ? actionItems : (actionItems || '').split('\n'))
            .map(t => t.trim()).filter(Boolean)
            .map(text => ({ id: new ObjectId().toString(), text, done: false }));

        const col = await getCollection(COLLECTIONS.HUB_MINUTAS);
        const minuta = {
            _id: new ObjectId(),
            meetingId: meetingId || null,
            title: title.trim(),
            date: date || '',
            summary: summary.trim(),
            decisions: decisions || '',
            actionItems: parsedActions,
            attendees: attendees || '',
            author: req.usuario.nombre,
            authorUsername: req.usuario.username,
            comments: [],
            createdAt: new Date(),
        };

        await col.insertOne(minuta);
        logger.info(`Hub minuta creada: "${title}" por ${req.usuario.username}`);
        res.status(201).json(minuta);
    } catch (error) {
        logger.error('Hub minuta POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/minutas/:id/comentarios — agregar comentario
app.post('/api/hub/minutas/:id/comentarios', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { content } = req.body;
        if (!content?.trim()) return res.status(400).json({ error: 'Contenido requerido' });

        const comment = {
            id: new ObjectId().toString(),
            userId: req.usuario.username,
            userName: req.usuario.nombre,
            content: content.trim(),
            ts: Date.now(),
        };

        const col = await getCollection(COLLECTIONS.HUB_MINUTAS);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $push: { comments: comment } }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: 'Minuta no encontrada' });

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.status(201).json(updated);
    } catch (error) {
        logger.error('Hub comentario POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/minutas/:id/acciones/:itemId — toggle punto de acción
app.patch('/api/hub/minutas/:id/acciones/:itemId', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_MINUTAS);
        const minuta = await col.findOne({ _id: new ObjectId(req.params.id) });
        if (!minuta) return res.status(404).json({ error: 'Minuta no encontrada' });

        const updatedActions = (minuta.actionItems || []).map(a =>
            a.id === req.params.itemId ? { ...a, done: !a.done } : a
        );

        await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { actionItems: updatedActions } }
        );

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updated);
    } catch (error) {
        logger.error('Hub acción PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// TAREAS (KANBAN)
// ─────────────────────────────────────────────────────────────

// GET /api/hub/tareas
app.get('/api/hub/tareas', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_TAREAS);
        const tareas = await col.find({}).sort({ columna: 1, orden: 1, createdAt: -1 }).toArray();
        res.json(tareas);
    } catch (error) {
        logger.error('Hub tareas GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/tareas
app.post('/api/hub/tareas', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { title, desc, priority, assignee, dueDate, tags } = req.body;
        if (!title?.trim()) return res.status(400).json({ error: 'El título es requerido' });

        const col = await getCollection(COLLECTIONS.HUB_TAREAS);
        const tarea = {
            _id: new ObjectId(),
            title: title.trim(),
            desc: desc || '',
            priority: priority || 'media',
            assignee: assignee || '',
            dueDate: dueDate || null,
            tags: Array.isArray(tags) ? tags : (tags || '').split(',').map(t => t.trim()).filter(Boolean),
            status: 'todo',
            orden: Date.now(),
            creadoPor: req.usuario.nombre,
            creadoPorUsername: req.usuario.username,
            createdAt: new Date(),
        };

        await col.insertOne(tarea);
        logger.info(`Hub tarea creada: "${title}" por ${req.usuario.username}`);
        res.status(201).json(tarea);
    } catch (error) {
        logger.error('Hub tarea POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/tareas/:id — mover columna o editar
app.patch('/api/hub/tareas/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const allowed = ['title', 'desc', 'priority', 'assignee', 'dueDate', 'tags', 'status', 'orden'];
        const updates = { updatedAt: new Date() };
        allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

        const col = await getCollection(COLLECTIONS.HUB_TAREAS);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updates }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: 'Tarea no encontrada' });

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updated);
    } catch (error) {
        logger.error('Hub tarea PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/tareas/:id
app.delete('/api/hub/tareas/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_TAREAS);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Tarea no encontrada' });
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub tarea DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// ANUNCIOS
// ─────────────────────────────────────────────────────────────

// GET /api/hub/anuncios
app.get('/api/hub/anuncios', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_ANUNCIOS);
        const anuncios = await col.find({}).sort({ pinned: -1, createdAt: -1 }).toArray();
        res.json(anuncios);
    } catch (error) {
        logger.error('Hub anuncios GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/anuncios — solo ADMIN o SISTEMAS
app.post('/api/hub/anuncios', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { title, content, priority, pinned } = req.body;
        if (!title?.trim() || !content?.trim()) {
            return res.status(400).json({ error: 'Título y contenido son requeridos' });
        }

        const col = await getCollection(COLLECTIONS.HUB_ANUNCIOS);
        const anuncio = {
            _id: new ObjectId(),
            title: title.trim(),
            content: content.trim(),
            priority: priority || 'normal',
            pinned: !!pinned,
            author: req.usuario.nombre,
            authorUsername: req.usuario.username,
            createdAt: new Date(),
        };

        await col.insertOne(anuncio);
        logger.info(`Hub anuncio creado: "${title}" por ${req.usuario.username}`);
        res.status(201).json(anuncio);
    } catch (error) {
        logger.error('Hub anuncio POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/anuncios/:id
app.delete('/api/hub/anuncios/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_ANUNCIOS);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Anuncio no encontrado' });
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub anuncio DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// RECURSOS — Hub v3.0
// Archivos y enlaces de Drive compartidos del área
// ─────────────────────────────────────────────────────────────

// GET /api/hub/recursos — listar (filtro ?categoria=documentos|presentaciones|hojas|manuales|otros)
app.get('/api/hub/recursos', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { categoria } = req.query;
        const filter = categoria ? { categoria } : {};

        const col = await getCollection(COLLECTIONS.HUB_RECURSOS);
        const recursos = await col.find(filter).sort({ createdAt: -1 }).toArray();
        res.json(recursos);
    } catch (error) {
        logger.error('Hub recursos GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/recursos — crear recurso (solo SISTEMAS/ADMIN)
app.post('/api/hub/recursos', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { nombre, descripcion, url, categoria, tipo } = req.body;

        if (!nombre?.trim())
            return res.status(400).json({ error: 'El nombre del recurso es requerido' });
        if (!url?.trim())
            return res.status(400).json({ error: 'La URL del recurso es requerida' });

        try { new URL(url.trim()); }
        catch { return res.status(400).json({ error: 'La URL proporcionada no es válida' }); }

        const categoriasValidas = ['documentos', 'presentaciones', 'hojas', 'manuales', 'otros'];
        const col = await getCollection(COLLECTIONS.HUB_RECURSOS);
        const recurso = {
            _id: new ObjectId(),
            nombre: nombre.trim(),
            descripcion: descripcion?.trim() || '',
            url: url.trim(),
            categoria: categoriasValidas.includes(categoria) ? categoria : 'otros',
            tipo: tipo || 'enlace',
            uploadedBy: req.usuario.nombre,
            uploadedByUsername: req.usuario.username,
            createdAt: new Date(),
        };

        await col.insertOne(recurso);
        logger.info(`Hub recurso creado: "${nombre}" por ${req.usuario.username}`);
        res.status(201).json(recurso);
    } catch (error) {
        logger.error('Hub recursos POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/recursos/:id
app.delete('/api/hub/recursos/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_RECURSOS);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0)
            return res.status(404).json({ error: 'Recurso no encontrado' });
        logger.info(`Hub recurso eliminado: ${req.params.id} por ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub recursos DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// GUÍAS — Hub v3.0
// Procedimientos y documentación técnica del área
// ─────────────────────────────────────────────────────────────

// GET /api/hub/guias — listar (filtro ?categoria=accesos|hardware|... y ?q=búsqueda)
app.get('/api/hub/guias', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { categoria, q } = req.query;
        const filter = {};

        if (categoria) filter.categoria = categoria;
        if (q?.trim()) {
            const regex = new RegExp(q.trim(), 'i');
            filter.$or = [{ titulo: regex }, { descripcion: regex }, { contenido: regex }];
        }

        const col = await getCollection(COLLECTIONS.HUB_GUIAS);
        const guias = await col.find(filter).sort({ createdAt: -1 }).toArray();
        res.json(guias);
    } catch (error) {
        logger.error('Hub guias GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/guias — crear guía
app.post('/api/hub/guias', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { titulo, descripcion, categoria, url, contenido, version, autor } = req.body;

        if (!titulo?.trim())
            return res.status(400).json({ error: 'El título de la guía es requerido' });

        if (url?.trim()) {
            try { new URL(url.trim()); }
            catch { return res.status(400).json({ error: 'La URL proporcionada no es válida' }); }
        }

        const categoriasValidas = ['accesos', 'hardware', 'correos', 'sistemas', 'soporte', 'procesos', 'otros'];
        const col = await getCollection(COLLECTIONS.HUB_GUIAS);
        const guia = {
            _id: new ObjectId(),
            titulo: titulo.trim(),
            descripcion: descripcion?.trim() || '',
            categoria: categoriasValidas.includes(categoria) ? categoria : 'otros',
            url: url?.trim() || '',
            contenido: contenido?.trim() || '',
            version: version?.trim() || '1.0',
            autor: autor?.trim() || req.usuario.nombre,
            autorUsername: req.usuario.username,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        await col.insertOne(guia);
        logger.info(`Hub guía creada: "${titulo}" por ${req.usuario.username}`);
        res.status(201).json(guia);
    } catch (error) {
        logger.error('Hub guias POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/guias/:id — actualizar (versión, contenido, URL, etc.)
app.patch('/api/hub/guias/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const allowed = ['titulo', 'descripcion', 'categoria', 'url', 'contenido', 'version'];
        const updates = { updatedAt: new Date() };
        allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

        const col = await getCollection(COLLECTIONS.HUB_GUIAS);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updates }
        );

        if (result.matchedCount === 0)
            return res.status(404).json({ error: 'Guía no encontrada' });

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updated);
    } catch (error) {
        logger.error('Hub guias PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/guias/:id
app.delete('/api/hub/guias/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_GUIAS);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0)
            return res.status(404).json({ error: 'Guía no encontrada' });
        logger.info(`Hub guía eliminada: ${req.params.id} por ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub guias DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// PLANTILLAS — Hub v3.0
// Formatos de responsiva y documentos oficiales del área
// ─────────────────────────────────────────────────────────────

// GET /api/hub/plantillas — listar (filtro ?tipo=responsiva|alta_baja|inventario|...)
app.get('/api/hub/plantillas', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { tipo } = req.query;
        const filter = tipo ? { tipo } : {};

        const col = await getCollection(COLLECTIONS.HUB_PLANTILLAS);
        const plantillas = await col.find(filter).sort({ tipo: 1, nombre: 1 }).toArray();
        res.json(plantillas);
    } catch (error) {
        logger.error('Hub plantillas GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/plantillas — crear plantilla
app.post('/api/hub/plantillas', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { nombre, descripcion, tipo, url, instrucciones } = req.body;

        if (!nombre?.trim())
            return res.status(400).json({ error: 'El nombre de la plantilla es requerido' });
        if (!url?.trim())
            return res.status(400).json({ error: 'La URL de la plantilla es requerida' });

        try { new URL(url.trim()); }
        catch { return res.status(400).json({ error: 'La URL proporcionada no es válida' }); }

        const tiposValidos = ['responsiva', 'alta_baja', 'inventario', 'incidencias', 'formatos', 'otros'];
        const col = await getCollection(COLLECTIONS.HUB_PLANTILLAS);
        const plantilla = {
            _id: new ObjectId(),
            nombre: nombre.trim(),
            descripcion: descripcion?.trim() || '',
            tipo: tiposValidos.includes(tipo) ? tipo : 'otros',
            url: url.trim(),
            instrucciones: instrucciones?.trim() || '',
            uploadedBy: req.usuario.nombre,
            uploadedByUsername: req.usuario.username,
            createdAt: new Date(),
        };

        await col.insertOne(plantilla);
        logger.info(`Hub plantilla creada: "${nombre}" por ${req.usuario.username}`);
        res.status(201).json(plantilla);
    } catch (error) {
        logger.error('Hub plantillas POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/plantillas/:id
app.delete('/api/hub/plantillas/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const col = await getCollection(COLLECTIONS.HUB_PLANTILLAS);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0)
            return res.status(404).json({ error: 'Plantilla no encontrada' });
        logger.info(`Hub plantilla eliminada: ${req.params.id} por ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub plantillas DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ─────────────────────────────────────────────────────────────
// CAPACITACIÓN — Hub v3.0
// Tracker del plan de capacitación del área (trainee / analista)
// ─────────────────────────────────────────────────────────────

// GET /api/hub/capacitacion — listar tareas (filtro ?progreso=sin_asignar|en_curso|...)
app.get('/api/hub/capacitacion', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { progreso } = req.query;
        const filter = progreso ? { progreso } : {};

        const col = await getCollection(COLLECTIONS.HUB_CAPACITACION);
        const tareas = await col.find(filter).sort({ orden: 1, createdAt: 1 }).toArray();
        res.json(tareas);
    } catch (error) {
        logger.error('Hub capacitacion GET error:', error);
        res.status(500).json({ error: error.message });
    }
});

// POST /api/hub/capacitacion — crear tarea
app.post('/api/hub/capacitacion', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const { funcion, frecuencia, herramienta, progreso, fecha, notas, confAnalista, confSupervisor } = req.body;

        if (!funcion?.trim())
            return res.status(400).json({ error: 'La función/actividad es requerida' });

        const progresoValidos     = ['sin_asignar', 'en_curso', 'completado', 'pausado'];
        const supervisorValidos   = ['pendiente', 'aprobado', 'rechazado'];

        // Auto-incrementar orden
        const col = await getCollection(COLLECTIONS.HUB_CAPACITACION);
        const lastTask = await col.findOne({}, { sort: { orden: -1 } });
        const nextOrden = (lastTask?.orden || 0) + 1;

        const tarea = {
            _id: new ObjectId(),
            orden: nextOrden,
            funcion: funcion.trim(),
            frecuencia: frecuencia?.trim() || 'Según necesidad',
            herramienta: herramienta?.trim() || '',
            progreso: progresoValidos.includes(progreso) ? progreso : 'sin_asignar',
            fecha: fecha || null,
            notas: notas?.trim() || '',
            confAnalista: !!confAnalista,
            confSupervisor: supervisorValidos.includes(confSupervisor) ? confSupervisor : null,
            creadoPor: req.usuario.nombre,
            creadoPorUsername: req.usuario.username,
            createdAt: new Date(),
            updatedAt: new Date(),
        };

        await col.insertOne(tarea);
        logger.info(`Hub capacitacion tarea creada: "${funcion.trim()}" por ${req.usuario.username}`);
        res.status(201).json(tarea);
    } catch (error) {
        logger.error('Hub capacitacion POST error:', error);
        res.status(500).json({ error: error.message });
    }
});

// PATCH /api/hub/capacitacion/:id — actualizar progreso, confirmaciones, fecha, notas
app.patch('/api/hub/capacitacion/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        const allowed = [
            'funcion', 'frecuencia', 'herramienta', 'progreso',
            'fecha', 'notas', 'confAnalista', 'confSupervisor', 'orden'
        ];
        const updates = { updatedAt: new Date() };
        allowed.forEach(k => { if (req.body[k] !== undefined) updates[k] = req.body[k]; });

        // Validar enum progreso
        if (updates.progreso) {
            const validos = ['sin_asignar', 'en_curso', 'completado', 'pausado'];
            if (!validos.includes(updates.progreso))
                return res.status(400).json({ error: `Valor de progreso inválido: ${updates.progreso}` });
        }

        // Validar enum confSupervisor (puede ser null para limpiar)
        if (updates.confSupervisor !== undefined && updates.confSupervisor !== null) {
            const validos = ['pendiente', 'aprobado', 'rechazado'];
            if (!validos.includes(updates.confSupervisor))
                updates.confSupervisor = null;
        }

        const col = await getCollection(COLLECTIONS.HUB_CAPACITACION);
        const result = await col.updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: updates }
        );

        if (result.matchedCount === 0)
            return res.status(404).json({ error: 'Tarea no encontrada' });

        const updated = await col.findOne({ _id: new ObjectId(req.params.id) });
        res.json(updated);
    } catch (error) {
        logger.error('Hub capacitacion PATCH error:', error);
        res.status(500).json({ error: error.message });
    }
});

// DELETE /api/hub/capacitacion/:id — solo ADMIN
app.delete('/api/hub/capacitacion/:id', authMiddleware, requireHubAccess, async (req, res) => {
    try {
        if (req.usuario.rol !== 'ADMIN')
            return res.status(403).json({ error: 'Solo el administrador puede eliminar tareas de capacitación' });

        const col = await getCollection(COLLECTIONS.HUB_CAPACITACION);
        const result = await col.deleteOne({ _id: new ObjectId(req.params.id) });
        if (result.deletedCount === 0)
            return res.status(404).json({ error: 'Tarea no encontrada' });

        logger.info(`Hub capacitacion tarea eliminada: ${req.params.id} por ${req.usuario.username}`);
        res.json({ success: true });
    } catch (error) {
        logger.error('Hub capacitacion DELETE error:', error);
        res.status(500).json({ error: error.message });
    }
});

// ── FIN ENDPOINTS HUB DE SISTEMAS ─────────────────────────────

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((req, res) => {
    res.status(404).json({
        error: 'Endpoint no encontrado',
        path: req.path,
        method: req.method
    });
});

app.use((err, req, res, next) => {
    logger.error('Unhandled error:', err);
    res.status(500).json({ 
        error: 'Internal server error',
        message: IS_PRODUCTION ? 'An error occurred' : err.message
    });
});

// ============================================================
// START SERVER
// ============================================================

async function startServer() {
    try {
        // Crear directorio de logs (solo local)
        if (!IS_CLOUD) {
            await fs.mkdir('logs', { recursive: true });
        }
        
        // Conectar MongoDB
        await connectDB();
        logger.info('✅ Connected to MongoDB Atlas');
        
        // Inicializar DB
        await initializeDB();
        
        // Verificar plantillas
        const plantillasStatus = await verificarPlantillas();
        
        // Iniciar servidor
        app.listen(PORT, () => {
            console.log('');
            console.log('='.repeat(60));
            console.log('🚀 SERVIDOR UNIFICADO v3.3 - MYG TELECOM');
            console.log('='.repeat(60));
            console.log('');
            console.log(`✅ Estado: ACTIVO`);
            console.log(`🌐 Puerto: ${PORT}`);
            console.log(`🔗 URL: http://localhost:${PORT}`);
            console.log(`📦 Modo: ${IS_CLOUD ? 'CLOUD (Render/Vercel)' : 'LOCAL'}`);
            console.log('');
            console.log('📦 Módulos cargados:');
            console.log('   ✅ MongoDB Middleware (IQU Agents)');
            console.log('   ✅ Sistema RH (Movimientos + Notificaciones)');
            console.log('   ✅ Generador de Formatos de Activación (HÍBRIDO)');
            console.log('   ✅ Chatbot IA — Proxy Anthropic Claude (v3.3)');
            console.log('');
            console.log('💾 Storage:');
            if (!IS_CLOUD) {
                console.log(`   📂 Filesystem: ${plantillasStatus.filesystem ? '✅' : '❌'}`);
            }
            console.log(`   ☁️  Google Drive: ${plantillasStatus.googleDrive ? '✅ (configurado)' : '❌ (no configurado)'}`);
            console.log(`   ♻️  Cache: ${templateCache.size} plantillas en memoria`);
            console.log('');
            console.log('🔐 Autenticación:');
            console.log('   Usuario: admin');
            console.log('   Password: myg2025');
            console.log('');
            console.log('📌 Endpoints principales:');
            console.log('   POST /api/auth/login                - Login');
            console.log('   GET  /api/users                     - Usuarios');
            console.log('   PATCH /api/users/:u/profile         - Perfil propio');
            console.log('   PATCH /api/users/:u/password        - Contraseña propia');
            console.log('   GET  /api/devices                   - Dispositivos IQU');
            console.log('   POST /api/rh/movimientos            - Movimientos RH');
            console.log('   GET  /api/notificaciones            - Notificaciones');
            console.log('   GET  /api/notificaciones/sse        - Notificaciones SSE');
            console.log('   POST /api/chat                      - Chatbot IA (Anthropic)');
            console.log('   GET  /api/formatos/sistemas         - Sistemas disponibles');
            console.log('   POST /api/formatos/generar          - Generar formato');
            console.log('   POST /api/formatos/clear-cache      - Limpiar caché (ADMIN)');
            console.log('');
            console.log('='.repeat(60));
            console.log('');
        });
        
    } catch (error) {
        logger.error('❌ Fatal error starting server:', error);
        process.exit(1);
    }
}

// Iniciar
startServer();

// Graceful shutdown
process.on('SIGINT', async () => {
    console.log('\n🛑 Shutting down server...');
    templateCache.clear();
    if (cachedClient) {
        await cachedClient.close();
        logger.info('✅ MongoDB connection closed');
    }
    process.exit(0);
});

process.on('SIGTERM', async () => {
    console.log('\n🛑 SIGTERM received, shutting down...');
    templateCache.clear();
    if (cachedClient) {
        await cachedClient.close();
    }
    process.exit(0);
});

// Export para Vercel
export default app;

