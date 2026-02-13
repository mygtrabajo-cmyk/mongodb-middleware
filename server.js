/* ==================================================================
   MYG TELECOM - SERVIDOR UNIFICADO v3.2 (HÍBRIDO)
   
   Características:
   - Detección automática de entorno (local/cloud)
   - Plantillas: filesystem (local) + Google Drive (cloud/fallback)
   - Caché en memoria para templates descargados
   - Sistema completo: MongoDB + RH + Formatos + Notificaciones
   - Compatible: Node.js local + Vercel serverless
   
   Autor: Director IT - MYG Telecom
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
const IS_PRODUCTION = process.env.NODE_ENV === 'production';
const TEMPLATES_DIR = path.join(__dirname, 'plantillas');

// Cache de plantillas en memoria (para cloud)
const templateCache = new Map();
const CACHE_TTL = 60 * 60 * 1000; // 1 hora

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
if (!IS_VERCEL) {
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
    NOTIFICACIONES: 'notificaciones'
};

// Configuración HÍBRIDA de plantillas (filesystem + Google Drive)
const ACTIVATION_TEMPLATES = {
    ACCWEB: {
        file: 'ACTIVACION_ACCWEB.xlsx',
        driveId: process.env.DRIVE_ID_ACCWEB,
        label: 'AccWeb',
        description: 'Sistema de Acceso Web',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    ASCC: {
        file: 'ACTIVACION_ASCC.xlsx',
        driveId: process.env.DRIVE_ID_ASCC,
        label: 'ASCC',
        description: 'Alta Servicio Call Center',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    ASD: {
        file: 'ACTIVACION_ASD.xlsx',
        driveId: process.env.DRIVE_ID_ASD,
        label: 'ASD',
        description: 'Sistema ASD',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    AVS: {
        file: 'ACTIVACION_AVS.xlsx',
        driveId: process.env.DRIVE_ID_AVS,
        label: 'AVS',
        description: 'Sistema AVS',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    DIGITAL: {
        file: 'ACTIVACION_DIGITAL.xlsx',
        driveId: process.env.DRIVE_ID_DIGITAL,
        label: 'DIGITAL',
        description: 'Sistema Digital',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    IC: {
        file: 'ACTIVACION_IC.xlsx',
        driveId: process.env.DRIVE_ID_IC,
        label: 'IC',
        description: 'Información Comercial',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    IDM: {
        file: 'ACTIVACION_IDM.xlsx',
        driveId: process.env.DRIVE_ID_IDM,
        label: 'IDM',
        description: 'Sistema IDM',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    OFA: {
        file: 'ACTIVACION_OFA.xlsx',
        driveId: process.env.DRIVE_ID_OFA,
        label: 'OFA',
        description: 'Sistema OFA',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    PAYMENTBOX: {
        file: 'ACTIVACION_PAYMENTBOX.xlsx',
        driveId: process.env.DRIVE_ID_PAYMENTBOX,
        label: 'PAYMENTBOX',
        description: 'Sistema Payment Box',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    RED: {
        file: 'ACTIVACION_RED.xlsx',
        driveId: process.env.DRIVE_ID_RED,
        label: 'RED',
        description: 'Sistema de Red',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    SALESFORCE: {
        file: 'ACTIVACION_SALESFORCE.xlsx',
        driveId: process.env.DRIVE_ID_SALESFORCE,
        label: 'SALESFORCE',
        description: 'Sistema Salesforce',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
    },
    VPN: {
        file: 'ACTIVACION_VPN.xlsx',
        driveId: process.env.DRIVE_ID_VPN,
        label: 'VPN',
        description: 'Red Privada Virtual',
        fields: { nombre: 'A6', attuid: 'B6', puesto: 'D6', pdv: 'F6', clave_pdv: 'G6', correo: 'H6' }
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
    activo: Joi.boolean().optional()
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
        env: IS_VERCEL ? 'vercel' : 'local'
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
    
    // 1. INTENTAR FILESYSTEM (si no estamos en Vercel)
    if (!IS_VERCEL) {
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
        mode: IS_VERCEL ? 'cloud' : 'local'
    };

    // Verificar filesystem (solo si no estamos en Vercel)
    if (!IS_VERCEL) {
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
        mode: IS_VERCEL ? 'cloud (Vercel)' : 'local',
        status: 'running',
        modules: [
            'MongoDB Middleware (IQU Agents)',
            'Sistema RH (Movimientos + Notificaciones)',
            'Generador de Formatos de Activación (Híbrido)'
        ],
        storage: {
            templates: IS_VERCEL ? 'Google Drive' : 'Filesystem + Google Drive (fallback)',
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
                mode: IS_VERCEL ? 'cloud' : 'local',
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
            mode: IS_VERCEL ? 'cloud' : 'local',
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
                environment: IS_VERCEL ? 'cloud' : 'local',
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
        res.setHeader('X-Source', IS_VERCEL ? 'drive' : 'filesystem');
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
// ENDPOINTS - NOTIFICACIONES
// ============================================================

app.get('/api/notificaciones', authMiddleware, async (req, res) => {
    try {
        const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
        const { username, soloNoLeidas } = req.query;
        
        const filter = { usuario_destino: username || req.usuario.username };
        if (soloNoLeidas === 'true') filter.leida = false;
        
        const notificacionesList = await notificaciones
            .find(filter)
            .sort({ fecha_creacion: -1 })
            .limit(50)
            .toArray();
        
        const total_no_leidas = await notificaciones.countDocuments({
            usuario_destino: username || req.usuario.username,
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
        if (!IS_VERCEL) {
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
            console.log('🚀 SERVIDOR UNIFICADO v3.2 - MYG TELECOM');
            console.log('='.repeat(60));
            console.log('');
            console.log(`✅ Estado: ACTIVO`);
            console.log(`🌐 Puerto: ${PORT}`);
            console.log(`🔗 URL: http://localhost:${PORT}`);
            console.log(`📦 Modo: ${IS_VERCEL ? 'CLOUD (Vercel)' : 'LOCAL'}`);
            console.log('');
            console.log('📦 Módulos cargados:');
            console.log('   ✅ MongoDB Middleware (IQU Agents)');
            console.log('   ✅ Sistema RH (Movimientos + Notificaciones)');
            console.log('   ✅ Generador de Formatos de Activación (HÍBRIDO)');
            console.log('');
            console.log('💾 Storage:');
            if (!IS_VERCEL) {
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
            console.log('   GET  /api/devices                   - Dispositivos IQU');
            console.log('   POST /api/rh/movimientos            - Movimientos RH');
            console.log('   GET  /api/notificaciones            - Notificaciones');
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
