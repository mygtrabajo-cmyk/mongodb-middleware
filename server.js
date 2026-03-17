// ============================================================
// MYG TELECOM — API SERVER v4.0.0
// Render (Node.js) + MongoDB Atlas
//
// Cambios v4.0:
// - 7 roles: ADMIN, GERENTE_OPERACIONES, COORDINADOR, ANALISTA,
//            GERENTE_COMERCIAL, EJECUTIVO_COMERCIAL, USUARIO
// - Campo 'area' requerido para COORDINADOR y ANALISTA
// - Campo 'rolSecundario' opcional (hasta 2 roles por usuario)
// - Campo 'preferencias' (tabsPinned persistente en MongoDB)
// - GERENTE_COMERCIAL / EJECUTIVO_COMERCIAL: permisos vacíos por defecto
//   (solo lo que Admin asigne explícitamente vía admin.permisos)
// - Panel Admin: exclusivo de ADMIN
// - PATCH /api/users/:username/profile → guarda preferencias
// - Backward compatibility: roles legacy remapeados automáticamente
// ============================================================

require('dotenv').config();

const express   = require('express');
const cors      = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const jwt       = require('jsonwebtoken');
const bcrypt    = require('bcryptjs');
const Joi       = require('joi');
const rateLimit = require('express-rate-limit');
const morgan    = require('morgan');

const app  = express();
const PORT = process.env.PORT || 5500;

// ── Middleware ─────────────────────────────────────────────
app.use(cors({
    origin: [
        'https://dashboard-myg-api.mygtrabajo.workers.dev',
        'https://myg-mongodb-api.onrender.com',
        'http://localhost:3000',
        'http://localhost:5500',
        'http://127.0.0.1:5500',
    ],
    methods: ['GET','POST','PUT','PATCH','DELETE','OPTIONS'],
    allowedHeaders: ['Content-Type','Authorization']
}));
app.use(express.json({ limit: '10mb' }));
app.use(morgan('combined'));

// ── Rate Limiting ──────────────────────────────────────────
const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 10,
    message: { error: 'Demasiados intentos de login. Espera 15 minutos.' }
});

const apiLimiter = rateLimit({
    windowMs: 1 * 60 * 1000,
    max: 200,
    message: { error: 'Demasiadas peticiones. Intenta de nuevo en 1 minuto.' }
});

app.use('/api/', apiLimiter);

// ── MongoDB ────────────────────────────────────────────────
let db;
const MONGO_URI = process.env.MONGODB_URI || 'mongodb+srv://...';
const DB_NAME   = 'iqu_telecom';

async function connectDB() {
    try {
        const client = new MongoClient(MONGO_URI, {
            serverSelectionTimeoutMS: 10000,
            socketTimeoutMS: 45000,
        });
        await client.connect();
        db = client.db(DB_NAME);
        console.log(`✅ MongoDB conectado: ${DB_NAME}`);

        // Crear índices
        await db.collection('usuarios').createIndex({ username: 1 }, { unique: true });
        await db.collection('access_logs').createIndex({ timestamp: 1 }, { expireAfterSeconds: 30 * 24 * 3600 });
        await db.collection('notificaciones').createIndex({ username: 1, leida: 1 });

        return client;
    } catch (error) {
        console.error('❌ Error conectando MongoDB:', error);
        throw error;
    }
}

// ── Constantes de roles v4.0 ───────────────────────────────
const ROLES_VALIDOS = [
    'ADMIN', 'GERENTE_OPERACIONES', 'COORDINADOR', 'ANALISTA',
    'GERENTE_COMERCIAL', 'EJECUTIVO_COMERCIAL',
    'GERENTE_RH', 'ANALISTA_RH',          // v4.1 — área RH implícita
    'USUARIO'
];

const AREAS_VALIDAS = ['Sistemas', 'Mantenimiento', 'Credito', 'Logistica'];

// Roles que requieren campo 'area'
const ROLES_CON_AREA = ['COORDINADOR', 'ANALISTA', 'GERENTE_RH', 'ANALISTA_RH']; // v4.1

// Mapa de roles legacy → nuevos roles
const LEGACY_ROLE_MAP = {
    'RH':       'ANALISTA_RH',  // v4.1: legacy RH → ANALISTA_RH (area pendiente de asignar)
    'SISTEMAS': 'COORDINADOR',  // area='Sistemas'
    'GERENTE':  'GERENTE_OPERACIONES',
    'USUARIO':  'USUARIO',
    'ADMIN':    'ADMIN',
};

// ── Módulos de permisos disponibles ───────────────────────
const MODULOS_PERMISOS = [
    'dashboard.ver', 'dashboard.rh', 'dashboard.headcount', 'dashboard.activos',
    'dashboard.tickets', 'dashboard.dispositivos', 'dashboard.kpi_sistemas',
    'hub.acceso', 'hub.mensajes', 'hub.reuniones', 'hub.minutas', 'hub.tareas',
    'hub.anuncios', 'hub.recursos', 'hub.guias', 'hub.plantillas',
    'hub.capacitacion', 'hub.asistencia', 'hub.vacaciones', 'hub.concentrado',
    'hub.asistencia.registrar', 'hub.asistencia.admin_registro',
    'hub.concentrado.ver', 'hub.peticiones.crear', 'hub.peticiones.aprobar',
    'hub.peticiones.ver_todas', 'formatos.generar',
    'rh.movimientos.crear', 'rh.movimientos.ver', 'rh.movimientos.gestionar',
    'activos.ver', 'activos.registrar', 'exportar_datos',
    'chatbot.usar', 'admin.panel', 'admin.usuarios',
    'admin.permisos', 'admin.logs', 'admin.formularios',
];

// ── Permisos por defecto para cada rol ────────────────────
// GERENTE_COMERCIAL y EJECUTIVO_COMERCIAL: vacíos — Admin asigna manualmente
const ROL_PERMISOS_DEFAULT = {
    ADMIN: ['*'],

    GERENTE_OPERACIONES: [
        'dashboard.ver', 'dashboard.rh', 'dashboard.headcount', 'dashboard.activos',
        'dashboard.tickets', 'dashboard.dispositivos', 'dashboard.kpi_sistemas',
        'hub.acceso', 'hub.concentrado.ver', 'hub.peticiones.ver_todas',
        'hub.peticiones.aprobar', 'exportar_datos', 'chatbot.usar',
    ],

    // COORDINADOR: permisos completos del área Sistemas (base)
    // Para otras áreas el admin puede agregar/quitar vía admin.permisos
    COORDINADOR: [
        'dashboard.ver', 'dashboard.rh', 'dashboard.headcount', 'dashboard.activos',
        'dashboard.tickets', 'dashboard.dispositivos', 'dashboard.kpi_sistemas',
        'hub.acceso', 'hub.mensajes', 'hub.reuniones', 'hub.minutas', 'hub.tareas',
        'hub.anuncios', 'hub.recursos', 'hub.guias', 'hub.plantillas',
        'hub.capacitacion', 'hub.asistencia', 'hub.vacaciones', 'hub.concentrado',
        'hub.asistencia.registrar', 'hub.asistencia.admin_registro',
        'hub.concentrado.ver', 'hub.peticiones.crear', 'hub.peticiones.aprobar',
        'hub.peticiones.ver_todas', 'formatos.generar',
        'rh.movimientos.crear', 'rh.movimientos.ver', 'rh.movimientos.gestionar',
        'activos.ver', 'activos.registrar', 'exportar_datos', 'chatbot.usar',
    ],

    ANALISTA: [
        'dashboard.ver', 'dashboard.rh', 'dashboard.headcount', 'dashboard.activos',
        'dashboard.tickets', 'dashboard.dispositivos', 'dashboard.kpi_sistemas',
        'rh.movimientos.ver', 'activos.ver', 'exportar_datos', 'chatbot.usar',
    ],

    // Solo lo que el Admin asigne manualmente
    GERENTE_COMERCIAL:    [],
    EJECUTIVO_COMERCIAL:  [],

    // GERENTE_RH: solo tabs RH y Headcount + gestión completa de movimientos
    // Más restringido que COORDINADOR (sin acceso a Tickets, Activos, Hub, Equipos, etc.)
    GERENTE_RH: [
        'dashboard.ver',
        'dashboard.rh',
        'dashboard.headcount',
        'rh.movimientos.crear',
        'rh.movimientos.ver',
        'rh.movimientos.gestionar',
        'exportar_datos',
        'chatbot.usar',
    ],

    // ANALISTA_RH: solo tabs RH y Headcount — consulta y crea movimientos, no aprueba
    ANALISTA_RH: [
        'dashboard.ver',
        'dashboard.rh',
        'dashboard.headcount',
        'rh.movimientos.crear',
        'rh.movimientos.ver',
        'exportar_datos',
        'chatbot.usar',
    ],

    USUARIO: ['dashboard.ver', 'chatbot.usar'],
};

// ── Helpers de normalización ───────────────────────────────
/**
 * Remapea un rol legacy al nuevo esquema si aplica.
 * Preserva roles v4.0 sin cambio.
 */
function normalizarRol(rol) {
    if (ROLES_VALIDOS.includes(rol)) return rol;
    return LEGACY_ROLE_MAP[rol] || 'USUARIO';
}

/**
 * Calcula permisos efectivos del usuario:
 * permisos del rol base + overrides del admin (permisosExtra) - permisosRevocados
 */
function calcularPermisos(usuario) {
    const rol = normalizarRol(usuario.rol);

    // Admin siempre tiene wildcard
    if (rol === 'ADMIN') return ['*'];

    const base    = ROL_PERMISOS_DEFAULT[rol] || [];
    const extra   = usuario.permisosExtra   || [];
    const revoked = usuario.permisosRevocados || [];

    const set = new Set([...base, ...extra]);
    revoked.forEach(p => set.delete(p));
    return Array.from(set);
}

// ── Schemas Joi v4.0 ───────────────────────────────────────
const schemaCrearUsuario = Joi.object({
    username:     Joi.string().min(3).max(50).required(),
    password:     Joi.string().min(6).required(),
    nombre:       Joi.string().min(2).max(100).required(),
    email:        Joi.string().email().optional().allow(''),
    rol:          Joi.string().valid(...ROLES_VALIDOS).required(), // v4.1: incluye GERENTE_RH, ANALISTA_RH
    area:         Joi.string().valid(...AREAS_VALIDAS).when('rol', {
                      // ROLES_CON_AREA incluye COORDINADOR, ANALISTA, GERENTE_RH, ANALISTA_RH
                      is: Joi.valid(...ROLES_CON_AREA),
                      then: Joi.required(),
                      otherwise: Joi.optional().allow(null, '')
                  }),
    rolSecundario: Joi.string().valid(...ROLES_VALIDOS).optional().allow(null, ''),
    activo:       Joi.boolean().default(true),
});

const schemaActualizarUsuario = Joi.object({
    nombre:           Joi.string().min(2).max(100).optional(),
    email:            Joi.string().email().optional().allow(''),
    rol:              Joi.string().valid(...ROLES_VALIDOS).optional(),
    area:             Joi.string().valid(...AREAS_VALIDAS).optional().allow(null, ''),
    rolSecundario:    Joi.string().valid(...ROLES_VALIDOS).optional().allow(null, ''),
    password:         Joi.string().min(6).optional(),
    activo:           Joi.boolean().optional(),
    permisosExtra:    Joi.array().items(Joi.string()).optional(),
    permisosRevocados: Joi.array().items(Joi.string()).optional(),
});

const schemaActualizarPerfil = Joi.object({
    nombre:      Joi.string().min(2).max(100).optional(),
    email:       Joi.string().email().optional().allow(''),
    avatar:      Joi.string().optional().allow(''),
    preferencias: Joi.object({
        tabsPinned: Joi.array().items(Joi.string()).optional(),
    }).optional(),
});

const schemaCambiarPassword = Joi.object({
    passwordActual: Joi.string().required(),
    passwordNueva:  Joi.string().min(6).required(),
});

// ── Middleware de autenticación ────────────────────────────
function requireAuth(req, res, next) {
    try {
        const header = req.headers.authorization;
        if (!header?.startsWith('Bearer ')) {
            return res.status(401).json({ error: 'Token no proporcionado' });
        }
        const token = header.slice(7);
        const payload = jwt.verify(token, process.env.JWT_SECRET);

        // Normalizar rol por si viene de JWT legacy
        payload.rol = normalizarRol(payload.rol);
        req.user = payload;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ error: 'Token expirado', code: 'TOKEN_EXPIRED' });
        }
        return res.status(401).json({ error: 'Token inválido' });
    }
}

function requireAdmin(req, res, next) {
    if (req.user?.rol !== 'ADMIN') {
        return res.status(403).json({ error: 'Acceso denegado. Se requiere rol ADMIN.' });
    }
    next();
}

function requirePermiso(permiso) {
    return (req, res, next) => {
        const permisos = req.user?.permisos || [];
        if (permisos.includes('*') || permisos.includes(permiso)) return next();
        return res.status(403).json({ error: `Permiso requerido: ${permiso}` });
    };
}

// ── Logging de accesos ─────────────────────────────────────
async function logAccess(username, action, details = {}) {
    try {
        if (!db) return;
        await db.collection('access_logs').insertOne({
            username, action, details,
            timestamp: new Date(),
            ip: details.ip || 'unknown'
        });
    } catch (err) {
        console.error('Error logging access:', err.message);
    }
}

// ── HEALTH CHECK ───────────────────────────────────────────
app.get('/health', (req, res) => {
    res.json({
        status: 'ok',
        version: '4.0.0',
        timestamp: new Date().toISOString(),
        db: db ? 'connected' : 'disconnected'
    });
});

// ── LOGIN ──────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password) {
            return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
        }

        const usuarioDoc = await db.collection('usuarios').findOne({ username: username.toLowerCase().trim() });

        if (!usuarioDoc) {
            await logAccess(username, 'LOGIN_FAILED', { reason: 'user_not_found', ip: req.ip });
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        if (!usuarioDoc.activo) {
            await logAccess(username, 'LOGIN_BLOCKED', { reason: 'account_disabled', ip: req.ip });
            return res.status(401).json({ error: 'Cuenta desactivada. Contacta al administrador.' });
        }

        const validPassword = await bcrypt.compare(password, usuarioDoc.password);
        if (!validPassword) {
            await logAccess(username, 'LOGIN_FAILED', { reason: 'wrong_password', ip: req.ip });
            return res.status(401).json({ error: 'Credenciales inválidas' });
        }

        // Normalizar rol si viene de esquema legacy
        const rolNormalizado = normalizarRol(usuarioDoc.rol);
        const permisos = calcularPermisos({ ...usuarioDoc, rol: rolNormalizado });

        const tokenPayload = {
            username:      usuarioDoc.username,
            nombre:        usuarioDoc.nombre,
            email:         usuarioDoc.email || '',
            rol:           rolNormalizado,
            area:          usuarioDoc.area || null,          // v4.0
            rolSecundario: usuarioDoc.rolSecundario || null, // v4.0
            permisos,
            preferencias:  usuarioDoc.preferencias || {},   // v4.0
        };

        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '8h' });

        // Actualizar último login
        await db.collection('usuarios').updateOne(
            { username: usuarioDoc.username },
            { $set: { ultimoLogin: new Date(), rol: rolNormalizado } }
        );

        await logAccess(usuarioDoc.username, 'LOGIN_SUCCESS', { ip: req.ip, rol: rolNormalizado });

        res.json({
            success: true,
            token,
            user: {
                username:      usuarioDoc.username,
                nombre:        usuarioDoc.nombre,
                email:         usuarioDoc.email || '',
                rol:           rolNormalizado,
                area:          usuarioDoc.area || null,
                rolSecundario: usuarioDoc.rolSecundario || null,
                permisos,
                preferencias:  usuarioDoc.preferencias || {},
            }
        });
    } catch (error) {
        console.error('Error en login:', error);
        res.status(500).json({ error: 'Error interno del servidor' });
    }
});

// ── USUARIOS — CRUD (solo ADMIN) ───────────────────────────
app.get('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const usuarios = await db.collection('usuarios')
            .find({}, { projection: { password: 0 } })
            .toArray();
        // Normalizar roles en la respuesta
        const normalizados = usuarios.map(u => ({
            ...u,
            rol: normalizarRol(u.rol)
        }));
        res.json(normalizados);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo usuarios' });
    }
});

app.post('/api/users', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { error, value } = schemaCrearUsuario.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });

        // Validar que rolSecundario no sea igual al rol principal
        if (value.rolSecundario && value.rolSecundario === value.rol) {
            return res.status(400).json({ error: 'El rol secundario no puede ser igual al rol principal' });
        }

        const existente = await db.collection('usuarios').findOne({ username: value.username.toLowerCase() });
        if (existente) return res.status(409).json({ error: 'El usuario ya existe' });

        const hashedPassword = await bcrypt.hash(value.password, 12);
        const nuevoUsuario = {
            username:         value.username.toLowerCase().trim(),
            password:         hashedPassword,
            nombre:           value.nombre.trim(),
            email:            value.email || '',
            rol:              value.rol,
            area:             value.area || null,
            rolSecundario:    value.rolSecundario || null,
            activo:           value.activo !== false,
            permisosExtra:    [],
            permisosRevocados: [],
            preferencias:     { tabsPinned: [] },
            createdAt:        new Date(),
            createdBy:        req.user.username,
        };

        await db.collection('usuarios').insertOne(nuevoUsuario);
        await logAccess(req.user.username, 'USER_CREATED', { targetUser: nuevoUsuario.username });

        const { password: _, ...sinPassword } = nuevoUsuario;
        res.status(201).json({ success: true, user: sinPassword });
    } catch (error) {
        console.error('Error creando usuario:', error);
        res.status(500).json({ error: 'Error creando usuario' });
    }
});

app.put('/api/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;

        // Proteger usuario admin principal
        if (username === 'admin' && req.body.rol && req.body.rol !== 'ADMIN') {
            return res.status(403).json({ error: 'No se puede cambiar el rol del administrador principal' });
        }

        const { error, value } = schemaActualizarUsuario.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });

        // Validar que rolSecundario != rol
        if (value.rolSecundario && value.rol && value.rolSecundario === value.rol) {
            return res.status(400).json({ error: 'El rol secundario no puede ser igual al rol principal' });
        }

        // Validar área si el rol la requiere
        if (value.rol && ROLES_CON_AREA.includes(value.rol) && !value.area) {
            // Obtener el área actual del usuario si no viene en el body
            const usuarioActual = await db.collection('usuarios').findOne({ username });
            if (!usuarioActual?.area) {
                return res.status(400).json({ error: `El rol ${value.rol} requiere campo 'area'` });
            }
        }

        const updates = { updatedAt: new Date(), updatedBy: req.user.username };

        if (value.nombre)           updates.nombre           = value.nombre.trim();
        if (value.email !== undefined) updates.email         = value.email || '';
        if (value.rol)              updates.rol              = value.rol;
        if (value.area !== undefined)  updates.area          = value.area || null;
        if (value.rolSecundario !== undefined) updates.rolSecundario = value.rolSecundario || null;
        if (value.activo !== undefined) updates.activo       = value.activo;
        if (value.permisosExtra)    updates.permisosExtra    = value.permisosExtra;
        if (value.permisosRevocados) updates.permisosRevocados = value.permisosRevocados;

        if (value.password) {
            updates.password = await bcrypt.hash(value.password, 12);
        }

        const result = await db.collection('usuarios').updateOne({ username }, { $set: updates });

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        await logAccess(req.user.username, 'USER_UPDATED', { targetUser: username, changes: Object.keys(updates) });
        res.json({ success: true, message: 'Usuario actualizado correctamente' });
    } catch (error) {
        console.error('Error actualizando usuario:', error);
        res.status(500).json({ error: 'Error actualizando usuario' });
    }
});

app.delete('/api/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin') return res.status(403).json({ error: 'No se puede eliminar el administrador principal' });
        if (username === req.user.username) return res.status(403).json({ error: 'No puedes eliminarte a ti mismo' });

        const result = await db.collection('usuarios').deleteOne({ username });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        await logAccess(req.user.username, 'USER_DELETED', { targetUser: username });
        res.json({ success: true, message: 'Usuario eliminado' });
    } catch (error) {
        res.status(500).json({ error: 'Error eliminando usuario' });
    }
});

// ── PERFIL DE USUARIO (cualquier usuario autenticado) ──────
// PATCH: actualiza perfil + preferencias (tabsPinned)
app.patch('/api/users/:username/profile', requireAuth, async (req, res) => {
    try {
        const { username } = req.params;

        // Solo el propio usuario o ADMIN pueden actualizar el perfil
        if (req.user.username !== username && req.user.rol !== 'ADMIN') {
            return res.status(403).json({ error: 'No tienes permiso para modificar este perfil' });
        }

        const { error, value } = schemaActualizarPerfil.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });

        const updates = { updatedAt: new Date() };

        if (value.nombre)   updates.nombre  = value.nombre.trim();
        if (value.email !== undefined) updates.email = value.email || '';
        if (value.avatar !== undefined) updates.avatar = value.avatar;

        // Guardar preferencias con merge (no reemplazar todo el objeto)
        if (value.preferencias) {
            if (value.preferencias.tabsPinned !== undefined) {
                updates['preferencias.tabsPinned'] = value.preferencias.tabsPinned;
            }
        }

        const result = await db.collection('usuarios').updateOne(
            { username },
            { $set: updates }
        );

        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });

        // Retornar preferencias actualizadas
        const usuarioActualizado = await db.collection('usuarios').findOne(
            { username },
            { projection: { password: 0 } }
        );

        res.json({
            success: true,
            message: 'Perfil actualizado correctamente',
            preferencias: usuarioActualizado.preferencias || {}
        });
    } catch (error) {
        console.error('Error actualizando perfil:', error);
        res.status(500).json({ error: 'Error actualizando perfil' });
    }
});

// PATCH: cambiar contraseña propia
app.patch('/api/users/:username/password', requireAuth, async (req, res) => {
    try {
        const { username } = req.params;
        if (req.user.username !== username && req.user.rol !== 'ADMIN') {
            return res.status(403).json({ error: 'No tienes permiso para cambiar esta contraseña' });
        }

        const { error, value } = schemaCambiarPassword.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });

        const usuario = await db.collection('usuarios').findOne({ username });
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

        // Si no es admin, verificar contraseña actual
        if (req.user.rol !== 'ADMIN') {
            const valid = await bcrypt.compare(value.passwordActual, usuario.password);
            if (!valid) return res.status(400).json({ error: 'Contraseña actual incorrecta' });
        }

        const hashedNueva = await bcrypt.hash(value.passwordNueva, 12);
        await db.collection('usuarios').updateOne({ username }, {
            $set: { password: hashedNueva, passwordChangedAt: new Date() }
        });

        await logAccess(req.user.username, 'PASSWORD_CHANGED', { targetUser: username });
        res.json({ success: true, message: 'Contraseña actualizada correctamente' });
    } catch (error) {
        res.status(500).json({ error: 'Error cambiando contraseña' });
    }
});

// ── ADMIN — Estadísticas del sistema ──────────────────────
app.get('/api/admin/stats', requireAuth, requireAdmin, async (req, res) => {
    try {
        const [totalUsuarios, usuariosActivos, registrosPorRol, ultimosLogins, formSubmissions] = await Promise.all([
            db.collection('usuarios').countDocuments(),
            db.collection('usuarios').countDocuments({ activo: true }),
            db.collection('usuarios').aggregate([
                { $group: { _id: '$rol', count: { $sum: 1 } } },
                { $sort: { count: -1 } }
            ]).toArray(),
            db.collection('access_logs')
                .find({ action: 'LOGIN_SUCCESS' })
                .sort({ timestamp: -1 })
                .limit(10)
                .toArray(),
            db.collection('form_submissions').countDocuments({ createdAt: { $gte: new Date(Date.now() - 7 * 24 * 3600 * 1000) } })
                .catch(() => 0)
        ]);

        // Estadísticas de áreas
        const porArea = await db.collection('usuarios').aggregate([
            { $match: { area: { $ne: null } } },
            { $group: { _id: '$area', count: { $sum: 1 } } }
        ]).toArray();

        res.json({
            resumen: {
                totalUsuarios,
                usuariosActivos,
                formSubmissionsUltima7Dias: formSubmissions,
            },
            porRol: registrosPorRol.reduce((acc, r) => {
                acc[normalizarRol(r._id)] = (acc[normalizarRol(r._id)] || 0) + r.count;
                return acc;
            }, {}),
            porArea: porArea.reduce((acc, r) => { acc[r._id] = r.count; return acc; }, {}),
            ultimosLogins,
        });
    } catch (error) {
        console.error('Error en stats:', error);
        res.status(500).json({ error: 'Error obteniendo estadísticas' });
    }
});

// ── ADMIN — Logs de acceso ─────────────────────────────────
app.get('/api/admin/access-logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 500);
        const page  = Math.max(parseInt(req.query.page) || 1, 1);
        const skip  = (page - 1) * limit;

        const filter = {};
        if (req.query.username) filter.username = req.query.username;
        if (req.query.action)   filter.action   = req.query.action;

        const [logs, total] = await Promise.all([
            db.collection('access_logs').find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
            db.collection('access_logs').countDocuments(filter)
        ]);

        res.json({ logs, total, page, totalPages: Math.ceil(total / limit) });
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo logs' });
    }
});

// ── ADMIN — Gestión de permisos de usuario ─────────────────
// Permite al ADMIN asignar permisos extra o revocar permisos del rol base
// Esto es el mecanismo para GERENTE_COMERCIAL / EJECUTIVO_COMERCIAL
app.patch('/api/admin/permissions/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const { permisosExtra, permisosRevocados } = req.body;

        if (!Array.isArray(permisosExtra) || !Array.isArray(permisosRevocados)) {
            return res.status(400).json({ error: 'permisosExtra y permisosRevocados deben ser arrays' });
        }

        const invalidosExtra   = permisosExtra.filter(p => !MODULOS_PERMISOS.includes(p));
        const invalidosRevocados = permisosRevocados.filter(p => !MODULOS_PERMISOS.includes(p));
        if (invalidosExtra.length > 0) return res.status(400).json({ error: `Permisos extra inválidos: ${invalidosExtra.join(', ')}` });
        if (invalidosRevocados.length > 0) return res.status(400).json({ error: `Permisos revocados inválidos: ${invalidosRevocados.join(', ')}` });

        await db.collection('usuarios').updateOne(
            { username },
            { $set: { permisosExtra, permisosRevocados, updatedAt: new Date(), updatedBy: req.user.username } }
        );

        await logAccess(req.user.username, 'PERMISSIONS_UPDATED', { targetUser: username });
        res.json({ success: true, message: `Permisos actualizados para ${username}` });
    } catch (error) {
        res.status(500).json({ error: 'Error actualizando permisos' });
    }
});

// GET permisos actuales de un usuario
app.get('/api/admin/permissions/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        const usuario = await db.collection('usuarios').findOne(
            { username },
            { projection: { rol: 1, area: 1, permisosExtra: 1, permisosRevocados: 1 } }
        );
        if (!usuario) return res.status(404).json({ error: 'Usuario no encontrado' });

        const rolNorm = normalizarRol(usuario.rol);
        const base    = ROL_PERMISOS_DEFAULT[rolNorm] || [];

        res.json({
            username,
            rol:               rolNorm,
            area:              usuario.area || null,
            permisosBase:      base,
            permisosExtra:     usuario.permisosExtra || [],
            permisosRevocados: usuario.permisosRevocados || [],
            permisosEfectivos: calcularPermisos(usuario),
            modulosDisponibles: MODULOS_PERMISOS,
        });
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo permisos' });
    }
});

// ── ADMIN — Form submissions ────────────────────────────────
app.get('/api/admin/form-submissions', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit) || 50, 500);
        const submissions = await db.collection('form_submissions')
            .find({})
            .sort({ createdAt: -1 })
            .limit(limit)
            .toArray();
        res.json(submissions);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo formularios' });
    }
});

// ── NOTIFICACIONES ─────────────────────────────────────────
app.get('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const { username } = req.user;
        const notifs = await db.collection('notificaciones')
            .find({ $or: [{ username }, { username: 'all' }] })
            .sort({ createdAt: -1 })
            .limit(30)
            .toArray();
        res.json(notifs);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo notificaciones' });
    }
});

app.patch('/api/notificaciones/:id/leer', requireAuth, async (req, res) => {
    try {
        await db.collection('notificaciones').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { leida: true } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error marcando notificación' });
    }
});

// ── RH MOVIMIENTOS ─────────────────────────────────────────
app.get('/api/rh/movimientos', requireAuth, requirePermiso('rh.movimientos.ver'), async (req, res) => {
    try {
        const query = {};
        if (req.query.tipo) query.tipo = req.query.tipo;
        const movimientos = await db.collection('rh_movimientos')
            .find(query).sort({ createdAt: -1 }).limit(200).toArray();
        res.json(movimientos);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo movimientos RH' });
    }
});

app.post('/api/rh/movimientos', requireAuth, requirePermiso('rh.movimientos.crear'), async (req, res) => {
    try {
        const movimiento = {
            ...req.body,
            creadoPor:  req.user.username,
            createdAt:  new Date(),
            estado:     'pendiente',
        };
        await db.collection('rh_movimientos').insertOne(movimiento);
        res.status(201).json({ success: true, movimiento });
    } catch (error) {
        res.status(500).json({ error: 'Error creando movimiento RH' });
    }
});

app.patch('/api/rh/movimientos/:id/estado', requireAuth, requirePermiso('rh.movimientos.gestionar'), async (req, res) => {
    try {
        const { estado, comentario } = req.body;
        await db.collection('rh_movimientos').updateOne(
            { _id: new ObjectId(req.params.id) },
            { $set: { estado, comentario, updatedAt: new Date(), updatedBy: req.user.username } }
        );
        res.json({ success: true });
    } catch (error) {
        res.status(500).json({ error: 'Error actualizando movimiento RH' });
    }
});

// ── ACTIVOS MOVIMIENTOS ────────────────────────────────────
app.get('/api/activos/movimientos', requireAuth, requirePermiso('activos.ver'), async (req, res) => {
    try {
        const movimientos = await db.collection('activos_movimientos')
            .find({}).sort({ createdAt: -1 }).limit(500).toArray();
        res.json(movimientos);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo activos' });
    }
});

app.post('/api/activos/movimientos', requireAuth, requirePermiso('activos.registrar'), async (req, res) => {
    try {
        const movimiento = {
            ...req.body,
            creadoPor:  req.user.username,
            createdAt:  new Date(),
        };
        await db.collection('activos_movimientos').insertOne(movimiento);
        res.status(201).json({ success: true, movimiento });
    } catch (error) {
        res.status(500).json({ error: 'Error registrando activo' });
    }
});

// ── DISPOSITIVOS ────────────────────────────────────────────
app.get('/api/devices', requireAuth, requirePermiso('dashboard.dispositivos'), async (req, res) => {
    try {
        const devices = await db.collection('dispositivos').find({}).toArray();
        res.json(devices);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo dispositivos' });
    }
});

// ── FORMATOS (ACTIVACIÓN) ──────────────────────────────────
app.get('/api/formatos/sistemas', requireAuth, requirePermiso('formatos.generar'), async (req, res) => {
    try {
        const sistemas = await db.collection('formatos_sistemas').find({ activo: true }).toArray();
        res.json(sistemas);
    } catch (error) {
        res.status(500).json({ error: 'Error obteniendo sistemas' });
    }
});

// ── 404 Handler ────────────────────────────────────────────
app.use('*', (req, res) => {
    res.status(404).json({ error: `Endpoint no encontrado: ${req.originalUrl}` });
});

// ── Error Handler ──────────────────────────────────────────
app.use((err, req, res, next) => {
    console.error('Error no manejado:', err);
    res.status(500).json({ error: 'Error interno del servidor' });
});

// ── Inicialización ─────────────────────────────────────────
async function start() {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`🚀 MYG API v4.0.0 corriendo en puerto ${PORT}`);
            console.log(`📋 Roles disponibles: ${ROLES_VALIDOS.join(', ')}`);
        });
    } catch (err) {
        console.error('❌ Error iniciando servidor:', err);
        process.exit(1);
    }
}

start();
