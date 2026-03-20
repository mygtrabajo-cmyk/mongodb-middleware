// ============================================================
// MYG TELECOM — API SERVER v4.3.1
// Render (Node.js) + MongoDB Atlas
//
// Cambios v4.3.1 (sobre v4.3.0):
// ─── FIXES IA MINUTAS ────────────────────────────────────────
// [FIX-S1] buildMinutaPrompt: prompt profesional detallado con contexto
//          MYG Telecom, instrucciones campo-por-campo y JSON estricto.
// [FIX-S2] Eliminado gate transcript < 30 chars que bloqueaba Groq/Gemini.
//          Ahora SIEMPRE se intenta IA, sin importar longitud del transcript.
// [FIX-S3] generarConGroq reescrito con fetch REST directo a api.groq.com
//          (sin depender del SDK groq-sdk instalado en producción).
//          Timeout de 22s propio para no exceder el límite de Cloudflare Worker.
// [FIX-S4] generarConGemini con timeout 22s y fallback limpio.
// [FIX-S5] generarConReglasLocales: acciones sin punto doble, mejor extracción.
// [FIX-S6] Endpoint generar-minuta: responde _proveedor y _ms al cliente.
// ─── Sin cambios en el resto del servidor ────────────────────
//
// Cambios v4.3.0 (sobre v4.2.0):
// - Hub Area Scoping: tareas, minutas, anuncios, recursos,
//   guías y plantillas aislados por área
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

// IA Minutas — SDK opcional (fallback a REST si no están instalados)
let GoogleGenerativeAI;
try { ({ GoogleGenerativeAI } = require('@google/generative-ai')); } catch (_) { console.warn('⚠️  @google/generative-ai no instalado — Gemini usará REST'); }

const app  = express();
const PORT = process.env.PORT || 5500;

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

const loginLimiter = rateLimit({ windowMs: 15*60*1000, max: 10, message: { error: 'Demasiados intentos. Espera 15 minutos.' } });
const apiLimiter   = rateLimit({ windowMs: 1*60*1000,  max: 200, message: { error: 'Demasiadas peticiones.' } });
app.use('/api/', apiLimiter);

let db;
const MONGO_URI = process.env.MONGODB_URI || 'mongodb+srv://...';
const DB_NAME   = 'iqu_telecom';

async function connectDB() {
    const client = new MongoClient(MONGO_URI, { serverSelectionTimeoutMS: 10000, socketTimeoutMS: 45000 });
    await client.connect();
    db = client.db(DB_NAME);
    console.log(`MongoDB conectado: ${DB_NAME}`);

    const idx = async (col, spec, opts={}) => {
        try {
            await db.collection(col).createIndex(spec, opts);
        } catch(e) {
            console.warn(`Indice ${col}: ${e.message?.split('\n')[0]}`);
        }
    };

    await idx('users',          { username: 1 },             { unique: true, name: 'username_unique' });
    await idx('access_logs',    { timestamp: 1 },            { expireAfterSeconds: 30*24*3600, name: 'ttl_30d' });
    await idx('notificaciones', { username: 1, leida: 1 },        { name: 'notif_username_leida' });
    await idx('notificaciones', { usuario_destino: 1, leida: 1 }, { name: 'notif_destino_leida' });
    await idx('hub_asistencia', { username: 1, fecha: 1 },   { name: 'asistencia_user_fecha' });
    await idx('hub_asistencia', { fecha: 1 },                { name: 'asistencia_fecha' });
    await idx('hub_asistencia', { area: 1, fecha: 1 },       { name: 'asistencia_area_fecha' });
    await idx('hub_mensajes',   { canal: 1, createdAt: -1 }, { name: 'mensajes_canal_fecha' });
    await idx('hub_tareas',     { area: 1, createdAt: -1 }, { name: 'tareas_area_fecha'     });
    await idx('hub_minutas',    { area: 1, createdAt: -1 }, { name: 'minutas_area_fecha'    });
    await idx('hub_anuncios',   { area: 1, createdAt: -1 }, { name: 'anuncios_area_fecha'   });
    await idx('hub_recursos',   { area: 1, createdAt: -1 }, { name: 'recursos_area_fecha'   });
    await idx('hub_guias',      { area: 1, createdAt: -1 }, { name: 'guias_area_fecha'      });
    await idx('hub_plantillas', { area: 1, createdAt: -1 }, { name: 'plantillas_area_fecha' });

    return client;
}

const ROLES_VALIDOS  = ['ADMIN','GERENTE_OPERACIONES','COORDINADOR','ANALISTA','GERENTE_COMERCIAL','EJECUTIVO_COMERCIAL','GERENTE_RH','ANALISTA_RH','USUARIO'];
const AREAS_VALIDAS  = ['Sistemas','Mantenimiento','Credito','Logistica'];
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
    'hub.concentrado.ver',
    'hub.concentrado.editar',
    'hub.peticiones.crear','hub.peticiones.aprobar',
    'hub.peticiones.ver_todas','formatos.generar',
    'rh.movimientos.crear','rh.movimientos.ver','rh.movimientos.gestionar',
    'activos.ver','activos.registrar','exportar_datos',
    'chatbot.usar','admin.panel','admin.usuarios','admin.permisos','admin.logs','admin.formularios',
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
        'exportar_datos','chatbot.usar',
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
    username:     Joi.string().min(3).max(50).required(),
    password:     Joi.string().min(6).required(),
    nombre:       Joi.string().min(2).max(100).required(),
    email:        Joi.string().email().optional().allow(''),
    rol:          Joi.string().valid(...ROLES_VALIDOS).required(),
    area:         Joi.string().valid(...AREAS_VALIDAS).when('rol', {
                      is: Joi.valid(...ROLES_CON_AREA), then: Joi.required(), otherwise: Joi.optional().allow(null,'')
                  }),
    rolSecundario: Joi.string().valid(...ROLES_VALIDOS).optional().allow(null,''),
    activo:       Joi.boolean().default(true),
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

// ── Auth middleware ────────────────────────────────────────────
function requireAuth(req, res, next) {
    try {
        const header = req.headers.authorization;
        if (!header?.startsWith('Bearer '))
            return res.status(401).json({ error: 'Token no proporcionado' });
        const token = header.slice(7);
        const payload = jwt.verify(token, process.env.JWT_SECRET);
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
        await db.collection('access_logs').insertOne({ username, action, details, timestamp: new Date(), ip: details.ip || 'unknown' });
    } catch (err) { console.error('Error logging:', err.message); }
}

// ── HEALTH ─────────────────────────────────────────────────────
app.get('/health', (req, res) => res.json({
    status: 'ok',
    version: '4.3.1',
    timestamp: new Date().toISOString(),
    db: db ? 'connected' : 'disconnected',
    ia: {
        groq:   !!process.env.GROQ_API_KEY,
        gemini: !!process.env.GEMINI_API_KEY,
    }
}));

// ── LOGIN ──────────────────────────────────────────────────────
app.post('/api/auth/login', loginLimiter, async (req, res) => {
    try {
        const { username, password } = req.body;
        if (!username || !password)
            return res.status(400).json({ error: 'Usuario y contrasena requeridos' });
        const usuarioDoc = await db.collection('users').findOne({ username: username.toLowerCase().trim() });
        if (!usuarioDoc) { await logAccess(username,'LOGIN_FAILED',{reason:'user_not_found',ip:req.ip}); return res.status(401).json({ error: 'Credenciales invalidas' }); }
        if (!usuarioDoc.activo) { await logAccess(username,'LOGIN_BLOCKED',{reason:'account_disabled',ip:req.ip}); return res.status(401).json({ error: 'Cuenta desactivada.' }); }
        const validPassword = await bcrypt.compare(password, usuarioDoc.password);
        if (!validPassword) { await logAccess(username,'LOGIN_FAILED',{reason:'wrong_password',ip:req.ip}); return res.status(401).json({ error: 'Credenciales invalidas' }); }
        const rolNormalizado = normalizarRol(usuarioDoc.rol);
        const permisos = calcularPermisos({ ...usuarioDoc, rol: rolNormalizado });
        const tokenPayload = {
            username: usuarioDoc.username, nombre: usuarioDoc.nombre, email: usuarioDoc.email||'',
            rol: rolNormalizado, area: usuarioDoc.area||null, rolSecundario: usuarioDoc.rolSecundario||null,
            permisos, preferencias: usuarioDoc.preferencias||{},
        };
        const token = jwt.sign(tokenPayload, process.env.JWT_SECRET, { expiresIn: '8h' });
        await db.collection('users').updateOne({ username: usuarioDoc.username }, { $set: { ultimoLogin: new Date(), rol: rolNormalizado } });
        await logAccess(usuarioDoc.username,'LOGIN_SUCCESS',{ip:req.ip,rol:rolNormalizado});
        res.json({ success: true, token, user: { ...tokenPayload } });
    } catch (error) { console.error('Error en login:', error); res.status(500).json({ error: 'Error interno' }); }
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
            username: value.username.toLowerCase().trim(), password: await bcrypt.hash(value.password, 12),
            nombre: value.nombre.trim(), email: value.email||'', rol: value.rol, area: value.area||null,
            rolSecundario: value.rolSecundario||null, activo: value.activo!==false,
            permisosExtra: [], permisosRevocados: [], preferencias: { tabsPinned: [] },
            createdAt: new Date(), createdBy: req.usuario.username,
        };
        await db.collection('users').insertOne(nuevoUsuario);
        await logAccess(req.usuario.username,'USER_CREATED',{targetUser:nuevoUsuario.username});
        const { password: _, ...sinPassword } = nuevoUsuario;
        res.status(201).json({ success: true, user: sinPassword });
    } catch (e) { console.error('Error creando usuario:', e); res.status(500).json({ error: 'Error creando usuario' }); }
});

app.put('/api/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin' && req.body.rol && req.body.rol !== 'ADMIN')
            return res.status(403).json({ error: 'No se puede cambiar el rol del administrador principal' });
        const { error, value } = schemaActualizarUsuario.validate(req.body);
        if (error) return res.status(400).json({ error: error.details[0].message });
        const updates = { updatedAt: new Date(), updatedBy: req.usuario.username };
        if (value.nombre)            updates.nombre        = value.nombre.trim();
        if (value.email !== undefined) updates.email       = value.email||'';
        if (value.rol)               updates.rol           = value.rol;
        if (value.area !== undefined) updates.area         = value.area||null;
        if (value.rolSecundario !== undefined) updates.rolSecundario = value.rolSecundario||null;
        if (value.activo !== undefined) updates.activo     = value.activo;
        if (value.permisosExtra)     updates.permisosExtra = value.permisosExtra;
        if (value.permisosRevocados) updates.permisosRevocados = value.permisosRevocados;
        if (value.password)          updates.password      = await bcrypt.hash(value.password, 12);
        const result = await db.collection('users').updateOne({ username }, { $set: updates });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        await logAccess(req.usuario.username,'USER_UPDATED',{targetUser:username,changes:Object.keys(updates)});
        res.json({ success: true, message: 'Usuario actualizado' });
    } catch (e) { console.error('Error actualizando usuario:', e); res.status(500).json({ error: 'Error actualizando usuario' }); }
});

app.delete('/api/users/:username', requireAuth, requireAdmin, async (req, res) => {
    try {
        const { username } = req.params;
        if (username === 'admin') return res.status(403).json({ error: 'No se puede eliminar el admin principal' });
        if (username === req.usuario.username) return res.status(403).json({ error: 'No puedes eliminarte a ti mismo' });
        const result = await db.collection('users').deleteOne({ username });
        if (result.deletedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        await logAccess(req.usuario.username,'USER_DELETED',{targetUser:username});
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
        if (value.nombre)              updates.nombre   = value.nombre.trim();
        if (value.email !== undefined) updates.email    = value.email||'';
        if (value.avatar !== undefined) updates.avatar  = value.avatar;
        if (value.preferencias?.tabsPinned !== undefined) updates['preferencias.tabsPinned'] = value.preferencias.tabsPinned;
        const result = await db.collection('users').updateOne({ username }, { $set: updates });
        if (result.matchedCount === 0) return res.status(404).json({ error: 'Usuario no encontrado' });
        const actualizado = await db.collection('users').findOne({ username }, { projection: { password: 0 } });
        res.json({ success: true, message: 'Perfil actualizado', preferencias: actualizado.preferencias||{} });
    } catch (e) { console.error('Error perfil:', e); res.status(500).json({ error: 'Error actualizando perfil' }); }
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
        await db.collection('users').updateOne({ username }, { $set: { password: await bcrypt.hash(value.passwordNueva, 12), passwordChangedAt: new Date() } });
        await logAccess(req.usuario.username,'PASSWORD_CHANGED',{targetUser:username});
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
            db.collection('form_submissions').countDocuments({ createdAt: { $gte: new Date(Date.now()-7*24*3600*1000) } }).catch(()=>0)
        ]);
        const porArea = await db.collection('users').aggregate([{ $match: { area: { $ne: null } } }, { $group: { _id: '$area', count: { $sum: 1 } } }]).toArray();
        res.json({
            resumen: { totalUsuarios, usuariosActivos, formSubmissionsUltima7Dias: formSubmissions },
            porRol:  registrosPorRol.reduce((acc, r) => { acc[normalizarRol(r._id)] = (acc[normalizarRol(r._id)]||0) + r.count; return acc; }, {}),
            porArea: porArea.reduce((acc, r) => { acc[r._id] = r.count; return acc; }, {}),
            ultimosLogins,
        });
    } catch (e) { console.error('Error stats:', e); res.status(500).json({ error: 'Error obteniendo estadisticas' }); }
});

app.get('/api/admin/access-logs', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit)||50, 500);
        const page  = Math.max(parseInt(req.query.page)||1, 1);
        const skip  = (page-1)*limit;
        const filter = {};
        if (req.query.username) filter.username = req.query.username;
        if (req.query.action)   filter.action   = req.query.action;
        const [logs, total] = await Promise.all([
            db.collection('access_logs').find(filter).sort({ timestamp: -1 }).skip(skip).limit(limit).toArray(),
            db.collection('access_logs').countDocuments(filter)
        ]);
        res.json({ logs, total, page, totalPages: Math.ceil(total/limit) });
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
        await db.collection('users').updateOne({ username }, { $set: { permisosExtra, permisosRevocados, updatedAt: new Date(), updatedBy: req.usuario.username } });
        await logAccess(req.usuario.username,'PERMISSIONS_UPDATED',{targetUser:username});
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
            username, rol: rolNorm, area: usuario.area||null,
            permisosBase:       base,
            permisosExtra:      usuario.permisosExtra||[],
            permisosRevocados:  usuario.permisosRevocados||[],
            permisosEfectivos:  calcularPermisos(usuario),
            modulosDisponibles: MODULOS_PERMISOS,
        });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo permisos' }); }
});

app.get('/api/admin/permissions/roles', requireAuth, requireAdmin, async (req, res) => {
    res.json({ roles: ROLES_VALIDOS, areasValidas: AREAS_VALIDAS, rolesConArea: ROLES_CON_AREA, modulosDisponibles: MODULOS_PERMISOS, permisosDefault: ROL_PERMISOS_DEFAULT });
});

app.get('/api/admin/form-submissions', requireAuth, requireAdmin, async (req, res) => {
    try {
        const limit = Math.min(parseInt(req.query.limit)||50, 500);
        const submissions = await db.collection('form_submissions').find({}).sort({ createdAt: -1 }).limit(limit).toArray();
        res.json(submissions);
    } catch (e) { res.status(500).json({ error: 'Error obteniendo formularios' }); }
});

// ── NOTIFICACIONES SSE ──────────────────────────────────────────
const sseClients = new Map();
function sseAdd(username, res) { if (!sseClients.has(username)) sseClients.set(username, new Set()); sseClients.get(username).add(res); }
function sseRemove(username, res) { sseClients.get(username)?.delete(res); }
function ssePush(username, evento, datos) {
    const targets = new Set();
    if (username === '*') { sseClients.forEach(set => set.forEach(r => targets.add(r))); }
    else { sseClients.get(username)?.forEach(r => targets.add(r)); sseClients.get('*')?.forEach(r => targets.add(r)); }
    const payload = `event: notificacion\ndata: ${JSON.stringify({ ...datos, _ts: Date.now() })}\n\n`;
    targets.forEach(r => { try { r.write(payload); } catch { } });
}

app.get('/api/notificaciones/sse', requireAuth, (req, res) => {
    res.setHeader('Content-Type','text/event-stream');
    res.setHeader('Cache-Control','no-cache');
    res.setHeader('Connection','keep-alive');
    res.setHeader('X-Accel-Buffering','no');
    res.flushHeaders();
    const username = req.usuario.username;
    sseAdd(username, res);
    res.write(`event: connected\ndata: ${JSON.stringify({ status:'ok', username })}\n\n`);
    const heartbeat = setInterval(() => { try { res.write(': heartbeat\n\n'); } catch { clearInterval(heartbeat); } }, 25000);
    req.on('close', () => { clearInterval(heartbeat); sseRemove(username, res); });
});

app.get('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const { username } = req.usuario;
        const notifs = await db.collection('notificaciones').find({ $or: [{ username }, { usuario_destino: username }, { usuario_destino: '*' }] }).sort({ createdAt: -1 }).limit(50).toArray();
        res.json({ notificaciones: notifs, total_no_leidas: notifs.filter(n => !n.leida).length });
    } catch (e) { res.status(500).json({ error: 'Error obteniendo notificaciones' }); }
});

app.post('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const { titulo, mensaje, tipo='info', icono, tab_destino, subtab, usuario_destino } = req.body;
        if (!titulo || !mensaje) return res.status(400).json({ error: 'titulo y mensaje requeridos' });
        const notif = { titulo, mensaje, tipo, icono:icono||null, tab_destino:tab_destino||null, subtab:subtab||null, usuario_destino:usuario_destino||req.usuario.username, creadaPor:req.usuario.username, leida:false, createdAt:new Date() };
        const result = await db.collection('notificaciones').insertOne(notif);
        notif._id = result.insertedId;
        ssePush(notif.usuario_destino,'notificacion',notif);
        res.status(201).json({ success: true, notificacion: notif });
    } catch (e) { res.status(500).json({ error: 'Error creando notificacion' }); }
});

app.patch('/api/notificaciones/leer-todas', requireAuth, async (req, res) => {
    try {
        await db.collection('notificaciones').updateMany({ $or:[{username:req.usuario.username},{usuario_destino:req.usuario.username}], leida:false }, { $set:{leida:true,leidaEn:new Date()} });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error marcando notificaciones' }); }
});

app.patch('/api/notificaciones/:id/leer', requireAuth, async (req, res) => {
    try {
        await db.collection('notificaciones').updateOne({ _id: new ObjectId(req.params.id) }, { $set:{leida:true,leidaEn:new Date()} });
        res.json({ success: true });
    } catch (e) { res.status(500).json({ error: 'Error marcando notificacion' }); }
});

app.delete('/api/notificaciones', requireAuth, async (req, res) => {
    try {
        const result = await db.collection('notificaciones').deleteMany({ $or:[{username:req.usuario.username},{usuario_destino:req.usuario.username}], leida:true });
        res.json({ success: true, eliminadas: result.deletedCount });
    } catch (e) { res.status(500).json({ error: 'Error eliminando notificaciones' }); }
});

// ── RH / ACTIVOS / FORMATOS / CHAT ──────────────────────────────
app.get('/api/rh/movimientos',         requireAuth, requirePermiso('rh.movimientos.ver'),      async (req, res) => { try { const q={}; if(req.query.tipo) q.tipo=req.query.tipo; res.json(await db.collection('rh_movimientos').find(q).sort({createdAt:-1}).limit(200).toArray()); } catch(e){res.status(500).json({error:'Error RH'})} });
app.post('/api/rh/movimientos',        requireAuth, requirePermiso('rh.movimientos.crear'),    async (req, res) => { try { const m={...req.body,creadoPor:req.usuario.username,createdAt:new Date(),estado:'pendiente'}; await db.collection('rh_movimientos').insertOne(m); res.status(201).json({success:true,movimiento:m}); } catch(e){res.status(500).json({error:'Error RH'})} });
app.put('/api/rh/movimientos/:id',     requireAuth, requirePermiso('rh.movimientos.gestionar'),async (req, res) => { try { const r=await db.collection('rh_movimientos').updateOne({_id:new ObjectId(req.params.id)},{$set:{...req.body,updatedAt:new Date(),updatedBy:req.usuario.username}}); if(!r.matchedCount) return res.status(404).json({error:'No encontrado'}); res.json({success:true}); } catch(e){res.status(500).json({error:'Error RH'})} });
app.patch('/api/rh/movimientos/:id/estado', requireAuth, requirePermiso('rh.movimientos.gestionar'), async (req, res) => { try { const {estado,comentario}=req.body; await db.collection('rh_movimientos').updateOne({_id:new ObjectId(req.params.id)},{$set:{estado,comentario,updatedAt:new Date(),updatedBy:req.usuario.username}}); res.json({success:true}); } catch(e){res.status(500).json({error:'Error RH'})} });
app.get('/api/activos/movimientos',    requireAuth, requirePermiso('activos.ver'),             async (req, res) => { try { res.json(await db.collection('activos_movimientos').find({}).sort({createdAt:-1}).limit(500).toArray()); } catch(e){res.status(500).json({error:'Error activos'})} });
app.post('/api/activos/movimientos',   requireAuth, requirePermiso('activos.registrar'),       async (req, res) => { try { const m={...req.body,creadoPor:req.usuario.username,createdAt:new Date()}; await db.collection('activos_movimientos').insertOne(m); res.status(201).json({success:true,movimiento:m}); } catch(e){res.status(500).json({error:'Error activos'})} });
app.get('/api/devices',                requireAuth, requirePermiso('dashboard.dispositivos'),  async (req, res) => { try { res.json(await db.collection('dispositivos').find({}).toArray()); } catch(e){res.status(500).json({error:'Error dispositivos'})} });
app.get('/api/formatos/sistemas',      requireAuth, requirePermiso('formatos.generar'),        async (req, res) => { try { res.json(await db.collection('formatos_sistemas').find({activo:true}).toArray()); } catch(e){res.status(500).json({error:'Error formatos'})} });
app.post('/api/formatos/generar',      requireAuth, requirePermiso('formatos.generar'),        async (req, res) => { try { const {sistema,userData}=req.body; if(!sistema) return res.status(400).json({error:'Sistema requerido'}); const s=await db.collection('formatos_sistemas').findOne({nombre:sistema,activo:true}); if(!s) return res.status(404).json({error:`Sistema '${sistema}' no encontrado`}); await db.collection('formatos_log').insertOne({sistema,userData,solicitadoPor:req.usuario.username,createdAt:new Date(),estado:'generado'}); res.json({success:true,sistema:s,userData}); } catch(e){res.status(500).json({error:'Error formato'})} });
app.post('/api/formatos/clear-cache',  requireAuth, requirePermiso('formatos.generar'),        (req, res) => res.json({ success: true, message: 'Cache limpiada' }));

app.post('/api/chat', requireAuth, requirePermiso('chatbot.usar'), async (req, res) => {
    try {
        const { messages, system, max_tokens=1000, temperature=0.7 } = req.body;
        if (!messages || !Array.isArray(messages) || !messages.length)
            return res.status(400).json({ error: 'messages[] requerido' });
        db.collection('chat_logs').insertOne({ username:req.usuario.username, messages:messages.slice(-3), createdAt:new Date() }).catch(()=>{});
        const anthropicKey = process.env.ANTHROPIC_API_KEY;
        if (anthropicKey) {
            try {
                const r = await fetch('https://api.anthropic.com/v1/messages', {
                    method:'POST',
                    headers:{'Content-Type':'application/json','x-api-key':anthropicKey,'anthropic-version':'2023-06-01'},
                    body: JSON.stringify({ model:'claude-3-haiku-20240307', max_tokens, system: system||'Eres un asistente del dashboard MYG Telecom. Responde en español conciso.', messages:messages.map(m=>({role:m.role,content:m.content})) }),
                });
                if (r.ok) { const data = await r.json(); return res.json({ ...data, _provider:'anthropic' }); }
            } catch(aiErr) { console.error('Anthropic error:', aiErr.message); }
        }
        res.status(503).json({ error: 'IA no configurada. Configura ANTHROPIC_API_KEY.' });
    } catch (e) { res.status(500).json({ error: 'Error en chat' }); }
});

// ================================================================
// HUB — Helpers CRUD genéricos v4.3
// ================================================================
const COLECCIONES_CON_AREA = new Set([
    'hub_tareas','hub_minutas','hub_anuncios','hub_recursos','hub_guias','hub_plantillas',
]);

function hubGet(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const limit  = Math.min(parseInt(req.query.limit)||100, 500);
            const filter = {};
            if (req.query.username) filter.username = req.query.username;
            if (req.query.mes)      filter.mes      = req.query.mes;
            if (req.query.estado)   filter.estado   = req.query.estado;
            if (COLECCIONES_CON_AREA.has(col) && req.query.area) {
                const area = req.query.area;
                if (area === 'Sistemas') {
                    filter.$or = [{ area: 'Sistemas' }, { area: { $exists: false } }, { area: null }];
                } else {
                    filter.area = area;
                }
            }
            res.json(await db.collection(col).find(filter).sort({ createdAt:-1 }).limit(limit).toArray());
        } catch (e) { res.status(500).json({ error: `Error ${col}` }); }
    }];
}

function hubPost(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const areaDefault = COLECCIONES_CON_AREA.has(col) && !req.body.area ? 'Sistemas' : undefined;
            const doc = {
                ...req.body,
                ...(areaDefault !== undefined && { area: areaDefault }),
                creadoPor: req.usuario.username,
                createdAt: new Date(),
            };
            const result = await db.collection(col).insertOne(doc);
            res.status(201).json({ success:true, id:result.insertedId, doc });
        } catch (e) { res.status(500).json({ error: `Error ${col}` }); }
    }];
}

function hubPatch(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            const result = await db.collection(col).updateOne(
                { _id: new ObjectId(req.params.id) },
                { $set: { ...req.body, updatedAt: new Date(), updatedBy: req.usuario.username } }
            );
            if (!result.matchedCount) return res.status(404).json({ error: 'No encontrado' });
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: `Error ${col}` }); }
    }];
}

function hubDelete(col, perm) {
    return [requireAuth, requirePermiso(perm), async (req, res) => {
        try {
            await db.collection(col).deleteOne({ _id: new ObjectId(req.params.id) });
            res.json({ success: true });
        } catch (e) { res.status(500).json({ error: `Error ${col}` }); }
    }];
}

// ── Hub general ────────────────────────────────────────────────
app.get('/api/hub/general', requireAuth, requirePermiso('hub.acceso'), async (req, res) => {
    try {
        const [reuniones,tareas,minutas,anuncios,recursos,guias,plantillas,capacitacion] = await Promise.all([
            db.collection('hub_reuniones').countDocuments(),
            db.collection('hub_tareas').countDocuments(),
            db.collection('hub_minutas').countDocuments(),
            db.collection('hub_anuncios').countDocuments(),
            db.collection('hub_recursos').countDocuments(),
            db.collection('hub_guias').countDocuments(),
            db.collection('hub_plantillas').countDocuments(),
            db.collection('hub_capacitacion').countDocuments(),
        ]);
        const anunciosRecientes = await db.collection('hub_anuncios').find({}).sort({ createdAt:-1 }).limit(100).toArray();
        res.json({ conteos:{reuniones,tareas,minutas,anuncios,recursos,guias,plantillas,capacitacion}, anunciosRecientes });
    } catch (e) { res.status(500).json({ error: 'Error hub general' }); }
});

// ── Reuniones ──────────────────────────────────────────────────
app.get('/api/hub/reuniones',        ...hubGet   ('hub_reuniones','hub.reuniones'));
app.post('/api/hub/reuniones',       ...hubPost  ('hub_reuniones','hub.reuniones'));
app.patch('/api/hub/reuniones/:id',  ...hubPatch ('hub_reuniones','hub.reuniones'));
app.delete('/api/hub/reuniones/:id', ...hubDelete('hub_reuniones','hub.reuniones'));

// ================================================================
// IA MINUTAS v4.3.1 — Groq REST + Gemini SDK + Local fallback
// ================================================================

// [FIX-S1] Prompt profesional detallado — contexto MYG Telecom + instrucciones por campo
const buildMinutaPrompt = ({ transcript, meetingTitle, meetingDate, meetingTime, attendees, agenda, duracion, notasAdicionales }) => {
    const durMin = Math.ceil((duracion || 0) / 60);
    const asistentes = Array.isArray(attendees) ? attendees.join(', ') : (attendees || 'No especificados');
    const hasTranscript = transcript && transcript.trim().length > 5;
    const transcriptText = hasTranscript ? transcript.trim() : '(Sin transcripción de voz — usar contexto de la agenda)';
    const notasText = notasAdicionales && notasAdicionales.trim() ? `\nNOTAS MANUALES DEL ORGANIZADOR: ${notasAdicionales.trim()}` : '';

    const systemPrompt = `Eres el asistente corporativo oficial de MYG Telecom, empresa de telecomunicaciones mexicana.
Tu especialidad es redactar minutas ejecutivas formales en español mexicano profesional para el área de Sistemas/IT.
REGLAS ABSOLUTAS:
1. Responde ÚNICAMENTE con JSON válido. Sin backticks, sin texto antes o después.
2. Todos los campos en español mexicano formal.
3. El campo "resumen" debe ser un párrafo ejecutivo de 3-5 oraciones que capture los temas principales.
4. El campo "decisions" debe listar solo decisiones concretas tomadas, como bullet points con "•".
5. El campo "acciones" debe ser un array de strings, cada uno con formato "Responsable: Acción concreta [Fecha límite si se mencionó]".
6. Si no hay información suficiente para un campo, escribe una cadena vacía "", NO inventes datos.
7. El campo "observaciones" es para notas adicionales, próximas reuniones, o contexto relevante.`;

    const userPrompt = `Genera la minuta ejecutiva formal para esta reunión de MYG Telecom:

DATOS DE LA REUNIÓN:
- Título: ${meetingTitle || 'Reunión de Sistemas MYG Telecom'}
- Fecha: ${meetingDate || 'No especificada'}${meetingTime ? ' a las ' + meetingTime : ''}
- Duración: ${durMin > 0 ? durMin + ' minutos' : 'No especificada'}
- Asistentes: ${asistentes}
- Agenda: ${agenda || 'No especificada'}${notasText}

TRANSCRIPCIÓN DE LA REUNIÓN:
${transcriptText}

Responde con este JSON exacto (sin backticks, sin texto adicional):
{
  "title": "Minuta: ${meetingTitle || 'Reunión de Sistemas'}",
  "resumen": "Párrafo ejecutivo de 3-5 oraciones sobre los temas tratados",
  "decisions": "• Primera decisión tomada\\n• Segunda decisión tomada",
  "acciones": ["Responsable: Acción concreta", "Responsable2: Otra acción"],
  "observaciones": "Observaciones adicionales, próxima reunión, etc."
}`;

    return { system: systemPrompt, user: userPrompt };
};

// [FIX-S3] Groq via REST directo — sin depender del SDK groq-sdk
const generarConGroq = async (pd) => {
    const apiKey = process.env.GROQ_API_KEY;
    if (!apiKey) throw new Error('GROQ_API_KEY no configurada');

    const p = buildMinutaPrompt(pd);
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 22000); // 22s timeout

    try {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: {
                'Content-Type':  'application/json',
                'Authorization': `Bearer ${apiKey}`,
            },
            signal: controller.signal,
            body: JSON.stringify({
                model:       'llama-3.3-70b-versatile',
                max_tokens:  1400,
                temperature: 0.25,
                messages: [
                    { role: 'system', content: p.system },
                    { role: 'user',   content: p.user   },
                ],
                response_format: { type: 'json_object' }, // fuerza JSON puro
            }),
        });

        clearTimeout(timeout);

        if (!response.ok) {
            const errBody = await response.text().catch(() => '');
            throw new Error(`Groq HTTP ${response.status}: ${errBody.slice(0, 200)}`);
        }

        const data = await response.json();
        const content = data.choices?.[0]?.message?.content || '';
        if (!content) throw new Error('Groq devolvió respuesta vacía');

        const parsed = JSON.parse(content.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim());
        if (!parsed || typeof parsed !== 'object') throw new Error('JSON inválido de Groq');
        return parsed;

    } finally {
        clearTimeout(timeout);
    }
};

// [FIX-S4] Gemini con timeout
const generarConGemini = async (pd) => {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) throw new Error('GEMINI_API_KEY no configurada');

    const p = buildMinutaPrompt(pd);

    // Path 1: SDK instalado
    if (GoogleGenerativeAI) {
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), 22000);
        try {
            const model = new GoogleGenerativeAI(apiKey).getGenerativeModel({
                model: 'gemini-2.0-flash',
                generationConfig: { temperature: 0.25, maxOutputTokens: 1400, responseMimeType: 'application/json' },
                systemInstruction: p.system,
            });
            const result = await model.generateContent(p.user);
            clearTimeout(timeout);
            const text = result.response.text().replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim();
            const parsed = JSON.parse(text);
            if (!parsed || typeof parsed !== 'object') throw new Error('JSON inválido de Gemini');
            return parsed;
        } finally {
            clearTimeout(timeout);
        }
    }

    // Path 2: REST directo si SDK no instalado
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 22000);
    try {
        const url = `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${apiKey}`;
        const response = await fetch(url, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            signal: controller.signal,
            body: JSON.stringify({
                contents: [{ parts: [{ text: p.user }] }],
                systemInstruction: { parts: [{ text: p.system }] },
                generationConfig: { temperature: 0.25, maxOutputTokens: 1400, responseMimeType: 'application/json' },
            }),
        });
        clearTimeout(timeout);
        if (!response.ok) throw new Error(`Gemini HTTP ${response.status}`);
        const data = await response.json();
        const text = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
        if (!text) throw new Error('Gemini devolvió respuesta vacía');
        return JSON.parse(text.replace(/```json\s*/gi, '').replace(/```\s*/gi, '').trim());
    } finally {
        clearTimeout(timeout);
    }
};

// [FIX-S5] Motor local mejorado — acciones sin punto doble
const generarConReglasLocales = (pd) => {
    const { transcript = '', meetingTitle = 'Reunión', meetingDate = '', meetingTime = '', attendees = [], agenda = '', duracion = 0, notasAdicionales = '' } = pd;
    const durMin = Math.ceil(duracion / 60);

    // Fuente de texto: transcript + notas
    const fuenteTexto = [transcript, notasAdicionales].filter(Boolean).join(' ').trim();
    const oraciones = fuenteTexto.split(/[.!?;]\s+/).map(s => s.trim()).filter(s => s.length > 15);

    const stopwords = new Set(['el','la','los','las','un','una','de','del','en','y','a','que','se','es','no','con','por','para','como','mas','pero','su','sus','al','lo','le','les']);
    const score = s => new Set(s.toLowerCase().split(/\s+/).filter(w => !stopwords.has(w) && w.length > 3)).size;

    const mejoresOraciones = oraciones
        .map(o => ({ text: o, score: score(o) }))
        .sort((a, b) => b.score - a.score)
        .slice(0, 5)
        .map(o => o.text + '.');

    // Decisiones: buscar patrones explícitos
    const decisiones = oraciones
        .filter(o => /\b(se decide|se acuerda|se aprueba|quedamos|acordamos|decidimos)\b/i.test(o))
        .slice(0, 5)
        .map(d => `• ${d.trim().replace(/\.$/, '')}.`);

    // Acciones: buscar compromisos — SIN añadir punto si ya termina en punto
    const acciones = oraciones
        .filter(o => /\b(pendiente|entregar|revisar|enviar|actualizar|verificar|contactar|coordinar|preparar|elaborar)\b/i.test(o))
        .slice(0, 6)
        .map(a => a.trim().replace(/\.$/, '')); // [FIX-S5] quitar punto antes de normalizeAcciones lo procese

    const agendaTexto = agenda ? `Agenda: ${agenda}.` : '';
    const resumenBase = mejoresOraciones.length > 0
        ? mejoresOraciones.join(' ')
        : `Reunión "${meetingTitle}" del ${meetingDate}${meetingTime ? ' a las ' + meetingTime : ''}. ${agendaTexto} Duración: ${durMin} min. Por favor complementa los detalles.`;

    return {
        title:        `Minuta: ${meetingTitle}`,
        resumen:      resumenBase,
        decisions:    decisiones.join('\n') || '',
        acciones,   // array de strings limpios
        observaciones: `Reunión de ${durMin > 0 ? durMin + ' min' : 'duración no registrada'} con ${Array.isArray(attendees) ? attendees.length : 0} asistente(s). ${notasAdicionales ? 'Notas: ' + notasAdicionales : ''}`.trim(),
    };
};

// ── Endpoint: Generar Minuta con IA ───────────────────────────
app.post('/api/hub/reuniones/:id/generar-minuta', requireAuth, requirePermiso('hub.reuniones'), async (req, res) => {
    try {
        const {
            transcript      = '',
            meetingTitle,
            meetingDate,
            meetingTime,
            attendees,
            agenda,
            duracion,
            notasAdicionales = '',  // [FIX-R1] nuevo campo
        } = req.body;

        const transcriptUtil = transcript.trim();
        const pd = { transcript: transcriptUtil, meetingTitle, meetingDate, meetingTime, attendees, agenda, duracion, notasAdicionales };

        // [FIX-S2] ELIMINADO el gate "if (length < 30) return local"
        // Ahora SIEMPRE intenta Groq → Gemini → local, sin importar longitud
        // Solo si realmente no hay NADA de texto Y no hay notas, se usa local directamente
        const sinContenido = !transcriptUtil && !notasAdicionales.trim() && !agenda;
        if (sinContenido) {
            console.log('[MinutaIA] Sin transcripción ni notas → motor local inmediato');
            const local = generarConReglasLocales(pd);
            return res.json({ ...local, _proveedor: 'local', _aviso: 'Sin transcripción. Completa los campos manualmente.' });
        }

        const forced = process.env.AI_PROVIDER;
        const cadena = [
            { nombre: 'groq',   fn: generarConGroq,                      activo: !forced || forced === 'groq',   tiene_key: !!process.env.GROQ_API_KEY   },
            { nombre: 'gemini', fn: generarConGemini,                     activo: !forced || forced === 'gemini', tiene_key: !!process.env.GEMINI_API_KEY  },
            { nombre: 'local',  fn: async d => generarConReglasLocales(d), activo: true,                          tiene_key: true                          },
        ];

        let resultado = null;
        let ultimoError = null;

        for (const proveedor of cadena) {
            if (!proveedor.activo || !proveedor.tiene_key) {
                console.log(`[MinutaIA] ${proveedor.nombre.toUpperCase()} omitido (activo=${proveedor.activo}, key=${proveedor.tiene_key})`);
                continue;
            }
            try {
                console.log(`[MinutaIA] Intentando ${proveedor.nombre.toUpperCase()}...`);
                const t0 = Date.now();
                resultado = await proveedor.fn(pd);
                const ms = Date.now() - t0;

                if (!resultado || typeof resultado !== 'object') throw new Error('Respuesta inválida del proveedor');

                // Validar que tenga al menos title o resumen
                if (!resultado.title && !resultado.resumen) throw new Error('Respuesta sin campos esperados');

                resultado._proveedor = proveedor.nombre;
                resultado._ms        = ms;
                console.log(`[MinutaIA] ✅ ${proveedor.nombre.toUpperCase()} respondió en ${ms}ms`);
                break;
            } catch (err) {
                console.warn(`[MinutaIA] ⚠️ ${proveedor.nombre.toUpperCase()} falló: ${err.message}`);
                ultimoError = err;
                // Rate limit → esperar antes del siguiente proveedor
                if (err.message?.includes('429') || err.message?.includes('rate_limit')) {
                    await new Promise(r => setTimeout(r, 2000));
                }
            }
        }

        if (!resultado) throw ultimoError || new Error('Todos los proveedores fallaron');

        // [FIX-S6] Incluir _proveedor en respuesta para que el frontend lo muestre
        const { _ms, ...respuesta } = resultado;
        console.log(`[MinutaIA] Respuesta final enviada (proveedor=${respuesta._proveedor}, ${_ms}ms, transcript=${transcriptUtil.length}chars)`);
        res.json(respuesta);

    } catch (err) {
        console.error('[MinutaIA] Error fatal:', err.message);
        res.status(500).json({ error: `Error generando minuta: ${err.message}` });
    }
});

// ── Tareas / Minutas / Anuncios / Recursos / Guías / Plantillas ─
app.get('/api/hub/tareas',           ...hubGet   ('hub_tareas',      'hub.tareas'));
app.post('/api/hub/tareas',          ...hubPost  ('hub_tareas',      'hub.tareas'));
app.patch('/api/hub/tareas/:id',     ...hubPatch ('hub_tareas',      'hub.tareas'));
app.delete('/api/hub/tareas/:id',    ...hubDelete('hub_tareas',      'hub.tareas'));

app.get('/api/hub/minutas',          ...hubGet   ('hub_minutas',     'hub.minutas'));
app.post('/api/hub/minutas',         ...hubPost  ('hub_minutas',     'hub.minutas'));
app.patch('/api/hub/minutas/:id',    ...hubPatch ('hub_minutas',     'hub.minutas'));
app.delete('/api/hub/minutas/:id',   ...hubDelete('hub_minutas',     'hub.minutas'));

app.get('/api/hub/anuncios',         ...hubGet   ('hub_anuncios',    'hub.anuncios'));
app.post('/api/hub/anuncios',        ...hubPost  ('hub_anuncios',    'hub.anuncios'));
app.patch('/api/hub/anuncios/:id',   ...hubPatch ('hub_anuncios',    'hub.anuncios'));
app.delete('/api/hub/anuncios/:id',  ...hubDelete('hub_anuncios',    'hub.anuncios'));

app.get('/api/hub/recursos',         ...hubGet   ('hub_recursos',    'hub.recursos'));
app.post('/api/hub/recursos',        ...hubPost  ('hub_recursos',    'hub.recursos'));
app.patch('/api/hub/recursos/:id',   ...hubPatch ('hub_recursos',    'hub.recursos'));
app.delete('/api/hub/recursos/:id',  ...hubDelete('hub_recursos',    'hub.recursos'));

app.get('/api/hub/guias',            ...hubGet   ('hub_guias',       'hub.guias'));
app.post('/api/hub/guias',           ...hubPost  ('hub_guias',       'hub.guias'));
app.patch('/api/hub/guias/:id',      ...hubPatch ('hub_guias',       'hub.guias'));
app.delete('/api/hub/guias/:id',     ...hubDelete('hub_guias',       'hub.guias'));

app.get('/api/hub/plantillas',       ...hubGet   ('hub_plantillas',  'hub.plantillas'));
app.post('/api/hub/plantillas',      ...hubPost  ('hub_plantillas',  'hub.plantillas'));
app.patch('/api/hub/plantillas/:id', ...hubPatch ('hub_plantillas',  'hub.plantillas'));
app.delete('/api/hub/plantillas/:id',...hubDelete('hub_plantillas',  'hub.plantillas'));

app.get('/api/hub/capacitacion',         ...hubGet   ('hub_capacitacion','hub.capacitacion'));
app.post('/api/hub/capacitacion',        ...hubPost  ('hub_capacitacion','hub.capacitacion'));
app.patch('/api/hub/capacitacion/:id',   ...hubPatch ('hub_capacitacion','hub.capacitacion'));
app.delete('/api/hub/capacitacion/:id',  ...hubDelete('hub_capacitacion','hub.capacitacion'));

// ── Minutas comentarios/acciones ───────────────────────────────
app.post('/api/hub/minutas/:minutaId/comentarios', requireAuth, requirePermiso('hub.minutas'), async (req, res) => {
    try {
        const comentario = { ...req.body, autor:req.usuario.username, createdAt:new Date() };
        await db.collection('hub_minutas').updateOne({ _id:new ObjectId(req.params.minutaId) }, { $push:{comentarios:comentario} });
        res.status(201).json({ success:true, comentario });
    } catch (e) { res.status(500).json({ error: 'Error comentario' }); }
});
app.patch('/api/hub/minutas/:minutaId/acciones/:itemId', requireAuth, requirePermiso('hub.minutas'), async (req, res) => {
    try {
        const fields = {}; Object.entries(req.body).forEach(([k,v])=>{fields[`acciones.$.${k}`]=v;}); fields['acciones.$.updatedAt']=new Date();
        await db.collection('hub_minutas').updateOne({ _id:new ObjectId(req.params.minutaId),'acciones._id':req.params.itemId }, { $set:fields });
        res.json({ success:true });
    } catch (e) { res.status(500).json({ error: 'Error accion' }); }
});

// ── Mensajes ───────────────────────────────────────────────────
app.get('/api/hub/mensajes/:canal', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { canal } = req.params;
        const limit = Math.min(parseInt(req.query.limit)||50, 200);
        const docs = await db.collection('hub_mensajes').find({ canal }).sort({ createdAt:-1 }).limit(limit).toArray();
        res.json({ mensajes: docs.reverse() });
    } catch (e) { res.status(500).json({ error: 'Error mensajes' }); }
});
app.post('/api/hub/mensajes/:canal', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const doc = { ...req.body, canal:req.params.canal, autor:req.usuario.username, autorNombre:req.usuario.nombre||req.usuario.username, reactions:[], createdAt:new Date() };
        const result = await db.collection('hub_mensajes').insertOne(doc);
        res.status(201).json({ success:true, id:result.insertedId, doc });
    } catch (e) { res.status(500).json({ error: 'Error mensaje' }); }
});
app.patch('/api/hub/mensajes/:id', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try { await db.collection('hub_mensajes').updateOne({ _id:new ObjectId(req.params.id) }, { $set:{...req.body,editadoEn:new Date()} }); res.json({success:true}); }
    catch (e) { res.status(500).json({ error: 'Error mensaje' }); }
});
app.delete('/api/hub/mensajes/:id', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try { await db.collection('hub_mensajes').deleteOne({ _id:new ObjectId(req.params.id) }); res.json({success:true}); }
    catch (e) { res.status(500).json({ error: 'Error mensaje' }); }
});
app.patch('/api/hub/mensajes/:id/reaction', requireAuth, requirePermiso('hub.mensajes'), async (req, res) => {
    try {
        const { emoji } = req.body; const username = req.usuario.username;
        const msg = await db.collection('hub_mensajes').findOne({ _id:new ObjectId(req.params.id) });
        if (!msg) return res.status(404).json({ error: 'Mensaje no encontrado' });
        const reactions = msg.reactions||[];
        const idx = reactions.findIndex(r=>r.emoji===emoji&&r.username===username);
        if (idx>=0) reactions.splice(idx,1); else reactions.push({emoji,username,createdAt:new Date()});
        await db.collection('hub_mensajes').updateOne({ _id:new ObjectId(req.params.id) }, { $set:{reactions} });
        res.json({ success:true, reactions });
    } catch (e) { res.status(500).json({ error: 'Error reaction' }); }
});

// ================================================================
// ASISTENCIA (v4.2 sin cambios)
// ================================================================
app.get('/api/hub/asistencia', requireAuth, requirePermiso('hub.asistencia'), async (req, res) => {
    try {
        const { usuario } = req;
        const filter = {};
        if (req.query.username) {
            filter.username = req.query.username;
            if (usuario.rol === 'COORDINADOR' && !tienePermiso(usuario,'hub.concentrado.ver')) {
                const targetUser = await db.collection('users').findOne({ username: req.query.username }, { projection:{area:1} });
                if (targetUser && targetUser.area !== usuario.area)
                    return res.status(403).json({ error: 'Solo puedes ver asistencia de usuarios de tu area' });
            }
        } else if (tienePermiso(usuario,'hub.concentrado.ver')) {
            if (usuario.rol === 'COORDINADOR') {
                const usuariosArea = await db.collection('users').find({ area: usuario.area, activo: true }, { projection:{username:1} }).toArray();
                filter.username = { $in: usuariosArea.map(u=>u.username) };
            }
        } else {
            filter.username = usuario.username;
        }
        if (req.query.mes) filter.fecha = { $regex: `^${req.query.mes}` };
        const docs = await db.collection('hub_asistencia').find(filter).sort({ fecha:-1, username:1 }).limit(500).toArray();
        res.json(docs);
    } catch (e) { console.error('Error GET asistencia:', e); res.status(500).json({ error: 'Error obteniendo asistencia' }); }
});

app.post('/api/hub/asistencia', requireAuth, async (req, res) => {
    const { targetUsername, fecha, tipo, horaEntrada, horaSalida, notas } = req.body;
    const { usuario } = req;
    const esAdminReg = targetUsername && targetUsername !== usuario.username;
    if (esAdminReg && !tienePermiso(usuario,'hub.asistencia.admin_registro'))
        return res.status(403).json({ error: 'Permiso insuficiente: hub.asistencia.admin_registro' });
    if (!esAdminReg && !tienePermiso(usuario,'hub.asistencia.registrar'))
        return res.status(403).json({ error: 'Permiso insuficiente: hub.asistencia.registrar' });
    if (!tipo) return res.status(400).json({ error: 'El campo tipo es requerido' });
    try {
        if (esAdminReg && usuario.rol === 'COORDINADOR') {
            const targetUser = await db.collection('users').findOne({ username: targetUsername }, { projection:{area:1} });
            if (targetUser && targetUser.area !== usuario.area)
                return res.status(403).json({ error: 'Solo puedes registrar asistencia para usuarios de tu area' });
        }
        const usernameDestino = esAdminReg ? targetUsername : usuario.username;
        const fechaRegistro   = fecha || new Date().toISOString().split('T')[0];
        const existe = await db.collection('hub_asistencia').findOne({ username:usernameDestino, fecha:fechaRegistro });
        if (existe) return res.status(409).json({ error:`Ya existe un registro para ${usernameDestino} el ${fechaRegistro}`, existingId:existe._id });
        const userDoc = await db.collection('users').findOne({ username: usernameDestino }, { projection:{area:1} });
        const doc = {
            username: usernameDestino, fecha: fechaRegistro, tipo,
            horaEntrada: horaEntrada||'', horaSalida: horaSalida||'',
            notas: notas||'', registradoPor: usuario.username,
            area: userDoc?.area || null,
            createdAt: new Date(),
        };
        await db.collection('hub_asistencia').insertOne(doc);
        res.status(201).json({ success:true, doc });
    } catch (e) { console.error('Error POST asistencia:', e); res.status(500).json({ error: 'Error registrando asistencia' }); }
});

app.patch('/api/hub/asistencia/:id', requireAuth, async (req, res) => {
    try {
        const doc = await db.collection('hub_asistencia').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
        const { usuario } = req;
        const esPropioUsuario = doc.username === usuario.username;
        const tieneAdmin      = tienePermiso(usuario,'hub.asistencia.admin_registro');
        const tieneRegistrar  = tienePermiso(usuario,'hub.asistencia.registrar');
        const tieneEditConc   = tienePermiso(usuario,'hub.concentrado.editar');
        let puedeEditar = tieneAdmin || (esPropioUsuario && tieneRegistrar) || tieneEditConc;
        if (!puedeEditar) return res.status(403).json({ error: 'Sin permiso para editar este registro' });
        if (usuario.rol === 'COORDINADOR' && !tienePermiso(usuario,'admin.panel')) {
            const targetUser = await db.collection('users').findOne({ username: doc.username }, { projection:{area:1} });
            if (targetUser && targetUser.area !== usuario.area)
                return res.status(403).json({ error: 'Solo puedes editar registros de usuarios de tu area' });
        }
        const updates = { ...req.body };
        if (!tieneAdmin) delete updates.username;
        updates.updatedAt = new Date();
        updates.updatedBy = usuario.username;
        await db.collection('hub_asistencia').updateOne({ _id:new ObjectId(req.params.id) }, { $set:updates });
        res.json({ success:true });
    } catch (e) { console.error('Error PATCH asistencia:', e); res.status(500).json({ error: 'Error actualizando asistencia' }); }
});

app.delete('/api/hub/asistencia/:id', requireAuth, async (req, res) => {
    try {
        const doc = await db.collection('hub_asistencia').findOne({ _id: new ObjectId(req.params.id) });
        if (!doc) return res.status(404).json({ error: 'Registro no encontrado' });
        const { usuario } = req;
        const esPropioUsuario = doc.username === usuario.username;
        const tieneAdmin      = tienePermiso(usuario,'hub.asistencia.admin_registro');
        const tieneRegistrar  = tienePermiso(usuario,'hub.asistencia.registrar');
        if (!tieneAdmin && !(esPropioUsuario && tieneRegistrar))
            return res.status(403).json({ error: 'Sin permiso para eliminar este registro' });
        if (usuario.rol === 'COORDINADOR' && !tieneAdmin) {
            const targetUser = await db.collection('users').findOne({ username: doc.username }, { projection:{area:1} });
            if (targetUser && targetUser.area !== usuario.area)
                return res.status(403).json({ error: 'Solo puedes eliminar registros de tu area' });
        }
        await db.collection('hub_asistencia').deleteOne({ _id:new ObjectId(req.params.id) });
        res.json({ success:true });
    } catch (e) { console.error('Error DELETE asistencia:', e); res.status(500).json({ error: 'Error eliminando asistencia' }); }
});

app.get('/api/hub/usuarios-activos', requireAuth, requirePermiso('hub.asistencia.admin_registro'), async (req, res) => {
    try {
        const { usuario } = req;
        const filter = { activo: true };
        if (usuario.rol === 'COORDINADOR') filter.area = usuario.area;
        const usuarios = await db.collection('users').find(filter, { projection:{password:0} }).toArray();
        res.json(usuarios.map(u => ({ username:u.username, nombre:u.nombre, rol:normalizarRol(u.rol), area:u.area||null, activo:u.activo })));
    } catch (e) { res.status(500).json({ error: 'Error obteniendo usuarios activos' }); }
});

// ── Concentrado ────────────────────────────────────────────────
app.get('/api/hub/concentrado', requireAuth, requirePermiso('hub.concentrado.ver'), async (req, res) => {
    try {
        const { usuario } = req;
        const filter = {};
        if (req.query.mes) filter.mes = req.query.mes;
        if (usuario.rol === 'COORDINADOR') {
            const usersArea = await db.collection('users').find({ area: usuario.area, activo: true }, { projection:{username:1} }).toArray();
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
        else if (!tienePermiso(req.usuario,'hub.peticiones.ver_todas')) filter.username = req.usuario.username;
        if (req.query.estado) filter.estado = req.query.estado;
        res.json(await db.collection('hub_vacaciones').find(filter).sort({createdAt:-1}).limit(200).toArray());
    } catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});
app.post('/api/hub/vacaciones', requireAuth, requirePermiso('hub.peticiones.crear'), async (req, res) => {
    try {
        const doc = { ...req.body, username:req.usuario.username, estado:'pendiente', createdAt:new Date() };
        await db.collection('hub_vacaciones').insertOne(doc);
        res.status(201).json({ success:true, doc });
    } catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});
app.patch('/api/hub/vacaciones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_vacaciones').updateOne({_id:new ObjectId(req.params.id)},{$set:{...req.body,updatedAt:new Date(),aprobadoPor:req.usuario.username}}); res.json({success:true}); }
    catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});
app.delete('/api/hub/vacaciones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_vacaciones').deleteOne({_id:new ObjectId(req.params.id)}); res.json({success:true}); }
    catch (e) { res.status(500).json({ error: 'Error vacaciones' }); }
});

// ── Peticiones ─────────────────────────────────────────────────
app.get('/api/hub/peticiones', requireAuth, requirePermiso('hub.acceso'), async (req, res) => {
    try {
        const { usuario } = req;
        const filter = {};
        if (tienePermiso(usuario,'hub.peticiones.ver_todas')) {
            if (usuario.rol === 'COORDINADOR') {
                const usersArea = await db.collection('users').find({ area:usuario.area }, { projection:{username:1} }).toArray();
                filter.username = { $in: usersArea.map(u=>u.username) };
            }
        } else {
            filter.username = usuario.username;
        }
        if (req.query.estado) filter.estado = req.query.estado;
        if (req.query.tipo)   filter.tipo   = req.query.tipo;
        res.json(await db.collection('hub_peticiones').find(filter).sort({createdAt:-1}).limit(200).toArray());
    } catch (e) { res.status(500).json({ error: 'Error peticiones' }); }
});
app.post('/api/hub/peticiones', requireAuth, requirePermiso('hub.peticiones.crear'), async (req, res) => {
    try {
        const doc = { ...req.body, username:req.usuario.username, nombre:req.usuario.nombre, estado:'pendiente', createdAt:new Date() };
        await db.collection('hub_peticiones').insertOne(doc);
        res.status(201).json({ success:true, doc });
    } catch (e) { res.status(500).json({ error: 'Error peticion' }); }
});
app.patch('/api/hub/peticiones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_peticiones').updateOne({_id:new ObjectId(req.params.id)},{$set:{...req.body,updatedAt:new Date(),aprobadoPor:req.usuario.username}}); res.json({success:true}); }
    catch (e) { res.status(500).json({ error: 'Error peticion' }); }
});
app.delete('/api/hub/peticiones/:id', requireAuth, requirePermiso('hub.peticiones.aprobar'), async (req, res) => {
    try { await db.collection('hub_peticiones').deleteOne({_id:new ObjectId(req.params.id)}); res.json({success:true}); }
    catch (e) { res.status(500).json({ error: 'Error peticion' }); }
});

// ── 404 / Error handler ────────────────────────────────────────
app.use('*', (req, res) => res.status(404).json({ error: `Endpoint no encontrado: ${req.originalUrl}` }));
app.use((err, req, res, next) => { console.error('Error no manejado:', err); res.status(500).json({ error: 'Error interno' }); });

async function start() {
    try {
        await connectDB();
        app.listen(PORT, () => {
            console.log(`MYG API v4.3.1 en puerto ${PORT}`);
            console.log(`IA Minutas: Groq=${!!process.env.GROQ_API_KEY ? '✅' : '❌ falta GROQ_API_KEY'} | Gemini=${!!process.env.GEMINI_API_KEY ? '✅' : '❌ falta GEMINI_API_KEY'} | Local=✅`);
            console.log(`Hub Area Scoping: ${[...COLECCIONES_CON_AREA].join(', ')}`);
        });
    } catch (err) { console.error('Error iniciando:', err); process.exit(1); }
}

start();
