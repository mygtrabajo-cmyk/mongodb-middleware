// ========== MONGODB MIDDLEWARE COMPLETO CON AUTENTICACIÓN + RH ==========

import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';
import crypto from 'crypto';
import Joi from 'joi';
import winston from 'winston';

const app = express();
const PORT = process.env.PORT || 3000;

// Configurar logger (para depuración y monitoreo)
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.json()
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ filename: 'error.log', level: 'error' })  // Log errores a file
    ]
});

// ============================================================
// CONFIGURACIÓN
// ============================================================

const MONGODB_URI = process.env.MONGODB_URI || 'mongodb+srv://iqu_api:UV1qiXyzk6Yducaz@cluster0.kb6nsgi.mongodb.net/?appName=Cluster0';
const JWT_SECRET = process.env.JWT_SECRET || 'AKfycbwJ6NPiIrwGMXOfZYLjoo-TXI07O3pz94QA-M7yOOb-fiBmsXb3bmFljw_FnVsebTK4hw';
const DB_NAME = 'iqu_telecom';

const COLLECTIONS = {
  USERS: 'users',
  DEVICES: 'devices',
  INVENTORY_HISTORY: 'inventory_history',
  COMMANDS: 'commands',
  AGENTS_LOG: 'agents_log',
  // === NUEVAS COLECCIONES RH ===
  RH_MOVIMIENTOS: 'rh_movimientos',
  NOTIFICACIONES: 'notificaciones'
};

// ============================================================
// SCHEMA DE VALIDACIÓN UNIFICADO (para create y update)
// ============================================================
const userSchema = Joi.object({
    username: Joi.string().min(3).max(50).required().messages({
        'string.min': 'Username debe tener al menos 3 caracteres',
        'any.required': 'Username es requerido'
    }),
    password: Joi.string().min(6).optional().messages({  // Opcional en update
        'string.min': 'Contraseña debe tener al menos 6 caracteres'
    }),
    nombre: Joi.string().min(3).max(100).required(),
    email: Joi.string().email().required(),
    rol: Joi.string().valid('ADMIN', 'RH', 'SISTEMAS', 'GERENTE', 'USUARIO').required().messages({  // Solo roles permitidos
        'any.only': 'Rol inválido. Opciones: ADMIN, RH, SISTEMAS, GERENTE, USUARIO'
    }),
    activo: Joi.boolean().default(true)
});

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json({ limit: '10mb' }));

app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});
const authMiddleware = async (req, res, next) => {
    try {
        const token = req.headers.authorization?.split(' ')[1];
        if (!token) return res.status(401).json({ error: 'Token requerido' });

        const payload = verifyJWT(token);
        req.usuario = payload;

        // Verificar si es admin para create/update/delete
        if (!SistemaPermisos.esAdmin(payload)) {
            logger.warn(`Intento no autorizado: ${payload.username} intentó operación admin`);
            return res.status(403).json({ error: 'Requiere rol ADMIN' });
        }

        next();
    } catch (error) {
        logger.error(`Error en auth: ${error.message}`);
        res.status(401).json({ error: 'Autenticación fallida' });
    }
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
  try {
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
  } catch (error) {
    throw new Error(`JWT verification failed: ${error.message}`);
  }
}

// ============================================================
// MIDDLEWARE DE AUTENTICACIÓN
// ============================================================

function requireAuth(req, res, next) {
  try {
    const authHeader = req.headers.authorization;
    
    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Token no proporcionado' });
    }

    const token = authHeader.substring(7);
    const payload = verifyJWT(token);
    
    req.usuario = payload;
    next();
  } catch (error) {
    return res.status(401).json({ error: 'Token inválido o expirado' });
  }
}

// ============================================================
// PASSWORD HASHING
// ============================================================

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

  return { client, db };
}

async function getCollection(collectionName) {
  const { db } = await connectDB();
  return db.collection(collectionName);
}

// ============================================================
// INICIALIZACIÓN
// ============================================================

async function initializeDB() {
  try {
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
      console.log('✅ Usuario admin creado');
    }
    
    // Crear índices para RH
    const rhMovimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
    await rhMovimientos.createIndex({ fecha_creacion: -1 });
    await rhMovimientos.createIndex({ estado: 1 });
    await rhMovimientos.createIndex({ 'creado_por.username': 1 });
    
    const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
    await notificaciones.createIndex({ usuario_destino: 1, leida: 1 });
    await notificaciones.createIndex({ fecha_creacion: -1 });
    
    console.log('✅ Índices RH creados');
  } catch (error) {
    console.error('Error inicializando DB:', error);
  }
}

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

    if (!user) {
      return res.status(401).json({ error: 'Credenciales inválidas' });
    }

    if (!user.activo) {
      return res.status(403).json({ error: 'Usuario inactivo' });
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
      exp: Date.now() + (24 * 60 * 60 * 1000) // 24 horas
    };

    const token = createJWT(payload);

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
    console.error('Error en login:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ENDPOINT CREAR USUARIO (POST /api/users) - Refactorizado
// ============================================================
app.post('/api/users', authMiddleware, async (req, res) => {
    const client = await connectDB();
    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTIONS.USERS);

    try {
        // Validar con Joi
        const { error, value } = userSchema.validate(req.body, { abortEarly: false });
        if (error) {
            const errors = error.details.map(d => d.message).join('; ');
            logger.warn(`Validación fallida al crear usuario: ${errors}`);
            return res.status(400).json({ error: errors });
        }

        // Requerir password en creación
        if (!value.password) {
            return res.status(400).json({ error: 'Contraseña requerida para creación' });
        }

        // Verificar duplicado
        const existing = await collection.findOne({ username: value.username });
        if (existing) {
            logger.warn(`Intento de duplicado: ${value.username}`);
            return res.status(409).json({ error: 'Username ya existe' });
        }

        // Hashear password
        const hashedPassword = await bcrypt.hash(value.password, 12);
        value.password = hashedPassword;  // Reemplazar plain con hash

        // Insertar con timestamp
        value.createdAt = new Date();
        const result = await collection.insertOne(value);

        logger.info(`Usuario creado: ${value.username} por ${req.usuario.username}`);
        res.status(201).json({ success: true, user: { ...value, _id: result.insertedId }, password: undefined });  // No retornar password

    } catch (error) {
        logger.error(`Error creando usuario: ${error.message}`);
        res.status(500).json({ error: 'Error interno al crear usuario' });
    }
});

// ============================================================
// ENDPOINT ACTUALIZAR USUARIO (PUT /api/users/:username) - Refactorizado
// ============================================================
app.put('/api/users/:username', authMiddleware, async (req, res) => {
    const client = await connectDB();
    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTIONS.USERS);

    try {
        const username = req.params.username;

        // Validar updates (password opcional)
        const { error, value } = userSchema.validate(req.body, { abortEarly: false, stripUnknown: true });  // Ignorar campos extra
        if (error) {
            const errors = error.details.map(d => d.message).join('; ');
            logger.warn(`Validación fallida al actualizar: ${errors}`);
            return res.status(400).json({ error: errors });
        }

        // Hashear si hay nueva password
        if (value.password) {
            value.password = await bcrypt.hash(value.password, 12);
        }

        // Actualizar con timestamp
        value.updatedAt = new Date();
        const result = await collection.updateOne(
            { username },
            { $set: value }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        logger.info(`Usuario actualizado: ${username} por ${req.usuario.username}`);
        res.json({ success: true });

    } catch (error) {
        logger.error(`Error actualizando usuario: ${error.message}`);
        res.status(500).json({ error: 'Error interno al actualizar' });
    }
});

// ============================================================
// ENDPOINT ELIMINAR (DELETE /api/users/:username) - Mejora: Soft delete
// ============================================================
app.delete('/api/users/:username', authMiddleware, async (req, res) => {
    const client = await connectDB();
    const db = client.db(DB_NAME);
    const collection = db.collection(COLLECTIONS.USERS);

    try {
        const username = req.params.username;

        // Soft delete: Set activo=false en vez de borrar
        const result = await collection.updateOne(
            { username },
            { $set: { activo: false, deletedAt: new Date() } }
        );

        if (result.matchedCount === 0) {
            return res.status(404).json({ error: 'Usuario no encontrado' });
        }

        logger.info(`Usuario eliminado (soft): ${username} por ${req.usuario.username}`);
        res.json({ success: true });

    } catch (error) {
        logger.error(`Error eliminando usuario: ${error.message}`);
        res.status(500).json({ error: 'Error interno al eliminar' });
    }
});

// ============================================================
// ENDPOINTS - DISPOSITIVOS (EXISTENTES - SIN CAMBIOS)
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
    
    const twentyMinAgo = new Date(Date.now() - 20 * 60 * 1000);
    await devices.updateMany(
      { 
        last_seen: { $lt: twentyMinAgo.toISOString() }, 
        status: 'online' 
      },
      { $set: { status: 'offline' } }
    );
    
    const deviceList = await devices
      .find(filter)
      .sort({ last_seen: -1 })
      .limit(500)
      .toArray();
    
    res.json(deviceList);
  } catch (error) {
    console.error('Error getting devices:', error);
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
    console.error('Error getting device:', error);
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
        $setOnInsert: { 
          created_at: new Date().toISOString() 
        }
      },
      { upsert: true }
    );
    
    res.json({ 
      success: true, 
      upsertedId: result.upsertedId,
      modifiedCount: result.modifiedCount
    });
  } catch (error) {
    console.error('Error upserting device:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ENDPOINTS - HISTORIAL (EXISTENTES - SIN CAMBIOS)
// ============================================================

app.post('/api/history/:agentId', async (req, res) => {
  try {
    const history = await getCollection(COLLECTIONS.INVENTORY_HISTORY);
    
    const historyData = {
      agent_id: req.params.agentId,
      ...req.body,
      timestamp: new Date().toISOString()
    };
    
    await history.insertOne(historyData);
    
    const thirtyDaysAgo = new Date(Date.now() - 30 * 24 * 60 * 60 * 1000);
    await history.deleteMany({
      agent_id: req.params.agentId,
      timestamp: { $lt: thirtyDaysAgo.toISOString() }
    });
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error adding history:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/history/:agentId', async (req, res) => {
  try {
    const history = await getCollection(COLLECTIONS.INVENTORY_HISTORY);
    const limit = parseInt(req.query.limit) || 100;
    
    const records = await history
      .find({ agent_id: req.params.agentId })
      .sort({ timestamp: -1 })
      .limit(limit)
      .toArray();
    
    res.json(records);
  } catch (error) {
    console.error('Error getting history:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ENDPOINTS - COMANDOS (EXISTENTES - SIN CAMBIOS)
// ============================================================

app.get('/api/commands/pending/:agentId', async (req, res) => {
  try {
    const commands = await getCollection(COLLECTIONS.COMMANDS);
    
    const pendingCommands = await commands
      .find({
        agent_id: req.params.agentId,
        status: 'pending'
      })
      .limit(10)
      .toArray();
    
    if (pendingCommands.length > 0) {
      const commandIds = pendingCommands.map(cmd => cmd._id);
      
      await commands.updateMany(
        { _id: { $in: commandIds } },
        { 
          $set: { 
            status: 'executing',
            started_at: new Date().toISOString()
          }
        }
      );
    }
    
    res.json(pendingCommands);
  } catch (error) {
    console.error('Error getting pending commands:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/commands/:agentId', async (req, res) => {
  try {
    const commands = await getCollection(COLLECTIONS.COMMANDS);
    
    const command = {
      agent_id: req.params.agentId,
      command: req.body.command,
      parameters: req.body.parameters || {},
      status: 'pending',
      created_at: new Date().toISOString(),
      issued_by: req.body.issued_by || 'system'
    };
    
    const result = await commands.insertOne(command);
    
    res.json({ 
      success: true, 
      command_id: result.insertedId 
    });
  } catch (error) {
    console.error('Error creating command:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/commands/:commandId/result', async (req, res) => {
  try {
    const commands = await getCollection(COLLECTIONS.COMMANDS);
    
    const result = await commands.updateOne(
      { 
        _id: new ObjectId(req.params.commandId),
        agent_id: req.body.agent_id
      },
      { 
        $set: {
          status: req.body.success ? 'completed' : 'failed',
          result: {
            success: req.body.success,
            output: req.body.output,
            error: req.body.error
          },
          completed_at: new Date().toISOString()
        }
      }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Comando no encontrado' });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating command result:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ENDPOINTS - LOGS (EXISTENTES - SIN CAMBIOS)
// ============================================================

app.post('/api/logs', async (req, res) => {
  try {
    const logs = await getCollection(COLLECTIONS.AGENTS_LOG);
    
    const logData = {
      ...req.body,
      timestamp: new Date().toISOString()
    };
    
    await logs.insertOne(logData);
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error adding log:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ENDPOINTS - ESTADÍSTICAS (EXISTENTES - SIN CAMBIOS)
// ============================================================

app.get('/api/stats', async (req, res) => {
  try {
    const devices = await getCollection(COLLECTIONS.DEVICES);
    
    const totalDevices = await devices.countDocuments();
    const onlineDevices = await devices.countDocuments({ status: 'online' });
    const offlineDevices = await devices.countDocuments({ status: 'offline' });
    
    const byLocation = await devices.aggregate([
      { $group: { _id: '$location', count: { $sum: 1 } } }
    ]).toArray();
    
    const byOS = await devices.aggregate([
      { $group: { _id: '$os_system', count: { $sum: 1 } } }
    ]).toArray();
    
    const highCPU = await devices.countDocuments({ 
      'cpu.usage_percent': { $gt: 80 } 
    });
    
    const highRAM = await devices.countDocuments({ 
      'memory.usage_percent': { $gt: 85 } 
    });
    
    const highDisk = await devices.countDocuments({ 
      'disk.usage_percent': { $gt: 90 } 
    });
    
    res.json({
      summary: {
        total: totalDevices,
        online: onlineDevices,
        offline: offlineDevices
      },
      by_location: byLocation,
      by_os: byOS,
      alerts: {
        high_cpu: highCPU,
        high_memory: highRAM,
        high_disk: highDisk
      }
    });
  } catch (error) {
    console.error('Error getting stats:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// === NUEVOS ENDPOINTS - MOVIMIENTOS RH ===
// ============================================================

app.post('/api/rh/movimientos', requireAuth, async (req, res) => {
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
    
    res.status(201).json(movimiento);
    
    console.log(`✅ Movimiento RH creado: ${movimiento._id} (${movimiento.tipo}) por ${req.usuario.username}`);
  } catch (error) {
    console.error('Error creando movimiento:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/rh/movimientos', requireAuth, async (req, res) => {
  try {
    const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
    const { tipo, estado, usuario, fecha_desde, fecha_hasta } = req.query;
    
    const filter = {};
    
    if (tipo && tipo !== 'todos') {
      filter.tipo = tipo;
    }
    
    if (estado && estado !== 'todos') {
      filter.estado = estado;
    }
    
    // Si el usuario es RH, solo ver sus movimientos
    if (req.usuario.rol === 'RH' || usuario) {
      filter['creado_por.username'] = usuario || req.usuario.username;
    }
    
    // Filtro de fechas
    if (fecha_desde || fecha_hasta) {
      filter.fecha_creacion = {};
      if (fecha_desde) {
        filter.fecha_creacion.$gte = new Date(fecha_desde).toISOString();
      }
      if (fecha_hasta) {
        filter.fecha_creacion.$lte = new Date(fecha_hasta).toISOString();
      }
    } else {
      // Por defecto, últimos 3 meses
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
    console.error('Error obteniendo movimientos:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/rh/movimientos/:id', requireAuth, async (req, res) => {
  try {
    const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
    const movimiento = await movimientos.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!movimiento) {
      return res.status(404).json({ error: 'Movimiento no encontrado' });
    }
    
    // Si es RH, solo puede ver sus propios movimientos
    if (req.usuario.rol === 'RH' && 
        movimiento.creado_por.username !== req.usuario.username) {
      return res.status(403).json({ error: 'Sin permisos para ver este movimiento' });
    }
    
    res.json(movimiento);
  } catch (error) {
    console.error('Error obteniendo movimiento:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/rh/movimientos/:id', requireAuth, async (req, res) => {
  try {
    const movimientos = await getCollection(COLLECTIONS.RH_MOVIMIENTOS);
    const updates = { ...req.body };
    
    const movimiento = await movimientos.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    if (!movimiento) {
      return res.status(404).json({ error: 'Movimiento no encontrado' });
    }
    
    // Validar permisos
    if (movimiento.estado !== 'PENDIENTE' && req.usuario.rol === 'RH') {
      return res.status(403).json({ 
        error: 'Solo puedes editar movimientos pendientes' 
      });
    }
    
    if (req.usuario.rol === 'RH' && 
        movimiento.creado_por.username !== req.usuario.username) {
      return res.status(403).json({ 
        error: 'Solo puedes editar tus propios movimientos' 
      });
    }
    
    // No permitir cambiar estado por esta ruta
    delete updates.estado;
    delete updates._id;
    
    updates.fecha_modificacion = new Date().toISOString();
    updates.modificado_por = {
      username: req.usuario.username,
      nombre: req.usuario.nombre
    };
    
    await movimientos.updateOne(
      { _id: new ObjectId(req.params.id) },
      { 
        $set: updates,
        $push: {
          historial: {
            estado: movimiento.estado,
            fecha: new Date().toISOString(),
            usuario: req.usuario.username,
            comentario: 'Movimiento actualizado'
          }
        }
      }
    );
    
    const movimientoActualizado = await movimientos.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    res.json(movimientoActualizado);
    
    console.log(`✅ Movimiento actualizado: ${req.params.id} por ${req.usuario.username}`);
  } catch (error) {
    console.error('Error actualizando movimiento:', error);
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/rh/movimientos/:id/estado', requireAuth, async (req, res) => {
  try {
    // Solo SISTEMAS y ADMIN pueden cambiar estados
    if (req.usuario.rol !== 'SISTEMAS' && req.usuario.rol !== 'ADMIN') {
      return res.status(403).json({ 
        error: 'Solo Sistemas y Admin pueden cambiar estados' 
      });
    }
    
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
      
      if (correo_creado) {
        updates.correo_creado = correo_creado;
      }
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
    
    const movimiento = await movimientos.findOne({ 
      _id: new ObjectId(req.params.id) 
    });
    
    res.json(movimiento);
    
    console.log(`✅ Estado cambiado: ${req.params.id} -> ${estado} por ${req.usuario.username}`);
  } catch (error) {
    console.error('Error cambiando estado:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// === NUEVOS ENDPOINTS - NOTIFICACIONES ===
// ============================================================

app.post('/api/notificaciones', requireAuth, async (req, res) => {
  try {
    const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
    
    const notificacion = {
      ...req.body,
      _id: new ObjectId(),
      leida: false,
      fecha_creacion: new Date().toISOString(),
      fecha_lectura: null
    };
    
    await notificaciones.insertOne(notificacion);
    
    res.status(201).json({ id: notificacion._id });
  } catch (error) {
    console.error('Error creando notificación:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/notificaciones', requireAuth, async (req, res) => {
  try {
    const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
    const { username, soloNoLeidas } = req.query;
    
    const filter = { 
      usuario_destino: username || req.usuario.username 
    };
    
    if (soloNoLeidas === 'true') {
      filter.leida = false;
    }
    
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
    console.error('Error obteniendo notificaciones:', error);
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/notificaciones/:id/leer', requireAuth, async (req, res) => {
  try {
    const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
    
    await notificaciones.updateOne(
      { 
        _id: new ObjectId(req.params.id),
        usuario_destino: req.usuario.username
      },
      { 
        $set: { 
          leida: true,
          fecha_lectura: new Date().toISOString()
        }
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error marcando notificación:', error);
    res.status(500).json({ error: error.message });
  }
});

app.patch('/api/notificaciones/leer-todas', requireAuth, async (req, res) => {
  try {
    const notificaciones = await getCollection(COLLECTIONS.NOTIFICACIONES);
    
    await notificaciones.updateMany(
      { 
        usuario_destino: req.usuario.username,
        leida: false
      },
      { 
        $set: { 
          leida: true,
          fecha_lectura: new Date().toISOString()
        }
      }
    );
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error marcando todas las notificaciones:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// HEALTH CHECK
// ============================================================

app.get('/health', async (req, res) => {
  try {
    await connectDB();
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      database: 'mongodb',
      endpoints: {
        auth: 'POST /api/auth/login',
        users: 'GET,POST,PUT,DELETE /api/users',
        devices: 'GET,POST /api/devices',
        commands: 'GET,POST /api/commands',
        rh: 'GET,POST,PUT,PATCH /api/rh/movimientos',
        notifications: 'GET,POST,PATCH /api/notificaciones'
      }
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      error: error.message 
    });
  }
});

app.get('/', (req, res) => {
  res.json({
    name: 'MongoDB Middleware API - MYG Telecom',
    version: '2.0.0',
    status: 'running',
    features: ['Agentes IQU', 'Gestión RH', 'Notificaciones'],
    documentation: '/health'
  });
});

// ============================================================
// ERROR HANDLER
// ============================================================

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ 
    error: 'Internal server error',
    message: err.message 
  });
});

// ============================================================
// START SERVER
// ============================================================

app.listen(PORT, async () => {
  console.log('');
  console.log('========================================');
  console.log('✅ MongoDB Middleware + RH iniciado');
  console.log(`🚀 Puerto: ${PORT}`);
  console.log(`🌍 URL: http://localhost:${PORT}`);
  console.log('========================================');
  console.log('');
  
  try {
    await connectDB();
    console.log('✅ Conectado a MongoDB Atlas');
    await initializeDB();
    console.log('✅ Base de datos inicializada');
    console.log('');
    console.log('📋 Endpoints disponibles:');
    console.log('   - Auth: /api/auth/login');
    console.log('   - Users: /api/users');
    console.log('   - Devices: /api/devices');
    console.log('   - Commands: /api/commands');
    console.log('   - RH: /api/rh/movimientos');
    console.log('   - Notifications: /api/notificaciones');
    console.log('');
  } catch (error) {
    console.error('❌ Error fatal al iniciar:', error);
    process.exit(1);
  }
});

// Manejo de cierre graceful
process.on('SIGINT', async () => {
  console.log('');
  console.log('🛑 Cerrando servidor...');
  if (cachedClient) {
    await cachedClient.close();
    console.log('✅ Conexión a MongoDB cerrada');
  }
  process.exit(0);
});

