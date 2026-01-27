// ========== MONGODB MIDDLEWARE ==========

import express from 'express';
import { MongoClient, ObjectId } from 'mongodb';
import cors from 'cors';

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================================
// CONFIGURACIÓN
// ============================================================

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = 'iqu_telecom';

const COLLECTIONS = {
  USERS: 'users',
  DEVICES: 'devices',
  INVENTORY_HISTORY: 'inventory_history',
  COMMANDS: 'commands',
  AGENTS_LOG: 'agents_log'
};

// ============================================================
// MIDDLEWARE
// ============================================================

app.use(cors());
app.use(express.json({ limit: '10mb' }));

// Logger
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

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
// ENDPOINTS - USUARIOS
// ============================================================

app.get('/api/users', async (req, res) => {
  try {
    const users = await getCollection(COLLECTIONS.USERS);
    const userList = await users.find({}).toArray();
    
    res.json(userList);
  } catch (error) {
    console.error('Error getting users:', error);
    res.status(500).json({ error: error.message });
  }
});

app.get('/api/users/:username', async (req, res) => {
  try {
    const users = await getCollection(COLLECTIONS.USERS);
    const user = await users.findOne({ username: req.params.username });
    
    if (!user) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json(user);
  } catch (error) {
    console.error('Error getting user:', error);
    res.status(500).json({ error: error.message });
  }
});

app.post('/api/users', async (req, res) => {
  try {
    const users = await getCollection(COLLECTIONS.USERS);
    const result = await users.insertOne(req.body);
    
    res.json({ success: true, insertedId: result.insertedId });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: error.message });
  }
});

app.put('/api/users/:username', async (req, res) => {
  try {
    const users = await getCollection(COLLECTIONS.USERS);
    const result = await users.updateOne(
      { username: req.params.username },
      { $set: req.body }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error updating user:', error);
    res.status(500).json({ error: error.message });
  }
});

app.delete('/api/users/:username', async (req, res) => {
  try {
    const users = await getCollection(COLLECTIONS.USERS);
    const result = await users.deleteOne({ username: req.params.username });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error deleting user:', error);
    res.status(500).json({ error: error.message });
  }
});

// ============================================================
// ENDPOINTS - DISPOSITIVOS (AGENTES)
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
    
    // Marcar como offline dispositivos sin reporte reciente (20 min)
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
// ENDPOINTS - HISTORIAL
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
    
    // Limpiar historial antiguo (mantener 30 días)
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
// ENDPOINTS - COMANDOS
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
    
    // Marcar como "executing"
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
// ENDPOINTS - LOGS
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
// ENDPOINTS - ESTADÍSTICAS
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
// HEALTH CHECK
// ============================================================

app.get('/health', async (req, res) => {
  try {
    await connectDB();
    res.json({ 
      status: 'ok', 
      timestamp: new Date().toISOString(),
      database: 'mongodb'
    });
  } catch (error) {
    res.status(500).json({ 
      status: 'error', 
      error: error.message 
    });
  }
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
  console.log(`MongoDB Middleware running on port ${PORT}`);
  
  try {
    await connectDB();
    console.log('Connected to MongoDB successfully');
  } catch (error) {
    console.error('Failed to connect to MongoDB:', error);
    process.exit(1);
  }
});
