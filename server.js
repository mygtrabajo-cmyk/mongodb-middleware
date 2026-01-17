// ========== MONGODB MIDDLEWARE API (Express + MongoDB) ==========
// Este servidor intermediario expone endpoints REST que tu Cloudflare Worker consumirá

const express = require('express');
const { MongoClient, ObjectId } = require('mongodb');
const cors = require('cors');

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());

// Conexión a MongoDB
let db;
let usersCollection;

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = 'myg_dashboard';
const COLLECTION_NAME = 'usuarios';

// Conectar a MongoDB
MongoClient.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
  .then((client) => {
    console.log('✅ Conectado a MongoDB');
    db = client.db(DB_NAME);
    usersCollection = db.collection(COLLECTION_NAME);
  })
  .catch((error) => {
    console.error('❌ Error conectando a MongoDB:', error);
    process.exit(1);
  });

// ========== ENDPOINTS ==========

// Health check
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    database: db ? 'connected' : 'disconnected'
  });
});

// GET - Obtener todos los usuarios
app.get('/api/users', async (req, res) => {
  try {
    const usuarios = await usersCollection.find({}).toArray();
    res.json(usuarios);
  } catch (error) {
    console.error('Error obteniendo usuarios:', error);
    res.status(500).json({ error: error.message });
  }
});

// GET - Obtener un usuario por username
app.get('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const usuario = await usersCollection.findOne({ username });
    
    if (!usuario) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json(usuario);
  } catch (error) {
    console.error('Error obteniendo usuario:', error);
    res.status(500).json({ error: error.message });
  }
});

// POST - Crear un nuevo usuario
app.post('/api/users', async (req, res) => {
  try {
    const userData = req.body;
    
    // Verificar si ya existe
    const existente = await usersCollection.findOne({ username: userData.username });
    if (existente) {
      return res.status(400).json({ error: 'El usuario ya existe' });
    }
    
    const result = await usersCollection.insertOne(userData);
    
    res.status(201).json({
      success: true,
      insertedId: result.insertedId
    });
  } catch (error) {
    console.error('Error creando usuario:', error);
    res.status(500).json({ error: error.message });
  }
});

// PUT - Actualizar un usuario
app.put('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    const updates = req.body;
    
    const result = await usersCollection.updateOne(
      { username },
      { $set: updates }
    );
    
    if (result.matchedCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json({ success: true, modifiedCount: result.modifiedCount });
  } catch (error) {
    console.error('Error actualizando usuario:', error);
    res.status(500).json({ error: error.message });
  }
});

// DELETE - Eliminar un usuario
app.delete('/api/users/:username', async (req, res) => {
  try {
    const { username } = req.params;
    
    if (username === 'admin') {
      return res.status(400).json({ error: 'No se puede eliminar el usuario admin' });
    }
    
    const result = await usersCollection.deleteOne({ username });
    
    if (result.deletedCount === 0) {
      return res.status(404).json({ error: 'Usuario no encontrado' });
    }
    
    res.json({ success: true });
  } catch (error) {
    console.error('Error eliminando usuario:', error);
    res.status(500).json({ error: error.message });
  }
});

// Iniciar servidor
app.listen(PORT, () => {
  console.log(`🚀 Middleware API ejecutándose en puerto ${PORT}`);
});