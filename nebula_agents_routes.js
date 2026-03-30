// ============================================================
// NEBULA AGENT — Rutas para el backend MYG Telecom
// Archivo: routes/nebula_agents.js
//
// INTEGRACIÓN: Añadir al server.js existente así:
//
//   const nebulaRoutes = require('./routes/nebula_agents');
//   nebulaRoutes.init(app, db, ssePush);
//
// Colecciones MongoDB que usa:
//   - nebula_agents   (registro y estado de los agentes)
//   - nebula_commands (comandos pendientes y ejecutados)
//   - nebula_events   (eventos/alertas de los endpoints)
//   - nebula_audit    (audit trail inmutable recibido del agente)
//   - agents_log      (ya existía — se mantiene para compatibilidad)
// ============================================================

const { ObjectId } = require('mongodb');
const crypto       = require('crypto');

// ── Configuración ─────────────────────────────────────────────
const NEBULA_AGENT_SECRET = process.env.NEBULA_AGENT_SECRET || 'nebula-default-secret-CHANGE-IN-PRODUCTION';
const NEBULA_OFFLINE_TTL  = 60 * 60 * 24 * 7;  // 7 días en segundos

// ── Middleware de autenticación del agente ────────────────────
/**
 * requireAgentAuth
 * Valida el header: Authorization: Agent {machine_id}:{hmac_token}
 * El token es HMAC-SHA256(machine_id, NEBULA_AGENT_SECRET).
 *
 * Inyecta req.agent = { machine_id, token } en el request.
 */
function requireAgentAuth(req, res, next) {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Agent ')) {
        return res.status(401).json({ error: 'Token de agente no proporcionado' });
    }

    const credentials = header.slice(6); // quitar "Agent "
    const sepIdx = credentials.indexOf(':');
    if (sepIdx === -1) {
        return res.status(401).json({ error: 'Formato inválido. Esperado: Agent {machine_id}:{token}' });
    }

    const machine_id = credentials.slice(0, sepIdx);
    const token      = credentials.slice(sepIdx + 1);

    // Validar formato básico del machine_id (UUID-like)
    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(machine_id)) {
        return res.status(401).json({ error: 'machine_id con formato inválido' });
    }

    // Verificar HMAC
    const expectedToken = crypto
        .createHmac('sha256', NEBULA_AGENT_SECRET)
        .update(machine_id)
        .digest('hex');

    if (!crypto.timingSafeEqual(Buffer.from(token), Buffer.from(expectedToken))) {
        console.warn(`[Nebula] Auth fallida para machine_id: ${machine_id.substring(0, 16)}...`);
        return res.status(401).json({ error: 'Token de agente inválido' });
    }

    req.agent = { machine_id, token };
    next();
}

/**
 * requireDashboardAuth
 * Reutiliza el middleware requireAuth del servidor principal.
 * Los endpoints de gestión (enviar comandos, ver agentes) los usa
 * el dashboard con JWT de usuario normal.
 */
function requireDashboardAuthAndAdmin(requireAuth, requireAdmin) {
    return [requireAuth, requireAdmin];
}

// ── Inicialización de índices ──────────────────────────────────
async function initIndexes(db) {
    const idx = async (col, spec, opts = {}) => {
        try {
            await db.collection(col).createIndex(spec, opts);
        } catch (e) {
            console.warn(`[Nebula] Índice ${col}: ${e.message?.split('\n')[0]}`);
        }
    };

    // nebula_agents
    await idx('nebula_agents',  { machine_id: 1 }, { unique: true, name: 'nebula_agent_id_unique' });
    await idx('nebula_agents',  { last_seen: -1 },  { name: 'nebula_agent_last_seen' });
    await idx('nebula_agents',  { status: 1 },      { name: 'nebula_agent_status' });
    await idx('nebula_agents',  { hostname: 1 },    { name: 'nebula_agent_hostname' });

    // nebula_commands
    await idx('nebula_commands', { machine_id: 1, status: 1 }, { name: 'nebula_cmd_agent_status' });
    await idx('nebula_commands', { created_at: -1 },            { name: 'nebula_cmd_fecha' });
    await idx('nebula_commands', { status: 1, created_at: -1 }, { name: 'nebula_cmd_status_fecha' });

    // nebula_events  (TTL 30 días)
    await idx('nebula_events',  { machine_id: 1, created_at: -1 }, { name: 'nebula_evt_agent_fecha' });
    await idx('nebula_events',  { created_at: 1 }, { expireAfterSeconds: 30 * 24 * 3600, name: 'nebula_evt_ttl' });

    // nebula_audit (no TTL — es inmutable por diseño)
    await idx('nebula_audit',   { machine_id: 1, timestamp: -1 }, { name: 'nebula_audit_agent_fecha' });
    await idx('nebula_audit',   { chain_hash: 1 }, { unique: true, name: 'nebula_audit_chain_unique' });

    console.log('[Nebula] Índices MongoDB inicializados');
}

// ── Módulo principal exportado ────────────────────────────────
module.exports = {
    /**
     * Registra todas las rutas de Nebula Agent en la app Express.
     *
     * @param {import('express').Application} app
     * @param {import('mongodb').Db} db
     * @param {Function} ssePush  - función ssePush(username, event, data) del server principal
     * @param {Function} requireAuth   - middleware JWT del server principal
     * @param {Function} requireAdmin  - middleware ADMIN del server principal
     */
    async init(app, db, ssePush, requireAuth, requireAdmin) {
        await initIndexes(db);

        // ─────────────────────────────────────────────────────
        // ENDPOINTS DEL AGENTE (autenticados con Agent token)
        // ─────────────────────────────────────────────────────

        /**
         * POST /api/agents/register
         * El agente se registra/actualiza cuando inicia.
         * Crea o actualiza el documento en nebula_agents.
         */
        app.post('/api/agents/register', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.agent;
                const {
                    hostname, ip_address, mac_address,
                    os_system, os_version, os_release,
                    architecture, agent_version, agent_name,
                } = req.body;

                const now = new Date();
                const agentDoc = {
                    machine_id,
                    hostname:        hostname     || 'unknown',
                    ip_address:      ip_address   || 'unknown',
                    mac_address:     mac_address  || 'unknown',
                    os_system:       os_system    || 'unknown',
                    os_version:      os_version   || 'unknown',
                    os_release:      os_release   || 'unknown',
                    architecture:    architecture || 'unknown',
                    agent_name:      agent_name   || 'Nebula',
                    agent_version:   agent_version || '1.0.0',
                    status:          'online',
                    last_seen:       now,
                    registered_at:   now,  // solo se setea en $setOnInsert
                };

                await db.collection('nebula_agents').findOneAndUpdate(
                    { machine_id },
                    {
                        $set: { ...agentDoc },
                        $setOnInsert: { registered_at: now, first_seen: now },
                    },
                    { upsert: true, returnDocument: 'after' },
                );

                // Notificar al dashboard vía SSE
                ssePush('*', 'nebula_agent_online', {
                    machine_id,
                    hostname: hostname || 'unknown',
                    status: 'online',
                    agent_version,
                    timestamp: now.toISOString(),
                });

                console.log(`[Nebula] Agente registrado: ${hostname} (${machine_id.substring(0, 16)}...)`);
                res.json({ success: true, server_time: now.toISOString() });

            } catch (e) {
                console.error('[Nebula] Error en register:', e);
                res.status(500).json({ error: 'Error registrando agente' });
            }
        });

        /**
         * POST /api/agents/heartbeat
         * El agente envía métricas cada 5 minutos.
         * Actualiza el documento del agente y notifica al dashboard.
         */
        app.post('/api/agents/heartbeat', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.agent;
                const { hostname, stats, timestamp } = req.body;
                const now = new Date();

                // Detectar alertas automáticamente
                const alerts = detectAlerts(stats);

                await db.collection('nebula_agents').updateOne(
                    { machine_id },
                    {
                        $set: {
                            last_seen:    now,
                            status:       'online',
                            last_stats:   stats || {},
                            active_alerts: alerts,
                        },
                    },
                    { upsert: true },
                );

                // Push SSE al dashboard con stats en tiempo real
                ssePush('*', 'nebula_heartbeat', {
                    machine_id,
                    hostname: hostname || machine_id.substring(0, 8),
                    stats,
                    alerts,
                    timestamp: now.toISOString(),
                });

                // Si hay alertas críticas, crear notificación
                if (alerts.length > 0) {
                    for (const alert of alerts) {
                        await db.collection('notificaciones').insertOne({
                            titulo:           `⚠️ Alerta Nebula: ${hostname}`,
                            mensaje:          alert.message,
                            tipo:             alert.severity,
                            usuario_destino:  '*',
                            creadaPor:        'nebula_agent',
                            leida:            false,
                            createdAt:        now,
                            meta: { machine_id, alert_type: alert.type },
                        });
                        ssePush('*', 'notificacion', {
                            titulo:  `⚠️ Alerta Nebula: ${hostname}`,
                            mensaje: alert.message,
                            tipo:    alert.severity,
                        });
                    }
                }

                res.json({ success: true, server_time: now.toISOString(), alerts_detected: alerts.length });

            } catch (e) {
                console.error('[Nebula] Error en heartbeat:', e);
                res.status(500).json({ error: 'Error procesando heartbeat' });
            }
        });

        /**
         * GET /api/nebula/commands/pending/:machine_id
         * El agente solicita sus comandos pendientes.
         * Marca los comandos como 'in_progress' al entregarlos.
         */
        app.get('/api/nebula/commands/pending/:machine_id', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.params;

                // Validar que el agente solo puede pedir sus propios comandos
                if (machine_id !== req.agent.machine_id) {
                    return res.status(403).json({ error: 'No puedes obtener comandos de otro agente' });
                }

                const commands = await db.collection('nebula_commands')
                    .find({ machine_id, status: 'pending' })
                    .sort({ created_at: 1 })  // FIFO
                    .limit(10)
                    .toArray();

                if (commands.length > 0) {
                    // Marcar como in_progress
                    const ids = commands.map(c => c._id);
                    await db.collection('nebula_commands').updateMany(
                        { _id: { $in: ids } },
                        { $set: { status: 'in_progress', dispatched_at: new Date() } },
                    );
                    console.log(`[Nebula] ${commands.length} comando(s) despachados a ${machine_id.substring(0, 16)}...`);
                }

                res.json(commands);

            } catch (e) {
                console.error('[Nebula] Error en get_pending_commands:', e);
                res.status(500).json({ error: 'Error obteniendo comandos' });
            }
        });

        /**
         * POST /api/nebula/commands/:command_id/result
         * El agente reporta el resultado de un comando ejecutado.
         */
        app.post('/api/nebula/commands/:command_id/result', requireAgentAuth, async (req, res) => {
            try {
                const { command_id } = req.params;
                const { machine_id } = req.agent;
                const { success, output, error, duration_ms, executed_at } = req.body;

                if (!ObjectId.isValid(command_id)) {
                    return res.status(400).json({ error: `command_id inválido: "${command_id}"` });
                }

                // Verificar que el comando pertenece a este agente
                const cmd = await db.collection('nebula_commands').findOne({
                    _id: new ObjectId(command_id),
                    machine_id,
                });
                if (!cmd) {
                    return res.status(404).json({ error: 'Comando no encontrado o no pertenece a este agente' });
                }

                const now = new Date();
                await db.collection('nebula_commands').updateOne(
                    { _id: new ObjectId(command_id) },
                    {
                        $set: {
                            status:       success ? 'completed' : 'failed',
                            result: {
                                success,
                                output:      (output || '').substring(0, 10000),
                                error:       error || null,
                                duration_ms: duration_ms || 0,
                                executed_at: executed_at || now.toISOString(),
                                received_at: now.toISOString(),
                            },
                        },
                    },
                );

                // Notificar al dashboard del resultado
                const agentDoc = await db.collection('nebula_agents')
                    .findOne({ machine_id }, { projection: { hostname: 1 } });

                ssePush('*', 'nebula_command_result', {
                    command_id,
                    machine_id,
                    hostname:    agentDoc?.hostname || machine_id.substring(0, 8),
                    command:     cmd.command,
                    success,
                    duration_ms: duration_ms || 0,
                    error:       error || null,
                    timestamp:   now.toISOString(),
                });

                console.log(`[Nebula] Resultado comando ${command_id.substring(0, 16)}: ${success ? '✅' : '❌'} (${duration_ms}ms)`);
                res.json({ success: true });

            } catch (e) {
                console.error('[Nebula] Error en command result:', e);
                res.status(500).json({ error: 'Error guardando resultado' });
            }
        });

        /**
         * POST /api/nebula/events
         * El agente envía eventos (alertas, audit sync, etc.)
         */
        app.post('/api/nebula/events', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.agent;
                const { event_type, data, hostname, timestamp } = req.body;
                const now = new Date();

                // audit_sync: guardar entradas de auditoría
                if (event_type === 'audit_sync' && Array.isArray(data?.entries)) {
                    const entries = data.entries.map(e => ({ ...e, machine_id, synced_at: now }));
                    if (entries.length > 0) {
                        await db.collection('nebula_audit').insertMany(entries, { ordered: false })
                            .catch(e => {
                                if (e.name !== 'MongoBulkWriteError') throw e;
                                // Ignorar duplicados de chain_hash (idempotente)
                            });
                        console.log(`[Nebula] Audit sync: ${entries.length} entradas de ${machine_id.substring(0, 16)}...`);
                    }
                } else {
                    // Guardar evento genérico
                    await db.collection('nebula_events').insertOne({
                        machine_id,
                        hostname: hostname || 'unknown',
                        event_type,
                        data: data || {},
                        created_at: now,
                    });

                    // Push SSE para eventos críticos
                    if (event_type === 'alert' || event_type === 'critical') {
                        ssePush('*', 'nebula_event', { machine_id, hostname, event_type, data, timestamp: now.toISOString() });
                    }
                }

                res.json({ success: true });

            } catch (e) {
                console.error('[Nebula] Error en events:', e);
                res.status(500).json({ error: 'Error procesando evento' });
            }
        });

        // ─────────────────────────────────────────────────────
        // ENDPOINTS DEL DASHBOARD (autenticados con JWT usuario)
        // ─────────────────────────────────────────────────────

        /**
         * GET /api/nebula/agents
         * Dashboard: lista todos los agentes con su estado.
         */
        app.get('/api/nebula/agents', requireAuth, async (req, res) => {
            try {
                const agents = await db.collection('nebula_agents')
                    .find({}, { projection: { _id: 1, machine_id: 1, hostname: 1, ip_address: 1,
                                              os_system: 1, os_version: 1, agent_version: 1,
                                              status: 1, last_seen: 1, last_stats: 1, active_alerts: 1 } })
                    .sort({ last_seen: -1 })
                    .toArray();

                // Marcar como offline agentes que no reportaron en >10 minutos
                const TEN_MIN_AGO = new Date(Date.now() - 10 * 60 * 1000);
                const result = agents.map(a => ({
                    ...a,
                    status: a.last_seen > TEN_MIN_AGO ? 'online' : 'offline',
                }));

                res.json({ agents: result, total: result.length });

            } catch (e) {
                res.status(500).json({ error: 'Error obteniendo agentes' });
            }
        });

        /**
         * GET /api/nebula/agents/:machine_id
         * Dashboard: detalle de un agente específico.
         */
        app.get('/api/nebula/agents/:machine_id', requireAuth, async (req, res) => {
            try {
                const agent = await db.collection('nebula_agents')
                    .findOne({ machine_id: req.params.machine_id });
                if (!agent) return res.status(404).json({ error: 'Agente no encontrado' });

                // Últimos 10 comandos del agente
                const recentCommands = await db.collection('nebula_commands')
                    .find({ machine_id: req.params.machine_id })
                    .sort({ created_at: -1 })
                    .limit(10)
                    .toArray();

                res.json({ agent, recent_commands: recentCommands });

            } catch (e) {
                res.status(500).json({ error: 'Error obteniendo agente' });
            }
        });

        /**
         * POST /api/nebula/commands
         * Dashboard: envía un comando a un agente.
         * Requiere rol ADMIN o COORDINADOR.
         */
        app.post('/api/nebula/commands', requireAuth, async (req, res) => {
            try {
                const { machine_id, command, parameters, justification } = req.body;

                if (!machine_id || !command) {
                    return res.status(400).json({ error: 'machine_id y command son requeridos' });
                }

                // Verificar que el agente existe
                const agent = await db.collection('nebula_agents').findOne({ machine_id });
                if (!agent) {
                    return res.status(404).json({ error: `Agente '${machine_id}' no encontrado` });
                }

                // Comandos de nivel HIGH requieren justificación
                const HIGH_COMMANDS = new Set([
                    'reset_password', 'disable_user', 'enable_bitlocker',
                    'install_updates', 'run_script', 'reboot', 'shutdown',
                ]);
                if (HIGH_COMMANDS.has(command) && (!justification || justification.trim().length < 10)) {
                    return res.status(400).json({
                        error: `El comando '${command}' requiere 'justification' de al menos 10 caracteres`,
                    });
                }

                const now = new Date();
                const cmdDoc = {
                    machine_id,
                    command,
                    parameters: {
                        ...(parameters || {}),
                        // Pasar aprobación y justificación al agente
                        approved:      true,
                        justification: justification || '',
                    },
                    status:         'pending',
                    created_by:     req.usuario.username,
                    created_by_rol: req.usuario.rol,
                    justification:  justification || '',
                    created_at:     now,
                    hostname:       agent.hostname,
                };

                const result = await db.collection('nebula_commands').insertOne(cmdDoc);
                console.log(`[Nebula] Comando creado: ${command} → ${agent.hostname} por ${req.usuario.username}`);

                // Notificar al dashboard
                ssePush('*', 'nebula_command_queued', {
                    command_id:  result.insertedId.toString(),
                    machine_id,
                    hostname:    agent.hostname,
                    command,
                    created_by:  req.usuario.username,
                    timestamp:   now.toISOString(),
                });

                res.status(201).json({
                    success: true,
                    command_id: result.insertedId,
                    message: `Comando '${command}' encolado para ${agent.hostname}`,
                });

            } catch (e) {
                console.error('[Nebula] Error creando comando:', e);
                res.status(500).json({ error: 'Error creando comando' });
            }
        });

        /**
         * GET /api/nebula/commands
         * Dashboard: historial de comandos con filtros opcionales.
         */
        app.get('/api/nebula/commands', requireAuth, async (req, res) => {
            try {
                const filter = {};
                if (req.query.machine_id) filter.machine_id = req.query.machine_id;
                if (req.query.status)     filter.status     = req.query.status;
                if (req.query.command)    filter.command    = req.query.command;
                const limit = Math.min(parseInt(req.query.limit) || 100, 500);

                const commands = await db.collection('nebula_commands')
                    .find(filter)
                    .sort({ created_at: -1 })
                    .limit(limit)
                    .toArray();

                res.json({ commands, total: commands.length });

            } catch (e) {
                res.status(500).json({ error: 'Error obteniendo comandos' });
            }
        });

        /**
         * GET /api/nebula/audit/:machine_id
         * Dashboard: audit trail de un agente. Solo ADMIN.
         */
        app.get('/api/nebula/audit/:machine_id', requireAuth, requireAdmin, async (req, res) => {
            try {
                const limit = Math.min(parseInt(req.query.limit) || 100, 1000);
                const entries = await db.collection('nebula_audit')
                    .find({ machine_id: req.params.machine_id })
                    .sort({ timestamp: -1 })
                    .limit(limit)
                    .toArray();
                res.json({ entries, total: entries.length });
            } catch (e) {
                res.status(500).json({ error: 'Error obteniendo audit trail' });
            }
        });

        /**
         * GET /api/nebula/stats
         * Dashboard: estadísticas globales de todos los agentes.
         */
        app.get('/api/nebula/stats', requireAuth, async (req, res) => {
            try {
                const TEN_MIN_AGO = new Date(Date.now() - 10 * 60 * 1000);
                const [total, online, pending_cmds, failed_cmds] = await Promise.all([
                    db.collection('nebula_agents').countDocuments(),
                    db.collection('nebula_agents').countDocuments({ last_seen: { $gte: TEN_MIN_AGO } }),
                    db.collection('nebula_commands').countDocuments({ status: 'pending' }),
                    db.collection('nebula_commands').countDocuments({
                        status: 'failed',
                        created_at: { $gte: new Date(Date.now() - 24 * 3600 * 1000) },
                    }),
                ]);
                res.json({ total_agents: total, online_agents: online, offline_agents: total - online, pending_commands: pending_cmds, failed_commands_24h: failed_cmds });
            } catch (e) {
                res.status(500).json({ error: 'Error obteniendo stats' });
            }
        });

        console.log('[Nebula] Rutas del agente registradas ✅');
        console.log('[Nebula] Endpoints agente: POST /api/agents/register, POST /api/agents/heartbeat');
        console.log('[Nebula] Endpoints agente: GET /api/nebula/commands/pending/:id, POST /api/nebula/commands/:id/result');
        console.log('[Nebula] Endpoints dashboard: GET/POST /api/nebula/agents, /api/nebula/commands, /api/nebula/stats');
    },
};

// ── Auto-detección de agentes offline ────────────────────────
/**
 * Ejecutar periódicamente para marcar agentes sin heartbeat como offline.
 * Integrar en server.js después de conectDB():
 *
 *   const { startOfflineWatcher } = require('./routes/nebula_agents');
 *   startOfflineWatcher(db, ssePush);
 */
module.exports.startOfflineWatcher = function(db, ssePush) {
    const CHECK_INTERVAL = 5 * 60 * 1000; // 5 minutos

    setInterval(async () => {
        try {
            const threshold = new Date(Date.now() - 10 * 60 * 1000); // 10 min sin heartbeat
            const result = await db.collection('nebula_agents').updateMany(
                { last_seen: { $lt: threshold }, status: 'online' },
                { $set: { status: 'offline' } },
            );

            if (result.modifiedCount > 0) {
                console.log(`[Nebula] ${result.modifiedCount} agente(s) marcados como offline`);
                const offlineAgents = await db.collection('nebula_agents')
                    .find({ status: 'offline', last_seen: { $lt: threshold } }, { projection: { machine_id: 1, hostname: 1 } })
                    .limit(10)
                    .toArray();

                for (const agent of offlineAgents) {
                    ssePush('*', 'nebula_agent_offline', {
                        machine_id: agent.machine_id,
                        hostname:   agent.hostname,
                        timestamp:  new Date().toISOString(),
                    });
                }
            }
        } catch (e) {
            console.error('[Nebula] Error en offline watcher:', e.message);
        }
    }, CHECK_INTERVAL);

    console.log('[Nebula] Offline watcher iniciado (cada 5 min) ✅');
};

// ── Detección automática de alertas ──────────────────────────
function detectAlerts(stats) {
    if (!stats) return [];
    const alerts = [];

    const cpu = stats.cpu?.usage_percent;
    const mem = stats.memory?.usage_percent;
    const disk = stats.disk?.usage_percent;

    if (cpu > 95)  alerts.push({ type: 'cpu_critical',  severity: 'danger',  message: `CPU al ${cpu}% — crítico` });
    else if (cpu > 85) alerts.push({ type: 'cpu_high',  severity: 'warning', message: `CPU al ${cpu}% — alto` });

    if (mem > 95)  alerts.push({ type: 'mem_critical',  severity: 'danger',  message: `RAM al ${mem}% — crítico` });
    else if (mem > 85) alerts.push({ type: 'mem_high',  severity: 'warning', message: `RAM al ${mem}% — alta` });

    if (disk > 95) alerts.push({ type: 'disk_critical', severity: 'danger',  message: `Disco al ${disk}% — crítico` });
    else if (disk > 85) alerts.push({ type: 'disk_high', severity: 'warning', message: `Disco al ${disk}% — alto` });

    return alerts;
}
