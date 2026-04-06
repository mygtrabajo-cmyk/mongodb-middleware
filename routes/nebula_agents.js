// ============================================================
// NEBULA AGENT — Rutas para el backend MYG Telecom v1.1.0
//
// Cambios v1.1.0:
//   [FILE-1] POST /api/nebula/deploy-file
//            Sube un archivo al backend y crea comando de deploy
//            en el/los agente(s) destino
//   [FILE-2] GET  /api/nebula/files/:file_id/download
//            Agente descarga el archivo via URL firmada
//   [FILE-3] POST /api/nebula/execute-script
//            Crea comando run_script con privilegios de administrador
//            opcionalmente después de un deploy_file
// ============================================================

const { ObjectId } = require('mongodb');
const crypto       = require('crypto');

const NEBULA_AGENT_SECRET = process.env.NEBULA_AGENT_SECRET || 'nebula-default-secret-CHANGE-IN-PRODUCTION';
const MAX_FILE_SIZE_MB    = 50;  // Límite de archivo deployable

// ── Middleware autenticación del agente ───────────────────────
function requireAgentAuth(req, res, next) {
    const header = req.headers.authorization || '';
    if (!header.startsWith('Agent '))
        return res.status(401).json({ error: 'Token de agente no proporcionado' });

    const credentials = header.slice(6); // quita "Agent "
    const sepIdx = credentials.indexOf(':');
    if (sepIdx === -1)
        return res.status(401).json({
            error: 'Formato inválido. Esperado: Agent {machine_id}:{token}'
        });

    const machine_id = credentials.slice(0, sepIdx);
    const token      = credentials.slice(sepIdx + 1);

    const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!UUID_RE.test(machine_id))
        return res.status(401).json({ error: 'machine_id con formato inválido' });

    // Calcular token esperado
    const expectedToken = crypto
        .createHmac('sha256', NEBULA_AGENT_SECRET)
        .update(machine_id)
        .digest('hex');

    // [FIX] timingSafeEqual LANZA excepción si los buffers tienen distinta longitud.
    // Verificar longitud ANTES para evitar crash no capturado → 500 en lugar de 401.
    let tokenValid = false;
    try {
        const bufToken    = Buffer.from(token,         'hex');
        const bufExpected = Buffer.from(expectedToken, 'hex');

        // Doble check: longitud + valor (timing-safe)
        tokenValid = bufToken.length === bufExpected.length &&
                     crypto.timingSafeEqual(bufToken, bufExpected);
    } catch (e) {
        // token tiene caracteres no-hex → inválido
        tokenValid = false;
    }

    if (!tokenValid) {
        console.warn(
            `[Nebula] ❌ Auth fallida: machine_id=${machine_id.substring(0, 16)}... ` +
            `token_prefix=${token.substring(0, 8)}... ` +
            `expected_prefix=${expectedToken.substring(0, 8)}... ` +
            `secret_hint=${NEBULA_AGENT_SECRET.substring(0, 8)}...`
        );
        return res.status(401).json({ error: 'Token de agente inválido' });
    }

    req.agent = { machine_id, token };
    next();
}

// ── Inicializar índices MongoDB ───────────────────────────────
async function initIndexes(db) {
    const idx = async (col, spec, opts = {}) => {
        try { await db.collection(col).createIndex(spec, opts); }
        catch (e) { console.warn(`[Nebula] Índice ${col}: ${e.message?.split('\n')[0]}`); }
    };

    await idx('nebula_agents',   { machine_id: 1 }, { unique: true, name: 'nebula_agent_id_unique' });
    await idx('nebula_agents',   { last_seen: -1 },  { name: 'nebula_agent_last_seen' });
    await idx('nebula_agents',   { status: 1 },      { name: 'nebula_agent_status' });
    await idx('nebula_commands', { machine_id: 1, status: 1 }, { name: 'nebula_cmd_agent_status' });
    await idx('nebula_commands', { created_at: -1 },  { name: 'nebula_cmd_fecha' });
    await idx('nebula_events',   { machine_id: 1, created_at: -1 }, { name: 'nebula_evt_agent_fecha' });
    await idx('nebula_events',   { created_at: 1 }, { expireAfterSeconds: 30 * 24 * 3600, name: 'nebula_evt_ttl' });
    await idx('nebula_audit',    { machine_id: 1, timestamp: -1 }, { name: 'nebula_audit_agent_fecha' });
    await idx('nebula_audit',    { chain_hash: 1 }, { unique: true, name: 'nebula_audit_chain_unique' });
    // [FILE-1] Índices para archivos deployables
    await idx('nebula_files',    { uploaded_by: 1, created_at: -1 }, { name: 'nebula_files_user_fecha' });
    await idx('nebula_files',    { created_at: 1 }, { expireAfterSeconds: 7 * 24 * 3600, name: 'nebula_files_ttl_7d' });
    await idx('nebula_zones',  { area: 1, name: 1 }, { name: 'nebula_zones_area_name' });
    await idx('nebula_zones',  { created_at: -1 },   { name: 'nebula_zones_fecha' });
    await idx('nebula_agents', { area: 1, zone: 1 }, { name: 'nebula_agents_area_zone' });

    console.log('[Nebula] Índices MongoDB inicializados ✅');
}

// ── Detección automática de alertas ──────────────────────────
function detectAlerts(stats) {
    if (!stats) return [];
    const alerts = [];
    const cpu  = stats.cpu?.usage_percent;
    const mem  = stats.memory?.usage_percent;
    const disk = stats.disk?.usage_percent;
    if (cpu  > 95) alerts.push({ type: 'cpu_critical',  severity: 'danger',  message: `CPU al ${cpu}% — crítico` });
    else if (cpu  > 85) alerts.push({ type: 'cpu_high',  severity: 'warning', message: `CPU al ${cpu}% — alto` });
    if (mem  > 95) alerts.push({ type: 'mem_critical',  severity: 'danger',  message: `RAM al ${mem}% — crítico` });
    else if (mem  > 85) alerts.push({ type: 'mem_high',  severity: 'warning', message: `RAM al ${mem}% — alta` });
    if (disk > 95) alerts.push({ type: 'disk_critical', severity: 'danger',  message: `Disco al ${disk}% — crítico` });
    else if (disk > 85) alerts.push({ type: 'disk_high', severity: 'warning', message: `Disco al ${disk}% — alto` });
    return alerts;
}

// ── Módulo principal ──────────────────────────────────────────
module.exports = {

    async init(app, db, ssePush, requireAuth, requireAdmin) {
        await initIndexes(db);

        // ═══════════════════════════════════════════════════
        // ENDPOINTS DEL AGENTE (Authorization: Agent ...)
        // ═══════════════════════════════════════════════════

        // POST /api/agents/register
        app.post('/api/agents/register', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.agent;
                const { hostname, ip_address, mac_address, os_system, os_version, os_release, architecture, agent_version, agent_name } = req.body;
                const now = new Date();
                await db.collection('nebula_agents').findOneAndUpdate(
                    { machine_id },
                    { $set: { machine_id, hostname: hostname||'unknown', ip_address: ip_address||'unknown', mac_address: mac_address||'unknown', os_system: os_system||'unknown', os_version: os_version||'unknown', os_release: os_release||'unknown', architecture: architecture||'unknown', agent_name: agent_name||'Nebula', agent_version: agent_version||'1.0.0', status: 'online', last_seen: now },
                      $setOnInsert: { registered_at: now, first_seen: now } },
                    { upsert: true, returnDocument: 'after' }
                );
                ssePush('*', 'nebula_agent_online', { machine_id, hostname: hostname||'unknown', status: 'online', agent_version, timestamp: now.toISOString() });
                console.log(`[Nebula] Agente registrado: ${hostname} (${machine_id.substring(0, 16)}...)`);
                res.json({ success: true, server_time: now.toISOString() });
            } catch (e) { console.error('[Nebula] Error register:', e); res.status(500).json({ error: 'Error registrando agente' }); }
        });

        // POST /api/agents/heartbeat
        app.post('/api/agents/heartbeat', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.agent;
                const { hostname, stats } = req.body;
                const now    = new Date();
                const alerts = detectAlerts(stats);
                await db.collection('nebula_agents').updateOne(
                    { machine_id },
                    { $set: { last_seen: now, status: 'online', last_stats: stats||{}, active_alerts: alerts } },
                    { upsert: true }
                );
                ssePush('*', 'nebula_heartbeat', { machine_id, hostname: hostname||machine_id.substring(0,8), stats, alerts, timestamp: now.toISOString() });
                if (alerts.length > 0) {
                    for (const alert of alerts) {
                        await db.collection('notificaciones').insertOne({ titulo: `⚠️ Nebula: ${hostname}`, mensaje: alert.message, tipo: alert.severity, usuario_destino: '*', creadaPor: 'nebula_agent', leida: false, createdAt: now, meta: { machine_id, alert_type: alert.type } });
                        ssePush('*', 'notificacion', { titulo: `⚠️ Nebula: ${hostname}`, mensaje: alert.message, tipo: alert.severity });
                    }
                }
                res.json({ success: true, server_time: now.toISOString(), alerts_detected: alerts.length });
            } catch (e) { console.error('[Nebula] Error heartbeat:', e); res.status(500).json({ error: 'Error heartbeat' }); }
        });

        // GET /api/nebula/commands/pending/:machine_id
        app.get('/api/nebula/commands/pending/:machine_id', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.params;
                if (machine_id !== req.agent.machine_id)
                    return res.status(403).json({ error: 'No puedes obtener comandos de otro agente' });
                const commands = await db.collection('nebula_commands')
                    .find({ machine_id, status: 'pending' })
                    .sort({ created_at: 1 })
                    .limit(10)
                    .toArray();
                if (commands.length > 0) {
                    await db.collection('nebula_commands').updateMany(
                        { _id: { $in: commands.map(c => c._id) } },
                        { $set: { status: 'in_progress', dispatched_at: new Date() } }
                    );
                    console.log(`[Nebula] ${commands.length} comando(s) despachados → ${machine_id.substring(0,16)}...`);
                }
                res.json(commands);
            } catch (e) { console.error('[Nebula] Error pending commands:', e); res.status(500).json({ error: 'Error comandos' }); }
        });

        // POST /api/nebula/commands/:command_id/result
        app.post('/api/nebula/commands/:command_id/result', requireAgentAuth, async (req, res) => {
            try {
                const { command_id } = req.params;
                const { machine_id } = req.agent;
                const { success, output, error, duration_ms, executed_at } = req.body;
                if (!ObjectId.isValid(command_id))
                    return res.status(400).json({ error: `command_id inválido: "${command_id}"` });
                const cmd = await db.collection('nebula_commands').findOne({ _id: new ObjectId(command_id), machine_id });
                if (!cmd) return res.status(404).json({ error: 'Comando no encontrado' });
                const now = new Date();
                await db.collection('nebula_commands').updateOne(
                    { _id: new ObjectId(command_id) },
                    { $set: { status: success ? 'completed' : 'failed', result: { success, output: (output||'').substring(0,10000), error: error||null, duration_ms: duration_ms||0, executed_at: executed_at||now.toISOString(), received_at: now.toISOString() } } }
                );
                const agentDoc = await db.collection('nebula_agents').findOne({ machine_id }, { projection: { hostname: 1 } });
                ssePush('*', 'nebula_command_result', { command_id, machine_id, hostname: agentDoc?.hostname||machine_id.substring(0,8), command: cmd.command, success, duration_ms: duration_ms||0, error: error||null, timestamp: now.toISOString() });
                console.log(`[Nebula] Resultado ${command_id.substring(0,16)}: ${success ? '✅' : '❌'} (${duration_ms}ms)`);
                res.json({ success: true });
            } catch (e) { console.error('[Nebula] Error command result:', e); res.status(500).json({ error: 'Error guardando resultado' }); }
        });

        // POST /api/nebula/events
        app.post('/api/nebula/events', requireAgentAuth, async (req, res) => {
            try {
                const { machine_id } = req.agent;
                const { event_type, data, hostname } = req.body;
                const now = new Date();
                if (event_type === 'audit_sync' && Array.isArray(data?.entries)) {
                    if (data.entries.length > 0) {
                        await db.collection('nebula_audit')
                            .insertMany(data.entries.map(e => ({ ...e, machine_id, synced_at: now })), { ordered: false })
                            .catch(e => { if (e.name !== 'MongoBulkWriteError') throw e; });
                        console.log(`[Nebula] Audit sync: ${data.entries.length} entradas de ${machine_id.substring(0,16)}...`);
                    }
                } else {
                    await db.collection('nebula_events').insertOne({ machine_id, hostname: hostname||'unknown', event_type, data: data||{}, created_at: now });
                    if (['alert','critical','windows_event_security'].includes(event_type))
                        ssePush('*', 'nebula_event', { machine_id, hostname, event_type, data, timestamp: now.toISOString() });
                }
                res.json({ success: true });
            } catch (e) { console.error('[Nebula] Error events:', e); res.status(500).json({ error: 'Error evento' }); }
        });

        // [FILE-2] GET /api/nebula/files/:file_id/download — el agente descarga el archivo
        app.get('/api/nebula/files/:file_id/download', requireAgentAuth, async (req, res) => {
            try {
                const { file_id } = req.params;
                if (!ObjectId.isValid(file_id))
                    return res.status(400).json({ error: 'file_id inválido' });
                const fileDoc = await db.collection('nebula_files').findOne({ _id: new ObjectId(file_id) });
                if (!fileDoc) return res.status(404).json({ error: 'Archivo no encontrado o expirado' });
                const fileBuffer = Buffer.from(fileDoc.data_b64, 'base64');
                res.setHeader('Content-Type', fileDoc.mime_type || 'application/octet-stream');
                res.setHeader('Content-Disposition', `attachment; filename="${fileDoc.filename}"`);
                res.setHeader('Content-Length', fileBuffer.length);
                res.send(fileBuffer);
                console.log(`[Nebula] Archivo descargado: ${fileDoc.filename} por ${req.agent.machine_id.substring(0,16)}...`);
            } catch (e) { console.error('[Nebula] Error file download:', e); res.status(500).json({ error: 'Error descargando archivo' }); }
        });
        // ─────────────────────────────────────────────────────────────
        // [ZON-1] GET /api/nebula/zones — lista todas las zonas
        // ─────────────────────────────────────────────────────────────
        app.get('/api/nebula/zones', requireAuth, async (req, res) => {
            try {
                const filter = {};
                if (req.query.area) filter.area = req.query.area;
                const zones = await db.collection('nebula_zones')
                    .find(filter)
                    .sort({ area: 1, name: 1 })
                    .toArray();
                res.json({ zones, total: zones.length });
            } catch (e) {
                console.error('[Nebula] Error GET zones:', e);
                res.status(500).json({ error: 'Error obteniendo zonas' });
            }
        });
         
        // ─────────────────────────────────────────────────────────────
        // [ZON-2] POST /api/nebula/zones — crear zona
        // Requiere ADMIN o COORDINADOR
        // ─────────────────────────────────────────────────────────────
        app.post('/api/nebula/zones', requireAuth, async (req, res) => {
            try {
                const { name, area, description } = req.body;
                if (!name?.trim()) return res.status(400).json({ error: 'name requerido' });
         
                // Solo roles privilegiados pueden crear zonas
                const rolesPermitidos = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
                if (!rolesPermitidos.includes(req.usuario.rol))
                    return res.status(403).json({ error: 'Sin permisos para crear zonas' });
         
                // Verificar duplicado
                const existe = await db.collection('nebula_zones').findOne({ name: name.trim(), area });
                if (existe) return res.status(409).json({ error: `La zona "${name}" ya existe en ${area}` });
         
                const doc = {
                    name:        name.trim(),
                    area:        area || 'Sistemas',
                    description: description?.trim() || '',
                    created_by:  req.usuario.username,
                    created_at:  new Date(),
                };
                const result = await db.collection('nebula_zones').insertOne(doc);
                console.log(`[Nebula] Zona creada: ${name} (${area}) por ${req.usuario.username}`);
                res.status(201).json({ success: true, zone: { ...doc, _id: result.insertedId } });
         
            } catch (e) {
                console.error('[Nebula] Error POST zones:', e);
                res.status(500).json({ error: 'Error creando zona' });
            }
        });
         
        // ─────────────────────────────────────────────────────────────
        // [ZON-3] DELETE /api/nebula/zones/:id — eliminar zona
        // ─────────────────────────────────────────────────────────────
        app.delete('/api/nebula/zones/:id', requireAuth, async (req, res) => {
            try {
                const { id } = req.params;
                if (!ObjectId.isValid(id)) return res.status(400).json({ error: 'ID inválido' });
         
                const rolesPermitidos = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
                if (!rolesPermitidos.includes(req.usuario.rol))
                    return res.status(403).json({ error: 'Sin permisos' });
         
                const zone = await db.collection('nebula_zones').findOne({ _id: new ObjectId(id) });
                if (!zone) return res.status(404).json({ error: 'Zona no encontrada' });
         
                // Quitar la zona de todos los agentes que la tenían asignada
                const updated = await db.collection('nebula_agents').updateMany(
                    { zone: zone.name },
                    { $unset: { zone: '' } }
                );
         
                await db.collection('nebula_zones').deleteOne({ _id: new ObjectId(id) });
                console.log(`[Nebula] Zona eliminada: ${zone.name} (${updated.modifiedCount} agentes actualizados)`);
                res.json({ success: true, agents_updated: updated.modifiedCount });
         
            } catch (e) {
                console.error('[Nebula] Error DELETE zones:', e);
                res.status(500).json({ error: 'Error eliminando zona' });
            }
        });
         
        // ─────────────────────────────────────────────────────────────
        // [ZON-4] PATCH /api/nebula/agents/:machine_id/zone
        // Asignar área y zona a un agente desde el dashboard
        // ─────────────────────────────────────────────────────────────
        app.patch('/api/nebula/agents/:machine_id/zone', requireAuth, async (req, res) => {
            try {
                const { machine_id } = req.params;
                const { area, zone }  = req.body;
         
                const rolesPermitidos = ['ADMIN', 'COORDINADOR', 'GERENTE_OPERACIONES'];
                if (!rolesPermitidos.includes(req.usuario.rol))
                    return res.status(403).json({ error: 'Sin permisos para asignar zona' });
         
                const AREAS_VALIDAS = ['Sistemas','Mantenimiento','Credito','Logistica','CoordinacionATT','Sin área'];
                if (area && !AREAS_VALIDAS.includes(area))
                    return res.status(400).json({ error: `Área inválida: ${area}` });
         
                const updates = { updated_at: new Date(), updated_by: req.usuario.username };
                if (area !== undefined) updates.area = area;
                if (zone !== undefined) updates.zone = zone?.trim() || null;
         
                const result = await db.collection('nebula_agents').updateOne(
                    { machine_id },
                    { $set: updates }
                );
                if (result.matchedCount === 0)
                    return res.status(404).json({ error: 'Agente no encontrado' });
         
                // Notificar al dashboard vía SSE
                ssePush('*', 'nebula_agent_zone_updated', { machine_id, area, zone, updated_by: req.usuario.username });
         
                console.log(`[Nebula] Zona asignada: ${machine_id.substring(0,16)} → ${area} / ${zone} por ${req.usuario.username}`);
                res.json({ success: true });
         
            } catch (e) {
                console.error('[Nebula] Error PATCH zone:', e);
                res.status(500).json({ error: 'Error asignando zona' });
            }
        });
         
        // ─────────────────────────────────────────────────────────────
        // [ZON-5] GET /api/nebula/agents/by-zone — agrupar agentes
        // Retorna agentes agrupados por área + zona para el panel
        // ─────────────────────────────────────────────────────────────
        app.get('/api/nebula/agents/by-zone', requireAuth, async (req, res) => {
            try {
                const TEN_MIN_AGO = new Date(Date.now() - 10 * 60 * 1000);
                const agents = await db.collection('nebula_agents')
                    .find({}, { projection: { _id:1, machine_id:1, hostname:1, ip_address:1,
                                              os_system:1, agent_version:1, status:1,
                                              last_seen:1, last_stats:1, active_alerts:1,
                                              area:1, zone:1, registered_at:1 } })
                    .sort({ area: 1, zone: 1, hostname: 1 })
                    .toArray();
         
                // Normalizar status
                const normalized = agents.map(a => ({
                    ...a,
                    status: a.last_seen > TEN_MIN_AGO ? 'online' : 'offline',
                    area:   a.area || 'Sin área',
                    zone:   a.zone || 'Sin zona',
                }));
         
                // Agrupar
                const grouped = {};
                for (const agent of normalized) {
                    const key = `${agent.area}||${agent.zone}`;
                    if (!grouped[key]) {
                        grouped[key] = {
                            area:    agent.area,
                            zone:    agent.zone,
                            agents:  [],
                            online:  0,
                            offline: 0,
                        };
                    }
                    grouped[key].agents.push(agent);
                    agent.status === 'online' ? grouped[key].online++ : grouped[key].offline++;
                }
         
                const groups = Object.values(grouped).sort((a, b) =>
                    a.area.localeCompare(b.area) || a.zone.localeCompare(b.zone)
                );
         
                res.json({
                    groups,
                    total_agents:  normalized.length,
                    total_online:  normalized.filter(a => a.status === 'online').length,
                    total_offline: normalized.filter(a => a.status === 'offline').length,
                });
         
            } catch (e) {
                console.error('[Nebula] Error agents/by-zone:', e);
                res.status(500).json({ error: 'Error obteniendo agentes por zona' });
            }
        });

        // ═══════════════════════════════════════════════════
        // ENDPOINTS DEL DASHBOARD (Authorization: Bearer JWT)
        // ═══════════════════════════════════════════════════

        // GET /api/nebula/agents
        app.get('/api/nebula/agents', requireAuth, async (req, res) => {
            try {
                const agents = await db.collection('nebula_agents')
                    .find({}, { projection: { _id:1, machine_id:1, hostname:1, ip_address:1, os_system:1, os_version:1, agent_version:1, status:1, last_seen:1, last_stats:1, active_alerts:1, registered_at:1 } })
                    .sort({ last_seen: -1 })
                    .toArray();
                const TEN_MIN_AGO = new Date(Date.now() - 10 * 60 * 1000);
                res.json({ agents: agents.map(a => ({ ...a, status: a.last_seen > TEN_MIN_AGO ? 'online' : 'offline' })), total: agents.length });
            } catch (e) { res.status(500).json({ error: 'Error obteniendo agentes' }); }
        });

        // GET /api/nebula/agents/:machine_id
        app.get('/api/nebula/agents/:machine_id', requireAuth, async (req, res) => {
            try {
                const agent = await db.collection('nebula_agents').findOne({ machine_id: req.params.machine_id });
                if (!agent) return res.status(404).json({ error: 'Agente no encontrado' });
                const recentCommands = await db.collection('nebula_commands')
                    .find({ machine_id: req.params.machine_id })
                    .sort({ created_at: -1 }).limit(20).toArray();
                const TEN_MIN_AGO = new Date(Date.now() - 10 * 60 * 1000);
                res.json({ agent: { ...agent, status: agent.last_seen > TEN_MIN_AGO ? 'online' : 'offline' }, recent_commands: recentCommands });
            } catch (e) { res.status(500).json({ error: 'Error obteniendo agente' }); }
        });

        // POST /api/nebula/commands — enviar comando desde dashboard
        app.post('/api/nebula/commands', requireAuth, async (req, res) => {
            try {
                const { machine_id, command, parameters, justification } = req.body;
                if (!machine_id || !command)
                    return res.status(400).json({ error: 'machine_id y command son requeridos' });
                const agent = await db.collection('nebula_agents').findOne({ machine_id });
                if (!agent) return res.status(404).json({ error: `Agente '${machine_id}' no encontrado` });

                const HIGH_COMMANDS = new Set(['reset_password','disable_user','enable_bitlocker','install_updates','run_script','reboot','shutdown','deploy_file']);
                if (HIGH_COMMANDS.has(command) && (!justification || justification.trim().length < 10))
                    return res.status(400).json({ error: `'${command}' requiere justification de al menos 10 caracteres` });

                const now = new Date();
                const cmdDoc = { machine_id, command, parameters: { ...(parameters||{}), approved: true, justification: justification||'' }, status: 'pending', created_by: req.usuario.username, created_by_rol: req.usuario.rol, justification: justification||'', created_at: now, hostname: agent.hostname };
                const result = await db.collection('nebula_commands').insertOne(cmdDoc);
                console.log(`[Nebula] Comando: ${command} → ${agent.hostname} por ${req.usuario.username}`);
                ssePush('*', 'nebula_command_queued', { command_id: result.insertedId.toString(), machine_id, hostname: agent.hostname, command, created_by: req.usuario.username, timestamp: now.toISOString() });
                res.status(201).json({ success: true, command_id: result.insertedId, message: `Comando '${command}' encolado para ${agent.hostname}` });
            } catch (e) { console.error('[Nebula] Error comando:', e); res.status(500).json({ error: 'Error creando comando' }); }
        });

        // GET /api/nebula/commands — historial
        app.get('/api/nebula/commands', requireAuth, async (req, res) => {
            try {
                const filter = {};
                if (req.query.machine_id) filter.machine_id = req.query.machine_id;
                if (req.query.status)     filter.status     = req.query.status;
                if (req.query.command)    filter.command    = req.query.command;
                const limit = Math.min(parseInt(req.query.limit)||100, 500);
                const commands = await db.collection('nebula_commands').find(filter).sort({ created_at: -1 }).limit(limit).toArray();
                res.json({ commands, total: commands.length });
            } catch (e) { res.status(500).json({ error: 'Error obteniendo comandos' }); }
        });

        // GET /api/nebula/stats
        app.get('/api/nebula/stats', requireAuth, async (req, res) => {
            try {
                const TEN_MIN_AGO = new Date(Date.now() - 10 * 60 * 1000);
                const [total, online, pending_cmds, failed_cmds, events_24h] = await Promise.all([
                    db.collection('nebula_agents').countDocuments(),
                    db.collection('nebula_agents').countDocuments({ last_seen: { $gte: TEN_MIN_AGO } }),
                    db.collection('nebula_commands').countDocuments({ status: 'pending' }),
                    db.collection('nebula_commands').countDocuments({ status: 'failed', created_at: { $gte: new Date(Date.now() - 24*3600*1000) } }),
                    db.collection('nebula_events').countDocuments({ created_at: { $gte: new Date(Date.now() - 24*3600*1000) } }),
                ]);
                res.json({ total_agents: total, online_agents: online, offline_agents: total-online, pending_commands: pending_cmds, failed_commands_24h: failed_cmds, events_24h });
            } catch (e) { res.status(500).json({ error: 'Error stats' }); }
        });

        // GET /api/nebula/audit/:machine_id — solo ADMIN
        app.get('/api/nebula/audit/:machine_id', requireAuth, requireAdmin, async (req, res) => {
            try {
                const limit = Math.min(parseInt(req.query.limit)||100, 1000);
                const entries = await db.collection('nebula_audit')
                    .find({ machine_id: req.params.machine_id })
                    .sort({ timestamp: -1 }).limit(limit).toArray();
                res.json({ entries, total: entries.length });
            } catch (e) { res.status(500).json({ error: 'Error audit trail' }); }
        });

        // ─────────────────────────────────────────────────────────
        // [FILE-1] POST /api/nebula/deploy-file
        // Dashboard sube un archivo para desplegarlo en endpoint(s)
        // ─────────────────────────────────────────────────────────
        app.post('/api/nebula/deploy-file', requireAuth, async (req, res) => {
            try {
                const {
                    machine_ids,       // string[] — agentes destino
                    filename,          // nombre del archivo
                    data_b64,          // contenido en base64
                    mime_type,         // MIME type
                    target_path,       // ruta destino en el endpoint: "C:\\Scripts\\setup.exe"
                    execute_after,     // boolean: ejecutar el archivo después del deploy
                    run_as_admin,      // boolean: ejecutar como administrador
                    script_args,       // string: argumentos para el ejecutable
                    justification,     // string: justificación obligatoria
                    sha256_expected,   // string (opcional): hash esperado del archivo
                } = req.body;

                // Validaciones
                if (!machine_ids || !Array.isArray(machine_ids) || machine_ids.length === 0)
                    return res.status(400).json({ error: 'machine_ids requerido (array de machine_id)' });
                if (!filename || !data_b64)
                    return res.status(400).json({ error: 'filename y data_b64 son requeridos' });
                if (!target_path)
                    return res.status(400).json({ error: 'target_path es requerido (ej: C:\\\\Scripts\\\\mi_archivo.exe)' });
                if (!justification || justification.trim().length < 10)
                    return res.status(400).json({ error: 'justification de al menos 10 caracteres es requerida' });

                // Validar tamaño
                const fileBytes = Buffer.from(data_b64, 'base64').length;
                const fileMB    = fileBytes / (1024 * 1024);
                if (fileMB > MAX_FILE_SIZE_MB)
                    return res.status(400).json({ error: `Archivo demasiado grande: ${fileMB.toFixed(1)}MB. Máximo: ${MAX_FILE_SIZE_MB}MB` });

                // Calcular SHA-256 del archivo
                const sha256_actual = crypto.createHash('sha256').update(Buffer.from(data_b64, 'base64')).digest('hex');
                if (sha256_expected && sha256_expected.toLowerCase() !== sha256_actual)
                    return res.status(400).json({ error: 'SHA-256 del archivo no coincide con el esperado' });

                // Verificar que todos los agentes existen
                const agents = await db.collection('nebula_agents')
                    .find({ machine_id: { $in: machine_ids } })
                    .toArray();
                const foundIds  = new Set(agents.map(a => a.machine_id));
                const notFound  = machine_ids.filter(id => !foundIds.has(id));
                if (notFound.length > 0)
                    return res.status(404).json({ error: `Agentes no encontrados: ${notFound.join(', ')}` });

                const now = new Date();

                // Guardar el archivo en MongoDB (TTL: 7 días)
                const fileDoc = { filename, data_b64, mime_type: mime_type||'application/octet-stream', size_bytes: fileBytes, sha256: sha256_actual, target_path, uploaded_by: req.usuario.username, uploaded_at: now, created_at: now };
                const fileResult = await db.collection('nebula_files').insertOne(fileDoc);
                const file_id = fileResult.insertedId.toString();

                // Crear un comando deploy_file por cada agente destino
                const cmds = machine_ids.map(machine_id => ({
                    machine_id,
                    command:     'deploy_file',
                    parameters: {
                        file_id,
                        filename,
                        target_path,
                        sha256:        sha256_actual,
                        execute_after: !!execute_after,
                        run_as_admin:  !!run_as_admin,
                        script_args:   script_args || '',
                        approved:      true,
                        justification: justification.trim(),
                    },
                    status:          'pending',
                    created_by:      req.usuario.username,
                    created_by_rol:  req.usuario.rol,
                    justification:   justification.trim(),
                    created_at:      now,
                    hostname:        agents.find(a => a.machine_id === machine_id)?.hostname || machine_id.substring(0,8),
                }));

                const insertResult = await db.collection('nebula_commands').insertMany(cmds);

                // Push SSE para cada agente
                for (const agent of agents) {
                    ssePush('*', 'nebula_command_queued', {
                        command_id:  Object.values(insertResult.insertedIds)[machine_ids.indexOf(agent.machine_id)]?.toString(),
                        machine_id:  agent.machine_id,
                        hostname:    agent.hostname,
                        command:     'deploy_file',
                        filename,
                        created_by:  req.usuario.username,
                        timestamp:   now.toISOString(),
                    });
                }

                console.log(`[Nebula] Deploy: ${filename} (${fileMB.toFixed(2)}MB) → ${machine_ids.length} equipo(s) por ${req.usuario.username}`);
                res.status(201).json({
                    success:       true,
                    file_id,
                    filename,
                    size_mb:       parseFloat(fileMB.toFixed(2)),
                    sha256:        sha256_actual,
                    agents_count:  machine_ids.length,
                    commands_ids:  Object.values(insertResult.insertedIds).map(id => id.toString()),
                    message:       `Archivo '${filename}' encolado para deploy en ${machine_ids.length} equipo(s)`,
                });

            } catch (e) { console.error('[Nebula] Error deploy-file:', e); res.status(500).json({ error: 'Error en deploy de archivo' }); }
        });

        // GET /api/nebula/files — lista archivos deployados
        app.get('/api/nebula/files', requireAuth, async (req, res) => {
            try {
                const limit = Math.min(parseInt(req.query.limit)||50, 200);
                const files = await db.collection('nebula_files')
                    .find({}, { projection: { data_b64: 0 } })  // excluir base64 del listado
                    .sort({ created_at: -1 }).limit(limit).toArray();
                res.json({ files, total: files.length });
            } catch (e) { res.status(500).json({ error: 'Error obteniendo archivos' }); }
        });

        console.log('[Nebula] Rutas registradas ✅');
        console.log('[Nebula] Agente:    POST /api/agents/register|heartbeat');
        console.log('[Nebula] Agente:    GET  /api/nebula/commands/pending/:id');
        console.log('[Nebula] Agente:    POST /api/nebula/commands/:id/result');
        console.log('[Nebula] Agente:    GET  /api/nebula/files/:id/download');
        console.log('[Nebula] Dashboard: GET  /api/nebula/agents|stats|commands|audit');
        console.log('[Nebula] Dashboard: POST /api/nebula/commands|deploy-file');
    },

    // ── Watcher de agentes offline ─────────────────────────
    startOfflineWatcher(db, ssePush) {
        setInterval(async () => {
            try {
                const threshold = new Date(Date.now() - 10 * 60 * 1000);
                const result = await db.collection('nebula_agents').updateMany(
                    { last_seen: { $lt: threshold }, status: 'online' },
                    { $set: { status: 'offline' } }
                );
                if (result.modifiedCount > 0) {
                    console.log(`[Nebula] ${result.modifiedCount} agente(s) → offline`);
                    const offlineAgents = await db.collection('nebula_agents')
                        .find({ status: 'offline', last_seen: { $lt: threshold } }, { projection: { machine_id:1, hostname:1 } })
                        .limit(10).toArray();
                    for (const a of offlineAgents)
                        ssePush('*', 'nebula_agent_offline', { machine_id: a.machine_id, hostname: a.hostname, timestamp: new Date().toISOString() });
                }
            } catch (e) { console.error('[Nebula] Error offline watcher:', e.message); }
        }, 5 * 60 * 1000);
        console.log('[Nebula] Offline watcher iniciado (cada 5 min) ✅');
    },
};
