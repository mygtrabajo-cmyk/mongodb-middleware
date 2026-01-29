// ========== ENDPOINTS DE MONITOREO PARA CLOUDFLARE WORKER ==========
// Agregar estos endpoints a tu worker de Cloudflare

// GET /api/devices - Obtener lista de dispositivos monitoreados
router.get('/api/devices', async (request, env) => {
    try {
        // Verificar autenticación
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'No autorizado' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const url = new URL(request.url);
        const location = url.searchParams.get('location');
        const status = url.searchParams.get('status');
        const search = url.searchParams.get('search');
        
        // Datos de ejemplo - reemplazar con consulta real a tu base de datos
        let devices = [
            {
                id: '1',
                hostname: 'TLM-ATT-GDL-001',
                ip_address: '192.168.1.10',
                location: 'Matriz Guadalajara',
                status: 'online',
                cpu: { 
                    usage_percent: 45, 
                    cores_physical: 4, 
                    cores_logical: 8 
                },
                memory: { 
                    usage_percent: 60, 
                    total_gb: 16, 
                    used_gb: 9.6, 
                    available_gb: 6.4 
                },
                disk: { 
                    usage_percent: 70, 
                    total_gb: 500, 
                    used_gb: 350, 
                    free_gb: 150 
                },
                logged_user: 'usuario.sistemas',
                last_seen: new Date().toISOString(),
                os: 'Windows 11 Pro',
                uptime_hours: 168
            },
            {
                id: '2',
                hostname: 'TLM-ATT-MTY-002',
                ip_address: '192.168.2.15',
                location: 'Monterrey',
                status: 'online',
                cpu: { 
                    usage_percent: 32, 
                    cores_physical: 4, 
                    cores_logical: 8 
                },
                memory: { 
                    usage_percent: 45, 
                    total_gb: 16, 
                    used_gb: 7.2, 
                    available_gb: 8.8 
                },
                disk: { 
                    usage_percent: 55, 
                    total_gb: 500, 
                    used_gb: 275, 
                    free_gb: 225 
                },
                logged_user: 'admin.local',
                last_seen: new Date().toISOString(),
                os: 'Windows 10 Pro',
                uptime_hours: 72
            },
            {
                id: '3',
                hostname: 'TLM-ATT-CDMX-003',
                ip_address: '192.168.3.20',
                location: 'Ciudad de México',
                status: 'offline',
                cpu: { usage_percent: 0, cores_physical: 4, cores_logical: 8 },
                memory: { usage_percent: 0, total_gb: 16, used_gb: 0, available_gb: 16 },
                disk: { usage_percent: 0, total_gb: 500, used_gb: 0, free_gb: 500 },
                logged_user: '',
                last_seen: new Date(Date.now() - 3600000).toISOString(),
                os: 'Windows 11 Pro',
                uptime_hours: 0
            }
        ];
        
        // Aplicar filtros
        if (location) {
            devices = devices.filter(d => 
                d.location.toLowerCase().includes(location.toLowerCase())
            );
        }
        
        if (status) {
            devices = devices.filter(d => d.status === status);
        }
        
        if (search) {
            const searchLower = search.toLowerCase();
            devices = devices.filter(d => 
                d.hostname.toLowerCase().includes(searchLower) ||
                d.ip_address.includes(search) ||
                d.logged_user.toLowerCase().includes(searchLower)
            );
        }
        
        return new Response(JSON.stringify({ devices }), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        console.error('Error en /api/devices:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
});

// GET /api/stats - Obtener estadísticas generales
router.get('/api/stats', async (request, env) => {
    try {
        // Verificar autenticación
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'No autorizado' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        // Datos de ejemplo - reemplazar con consulta real
        const stats = {
            summary: {
                total: 150,
                online: 142,
                offline: 8
            },
            alerts: {
                high_cpu: 5,
                high_memory: 3,
                high_disk: 7
            },
            by_location: {
                'Guadalajara': 45,
                'Monterrey': 38,
                'Ciudad de México': 35,
                'Otros': 32
            },
            performance: {
                avg_cpu: 42.5,
                avg_memory: 55.3,
                avg_disk: 62.1
            }
        };
        
        return new Response(JSON.stringify(stats), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        console.error('Error en /api/stats:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
});

// POST /api/devices/:id/command - Enviar comando a dispositivo
router.post('/api/devices/:id/command', async (request, env) => {
    try {
        // Verificar autenticación y permisos de admin
        const authHeader = request.headers.get('Authorization');
        if (!authHeader) {
            return new Response(JSON.stringify({ error: 'No autorizado' }), {
                status: 401,
                headers: { 'Content-Type': 'application/json' }
            });
        }

        const { id } = request.params;
        const body = await request.json();
        const { command, parameters } = body;
        
        // Aquí iría la lógica para enviar el comando al agente
        // Por ahora retornamos una respuesta simulada
        
        return new Response(JSON.stringify({ 
            success: true,
            message: `Comando ${command} enviado al dispositivo ${id}`,
            command_id: `cmd_${Date.now()}`
        }), {
            headers: { 
                'Content-Type': 'application/json',
                'Access-Control-Allow-Origin': '*'
            }
        });
    } catch (error) {
        console.error('Error en /api/devices/:id/command:', error);
        return new Response(JSON.stringify({ error: error.message }), {
            status: 500,
            headers: { 'Content-Type': 'application/json' }
        });
    }
});