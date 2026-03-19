/* ============================================================
   CONFIGURACIÓN GLOBAL - MYG TELECOM DASHBOARD
   Versión: 4.2.0
   Cambios v4.0:
   - Nueva estructura de 7 roles: ADMIN, GERENTE_OPERACIONES,
     COORDINADOR(+area), ANALISTA(+area), GERENTE_COMERCIAL,
     EJECUTIVO_COMERCIAL, USUARIO
   - Configuración de 4 áreas: Sistemas, Mantenimiento, Crédito, Logística
   - Tabs anclados persistentes en MongoDB (preferencias.tabsPinned)
   - Panel Admin unificado (fusiona admin-panel + admin-usuarios)
   ============================================================ */

var CONFIG = {
    // Auto-actualización de datos
    autoUpdateMinutes: 5,

    // URLs de Google Sheets públicas
    sheetsPublicUrls: {
        rh:                '11PSvIpkHf9q18LjB486gaAkMuudrdQBJ',
        headcount:         '1Gs9ocGbfv7z1XpbYQt_yD5F6ai5OReWrIGz_UbBZpLc',
        activos:           '1SGZNU2cyyQsHGtoyRRysOqaCOhag9CHGmEdjPnLGIgE',
        reposiciones:      '1m60WsG6fdjg6xxL8UxKEwSQQnoqyz7TqIQGyuCDWPoY',
        correos:           '1nR1Igo_bf0RcnbTvPtoN_HGMN1e3Qhf4QOZV_L0np1g',
        equiposIQU:        '12nG-UPe8JPj5LC2QvQ1yLA3dtC1hIS4rVi8BMw_hVeE',
        dashboardTickets:  '15D9LtufL60YwhOh26hrJmuEFkJolTURN22iiPcHwX1Q',
        pdvDetalles:       '1oqWDNGdZhACoTepi9pGTYKE-UhVZPNCpxSHW0GCINL8',
        correosDetallados: '12sZGOsKCpyHpc6poigKdc2KjalpYcWUo',
        ticketsConteo:     '1jxDODo8aVGoy1uhotLS2E4Lq5ogQTA_rlfTZxn1Yo38',
        rhPOC:             '15WKfjBVel38DKRdHO1EtjOqi9EGRTB1cuhCnqAGb1V0',
        rhHistorico:       '14ei47FFgK5ZRgCHEtZ_eMToKZqZ6XZZtr8U6PGlJsY8'
    },

    // ========== API Backend Unificado v4.0 ==========
    api: {
        baseURL: window.location.hostname === 'localhost'
            ? 'http://localhost:5500'
            : 'https://dashboard-myg-api.mygtrabajo.workers.dev',

        sseBaseURL: window.location.hostname === 'localhost'
            ? 'http://localhost:5500'
            : 'https://myg-mongodb-api.onrender.com',

        endpoints: {
            login:              '/api/auth/login',
            users:              '/api/users',
            devices:            '/api/devices',
            rhMovimientos:      '/api/rh/movimientos',
            notificaciones:     '/api/notificaciones',
            formatosSistemas:   '/api/formatos/sistemas',
            formatosGenerar:    '/api/formatos/generar',
            formatosClearCache: '/api/formatos/clear-cache',
            activosMovimientos: '/api/activos/movimientos',
            adminStats:         '/api/admin/stats',
            adminAccessLogs:    '/api/admin/access-logs',
            adminSubmissions:   '/api/admin/form-submissions',
            adminRolePerms:     '/api/admin/permissions/roles',
            adminUserPerms:     '/api/admin/permissions/users',
        },

        timeout: 30000,
        retries: 2
    },

    // ========== ESTRUCTURA DE ROLES v4.0 ==========
    // nivel: jerarquía (menor número = más privilegios)
    // tieneArea: si el rol requiere campo 'area' adicional
    roles: {
        ADMIN: {
            nombre:      'Administrador',
            nivel:       1,
            tieneArea:   false,
            color:       'red',
            colorHex:    '#EF4444',
            badge:       '🔴',
            descripcion: 'Acceso completo al sistema y gestión total de usuarios'
        },
        GERENTE_OPERACIONES: {
            nombre:      'Gerente Operaciones',
            nivel:       2,
            tieneArea:   false,
            color:       'purple',
            colorHex:    '#8B5CF6',
            badge:       '🟣',
            descripcion: 'Visibilidad completa de todas las áreas operativas'
        },
        COORDINADOR: {
            nombre:      'Coordinador/a',
            nivel:       3,
            tieneArea:   true,
            color:       'blue',
            colorHex:    '#3B82F6',
            badge:       '🔵',
            descripcion: 'Gestión y coordinación de su área asignada'
        },
        ANALISTA: {
            nombre:      'Analista',
            nivel:       4,
            tieneArea:   true,
            color:       'cyan',
            colorHex:    '#06B6D4',
            badge:       '🩵',
            descripcion: 'Análisis y consulta de datos en su área asignada'
        },
        GERENTE_COMERCIAL: {
            nombre:      'Gerente Comercial',
            nivel:       5,
            tieneArea:   false,
            color:       'green',
            colorHex:    '#10B981',
            badge:       '🟢',
            descripcion: 'Acceso definido por el Administrador'
        },
        EJECUTIVO_COMERCIAL: {
            nombre:      'Ejecutivo Comercial',
            nivel:       6,
            tieneArea:   false,
            color:       'teal',
            colorHex:    '#14B8A6',
            badge:       '🩵',
            descripcion: 'Acceso definido por el Administrador'
        },
        GERENTE_RH: {
            nombre:      'Gerente RH',
            nivel:       7,
            tieneArea:   true,            // Requiere campo 'area' (ej: 'RH Corporativo')
            color:       'rose',
            colorHex:    '#F43F5E',
            badge:       '🌹',
            descripcion: 'Gestión y aprobación de movimientos de Recursos Humanos'
        },
        ANALISTA_RH: {
            nombre:      'Analista RH',
            nivel:       8,
            tieneArea:   true,            // Requiere campo 'area' (ej: 'RH Corporativo')
            color:       'pink',
            colorHex:    '#EC4899',
            badge:       '🩷',
            descripcion: 'Consulta y registro de movimientos de Recursos Humanos'
        },
        USUARIO: {
            nombre:      'Usuario',
            nivel:       9,
            tieneArea:   false,
            color:       'gray',
            colorHex:    '#6B7280',
            badge:       '⚪',
            descripcion: 'Acceso básico al sistema'
        }
    },

    // ========== ÁREAS OPERATIVAS ==========
    // tabs: IDs de pestañas disponibles en esa área
    // Las áreas sin tabs están reservadas para desarrollo futuro
    areas: {
        Sistemas: {
            emoji:      '💻',
            color:      'blue',
            colorHex:   '#3B82F6',
            label:      'Sistemas',
            descripcion:'Infraestructura, Tecnología y Herramientas IT',
            tabs: [
                'kpi', 'overview', 'tickets', 'rh',
                'monitoreo', 'headcount', 'activos',
                'reposiciones', 'equipos', 'contactos', 'hub'
            ]
        },
        Mantenimiento: {
            emoji:      '🔧',
            color:      'yellow',
            colorHex:   '#F59E0B',
            label:      'Mantenimiento',
            descripcion:'Mantenimiento Preventivo y Correctivo',
            tabs:       ['hub_mantenimiento']  // v4.2 — Hub propio de área
        },
        Credito: {
            emoji:      '💳',
            color:      'green',
            colorHex:   '#10B981',
            label:      'Crédito',
            descripcion:'Crédito, Cobranza y Gestión Financiera',
            tabs:       ['hub_credito']        // v4.2 — Hub propio de área
        },
        Logistica: {
            emoji:      '🚚',
            color:      'orange',
            colorHex:   '#F97316',
            label:      'Logística',
            descripcion:'Logística, Distribución y Cadena de Suministro',
            tabs:       ['hub_logistica']      // v4.2 — Hub propio de área
        }
    },

    // Áreas que tienen 'area' como campo requerido
    rolesConArea: ['COORDINADOR', 'ANALISTA', 'GERENTE_RH', 'ANALISTA_RH'], // v4.1

    // Roles que ven el selector de áreas al iniciar
    rolesConAreaSelector: ['ADMIN', 'GERENTE_OPERACIONES'],
};

// Paginación global
const ITEMS_POR_PAGINA = 30;

// Validación de configuración al cargar
(() => {
    const esLocal = window.location.hostname === 'localhost';
    console.log('📋 Config MYG v4.2 cargada:');
    console.log('   Entorno:',  esLocal ? '🛠️  Local' : '🌐 Producción');
    console.log('   API Base:', CONFIG.api.baseURL);
    console.log('   Roles:',    Object.keys(CONFIG.roles).length);
    console.log('   Áreas:',    Object.keys(CONFIG.areas).length);
    console.log('   Sheets:',   Object.keys(CONFIG.sheetsPublicUrls).length);
})();
