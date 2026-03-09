/* ============================================================
   CONFIGURACIÓN GLOBAL - MYG TELECOM DASHBOARD
   
   Versión: 3.3.0
   Cambios:
   - Fix: hostname check corregido (includes en lugar de ===)
   - Fix: baseURL apunta al Worker para TODO entorno no-localhost
   - Add: endpoints del Admin Panel v1.0
   ============================================================ */

// IMPORTANTE: Usar 'var' (no const/let) para que CONFIG sea accesible
// como window.CONFIG desde otros scripts cargados en el HTML
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
        ticketsConteo:     '1jxDODo8aVGoy1uhotLS2E4Lq5ogQTA_rlfTZxn1Yo38'
    },

    // ========== API Backend Unificado v3.3 ==========
    api: {
        // ── FIX: antes usaba === 'Netlify' (nunca era true porque hostname
        //    devuelve el dominio real, ej. "mygtelecom.netlify.app").
        //    Ahora: localhost → Render directo; todo lo demás → Worker.
        //    El Worker es la única entrada a producción; Render no es público.
        baseURL: window.location.hostname === 'localhost'
            ? 'http://localhost:5500'
            : 'https://dashboard-myg-api.mygtrabajo.workers.dev',

        // URL directa a Render para SSE — NO pasa por Cloudflare Worker.
        // Workers tiene límite ~30s por request; SSE dura horas → Worker lo corta.
        sseBaseURL: window.location.hostname === 'localhost'
            ? 'http://localhost:5500'
            : 'https://myg-mongodb-api.onrender.com',

        // Endpoints disponibles
        endpoints: {
            // ── Autenticación ─────────────────────────────────────
            login:              '/api/auth/login',

            // ── Usuarios ──────────────────────────────────────────
            users:              '/api/users',

            // ── Dispositivos IQU ──────────────────────────────────
            devices:            '/api/devices',

            // ── RH y Movimientos ──────────────────────────────────
            rhMovimientos:      '/api/rh/movimientos',
            notificaciones:     '/api/notificaciones',

            // ── Formatos de Activación ────────────────────────────
            formatosSistemas:   '/api/formatos/sistemas',
            formatosGenerar:    '/api/formatos/generar',
            formatosClearCache: '/api/formatos/clear-cache',

            // ── Activos ───────────────────────────────────────────
            activosMovimientos: '/api/activos/movimientos',

            // ── Admin Panel v1.0 (solo rol ADMIN) ─────────────────
            adminStats:         '/api/admin/stats',
            adminAccessLogs:    '/api/admin/access-logs',
            adminSubmissions:   '/api/admin/form-submissions',
            adminRolePerms:     '/api/admin/permissions/roles',
            adminUserPerms:     '/api/admin/permissions/users', // + /:username
        },

        // Timeout para requests (ms)
        timeout: 30000,

        // Reintentos en caso de error
        retries: 2
    }
};

// Paginación global
const ITEMS_POR_PAGINA = 30;

// Validación de configuración al cargar
(() => {
    const esLocal = window.location.hostname === 'localhost';
    console.log('📋 Config MYG v3.3 cargada:');
    console.log('   Entorno:', esLocal ? '🛠️  Local (Render directo)' : '🌐 Producción (Cloudflare Worker)');
    console.log('   API Base URL:', CONFIG.api.baseURL);
    console.log('   SSE URL:', CONFIG.api.sseBaseURL);
    console.log('   Sheets configuradas:', Object.keys(CONFIG.sheetsPublicUrls).length);
    console.log('   Endpoints API:', Object.keys(CONFIG.api.endpoints).length);
})();
