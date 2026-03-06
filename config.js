/* ============================================================
   CONFIGURACIÓN GLOBAL - MYG TELECOM DASHBOARD
   
   Versión: 3.2.0 (Actualizado para servidor unificado)
   ============================================================ */

// IMPORTANTE: Usar 'var' (no const/let) para que CONFIG sea accesible
// como window.CONFIG desde otros scripts cargados en el HTML
var CONFIG = {
    // Auto-actualización de datos
    autoUpdateMinutes: 5,
    
    // URLs de Google Sheets públicas
    sheetsPublicUrls: {
        rh: '11PSvIpkHf9q18LjB486gaAkMuudrdQBJ',
        headcount: '1Gs9ocGbfv7z1XpbYQt_yD5F6ai5OReWrIGz_UbBZpLc',
        activos: '1SGZNU2cyyQsHGtoyRRysOqaCOhag9CHGmEdjPnLGIgE',
        reposiciones: '1m60WsG6fdjg6xxL8UxKEwSQQnoqyz7TqIQGyuCDWPoY',
        correos: '1nR1Igo_bf0RcnbTvPtoN_HGMN1e3Qhf4QOZV_L0np1g',
        equiposIQU: '12nG-UPe8JPj5LC2QvQ1yLA3dtC1hIS4rVi8BMw_hVeE',
        dashboardTickets: '15D9LtufL60YwhOh26hrJmuEFkJolTURN22iiPcHwX1Q',
        pdvDetalles: '1oqWDNGdZhACoTepi9pGTYKE-UhVZPNCpxSHW0GCINL8', 
        correosDetallados: '12sZGOsKCpyHpc6poigKdc2KjalpYcWUo',
        ticketsConteo: '1jxDODo8aVGoy1uhotLS2E4Lq5ogQTA_rlfTZxn1Yo38'
    },
    
    // ========== NUEVO: API Backend Unificado v3.2 ==========
    api: {
        // URL base del servidor (ajustar según entorno)
        baseURL: window.location.hostname === 'Netlify' 
            ? 'https://mygtelecom.netlify.app/'  
            : 'https://myg-mongodb-api.onrender.com',

        // URL directa a Render para SSE — NO pasa por Cloudflare Worker.
        // Workers tiene límite ~30s por request; SSE dura horas → Worker lo corta.
        sseBaseURL: window.location.hostname === 'localhost'
            ? 'http://localhost:5500'
            : 'https://myg-mongodb-api.onrender.com',
        
        // Endpoints disponibles
        endpoints: {
            // Autenticación
            login: '/api/auth/login',
            
            // Usuarios
            users: '/api/users',
            
            // Dispositivos IQU
            devices: '/api/devices',
            
            // RH y Movimientos
            rhMovimientos: '/api/rh/movimientos',
            notificaciones: '/api/notificaciones',
            
            // Formatos de Activación (NUEVO)
            formatosSistemas: '/api/formatos/sistemas',
            formatosGenerar: '/api/formatos/generar',
            formatosClearCache: '/api/formatos/clear-cache',

            activosMovimientos: '/api/activos/movimientos'
        },
        
        // Timeout para requests (ms)
        timeout: 30000,
        
        // Reintentos en caso de error
        retries: 2
    }
};

// Paginación
const ITEMS_POR_PAGINA = 30;

// Validación de configuración
(() => {
    console.log('📋 Configuración cargada:');
    console.log('   API Base URL:', CONFIG.api.baseURL);
    console.log('   Sheets configuradas:', Object.keys(CONFIG.sheetsPublicUrls).length);
    console.log('   Endpoints API:', Object.keys(CONFIG.api.endpoints).length);
})();

