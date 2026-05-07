# Política de Seguridad — MYG Telecom Dashboard

## Versiones con soporte activo

| Componente | Versión | Soporte |
|------------|---------|---------|
| Backend API (Render) | 5.6.x | ✅ Activa |
| Worker (Cloudflare) | 4.7.x | ✅ Activa |
| Frontend (Netlify) | 4.2.x | ✅ Activa |
| Backend API < 5.0 | < 5.0 | ❌ Sin soporte |

## Reportar una vulnerabilidad

Si encuentras una vulnerabilidad de seguridad **NO abras un issue público**.

### Proceso de reporte:

1. Envía los detalles por email a: **sistemas@mygtelecom.mx**
2. Asunto: `[SECURITY] Descripción breve del problema`
3. Incluye en el cuerpo:
   - Descripción de la vulnerabilidad
   - Pasos para reproducirla
   - Impacto potencial
   - Versión afectada
4. Recibirás confirmación en **48 horas hábiles**
5. Vulnerabilidades críticas serán corregidas en **7 días**

## Scope del sistema

| URL | Componente | En scope |
|-----|------------|----------|
| `https://mygtelecom.netlify.app` | Frontend React | ✅ |
| `https://dashboard-myg-api.mygtrabajo.workers.dev` | Cloudflare Worker | ✅ |
| `https://myg-mongodb-api.onrender.com` | Backend Express | ✅ |
| MongoDB Atlas cluster | Base de datos | ✅ |

## Vulnerabilidades fuera de scope

- Ataques que requieran acceso físico al dispositivo
- Vulnerabilidades en dependencias de terceros ya conocidas y sin fix disponible
- Ataques de fuerza bruta contra cuentas de prueba
- Bugs de UX que no tienen impacto de seguridad

## Política de divulgación

Seguimos una política de divulgación responsable coordinada (**Coordinated Vulnerability Disclosure**):
- El equipo tiene **30 días** para corregir la vulnerabilidad antes de divulgación pública
- Se dará crédito al investigador en el changelog si así lo desea

## Controles de seguridad implementados

- ✅ JWT HS256 con expiración 8h
- ✅ Rate limiting: 10 intentos de login / 15 min por IP
- ✅ Rate limiting API: 300 req/min por usuario autenticado
- ✅ CORS restrictivo (whitelist de 5 orígenes)
- ✅ Helmet CSP/HSTS/X-Frame-Options
- ✅ bcrypt rounds 10 con rehash progresivo
- ✅ Validación de entrada con Joi en endpoints críticos
- ✅ Roles y permisos granulares (7 roles, permisos por feature)
- ✅ Sentry error tracking con DSN configurado
- ✅ MongoDB Atlas M0 con autenticación — sin acceso público directo
