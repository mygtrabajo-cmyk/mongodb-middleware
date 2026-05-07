// __tests__/requireAuth.test.js
// [MAINT-002] Tests para el middleware requireAuth
// Cubre: sin token, token inválido, token expirado, token válido

import { describe, it, expect, vi } from 'vitest';
import jwt from 'jsonwebtoken';

const JWT_SECRET = 'test-secret-para-vitest-32chars!!';

// ── Copia de requireAuth y normalizarRol de server.js ───────────
const LEGACY_ROLE_MAP = { RH: 'ANALISTA_RH', SISTEMAS: 'COORDINADOR', GERENTE: 'GERENTE_OPERACIONES' };
function normalizarRol(rol) { return LEGACY_ROLE_MAP[rol] || rol; }

function requireAuth(req, res, next) {
    try {
        const header = req.headers?.authorization;
        if (!header?.startsWith('Bearer '))
            return res.status(401).json({ error: 'Token no proporcionado' });
        const token = header.slice(7);
        const payload = jwt.verify(token, JWT_SECRET);
        payload.rol = normalizarRol(payload.rol);
        req.usuario = payload;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError')
            return res.status(401).json({ error: 'Token expirado', code: 'TOKEN_EXPIRED' });
        return res.status(401).json({ error: 'Token invalido' });
    }
}

// ── Helper: mock req/res/next ────────────────────────────────────
function mockHttp(authHeader = null) {
    const req = { headers: authHeader ? { authorization: authHeader } : {}, usuario: null };
    const res = { statusCode: null, body: null };
    res.status = (code) => { res.statusCode = code; return res; };
    res.json   = (body)  => { res.body = body; return res; };
    const next = vi.fn();
    return { req, res, next };
}

function makeToken(payload, expiresIn = '8h') {
    return jwt.sign(payload, JWT_SECRET, { expiresIn });
}

// ── Tests ────────────────────────────────────────────────────────
describe('requireAuth middleware', () => {

    describe('sin token', () => {
        it('rechaza sin header Authorization', () => {
            const { req, res, next } = mockHttp();
            requireAuth(req, res, next);
            expect(res.statusCode).toBe(401);
            expect(res.body.error).toContain('Token no proporcionado');
            expect(next).not.toHaveBeenCalled();
        });

        it('rechaza Authorization sin Bearer prefix', () => {
            const { req, res, next } = mockHttp('Basic abc123');
            requireAuth(req, res, next);
            expect(res.statusCode).toBe(401);
            expect(next).not.toHaveBeenCalled();
        });
    });

    describe('token inválido', () => {
        it('rechaza token malformado', () => {
            const { req, res, next } = mockHttp('Bearer not.valid.token');
            requireAuth(req, res, next);
            expect(res.statusCode).toBe(401);
            expect(res.body.error).toBe('Token invalido');
            expect(next).not.toHaveBeenCalled();
        });

        it('rechaza token con firma incorrecta', () => {
            const fakeToken = jwt.sign({ username: 'hacker', rol: 'ADMIN' }, 'wrong-secret');
            const { req, res, next } = mockHttp(`Bearer ${fakeToken}`);
            requireAuth(req, res, next);
            expect(res.statusCode).toBe(401);
            expect(next).not.toHaveBeenCalled();
        });

        it('rechaza string vacío después de Bearer', () => {
            const { req, res, next } = mockHttp('Bearer ');
            requireAuth(req, res, next);
            expect(res.statusCode).toBe(401);
            expect(next).not.toHaveBeenCalled();
        });
    });

    describe('token expirado', () => {
        it('retorna 401 con code TOKEN_EXPIRED', () => {
            const expired = makeToken({ username: 'jperez', rol: 'ANALISTA' }, '-1s');
            const { req, res, next } = mockHttp(`Bearer ${expired}`);
            requireAuth(req, res, next);
            expect(res.statusCode).toBe(401);
            expect(res.body.code).toBe('TOKEN_EXPIRED');
            expect(next).not.toHaveBeenCalled();
        });
    });

    describe('token válido', () => {
        it('llama a next() con token válido', () => {
            const token = makeToken({ username: 'jperez', rol: 'ANALISTA', area: 'Sistemas' });
            const { req, res, next } = mockHttp(`Bearer ${token}`);
            requireAuth(req, res, next);
            expect(next).toHaveBeenCalledOnce();
            expect(req.usuario.username).toBe('jperez');
            expect(req.usuario.rol).toBe('ANALISTA');
        });

        it('normaliza roles legacy: SISTEMAS → COORDINADOR', () => {
            const token = makeToken({ username: 'admin1', rol: 'SISTEMAS' });
            const { req, res, next } = mockHttp(`Bearer ${token}`);
            requireAuth(req, res, next);
            expect(next).toHaveBeenCalled();
            expect(req.usuario.rol).toBe('COORDINADOR');
        });

        it('normaliza roles legacy: RH → ANALISTA_RH', () => {
            const token = makeToken({ username: 'rh1', rol: 'RH' });
            const { req, res, next } = mockHttp(`Bearer ${token}`);
            requireAuth(req, res, next);
            expect(req.usuario.rol).toBe('ANALISTA_RH');
        });

        it('normaliza roles legacy: GERENTE → GERENTE_OPERACIONES', () => {
            const token = makeToken({ username: 'mgr1', rol: 'GERENTE' });
            const { req, res, next } = mockHttp(`Bearer ${token}`);
            requireAuth(req, res, next);
            expect(req.usuario.rol).toBe('GERENTE_OPERACIONES');
        });

        it('no modifica roles nuevos (ADMIN, COORDINADOR, etc.)', () => {
            const token = makeToken({ username: 'admin1', rol: 'ADMIN' });
            const { req, res, next } = mockHttp(`Bearer ${token}`);
            requireAuth(req, res, next);
            expect(req.usuario.rol).toBe('ADMIN');
        });

        it('preserva campo area en req.usuario', () => {
            const token = makeToken({ username: 'coord1', rol: 'COORDINADOR', area: 'Crédito' });
            const { req, res, next } = mockHttp(`Bearer ${token}`);
            requireAuth(req, res, next);
            expect(req.usuario.area).toBe('Crédito');
        });
    });
});
