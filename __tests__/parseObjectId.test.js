// __tests__/parseObjectId.test.js
// [MAINT-002] Tests unitarios para el helper parseObjectId
// Cubre: IDs válidos, inválidos, null/undefined, strings vacíos

import { describe, it, expect } from 'vitest';
import { ObjectId } from 'mongodb';

// ── Extraemos parseObjectId del server.js via un helper de test ──
// parseObjectId usa ObjectId de mongodb, que ya está en devDeps.
// La función es pura salvo el `res` — podemos testarla directamente.

/**
 * Copia de parseObjectId de server.js para aislar el test del server entero.
 * MANTENER SINCRONIZADA si se modifica server.js.
 */
function parseObjectId(idStr, res) {
    if (!idStr || typeof idStr !== 'string' || idStr.trim() === '') {
        if (res) res.status(400).json({ ok: false, error: 'ID requerido' });
        return null;
    }
    try {
        return new ObjectId(idStr.trim());
    } catch {
        if (res) res.status(400).json({ ok: false, error: `ID inválido: ${idStr}` });
        return null;
    }
}

// ── Helper: mock de res ──────────────────────────────────────────
function mockRes() {
    const res = { statusCode: null, body: null };
    res.status = (code) => { res.statusCode = code; return res; };
    res.json   = (body)  => { res.body = body; return res; };
    return res;
}

// ── Tests ────────────────────────────────────────────────────────
describe('parseObjectId', () => {

    describe('IDs válidos', () => {
        it('acepta un ObjectId válido (24 hex chars)', () => {
            const validId = '64a5c3b2e4f1a0b3c2d1e0f9';
            const result = parseObjectId(validId, null);
            expect(result).toBeInstanceOf(ObjectId);
            expect(result.toHexString()).toBe(validId);
        });

        it('trim de espacios antes de parsear', () => {
            const validId = '  64a5c3b2e4f1a0b3c2d1e0f9  ';
            const result = parseObjectId(validId, null);
            expect(result).toBeInstanceOf(ObjectId);
        });

        it('no llama a res cuando el ID es válido', () => {
            const res = mockRes();
            parseObjectId('64a5c3b2e4f1a0b3c2d1e0f9', res);
            expect(res.statusCode).toBeNull();
        });
    });

    describe('IDs inválidos — retorna null y envía 400', () => {
        it('retorna null para string inválido', () => {
            const res = mockRes();
            const result = parseObjectId('not-a-valid-id', res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
            expect(res.body.ok).toBe(false);
            expect(res.body.error).toContain('ID inválido');
        });

        it('retorna null para string demasiado corto', () => {
            const res = mockRes();
            const result = parseObjectId('abc123', res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
        });

        it('retorna null para string demasiado largo', () => {
            const res = mockRes();
            const result = parseObjectId('a'.repeat(100), res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
        });
    });

    describe('IDs vacíos/nulos — retorna null y envía 400', () => {
        it('retorna null para null', () => {
            const res = mockRes();
            const result = parseObjectId(null, res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
            expect(res.body.error).toBe('ID requerido');
        });

        it('retorna null para undefined', () => {
            const res = mockRes();
            const result = parseObjectId(undefined, res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
        });

        it('retorna null para string vacío', () => {
            const res = mockRes();
            const result = parseObjectId('', res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
        });

        it('retorna null para string solo espacios', () => {
            const res = mockRes();
            const result = parseObjectId('   ', res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
        });

        it('retorna null para número (no-string)', () => {
            const res = mockRes();
            const result = parseObjectId(12345, res);
            expect(result).toBeNull();
            expect(res.statusCode).toBe(400);
        });
    });

    describe('sin res (null) — no lanza excepción', () => {
        it('retorna null sin lanzar cuando res es null e ID es inválido', () => {
            expect(() => parseObjectId('invalid', null)).not.toThrow();
            expect(parseObjectId('invalid', null)).toBeNull();
        });
    });
});
