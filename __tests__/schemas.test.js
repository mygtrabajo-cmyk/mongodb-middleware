// __tests__/schemas.test.js
// [MAINT-002] Tests para los esquemas Joi de validación
// Cubre: login schema, rhMovimiento schema, rhMovimientoPatch schema

import { describe, it, expect } from 'vitest';
import Joi from 'joi';

// ── Esquemas copiados de server.js (mantener sincronizados) ─────
const schemas = {
    login: Joi.object({
        username: Joi.string().trim().min(2).max(60).required()
            .messages({ 'any.required': 'El usuario es requerido' }),
        password: Joi.string().min(4).max(200).required()
            .messages({ 'any.required': 'La contraseña es requerida' }),
        remember: Joi.boolean().default(false),
    }),

    rhMovimiento: Joi.object({
        tipo: Joi.string().valid(
            'ALTA','ALTA_UDP','BAJA','CAMBIO_PDV','CAMBIO_PUESTO','CAMBIO_COMBINADO'
        ).required()
            .messages({ 'any.only': 'Tipo de movimiento inválido' }),
        nombre:        Joi.string().trim().max(200).optional(),
        colaborador:   Joi.string().trim().max(200).optional(),
        area:          Joi.string().trim().max(100).optional(),
        pdvOrigen:     Joi.string().trim().max(200).optional(),
        pdvDestino:    Joi.string().trim().max(200).optional(),
        puestoOrigen:  Joi.string().trim().max(200).optional(),
        puestoDestino: Joi.string().trim().max(200).optional(),
        efectivo:      Joi.string().trim().max(50).optional(),
        comentario:    Joi.string().trim().max(1000).optional(),
    }).unknown(true),

    rhMovimientoPatch: Joi.object({
        estado:     Joi.string().valid('pendiente','aprobado','rechazado','procesado').optional(),
        comentario: Joi.string().trim().max(1000).optional(),
    }).min(1).messages({ 'object.min': 'Se requiere al menos un campo para actualizar' }),
};

const opts = { stripUnknown: true, abortEarly: false, convert: true };

// ── Tests login schema ────────────────────────────────────────────
describe('schemas.login', () => {
    it('acepta username + password válidos', () => {
        const { error, value } = schemas.login.validate(
            { username: 'jperez', password: 'pass1234' }, opts
        );
        expect(error).toBeUndefined();
        expect(value.remember).toBe(false); // default
    });

    it('rechaza username muy corto (< 2 chars)', () => {
        const { error } = schemas.login.validate({ username: 'a', password: 'pass1234' }, opts);
        expect(error).toBeDefined();
    });

    it('rechaza password muy corto (< 4 chars)', () => {
        const { error } = schemas.login.validate({ username: 'jperez', password: 'abc' }, opts);
        expect(error).toBeDefined();
    });

    it('rechaza cuando falta username', () => {
        const { error } = schemas.login.validate({ password: 'pass1234' }, opts);
        expect(error).toBeDefined();
        const msgs = error.details.map(d => d.message);
        expect(msgs.some(m => m.includes('usuario') || m.includes('required'))).toBe(true);
    });

    it('convierte remember string "true" a boolean', () => {
        const { value } = schemas.login.validate(
            { username: 'jperez', password: 'pass1234', remember: 'true' }, opts
        );
        expect(value.remember).toBe(true);
    });

    it('strip de campos desconocidos', () => {
        const { value } = schemas.login.validate(
            { username: 'jperez', password: 'pass1234', hack: 'injection' }, opts
        );
        expect(value.hack).toBeUndefined();
    });

    it('rechaza username demasiado largo (> 60 chars)', () => {
        const { error } = schemas.login.validate(
            { username: 'a'.repeat(61), password: 'pass1234' }, opts
        );
        expect(error).toBeDefined();
    });
});

// ── Tests rhMovimiento schema ─────────────────────────────────────
describe('schemas.rhMovimiento', () => {
    it('acepta tipo ALTA válido', () => {
        const { error } = schemas.rhMovimiento.validate({ tipo: 'ALTA' }, opts);
        expect(error).toBeUndefined();
    });

    it('acepta todos los tipos válidos', () => {
        const tipos = ['ALTA','ALTA_UDP','BAJA','CAMBIO_PDV','CAMBIO_PUESTO','CAMBIO_COMBINADO'];
        for (const tipo of tipos) {
            const { error } = schemas.rhMovimiento.validate({ tipo }, opts);
            expect(error).toBeUndefined();
        }
    });

    it('rechaza tipo desconocido', () => {
        const { error } = schemas.rhMovimiento.validate({ tipo: 'HACK' }, opts);
        expect(error).toBeDefined();
    });

    it('rechaza sin tipo', () => {
        const { error } = schemas.rhMovimiento.validate({ nombre: 'Juan' }, opts);
        expect(error).toBeDefined();
    });

    it('permite campos extra (unknown: true)', () => {
        const { error } = schemas.rhMovimiento.validate(
            { tipo: 'ALTA', campoExtra: 'valor', otro: 123 }, opts
        );
        expect(error).toBeUndefined();
    });

    it('trim de espacios en nombre', () => {
        const { value } = schemas.rhMovimiento.validate(
            { tipo: 'ALTA', nombre: '  Juan Perez  ' }, opts
        );
        expect(value.nombre).toBe('Juan Perez');
    });

    it('rechaza nombre demasiado largo (> 200 chars)', () => {
        const { error } = schemas.rhMovimiento.validate(
            { tipo: 'ALTA', nombre: 'a'.repeat(201) }, opts
        );
        expect(error).toBeDefined();
    });
});

// ── Tests rhMovimientoPatch schema ────────────────────────────────
describe('schemas.rhMovimientoPatch', () => {
    it('acepta estado válido', () => {
        const { error } = schemas.rhMovimientoPatch.validate({ estado: 'aprobado' }, opts);
        expect(error).toBeUndefined();
    });

    it('acepta solo comentario (sin estado)', () => {
        const { error } = schemas.rhMovimientoPatch.validate(
            { comentario: 'Aprobado por gerencia' }, opts
        );
        expect(error).toBeUndefined();
    });

    it('rechaza objeto vacío (min: 1 campo)', () => {
        const { error } = schemas.rhMovimientoPatch.validate({}, opts);
        expect(error).toBeDefined();
    });

    it('rechaza estado desconocido', () => {
        const { error } = schemas.rhMovimientoPatch.validate({ estado: 'cancelado' }, opts);
        expect(error).toBeDefined();
    });
});
