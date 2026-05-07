// vitest.config.js — MYG Telecom Backend
// Los tests usan ESM (import/export) aunque server.js sea CommonJS.
// Vitest transpila automáticamente — no se necesita transform manual.

import { defineConfig } from 'vitest/config';

export default defineConfig({
    test: {
        environment: 'node',
        include:     ['__tests__/**/*.test.js'],
        coverage: {
            provider: 'v8',
            reporter: ['text', 'html'],
            include:  ['server.js'],
        },
        // Cada archivo de test corre en su propio contexto (isolate=true default)
    },
});
