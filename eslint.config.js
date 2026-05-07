// eslint.config.js — ESLint v9+ Flat Config
// MYG Telecom Backend (Node.js / CommonJS)

import js from '@eslint/js';

export default [
    js.configs.recommended,
    {
        languageOptions: {
            ecmaVersion: 2022,
            sourceType:  'commonjs',
            globals: {
                // Node.js globals
                require:   'readonly',
                module:    'readonly',
                exports:   'readonly',
                __dirname: 'readonly',
                __filename:'readonly',
                process:   'readonly',
                console:   'readonly',
                Buffer:    'readonly',
                setTimeout:'readonly',
                setInterval:'readonly',
                clearTimeout:'readonly',
                clearInterval:'readonly',
            },
        },
        rules: {
            'no-unused-vars':         ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
            'no-undef':               'warn',
            'no-var':                 'warn',
            'eqeqeq':                 ['warn', 'always'],
            'no-eval':                'error',
            'no-implied-eval':        'error',
            'no-console':             'off',
            // Reglas de recommended bajadas a warn para adopción gradual del codebase existente
            'no-empty':               ['warn', { allowEmptyCatch: true }],
            'no-extra-boolean-cast':  'warn',
        },
        files: ['server.js', 'routes/**/*.js', 'env-validator.js'],
        ignores: ['node_modules/**', '.husky/**'],
    },
    // ── Configuración específica para tests Vitest ─────────────────
    {
        files: ['__tests__/**/*.test.js'],
        languageOptions: {
            ecmaVersion: 2022,
            sourceType:  'module',   // Tests usan ESM import/export
            globals: {
                // Vitest globals (describe, it, expect, vi, etc.)
                describe:   'readonly',
                it:         'readonly',
                expect:     'readonly',
                vi:         'readonly',
                beforeEach: 'readonly',
                afterEach:  'readonly',
                beforeAll:  'readonly',
                afterAll:   'readonly',
                test:       'readonly',
                // Node globals
                process:    'readonly',
                console:    'readonly',
            },
        },
        rules: {
            'no-unused-vars': ['warn', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
            'no-undef':       'warn',
            'no-console':     'off',
        },
    },
];
