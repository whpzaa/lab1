import js from '@eslint/js';
import security from 'eslint-plugin-security';

export default [
  {
    ignores: ['node_modules/**', 'coverage/**', 'reports/**', 'data/**', 'cve/**']
  },
  js.configs.recommended,
  security.configs.recommended,
  {
    files: ['**/*.js', '**/*.mjs'],
    languageOptions: {
      ecmaVersion: 'latest',
      sourceType: 'module',
      globals: {
        Buffer: 'readonly',
        clearTimeout: 'readonly',
        console: 'readonly',
        process: 'readonly',
        setTimeout: 'readonly'
      }
    },
    rules: {
      'no-console': 'off',
      'security/detect-non-literal-fs-filename': 'off',
      'security/detect-object-injection': 'off'
    }
  }
];
