import eslint from '@eslint/js';
import tseslint from 'typescript-eslint';
import eslintConfigPrettier from 'eslint-config-prettier';
import { defineConfig } from 'eslint/config';

export default defineConfig([
   eslint.configs.recommended,
   ...tseslint.configs.recommended,
   eslintConfigPrettier,
   {
      rules: {
         'no-console': 'warn',
         '@typescript-eslint/no-explicit-any': 'off',
         '@typescript-eslint/no-unused-vars': [
            'error',
            { argsIgnorePattern: '^_', ignoreRestSiblings: true },
         ],
         'prefer-const': 'error',
      },
   },
   {
      files: ['build-any.mjs'],
      languageOptions: {
         env: {
            node: true,
         },
      },
   },
]);
