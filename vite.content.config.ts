import react from '@vitejs/plugin-react'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const rootDir = dirname(fileURLToPath(import.meta.url))

// Build a *single-file* classic content script (no ESM `import` statements).
// Chrome loads `content_scripts[].js` as a classic script, so code-splitting / ESM
// imports will crash at runtime.
export default defineConfig({
  plugins: [react()],
  build: {
    emptyOutDir: false,
    rollupOptions: {
      input: {
        content: resolve(rootDir, 'src/content/index.ts'),
      },
      output: {
        format: 'iife',
        inlineDynamicImports: true,
        entryFileNames: 'assets/content-module.js',
        chunkFileNames: 'assets/chunks/[name].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
})

