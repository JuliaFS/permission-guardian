import react from '@vitejs/plugin-react'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const rootDir = dirname(fileURLToPath(import.meta.url))

// Build everything *except* the content script (which must be a single-file
// classic script; see `vite.content.config.ts`).
export default defineConfig({
  plugins: [react()],
  build: {
    rollupOptions: {
      input: {
        index: resolve(rootDir, 'index.html'),
        popup: resolve(rootDir, 'popup.html'),
        background: resolve(rootDir, 'src/background/index.ts'),
      },
      output: {
        entryFileNames: (chunk) => {
          if (chunk.name === 'background') return 'assets/background.js'
          if (chunk.name === 'popup') return 'assets/popup.js'
          return 'assets/[name].js'
        },
        chunkFileNames: 'assets/chunks/[name].js',
        assetFileNames: 'assets/[name][extname]',
      },
    },
  },
})

