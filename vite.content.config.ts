import react from '@vitejs/plugin-react'
import { dirname, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'
import { defineConfig } from 'vite'

const rootDir = dirname(fileURLToPath(import.meta.url))

// Build the content script as an ES module to enable code-splitting.
// Reverting to IIFE format as Chrome content scripts may not fully support ESM code splitting,
// and ensuring the output filename matches the manifest.
export default defineConfig({
  plugins: [react()],
  build: {
    emptyOutDir: false,
    rollupOptions: {
      input: {
        content: resolve(rootDir, 'src/content/index.ts'),
      },
      output: {
        format: 'iife', // Ensure IIFE format for content script compatibility
        // inlineDynamicImports: true, // This option is ignored when codeSplitting is false (implicit with 'iife' format)
        entryFileNames: 'assets/content-module.js', // Explicitly name the output file
        assetFileNames: (assetInfo) => {
          // Ensure panel.css is output directly to the dist folder, as specified in manifest.json
          if (assetInfo.name === 'panel.css') {
            return 'panel.css';
          }
          return 'assets/[name][extname]'; // Other assets go into 'assets/'
        },
      },
    },
    cssCodeSplit: true, // Explicitly enable CSS code splitting to ensure CSS is extracted
  },
})
