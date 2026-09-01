import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

// GitHub Pages serves the dashboard under /fox-shield/.
export default defineConfig({
  base: '/fox-shield/',
  plugins: [preact()],
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
