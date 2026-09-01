import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

// Developer Mode is a private local viewer — no base path needed.
export default defineConfig({
  base: '/',
  plugins: [preact()],
  server: {
    port: 5173,
    proxy: {
      '/api': 'http://localhost:8788',
    },
  },
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
