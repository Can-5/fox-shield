import { defineConfig } from 'vite';
import preact from '@preact/preset-vite';

// Cloudflare Pages serves at /, GitHub Pages at /fox-shield/. Use env to switch.
export default defineConfig({
  base: process.env.PAGES_BASE || '/',
  plugins: [preact()],
  build: {
    outDir: 'dist',
    sourcemap: false,
  },
});
