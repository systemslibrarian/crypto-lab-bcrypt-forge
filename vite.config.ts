import { defineConfig } from 'vite';

export default defineConfig({
  base: '/crypto-lab-bcrypt-forge/',
  build: {
    outDir: 'dist',
    target: 'es2020',
  },
});
