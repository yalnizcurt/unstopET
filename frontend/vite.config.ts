import { defineConfig } from "vite";

// Keep cookies on the browser's origin during local development as in Vercel.
export default defineConfig({
  server: { proxy: { "/api": { target: process.env.VITE_API_PROXY || "http://127.0.0.1:8000" } } },
});
