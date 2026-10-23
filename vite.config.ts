import { defineConfig } from "vite";
import { resolve } from "node:path";

export default defineConfig({
  base: "/monkeytoolV2/",
  build: {
    rollupOptions: {
      input: {
        home: resolve(import.meta.dirname, "index.html"),
        ip: resolve(import.meta.dirname, "ip/index.html"),
        dominio: resolve(import.meta.dirname, "dominio/index.html"),
        hash: resolve(import.meta.dirname, "hash/index.html")
      }
    }
  }
});
