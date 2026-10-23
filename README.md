# Monkeytools V2 — Laboratorio

Portal de pruebas GitHub Pages + Vite/TypeScript. No se altera el dominio de producción.

## Frontend

- /monkeytoolV2/ · Portada
- /monkeytoolV2/ip/ · Analizador IP migrado a TypeScript
- /monkeytoolV2/dominio/ · Placeholder
- /monkeytoolV2/hash/ · Placeholder

```sh
npm install
npm run dev
npm run build
npm run check:worker
```

GitHub > Settings > Pages > Source: GitHub Actions.
https://jmarf37.github.io/monkeytoolV2/

## Analizador IP

Backend independiente en `worker/index.ts` listo para Cloudflare Workers. Proveedores: VirusTotal, AbuseIPDB, AlienVault OTX (IPv4), IPQualityScore, RDAP y blacklist S2Grupo.

**IMPORTANTE:** el frontend en GitHub Pages no realiza consultas hasta desplegar el Worker y establecer su URL HTTPS en el formulario /ip/. En Cloudflare, definir secretos `VT_API`, `ABUSE_API`, `ALIEN_API` y `IPQ_API` (consultar `worker/README.md`). Revocar claves previas que hayan estado accesibles en GitHub.

La API responde a `POST /api/ip/analyze` con `{ips:"8.8.8.8, 1.1.1.1"}`. Máximo 5 indicadores por solicitud. El Worker permite peticiones originadas en `https://jmarf37.github.io` por defecto.

**Pendiente antes de la exposición pública:** desplegar Worker, validar datos con las APIs reales, implementar limitación persistente de solicitudes y cachear blacklist. Los subdominios y DNS actuales permanecen intactos.

El fondo se referencia temporalmente desde el repositorio original, sin modificarlo.
