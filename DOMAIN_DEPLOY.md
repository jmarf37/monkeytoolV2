# Monkeytools V2 — despliegue aislado de dominios

Este proyecto **NO debe reemplazar** el Worker de IP `monkeytoolv2`.

## Segundo Worker en Cloudflare
Crea un proyecto Workers nuevo conectado al mismo repositorio `jmarf37/monkeytoolV2`, rama `main`.
- Nombre: `monkeytoolv2-domain`
- Build command: vacío
- Deploy command: `npx wrangler deploy --config wrangler-domain.jsonc`
- Preview command (si es obligatorio): `npx wrangler versions upload --config wrangler-domain.jsonc`
- Root directory: raíz del repositorio

El Worker de dominios utiliza `worker/domain-entry.ts`, distinto de `worker/index.ts`.
Están aislados por despliegue, configuraciones y secretos.

## Secretos del Worker de dominios
Configurar en **ese nuevo Worker** (no en el de IP):
- `VT_API`: VirusTotal
- `ALIEN_API`: AlienVault OTX
- `URLSCAN_API`: urlscan.io

No incorporar claves al repositorio ni a las URLs del navegador. El script Python original contenía claves incrustadas: revocarlas y sustituirlas por claves nuevas.

## Verificación
`GET https://<worker-dominio>.workers.dev/health` debe responder `{"ok":true,"service":"monkeytools-domain"}`.

Frontend en `https://jmarf37.github.io/monkeytoolV2/dominio/`.
En el campo Worker, introducir la dirección asignada al **segundo** Worker. Las consultas de dominios usan `POST /api/domain/analyze`.

El analizador IP continúa con su Worker original y `POST /api/ip/analyze`.
