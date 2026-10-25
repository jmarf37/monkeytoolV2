# Monkeytools V2 — Hashes

Tercer Cloudflare Worker independiente, dentro de `jmarf37/monkeytoolV2`.

## Cloudflare
Workers & Pages > Create > Connect to Git
- Repositorio: `jmarf37/monkeytoolV2`
- Rama: `main`
- Nombre: `monkeytoolv2-hash`
- Root directory: `/`
- Build command: dejar vacío
- Deploy command: `npx wrangler deploy --config wrangler-hash.jsonc`
- Preview/version command (si se solicita): `npx wrangler versions upload --config wrangler-hash.jsonc`

## Variables y secretos DEL NUEVO WORKER
- `VT_API`: clave VirusTotal
- `ALIEN_API`: clave OTX AlienVault
- `HYBRID_API`: clave API de Hybrid Analysis
- `MALWAREBAZAAR_API`: Auth-Key de MalwareBazaar (abuse.ch)

Reutilizar las claves VT y OTX significa introducirlas nuevamente en el panel de este Worker. No se copian automáticamente entre proyectos.

## Prueba
- GET `https://monkeytoolv2-hash.jesusmartinezferrer.workers.dev/health`
- Abrir `https://jmarf37.github.io/monkeytoolV2/hash/`
- Probar el MD5 EICAR `44d88612fea8a8f36de82e1278abb02f`.

La interfaz tiene precargada la URL del nuevo Worker. Si Cloudflare utiliza un subdominio diferente, habrá que actualizar `ENDPOINT` en `src/hash.ts`.

Se consultan hashes ya conocidos, sin subir ni ejecutar archivos. Permite MD5/SHA-1/SHA-256 y hasta 15 por análisis. Cuotas y permisos dependen del plan de cada proveedor.

Workers IP y Dominio no se modifican.
