# Backend Cloudflare Workers (laboratorio)
Este backend **no se despliega mediante GitHub Pages**. El código usa fetch y secretos de Cloudflare.
Configuración en Cloudflare (nunca en GitHub):
```
npx wrangler secret put VT_API
npx wrangler secret put ABUSE_API
npx wrangler secret put ALIEN_API
npx wrangler secret put IPQ_API
```
Opcionales: ALLOWED_ORIGIN=https://jmarf37.github.io y BLACKLIST_URL.
Publicar desde entorno local con `npx wrangler deploy` o conectar el mismo repositorio en Cloudflare.
Por defecto se permiten solicitudes POST desde https://jmarf37.github.io hacia /api/ip/analyze.
Limitación del laboratorio: validación de IP IPv6 conservadora, blacklist descargada por solicitud, y falta de rate limiting persistente. Mejorar antes de exponer a tráfico público. Revocar las credenciales antiguas expuestas en el repositorio original.
