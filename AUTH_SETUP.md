# Monkeytools V2 — autenticación propia

## Estado y precauciones
- El código está añadido al repositorio. **NO está activado hasta completar los siguientes pasos.**
- El portal actual seguirá activo hasta que el nuevo despliegue se complete con éxito.
- No compartas contraseñas, tokens, capturas de secretos ni claves API en GitHub o chats.
- Si habías activado Cloudflare Access con tu cuenta de administrador, desactiva la protección Access SOLO en `monkeytools-portal` cuando el login propio ya esté funcionando. No uses la cuenta de Cloudflare como login de Monkeytools.
- La ruta `/login/` es pública; la portada, analizadores y `/api/*` requieren cookie de sesión (excepto login/setup/logout). Las claves API siguen únicamente en los Workers.

## 1. Cloudflare D1
En Cloudflare: **Workers & Pages → D1 SQL Database → Create database**.
Nombre: `monkeytools-auth`. Localiza su **Database ID**, no lo compartas como secreto, y reemplaza el marcador `REPLACE_WITH_D1_DATABASE_ID` en `wrangler-portal.jsonc` dentro de GitHub.

En D1 → `monkeytools-auth` → Console, ejecuta el contenido de `db/schema.sql` (dos tablas y el índice). Hazlo en la base remota de producción, no una base local.

## 2. Worker del portal
Worker `monkeytools-portal`, vinculado al repo `jmarf37/monkeytoolV2`:
- Build command: `CF_DEPLOY=1 npm run build`
- Deploy command: `npx wrangler deploy --config wrangler-portal.jsonc`
- Service Bindings: `IP_SERVICE` → `monkeytoolv2`, `DOMAIN_SERVICE` → `monkeytoolv2-domain`, `HASH_SERVICE` → `monkeytoolv2-hash`, configurados en el archivo.
- D1 binding: `DB` → `monkeytools-auth`.
- Asset binding: `ASSETS` → `./dist`.

## 3. Primer usuario admin
Genera en tu propio equipo una cadena aleatoria con al menos 32 bytes y configúrala en Cloudflare como secreto del Worker **ADMIN_SETUP_TOKEN** (no en GitHub).

La API `POST /api/auth/setup` solo acepta el header `x-setup-token` que coincide con ese secreto, y se deshabilita automáticamente si ya existe algún usuario. Contraseña inicial de al menos **16 caracteres**.

Desde tu equipo puedes utilizar:
```bash
curl -X POST 'https://monkeytools-portal.jesusmartinezferrer.workers.dev/api/auth/setup' \
  -H 'Content-Type: application/json' \
  -H 'x-setup-token: TOKEN_TEMPORAL_AQUI' \
  --data '{"username":"admin","password":"CONTRASENA_MUY_LARGA_AQUI"}'
```
**No incluyas la contraseña real en archivos, historial ni capturas**. Más seguro: usar un cliente HTTP con campo secreto y pedir el cuerpo por entrada privada. Tras el alta, elimina `ADMIN_SETUP_TOKEN` de la configuración del Worker y despliega de nuevo.

## 4. Pruebas
- Ventana privada: `https://monkeytools-portal.jesusmartinezferrer.workers.dev/` redirige a `/login/`.
- Usuario incorrecto: denegado.
- Usuario admin correcto: login y redirección a portada.
- Desde el portal con sesión: las tres rutas `/api/ip/analyze`, `/api/domain/analyze`, `/api/hash/analyze` deben funcionar mediante Service Bindings.
- Sin sesión: las tres rutas devuelven 401.
- Cerrar sesión invalida el token en D1.

## 5. Impedir el uso directo de los Workers backend (OBLIGATORIO antes de considerar privada la aplicación)
Al completar las pruebas anteriores, cambia a `workers_dev:false` los tres archivos `wrangler.jsonc`, `wrangler-domain.jsonc`, `wrangler-hash.jsonc`; despliega las tres API. Comprueba que no tienen rutas públicas personalizadas. Los Service Bindings seguirán permitiendo que el portal autenticado las invoque internamente.
**NO desactives sus dominios workers.dev antes de verificar las consultas desde el portal**, porque GitHub Pages dejaría de funcionar.

## 6. Dominio definitivo
Cloudflare → Worker `monkeytools-portal` → Domains & Routes → Custom Domain → `monkeytools.es`. El dominio debe estar activo en Cloudflare. Resolver los DNS antiguos de GitHub Pages que interfieran; configurar `www.monkeytools.es` como alias o redirección segura. Validar SSL y HTTPS.

## V3
D1 ya separa identidad y sesiones. Podemos añadir roles y claves API individuales **cifradas mediante WebCrypto con clave maestra como secreto de Worker**, además de límites de uso y auditoría. No almacenar jamás claves individuales en el frontend.

## Seguridad adicional
Activar Cloudflare WAF/rate-limiting para `/api/auth/login` y `/api/auth/setup`, y monitorizar intentos de acceso. Las contraseñas utilizan PBKDF2-SHA256 y 310.000 iteraciones con sal individual; las sesiones se almacenan mediante hash SHA-256 en D1, duran 24 horas y usan cookie HttpOnly/Secure/SameSite=Lax.
