# Publicación de Monkeytools en monkeytools.es

## Preparación (ya realizada en GitHub)
- `wrangler-portal.jsonc`: Worker independiente `monkeytools-portal` que publica `./dist`.
- `vite.config.ts`: cuando `CF_DEPLOY=1`, las rutas son relativas a la raíz del dominio. GitHub Pages conserva `/monkeytoolV2/`.
- El repositorio continúa siendo `jmarf37/monkeytoolV2`.
- **No se han cambiado registros DNS ni activado todavía autenticación.**

## En Cloudflare
1. Añadir `monkeytools.es` a la cuenta como dominio (si no figura ya), verificar los registros DNS actuales y completar la activación de la zona con los servidores DNS que Cloudflare asigne. En Dondominio se cambian solo cuando se han verificado registros, DNSSEC y correo.
2. Workers & Pages > Create > Worker > Import Git repository: `jmarf37/monkeytoolV2`, rama `main`, nombre `monkeytools-portal`.
3. Build command: `CF_DEPLOY=1 npm run build`.
4. Deploy command: `npx wrangler deploy --config wrangler-portal.jsonc`.
5. Conectar `monkeytools.es` en el Worker > Settings > Domains & Routes > Add > Custom Domain. Repetir con `www.monkeytools.es` si se desea, o añadir una regla de redirección permanente de www al dominio raíz.
6. Comprobar portada, rutas `/ip/`, `/dominio/` y `/hash/`, imágenes y consultas.
7. Zero Trust > Access > Applications: crear regla que permita **solo el correo del administrador**, mediante proveedor de identidad/código OTP. Proteger Worker `monkeytools-portal` desde su pestaña Access, para cubrir también la URL `workers.dev`. Si se utiliza protección por hostname solamente, la URL `workers.dev` puede quedar expuesta.
8. **IMPORTANTE: los 3 Workers de consultas de IP, dominio y hash están separados y actualmente reciben peticiones desde el navegador a sus URL `workers.dev`. No se consideran protegidos por asegurar solo el portal.** Antes de dar por completado el acceso privado, rediseñar esas peticiones para que pasen por un gateway autenticado en Cloudflare que invoque los Workers mediante Service Bindings, o equivalentes, y bloquear el acceso público a los Workers backend. No activar Access en los tres backends directamente sin preparar el gateway: las peticiones del navegador podrían dejar de funcionar por CORS/redirecciones de autenticación.
9. Una vez migrado y protegido todo, cerrar publicación pública de GitHub Pages o dejar de desplegar allí para no permitir acceso directo a la interfaz estática. GitHub Pages no almacena las API keys; los Workers sí deben protegerse.

## V3
Identidad de Access por usuario + base de datos D1 con roles, cuotas y claves API cifradas; cada Worker obtiene la configuración solo del backend.

Nunca guardar API keys en el repositorio ni en archivos JavaScript del navegador.
