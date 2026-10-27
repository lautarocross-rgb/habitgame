# Racha

Tracker de hábitos y tareas (PWA) con cuentas y sincronización en tiempo real.
Corre en Cloudflare Workers (assets estáticos + API) con base D1.

## Estructura

- `index.html`, `sw.js`, `manifest.webmanifest`, `icons/`: la app.
- `_worker.js`: API (`/api/register`, `/api/login`, `/api/logout`, `/api/me`, `/api/state`).
- `wrangler.toml`: configuración del Worker y enlace a D1 (`DB`).
- `schema.sql`: referencia del esquema (el Worker crea las tablas solo).

## Despliegue automático

Cada push a `main` despliega con GitHub Actions (`.github/workflows/deploy.yml`).
Hay que cargar dos secretos en GitHub (Settings → Secrets and variables → Actions):

- `CLOUDFLARE_API_TOKEN`: token con la plantilla "Edit Cloudflare Workers" y permiso de edición sobre D1.
- `CLOUDFLARE_ACCOUNT_ID`: el ID de tu cuenta de Cloudflare.

## Desarrollo local

```
npx wrangler dev
```
