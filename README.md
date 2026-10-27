# Racha

Tracker de hábitos y tareas (PWA) con cuentas y sincronización en tiempo real.
Corre en Cloudflare Workers (assets estáticos + API) con base D1.

## Estructura

- `index.html`, `sw.js`, `manifest.webmanifest`, `icons/`: la app.
- `_worker.js`: API (`/api/register`, `/api/login`, `/api/logout`, `/api/me`, `/api/state`).
- `wrangler.toml`: configuración del Worker y enlace a D1 (`DB`).
- `schema.sql`: referencia del esquema (el Worker crea las tablas solo).

## Despliegue automático

El repo está conectado a Cloudflare (Workers Builds): cada push a `main` construye y despliega
el Worker `habitgame`. El nombre en `wrangler.toml` tiene que coincidir con el del Worker en Cloudflare.

## Desarrollo local

```
npx wrangler dev
```
