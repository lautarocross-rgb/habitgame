/* Racha · API de cuentas y sincronización
   Cloudflare Worker con static assets: sirve la app estática y atiende
   /api/register, /api/login, /api/logout, /api/me y /api/state.
   La base D1 se enlaza como DB desde wrangler.toml.

   Cuentas: usuario + contraseña (PBKDF2-SHA256 con sal propia).
   Sesiones: token aleatorio "rs_..." que se guarda hasheado en D1.
   Compatibilidad: los códigos de sincronización anteriores siguen
   funcionando en /api/state si el token no empieza con "rs_". */

const JSON_HEADERS = {
  "Content-Type": "application/json; charset=utf-8",
  "Cache-Control": "no-store",
  "X-Content-Type-Options": "nosniff"
};
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_AUTH_BODY_BYTES = 4 * 1024;
const MIN_CODE_LENGTH = 16;
const MAX_CODE_LENGTH = 128;
const CODE_PATTERN = /^[A-Za-z0-9_-]+$/;

const SESSION_PREFIX = "rs_";
const SESSION_DAYS = 90;
const SESSION_MS = SESSION_DAYS * 24 * 60 * 60 * 1000;
const PBKDF2_ITERATIONS = 100000; // máximo que permite Cloudflare Workers
const USERNAME_PATTERN = /^[a-z0-9][a-z0-9_.-]{2,31}$/;
const MIN_PASSWORD = 8;
const MAX_PASSWORD = 128;
const MAX_FAILS = 8;
const FAIL_WINDOW_MS = 15 * 60 * 1000;

let schemaReady = false;

function json(body, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: JSON_HEADERS });
}

/* ---------- Utilidades de cifrado ---------- */

function toHex(buffer) {
  return [...new Uint8Array(buffer)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

function fromHex(hex) {
  const out = new Uint8Array(hex.length / 2);
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
  return out;
}

function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
}

async function sha256Hex(text) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return toHex(digest);
}

async function derivePassword(password, saltBytes, iterations) {
  const key = await crypto.subtle.importKey(
    "raw", new TextEncoder().encode(password), "PBKDF2", false, ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", hash: "SHA-256", salt: saltBytes, iterations },
    key, 256
  );
  return toHex(bits);
}

function safeEqual(a, b) {
  if (a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

/* ---------- Base de datos ---------- */

async function ensureSchema(env) {
  if (schemaReady) return;
  await env.DB.batch([
    env.DB.prepare("CREATE TABLE IF NOT EXISTS states (sync_id TEXT PRIMARY KEY, data TEXT NOT NULL, updated_at INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, username TEXT NOT NULL UNIQUE, salt TEXT NOT NULL, pass_hash TEXT NOT NULL, iterations INTEGER NOT NULL, created_at INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, user_id TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)"),
    env.DB.prepare("CREATE TABLE IF NOT EXISTS login_attempts (key TEXT PRIMARY KEY, fails INTEGER NOT NULL, first_at INTEGER NOT NULL)")
  ]);
  schemaReady = true;
}

/* ---------- Autenticación ---------- */

function getBearer(request) {
  const auth = request.headers.get("Authorization") || "";
  const match = auth.match(/^Bearer\s+(.+)$/i);
  return match ? match[1].trim() : "";
}

function isLegacyCode(code) {
  return code.length >= MIN_CODE_LENGTH && code.length <= MAX_CODE_LENGTH && CODE_PATTERN.test(code);
}

/* Devuelve { syncId, userId, username } o null. */
async function authenticate(request, env) {
  const token = getBearer(request);
  if (!token) return null;

  if (token.startsWith(SESSION_PREFIX)) {
    if (token.length > MAX_CODE_LENGTH || !CODE_PATTERN.test(token)) return null;
    await ensureSchema(env);
    const tokenHash = await sha256Hex(token);
    const row = await env.DB
      .prepare("SELECT s.user_id AS user_id, s.expires_at AS expires_at, u.username AS username FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.token_hash = ?")
      .bind(tokenHash)
      .first();
    if (!row || Number(row.expires_at) < Date.now()) return null;
    return { syncId: `user:${row.user_id}`, userId: row.user_id, username: row.username, tokenHash };
  }

  if (!isLegacyCode(token)) return null;
  return { syncId: await sha256Hex(token), userId: null, username: null, tokenHash: null };
}

async function createSession(env, userId) {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const token = SESSION_PREFIX + toBase64Url(bytes);
  const now = Date.now();
  await env.DB
    .prepare("INSERT INTO sessions (token_hash, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)")
    .bind(await sha256Hex(token), userId, now, now + SESSION_MS)
    .run();
  // Limpieza de sesiones vencidas (barata y ocasional).
  if (Math.random() < 0.05) {
    await env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(now).run();
  }
  return token;
}

function normalizeUsername(value) {
  return String(value || "").trim().toLowerCase();
}

async function readAuthBody(request) {
  const contentLength = Number(request.headers.get("Content-Length") || 0);
  if (Number.isFinite(contentLength) && contentLength > MAX_AUTH_BODY_BYTES) return null;
  try {
    const body = await request.json();
    if (!body || typeof body !== "object" || Array.isArray(body)) return null;
    return body;
  } catch (error) {
    return null;
  }
}

/* Límite simple de intentos fallidos por usuario + IP. */
async function isLocked(env, key) {
  const row = await env.DB.prepare("SELECT fails, first_at FROM login_attempts WHERE key = ?").bind(key).first();
  if (!row) return false;
  if (Date.now() - Number(row.first_at) > FAIL_WINDOW_MS) return false;
  return Number(row.fails) >= MAX_FAILS;
}

async function registerFail(env, key) {
  const now = Date.now();
  const row = await env.DB.prepare("SELECT fails, first_at FROM login_attempts WHERE key = ?").bind(key).first();
  if (!row || now - Number(row.first_at) > FAIL_WINDOW_MS) {
    await env.DB
      .prepare("INSERT INTO login_attempts (key, fails, first_at) VALUES (?, 1, ?) ON CONFLICT(key) DO UPDATE SET fails = 1, first_at = excluded.first_at")
      .bind(key, now).run();
  } else {
    await env.DB.prepare("UPDATE login_attempts SET fails = fails + 1 WHERE key = ?").bind(key).run();
  }
}

async function clearFails(env, key) {
  await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind(key).run();
}

async function handleRegister(request, env) {
  try {
    const body = await readAuthBody(request);
    if (!body) return json({ ok: false, error: "Datos inválidos." }, 400);

    const username = normalizeUsername(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    if (!USERNAME_PATTERN.test(username)) {
      return json({ ok: false, error: "El usuario debe tener entre 3 y 32 caracteres: letras, números, punto, guion o guion bajo." }, 400);
    }
    if (password.length < MIN_PASSWORD || password.length > MAX_PASSWORD) {
      return json({ ok: false, error: `La contraseña debe tener entre ${MIN_PASSWORD} y ${MAX_PASSWORD} caracteres.` }, 400);
    }

    await ensureSchema(env);
    const existing = await env.DB.prepare("SELECT id FROM users WHERE username = ?").bind(username).first();
    if (existing) return json({ ok: false, error: "Ese usuario ya existe. Probá con otro o iniciá sesión." }, 409);

    const saltBytes = new Uint8Array(16);
    crypto.getRandomValues(saltBytes);
    const hash = await derivePassword(password, saltBytes, PBKDF2_ITERATIONS);
    const userId = crypto.randomUUID();

    try {
      await env.DB
        .prepare("INSERT INTO users (id, username, salt, pass_hash, iterations, created_at) VALUES (?, ?, ?, ?, ?, ?)")
        .bind(userId, username, toHex(saltBytes), hash, PBKDF2_ITERATIONS, Date.now())
        .run();
    } catch (error) {
      return json({ ok: false, error: "Ese usuario ya existe. Probá con otro o iniciá sesión." }, 409);
    }

    const token = await createSession(env, userId);
    return json({ ok: true, token, username });
  } catch (error) {
    console.error("POST /api/register", error);
    return json({ ok: false, error: "No se pudo crear la cuenta. Revisá la base D1." }, 500);
  }
}

async function handleLogin(request, env) {
  try {
    const body = await readAuthBody(request);
    if (!body) return json({ ok: false, error: "Datos inválidos." }, 400);

    const username = normalizeUsername(body.username);
    const password = typeof body.password === "string" ? body.password : "";
    if (!username || !password || password.length > MAX_PASSWORD) {
      return json({ ok: false, error: "Usuario o contraseña incorrectos." }, 401);
    }

    await ensureSchema(env);
    const ip = request.headers.get("CF-Connecting-IP") || "unknown";
    const lockKey = await sha256Hex(`${username}|${ip}`);
    if (await isLocked(env, lockKey)) {
      return json({ ok: false, error: "Demasiados intentos. Esperá unos minutos y probá de nuevo." }, 429);
    }

    const user = await env.DB
      .prepare("SELECT id, username, salt, pass_hash, iterations FROM users WHERE username = ?")
      .bind(username)
      .first();

    // Se calcula el hash aunque el usuario no exista, para no revelar cuáles existen.
    const saltBytes = user ? fromHex(user.salt) : new Uint8Array(16);
    const iterations = user ? Number(user.iterations) || PBKDF2_ITERATIONS : PBKDF2_ITERATIONS;
    const candidate = await derivePassword(password, saltBytes, iterations);
    const valid = user ? safeEqual(candidate, user.pass_hash) : false;

    if (!valid) {
      await registerFail(env, lockKey);
      return json({ ok: false, error: "Usuario o contraseña incorrectos." }, 401);
    }

    await clearFails(env, lockKey);
    const token = await createSession(env, user.id);
    return json({ ok: true, token, username: user.username });
  } catch (error) {
    console.error("POST /api/login", error);
    return json({ ok: false, error: "No se pudo iniciar sesión. Revisá la base D1." }, 500);
  }
}

async function handleLogout(request, env) {
  try {
    const auth = await authenticate(request, env);
    if (auth && auth.tokenHash) {
      await env.DB.prepare("DELETE FROM sessions WHERE token_hash = ?").bind(auth.tokenHash).run();
    }
    return json({ ok: true });
  } catch (error) {
    console.error("POST /api/logout", error);
    return json({ ok: true });
  }
}

async function handleMe(request, env) {
  try {
    const auth = await authenticate(request, env);
    if (!auth || !auth.userId) return json({ ok: false, error: "Sesión inválida." }, 401);
    return json({ ok: true, username: auth.username });
  } catch (error) {
    console.error("GET /api/me", error);
    return json({ ok: false, error: "No se pudo verificar la sesión." }, 500);
  }
}

/* ---------- Estado sincronizado ---------- */

async function handleGet(request, env) {
  try {
    const auth = await authenticate(request, env);
    if (!auth) return json({ ok: false, error: "Sesión vencida o código inválido. Iniciá sesión de nuevo." }, 401);

    await ensureSchema(env);

    // Consulta liviana para sincronizar casi en tiempo real: si no hubo cambios, no se envían los datos.
    const since = Number(new URL(request.url).searchParams.get("since")) || 0;
    if (since > 0) {
      const meta = await env.DB
        .prepare("SELECT updated_at FROM states WHERE sync_id = ?")
        .bind(auth.syncId)
        .first();
      if (meta && Number(meta.updated_at) === since) {
        return json({ ok: true, exists: true, unchanged: true, updatedAt: since });
      }
    }

    const row = await env.DB
      .prepare("SELECT data, updated_at FROM states WHERE sync_id = ?")
      .bind(auth.syncId)
      .first();

    if (!row) return json({ ok: true, exists: false, data: null, updatedAt: 0 });

    let data;
    try {
      data = JSON.parse(row.data);
    } catch (error) {
      return json({ ok: false, error: "Los datos de la nube están corruptos." }, 500);
    }

    return json({
      ok: true,
      exists: true,
      data,
      updatedAt: Number(row.updated_at) || 0
    });
  } catch (error) {
    console.error("GET /api/state", error);
    return json({ ok: false, error: "No se pudo leer la nube. Revisá la base D1." }, 500);
  }
}

async function handlePut(request, env) {
  try {
    const auth = await authenticate(request, env);
    if (!auth) return json({ ok: false, error: "Sesión vencida o código inválido. Iniciá sesión de nuevo." }, 401);

    const contentLength = Number(request.headers.get("Content-Length") || 0);
    if (Number.isFinite(contentLength) && contentLength > MAX_BODY_BYTES) {
      return json({ ok: false, error: "Los datos son demasiado grandes." }, 413);
    }

    let body;
    try {
      body = await request.json();
    } catch (error) {
      return json({ ok: false, error: "El cuerpo no es un JSON válido." }, 400);
    }

    if (!body || typeof body !== "object" || Array.isArray(body)) {
      return json({ ok: false, error: "Faltan los datos." }, 400);
    }

    const data = body.data;
    if (!data || typeof data !== "object" || Array.isArray(data)) {
      return json({ ok: false, error: "Faltan los datos." }, 400);
    }
    if (!Array.isArray(data.habits) || !Array.isArray(data.tasks)) {
      return json({ ok: false, error: "El formato de los datos no es válido." }, 400);
    }

    const serialized = JSON.stringify(data);
    if (serialized.length > MAX_BODY_BYTES) {
      return json({ ok: false, error: "Los datos son demasiado grandes." }, 413);
    }

    await ensureSchema(env);
    const updatedAt = Date.now();

    await env.DB.prepare(
      `INSERT INTO states (sync_id, data, updated_at)
       VALUES (?, ?, ?)
       ON CONFLICT(sync_id) DO UPDATE SET
         data = excluded.data,
         updated_at = excluded.updated_at`
    ).bind(auth.syncId, serialized, updatedAt).run();

    return json({ ok: true, updatedAt });
  } catch (error) {
    console.error("PUT /api/state", error);
    return json({ ok: false, error: "No se pudo guardar en la nube. Revisá la base D1." }, 500);
  }
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname.replace(/\/+$/, "");

    if (path === "/api/state") {
      if (request.method === "GET") return handleGet(request, env);
      if (request.method === "PUT") return handlePut(request, env);
      return json({ ok: false, error: "Método no permitido." }, 405);
    }
    if (path === "/api/register") {
      return request.method === "POST" ? handleRegister(request, env) : json({ ok: false, error: "Método no permitido." }, 405);
    }
    if (path === "/api/login") {
      return request.method === "POST" ? handleLogin(request, env) : json({ ok: false, error: "Método no permitido." }, 405);
    }
    if (path === "/api/logout") {
      return request.method === "POST" ? handleLogout(request, env) : json({ ok: false, error: "Método no permitido." }, 405);
    }
    if (path === "/api/me") {
      return request.method === "GET" ? handleMe(request, env) : json({ ok: false, error: "Método no permitido." }, 405);
    }

    if (url.pathname.startsWith("/api/")) {
      return json({ ok: false, error: "No encontrado." }, 404);
    }

    return env.ASSETS.fetch(request);
  }
};
