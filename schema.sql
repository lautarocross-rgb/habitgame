-- Racha · esquema de cuentas y sincronización
-- El _worker.js crea estas tablas solo en el primer pedido.
-- Este archivo sirve para crearlas a mano con wrangler d1 execute.

CREATE TABLE IF NOT EXISTS states (
  sync_id TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  username TEXT NOT NULL UNIQUE,
  salt TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  iterations INTEGER NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id TEXT NOT NULL,
  created_at INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS login_attempts (
  key TEXT PRIMARY KEY,
  fails INTEGER NOT NULL,
  first_at INTEGER NOT NULL
);
