-- Limitky D1 Schema
-- Spusti: wrangler d1 execute limitky --file=schema.sql

CREATE TABLE IF NOT EXISTS products (
  id         TEXT PRIMARY KEY,
  code       TEXT NOT NULL,
  name       TEXT NOT NULL,
  qty        TEXT DEFAULT '',
  price      TEXT DEFAULT '',
  miesto     TEXT DEFAULT '',
  date       TEXT DEFAULT '',
  note       TEXT DEFAULT '',
  poznamka   TEXT DEFAULT '',
  status     TEXT DEFAULT 'stock',
  photo_key  TEXT,           -- R2 object key, napr. "photos/{id}.jpg"
  archived   INTEGER DEFAULT 0,
  deleted    INTEGER DEFAULT 0,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_products_status     ON products(status);
CREATE INDEX IF NOT EXISTS idx_products_archived   ON products(archived);
CREATE INDEX IF NOT EXISTS idx_products_deleted    ON products(deleted);
CREATE INDEX IF NOT EXISTS idx_products_created_at ON products(created_at);

CREATE TABLE IF NOT EXISTS recent_codes (
  position INTEGER PRIMARY KEY,
  code     TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
  id            TEXT PRIMARY KEY,
  email         TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  created_at    TEXT NOT NULL
);
