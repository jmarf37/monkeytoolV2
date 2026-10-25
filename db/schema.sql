CREATE TABLE IF NOT EXISTS users (
 id TEXT PRIMARY KEY,
 username TEXT NOT NULL UNIQUE,
 password_salt TEXT NOT NULL,
 password_hash TEXT NOT NULL,
 password_iterations INTEGER NOT NULL,
 role TEXT NOT NULL DEFAULT 'admin',
 active INTEGER NOT NULL DEFAULT 1,
 created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
 id_hash TEXT PRIMARY KEY,
 user_id TEXT NOT NULL REFERENCES users(id),
 expires_at INTEGER NOT NULL,
 created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_sessions_expiry ON sessions(expires_at);
