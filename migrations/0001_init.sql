CREATE TABLE IF NOT EXISTS servers (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  url TEXT NOT NULL,
  enabled INTEGER NOT NULL DEFAULT 1,
  random_enabled INTEGER NOT NULL DEFAULT 1,
  min_minutes INTEGER NOT NULL DEFAULT 5,
  max_minutes INTEGER NOT NULL DEFAULT 14,
  fixed_minutes INTEGER NOT NULL DEFAULT 10,
  next_ping_at INTEGER NOT NULL DEFAULT 0,
  last_ping_at INTEGER,
  last_status TEXT DEFAULT 'unknown',
  last_http_status INTEGER,
  last_response_ms INTEGER,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS ping_logs (
  id TEXT PRIMARY KEY,
  server_id TEXT NOT NULL,
  pinged_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  http_status INTEGER,
  response_ms INTEGER,
  error TEXT,
  FOREIGN KEY(server_id) REFERENCES servers(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_servers_next_ping ON servers(enabled, next_ping_at);
CREATE INDEX IF NOT EXISTS idx_ping_logs_server_time ON ping_logs(server_id, pinged_at DESC);
