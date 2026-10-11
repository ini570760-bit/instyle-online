CREATE TABLE IF NOT EXISTS site_state (
  state_key TEXT PRIMARY KEY,
  state_value TEXT,
  updated_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS messages (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  category TEXT NOT NULL,
  name TEXT,
  email TEXT NOT NULL,
  description TEXT NOT NULL,
  attachment_name TEXT,
  attachment_type TEXT,
  attachment_size INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_messages_created_at
ON messages(created_at);
