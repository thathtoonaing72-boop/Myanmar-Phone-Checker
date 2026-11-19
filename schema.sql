CREATE TABLE IF NOT EXISTS tac_records (
  tac CHAR(8) PRIMARY KEY CHECK (tac ~ '^[0-9]{8}$'),
  brand TEXT NOT NULL,
  model TEXT NOT NULL,
  device_type TEXT,
  source TEXT,
  verified BOOLEAN NOT NULL DEFAULT FALSE,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS tac_records_brand_idx ON tac_records (brand);
