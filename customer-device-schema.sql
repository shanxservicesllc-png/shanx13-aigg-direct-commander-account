-- Additive v0.2 commercial device control schema, separate from canonical HemiSync tasks.
-- Apply only to dedicated shanx13-aigg-direct-commander-usage D1 after B snapshot.
CREATE TABLE IF NOT EXISTS customer_device_control (
 agent_id TEXT PRIMARY KEY,
 tenant_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 mode TEXT NOT NULL DEFAULT 'STOP' CHECK(mode IN ('STOP','LIMITED','GO')),
 epoch INTEGER NOT NULL DEFAULT 1,
 locked INTEGER NOT NULL DEFAULT 0 CHECK(locked IN (0,1)),
 last_seen_at TEXT,
 updated_at TEXT NOT NULL,
 UNIQUE(tenant_id,device_id)
);
CREATE TABLE IF NOT EXISTS customer_device_jobs (
 request_id TEXT PRIMARY KEY,
 agent_id TEXT NOT NULL,
 tenant_id TEXT NOT NULL,
 device_id TEXT NOT NULL,
 action TEXT NOT NULL CHECK(action IN ('system_info','list_dir','read_file','write_file')),
 arguments_json TEXT NOT NULL,
 state TEXT NOT NULL CHECK(state IN ('QUEUED','DELIVERED','RUNNING','EXECUTED','FAILED','REJECTED','UNKNOWN','CANCELLED','EXPIRED')),
 control_epoch INTEGER NOT NULL,
 created_at TEXT NOT NULL,
 updated_at TEXT NOT NULL,
 expires_at_ms INTEGER NOT NULL,
 result_json TEXT
);
CREATE INDEX IF NOT EXISTS customer_jobs_by_tenant ON customer_device_jobs(tenant_id,created_at DESC);
CREATE INDEX IF NOT EXISTS customer_jobs_by_agent_state ON customer_device_jobs(agent_id,state,expires_at_ms);
