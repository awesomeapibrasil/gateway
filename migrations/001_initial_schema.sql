-- Gateway Database Schema Migration
-- Version: 001
-- Description: Initial schema setup for Gateway

-- Gateway configuration table
CREATE TABLE IF NOT EXISTS gateway_config (
    id SERIAL PRIMARY KEY,
    key VARCHAR(255) NOT NULL UNIQUE,
    value JSONB NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- WAF rules table
CREATE TABLE IF NOT EXISTS waf_rules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    rule_id VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    severity VARCHAR(50) NOT NULL,
    enabled BOOLEAN DEFAULT true,
    conditions JSONB NOT NULL,
    action JSONB NOT NULL,
    metadata JSONB DEFAULT '{}',
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Rate limiting entries table
CREATE TABLE IF NOT EXISTS rate_limit_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(64) NOT NULL,
    key_type VARCHAR(50) NOT NULL,
    key_value VARCHAR(255) NOT NULL,
    requests INTEGER NOT NULL DEFAULT 0,
    window_start TIMESTAMP WITH TIME ZONE NOT NULL,
    last_request TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Create indexes for rate limiting
CREATE INDEX IF NOT EXISTS idx_rate_limit_key_hash ON rate_limit_entries(key_hash);
CREATE INDEX IF NOT EXISTS idx_rate_limit_window_start ON rate_limit_entries(window_start);
CREATE INDEX IF NOT EXISTS idx_rate_limit_last_request ON rate_limit_entries(last_request);

-- Backend health status table
CREATE TABLE IF NOT EXISTS backend_health (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backend_name VARCHAR(255) NOT NULL,
    backend_address VARCHAR(255) NOT NULL,
    healthy BOOLEAN NOT NULL DEFAULT true,
    last_check TIMESTAMP WITH TIME ZONE NOT NULL,
    response_time_ms INTEGER,
    status_code INTEGER,
    error_message TEXT,
    consecutive_failures INTEGER DEFAULT 0,
    consecutive_successes INTEGER DEFAULT 0,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_backend_health_name ON backend_health(backend_name);
CREATE INDEX IF NOT EXISTS idx_backend_health_last_check ON backend_health(last_check);

-- Gateway statistics table
CREATE TABLE IF NOT EXISTS gateway_stats (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    total_requests BIGINT NOT NULL DEFAULT 0,
    total_responses BIGINT NOT NULL DEFAULT 0,
    active_connections INTEGER NOT NULL DEFAULT 0,
    cache_hits BIGINT NOT NULL DEFAULT 0,
    cache_misses BIGINT NOT NULL DEFAULT 0,
    waf_blocks BIGINT NOT NULL DEFAULT 0,
    rate_limit_blocks BIGINT NOT NULL DEFAULT 0,
    backend_errors BIGINT NOT NULL DEFAULT 0,
    average_response_time_ms REAL NOT NULL DEFAULT 0,
    memory_usage_bytes BIGINT NOT NULL DEFAULT 0,
    cpu_usage_percent REAL NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_gateway_stats_timestamp ON gateway_stats(timestamp);

-- Request logs table (optional, for detailed auditing)
CREATE TABLE IF NOT EXISTS request_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    request_id VARCHAR(255) NOT NULL,
    timestamp TIMESTAMP WITH TIME ZONE NOT NULL,
    client_ip INET NOT NULL,
    method VARCHAR(10) NOT NULL,
    uri TEXT NOT NULL,
    user_agent TEXT,
    status_code INTEGER,
    response_time_ms INTEGER,
    bytes_sent BIGINT,
    bytes_received BIGINT,
    backend_name VARCHAR(255),
    cache_hit BOOLEAN DEFAULT false,
    waf_action VARCHAR(50),
    auth_user VARCHAR(255),
    metadata JSONB DEFAULT '{}'
);

-- Indexes for request logs
CREATE INDEX IF NOT EXISTS idx_request_logs_timestamp ON request_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_request_logs_client_ip ON request_logs(client_ip);
CREATE INDEX IF NOT EXISTS idx_request_logs_status_code ON request_logs(status_code);
CREATE INDEX IF NOT EXISTS idx_request_logs_request_id ON request_logs(request_id);

-- Users table (for authentication)
CREATE TABLE IF NOT EXISTS users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    roles JSONB DEFAULT '[]',
    permissions JSONB DEFAULT '[]',
    active BOOLEAN DEFAULT true,
    last_login TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_hash VARCHAR(64) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    user_id UUID REFERENCES users(id) ON DELETE CASCADE,
    scopes JSONB DEFAULT '[]',
    active BOOLEAN DEFAULT true,
    expires_at TIMESTAMP WITH TIME ZONE,
    last_used TIMESTAMP WITH TIME ZONE,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_api_keys_hash ON api_keys(key_hash);
CREATE INDEX IF NOT EXISTS idx_api_keys_user_id ON api_keys(user_id);

-- Cache entries table (for persistent cache)
CREATE TABLE IF NOT EXISTS cache_entries (
    key_hash VARCHAR(64) PRIMARY KEY,
    key_value TEXT NOT NULL,
    value_data BYTEA NOT NULL,
    content_type VARCHAR(255),
    compressed BOOLEAN DEFAULT false,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    access_count BIGINT DEFAULT 0,
    last_accessed TIMESTAMP WITH TIME ZONE DEFAULT NOW(),
    created_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_cache_entries_expires_at ON cache_entries(expires_at);
CREATE INDEX IF NOT EXISTS idx_cache_entries_last_accessed ON cache_entries(last_accessed);

-- Circuit breaker states table
CREATE TABLE IF NOT EXISTS circuit_breaker_states (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    backend_name VARCHAR(255) NOT NULL UNIQUE,
    state VARCHAR(20) NOT NULL CHECK (state IN ('closed', 'open', 'half_open')),
    failure_count INTEGER NOT NULL DEFAULT 0,
    last_failure_time TIMESTAMP WITH TIME ZONE,
    next_attempt_time TIMESTAMP WITH TIME ZONE,
    success_count INTEGER NOT NULL DEFAULT 0,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT NOW()
);

-- Functions for automatic timestamp updates
CREATE OR REPLACE FUNCTION update_updated_at_column()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = NOW();
    RETURN NEW;
END;
$$ language 'plpgsql';

-- Add triggers for updated_at columns
CREATE TRIGGER update_gateway_config_updated_at BEFORE UPDATE ON gateway_config FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_waf_rules_updated_at BEFORE UPDATE ON waf_rules FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_rate_limit_entries_updated_at BEFORE UPDATE ON rate_limit_entries FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_backend_health_updated_at BEFORE UPDATE ON backend_health FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_users_updated_at BEFORE UPDATE ON users FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_api_keys_updated_at BEFORE UPDATE ON api_keys FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();
CREATE TRIGGER update_circuit_breaker_states_updated_at BEFORE UPDATE ON circuit_breaker_states FOR EACH ROW EXECUTE FUNCTION update_updated_at_column();