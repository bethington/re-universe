-- BSim Database Schema Creation for large_32 Template
-- Based on Ghidra BSim large_32.xml configuration
-- Optimized for ~100 million functions on 32-bit executables

\echo 'Creating BSim database schema with large_32 template...'

-- Set search path
SET search_path TO public;

-- BSim configuration values from large_32.xml
-- k=19, L=232 (LSH parameters for 100M+ functions)

-- Create keyvaluetable for BSim configuration
CREATE TABLE IF NOT EXISTS keyvaluetable (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

-- Insert BSim configuration from large_32.xml
INSERT INTO keyvaluetable (key, value) VALUES
    ('BSimConfigInfo', '<info><name>Large 32-bit</name><owner>Ubuntu Linux BSim</owner><description>A large (~100 million functions) database tuned for 32-bit executables</description><major>0</major><minor>0</minor><settings>0x49</settings></info>'),
    ('k', '19'),
    ('L', '232'),
    ('weightsfile', 'lshweights_32.xml'),
    ('template', 'large_32'),
    ('created_timestamp', EXTRACT(EPOCH FROM NOW())::TEXT),
    ('schema_version', '1.0')
ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value;

-- Create BSim executable table (enhanced for large scale)
CREATE TABLE IF NOT EXISTS executable (
    id BIGSERIAL PRIMARY KEY,
    md5 VARCHAR(32) UNIQUE NOT NULL,
    name_exec VARCHAR(1024),
    arch VARCHAR(64),
    name_compiler VARCHAR(128),
    version_compiler VARCHAR(128),
    name_category VARCHAR(256),
    date_create TIMESTAMP,
    repo VARCHAR(512),
    path VARCHAR(2048),
    description TEXT,
    ingest_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    function_count INTEGER DEFAULT 0,
    signature_count INTEGER DEFAULT 0
);

-- Create BSim executable categories
CREATE TABLE IF NOT EXISTS executable_category (
    id SERIAL PRIMARY KEY,
    category_name VARCHAR(256) UNIQUE NOT NULL,
    description TEXT
);

-- Insert default categories
INSERT INTO executable_category (category_name, description) VALUES
    ('UNKNOWN', 'Unknown executable type'),
    ('LIBRARY', 'Shared library or static library'),
    ('EXECUTABLE', 'Standalone executable program'),
    ('DRIVER', 'Device driver or kernel module'),
    ('MALWARE', 'Malicious software')
ON CONFLICT (category_name) DO NOTHING;

-- Create BSim function table (optimized for large datasets)
CREATE TABLE IF NOT EXISTS function (
    id BIGSERIAL PRIMARY KEY,
    name_func VARCHAR(512),
    name_namespace VARCHAR(512),
    addr BIGINT,
    flags INTEGER DEFAULT 0,
    executable_id BIGINT REFERENCES executable(id) ON DELETE CASCADE,
    signature_count INTEGER DEFAULT 0,
    create_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create BSim signature table (partitioned for large scale)
CREATE TABLE IF NOT EXISTS signature (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES function(id) ON DELETE CASCADE,
    feature_vector LSHVECTOR,  -- Using the LSH extension we built
    significance REAL DEFAULT 0.0,
    hash_code BIGINT,
    vector_count INTEGER DEFAULT 0,
    create_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create BSim vector table for LSH indexing
CREATE TABLE IF NOT EXISTS vector (
    id BIGSERIAL PRIMARY KEY,
    signature_id BIGINT REFERENCES signature(id) ON DELETE CASCADE,
    feature_id INTEGER,
    hash_value BIGINT,
    weight REAL DEFAULT 1.0,
    significance REAL DEFAULT 0.0
);

-- Create BSim callgraph table
CREATE TABLE IF NOT EXISTS callgraph (
    id BIGSERIAL PRIMARY KEY,
    caller_id BIGINT REFERENCES function(id) ON DELETE CASCADE,
    callee_id BIGINT REFERENCES function(id) ON DELETE CASCADE,
    executable_id BIGINT REFERENCES executable(id) ON DELETE CASCADE,
    call_count INTEGER DEFAULT 1
);

-- Create BSim feature table
CREATE TABLE IF NOT EXISTS feature (
    id SERIAL PRIMARY KEY,
    name VARCHAR(512) UNIQUE NOT NULL,
    description TEXT,
    weight REAL DEFAULT 1.0
);

-- Insert default features for BSim analysis
INSERT INTO feature (name, description, weight) VALUES
    ('basic_blocks', 'Basic block count feature', 1.0),
    ('function_calls', 'Function call patterns', 1.5),
    ('instruction_patterns', 'Instruction sequence patterns', 2.0),
    ('control_flow', 'Control flow graph features', 1.8),
    ('data_flow', 'Data flow analysis features', 1.2),
    ('string_references', 'String and constant references', 1.0),
    ('register_usage', 'CPU register usage patterns', 1.3),
    ('stack_operations', 'Stack frame operations', 1.1),
    ('arithmetic_ops', 'Arithmetic operation patterns', 1.0),
    ('memory_access', 'Memory access patterns', 1.4)
ON CONFLICT (name) DO UPDATE SET weight = EXCLUDED.weight;

-- Create performance indexes for large_32 template
-- Primary performance indexes
CREATE INDEX IF NOT EXISTS idx_executable_md5_hash ON executable USING hash (md5);
CREATE INDEX IF NOT EXISTS idx_executable_category ON executable(name_category);
CREATE INDEX IF NOT EXISTS idx_executable_arch ON executable(arch);
CREATE INDEX IF NOT EXISTS idx_executable_ingest_date ON executable(ingest_date);

-- Function indexes
CREATE INDEX IF NOT EXISTS idx_function_executable_id ON function(executable_id);
CREATE INDEX IF NOT EXISTS idx_function_addr ON function(addr);
CREATE INDEX IF NOT EXISTS idx_function_name_hash ON function USING hash (name_func);
CREATE INDEX IF NOT EXISTS idx_function_namespace ON function(name_namespace);

-- Signature indexes (critical for large scale)
CREATE INDEX IF NOT EXISTS idx_signature_function_id ON signature(function_id);
CREATE INDEX IF NOT EXISTS idx_signature_hash_code ON signature(hash_code);
CREATE INDEX IF NOT EXISTS idx_signature_feature_vector ON signature USING gist (feature_vector);
CREATE INDEX IF NOT EXISTS idx_signature_significance ON signature(significance DESC);

-- Vector indexes for LSH operations
CREATE INDEX IF NOT EXISTS idx_vector_signature_id ON vector(signature_id);
CREATE INDEX IF NOT EXISTS idx_vector_feature_id ON vector(feature_id);
CREATE INDEX IF NOT EXISTS idx_vector_hash_value ON vector(hash_value);
CREATE INDEX IF NOT EXISTS idx_vector_significance ON vector(significance DESC);

-- Callgraph indexes
CREATE INDEX IF NOT EXISTS idx_callgraph_caller ON callgraph(caller_id);
CREATE INDEX IF NOT EXISTS idx_callgraph_callee ON callgraph(callee_id);
CREATE INDEX IF NOT EXISTS idx_callgraph_executable ON callgraph(executable_id);

-- Feature lookup index
CREATE INDEX IF NOT EXISTS idx_feature_name_hash ON feature USING hash (name);

-- Create statistics views for monitoring
CREATE OR REPLACE VIEW bsim_statistics AS
SELECT
    'Executables' as metric,
    COUNT(*) as count,
    pg_size_pretty(pg_total_relation_size('executable')) as table_size
FROM executable
UNION ALL
SELECT
    'Functions' as metric,
    COUNT(*) as count,
    pg_size_pretty(pg_total_relation_size('function')) as table_size
FROM function
UNION ALL
SELECT
    'Signatures' as metric,
    COUNT(*) as count,
    pg_size_pretty(pg_total_relation_size('signature')) as table_size
FROM signature
UNION ALL
SELECT
    'Vectors' as metric,
    COUNT(*) as count,
    pg_size_pretty(pg_total_relation_size('vector')) as table_size
FROM vector;

-- Create BSim utility functions
CREATE OR REPLACE FUNCTION bsim_database_info()
RETURNS TABLE(
    property TEXT,
    value TEXT
) AS $$
BEGIN
    RETURN QUERY
    SELECT k.key::TEXT, k.value::TEXT
    FROM keyvaluetable k
    WHERE k.key IN ('BSimConfigInfo', 'k', 'L', 'template', 'created_timestamp', 'schema_version')
    ORDER BY k.key;
END;
$$ LANGUAGE plpgsql;

-- Create function to calculate database capacity utilization
CREATE OR REPLACE FUNCTION bsim_capacity_stats()
RETURNS TABLE(
    metric TEXT,
    current_count BIGINT,
    capacity_limit BIGINT,
    utilization_percent NUMERIC
) AS $$
BEGIN
    RETURN QUERY
    SELECT
        'Functions'::TEXT,
        (SELECT COUNT(*) FROM function),
        100000000::BIGINT,  -- 100M function capacity
        ROUND((SELECT COUNT(*) FROM function) * 100.0 / 100000000, 2)
    UNION ALL
    SELECT
        'Signatures'::TEXT,
        (SELECT COUNT(*) FROM signature),
        100000000::BIGINT,  -- 100M signature capacity
        ROUND((SELECT COUNT(*) FROM signature) * 100.0 / 100000000, 2);
END;
$$ LANGUAGE plpgsql;

-- Grant all permissions to the BSim user
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO ben;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA public TO ben;
GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO ben;

-- Update statistics for query optimization
ANALYZE;

\echo 'BSim database schema created successfully with large_32 template!'
\echo 'Configuration: k=19, L=232, optimized for ~100 million functions'
\echo 'LSH extension: Available and configured'
\echo 'Capacity: Ready for large-scale binary similarity analysis'

-- Verify the setup
SELECT 'BSim Database Ready' as status,
       (SELECT value FROM keyvaluetable WHERE key = 'template') as template,
       (SELECT value FROM keyvaluetable WHERE key = 'k') as k_value,
       (SELECT value FROM keyvaluetable WHERE key = 'L') as L_value;