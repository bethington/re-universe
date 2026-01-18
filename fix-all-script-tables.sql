-- Complete Schema Fix for All Ghidra Scripts
-- This creates all missing tables that the Ghidra scripts expect

-- Enhanced signatures table (Step2)
CREATE TABLE IF NOT EXISTS enhanced_signatures (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id BIGINT NOT NULL REFERENCES exetable(id) ON DELETE CASCADE,
    signature_hash VARCHAR(64) NOT NULL,
    mnemonic_hash VARCHAR(64),
    control_flow_hash VARCHAR(64),
    data_flow_hash VARCHAR(64),
    call_pattern_hash VARCHAR(64),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(function_id)
);

-- Function similarity matrix table (Step4)
CREATE TABLE IF NOT EXISTS function_similarity_matrix (
    id BIGSERIAL PRIMARY KEY,
    source_function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    target_function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    similarity_score DOUBLE PRECISION NOT NULL CHECK (similarity_score >= 0 AND similarity_score <= 1),
    confidence_level DOUBLE PRECISION DEFAULT 0.8,
    algorithm_version VARCHAR(32) DEFAULT '1.0',
    computed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_function_id, target_function_id)
);

-- Cross version functions table (Step5)
CREATE TABLE IF NOT EXISTS cross_version_functions (
    id BIGSERIAL PRIMARY KEY,
    function_name VARCHAR(512) NOT NULL,
    base_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    signature_pattern VARCHAR(128),
    confidence_score DOUBLE PRECISION DEFAULT 1.0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cross version function mappings table (Step5)
CREATE TABLE IF NOT EXISTS cross_version_function_mappings (
    id BIGSERIAL PRIMARY KEY,
    cross_version_id BIGINT NOT NULL REFERENCES cross_version_functions(id) ON DELETE CASCADE,
    function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id BIGINT NOT NULL REFERENCES exetable(id) ON DELETE CASCADE,
    version_key VARCHAR(32) NOT NULL,
    address_offset BIGINT,
    confidence DOUBLE PRECISION DEFAULT 1.0,
    UNIQUE(cross_version_id, function_id)
);

-- String references table (Step3b)
CREATE TABLE IF NOT EXISTS string_references (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    string_value TEXT NOT NULL,
    reference_address BIGINT,
    reference_type VARCHAR(32) DEFAULT 'direct',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Cross references table (Step3c)
CREATE TABLE IF NOT EXISTS cross_references (
    id BIGSERIAL PRIMARY KEY,
    from_function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    to_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    reference_type VARCHAR(32) NOT NULL, -- 'call', 'jump', 'data_ref', etc.
    from_address BIGINT NOT NULL,
    to_address BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Import/Export mappings table (Step3e)
CREATE TABLE IF NOT EXISTS import_export_mappings (
    id BIGSERIAL PRIMARY KEY,
    executable_id BIGINT NOT NULL REFERENCES exetable(id) ON DELETE CASCADE,
    function_id BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    symbol_name VARCHAR(512) NOT NULL,
    symbol_type VARCHAR(16) NOT NULL, -- 'import' or 'export'
    ordinal INTEGER,
    library_name VARCHAR(256),
    address_offset BIGINT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Create comprehensive indexes for performance
CREATE INDEX IF NOT EXISTS idx_enhanced_signatures_function_id ON enhanced_signatures(function_id);
CREATE INDEX IF NOT EXISTS idx_enhanced_signatures_executable_id ON enhanced_signatures(executable_id);
CREATE INDEX IF NOT EXISTS idx_enhanced_signatures_hash ON enhanced_signatures(signature_hash);

CREATE INDEX IF NOT EXISTS idx_similarity_matrix_source ON function_similarity_matrix(source_function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_matrix_target ON function_similarity_matrix(target_function_id);
CREATE INDEX IF NOT EXISTS idx_similarity_matrix_score ON function_similarity_matrix(similarity_score DESC);

CREATE INDEX IF NOT EXISTS idx_cross_version_functions_name ON cross_version_functions(function_name);

CREATE INDEX IF NOT EXISTS idx_cross_version_mappings_cv_id ON cross_version_function_mappings(cross_version_id);
CREATE INDEX IF NOT EXISTS idx_cross_version_mappings_func_id ON cross_version_function_mappings(function_id);
CREATE INDEX IF NOT EXISTS idx_cross_version_mappings_version ON cross_version_function_mappings(version_key);

CREATE INDEX IF NOT EXISTS idx_string_references_function_id ON string_references(function_id);
CREATE INDEX IF NOT EXISTS idx_string_references_value ON string_references(string_value);

CREATE INDEX IF NOT EXISTS idx_cross_references_from ON cross_references(from_function_id);
CREATE INDEX IF NOT EXISTS idx_cross_references_to ON cross_references(to_function_id);
CREATE INDEX IF NOT EXISTS idx_cross_references_type ON cross_references(reference_type);

CREATE INDEX IF NOT EXISTS idx_import_export_executable_id ON import_export_mappings(executable_id);
CREATE INDEX IF NOT EXISTS idx_import_export_function_id ON import_export_mappings(function_id);
CREATE INDEX IF NOT EXISTS idx_import_export_symbol_name ON import_export_mappings(symbol_name);
CREATE INDEX IF NOT EXISTS idx_import_export_type ON import_export_mappings(symbol_type);

-- Add table comments
COMMENT ON TABLE enhanced_signatures IS 'Enhanced function signatures from Step2 analysis';
COMMENT ON TABLE function_similarity_matrix IS 'Function similarity scores from Step4 analysis';
COMMENT ON TABLE cross_version_functions IS 'Cross-version function tracking from Step5';
COMMENT ON TABLE cross_version_function_mappings IS 'Version-specific function mappings';
COMMENT ON TABLE string_references IS 'String references from Step3b analysis';
COMMENT ON TABLE cross_references IS 'Function cross-references from Step3c analysis';
COMMENT ON TABLE import_export_mappings IS 'Import/export symbol mappings from Step3e';

-- Grant permissions
GRANT ALL PRIVILEGES ON enhanced_signatures TO ben;
GRANT ALL PRIVILEGES ON function_similarity_matrix TO ben;
GRANT ALL PRIVILEGES ON cross_version_functions TO ben;
GRANT ALL PRIVILEGES ON cross_version_function_mappings TO ben;
GRANT ALL PRIVILEGES ON string_references TO ben;
GRANT ALL PRIVILEGES ON cross_references TO ben;
GRANT ALL PRIVILEGES ON import_export_mappings TO ben;

GRANT USAGE, SELECT ON SEQUENCE enhanced_signatures_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE function_similarity_matrix_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE cross_version_functions_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE cross_version_function_mappings_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE string_references_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE cross_references_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE import_export_mappings_id_seq TO ben;

SELECT
    COUNT(*) FILTER (WHERE table_name LIKE 'enhanced_%') as enhanced_tables,
    COUNT(*) FILTER (WHERE table_name LIKE 'function_%') as function_tables,
    COUNT(*) FILTER (WHERE table_name LIKE 'cross_%') as cross_tables,
    'All script tables created successfully' as status
FROM information_schema.tables
WHERE table_schema = 'public'
AND table_name IN (
    'enhanced_signatures',
    'function_similarity_matrix',
    'cross_version_functions',
    'cross_version_function_mappings',
    'string_references',
    'cross_references',
    'import_export_mappings'
);