-- BSim Schema Extension for Documentation Propagation
-- Purpose: Add documentation storage and cross-version mapping to BSim database
-- See: docs/BSIM-SCHEMA-EXTENSION.md for full documentation
--
-- Auto-executed on container initialization via /docker-entrypoint-initdb.d/
-- Runs after: 04-create-bsim-schema.sql (requires base BSim tables to exist)
--
-- Manual run: psql -U $BSIM_DB_USER -d $BSIM_DB_NAME -f 05-bsim-schema-extension.sql
-- Via Docker: docker exec -i bsim-postgres psql -U $BSIM_DB_USER -d $BSIM_DB_NAME < bsim-init/05-bsim-schema-extension.sql
--
-- Idempotent: Safe to re-run (uses IF NOT EXISTS, ADD COLUMN IF NOT EXISTS, ON CONFLICT)

BEGIN;

-- ============================================================================
-- STEP 1: Extend desctable with documentation columns
-- ============================================================================

-- Documentation content
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS return_type VARCHAR(256);
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS calling_convention VARCHAR(64);
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS namespace VARCHAR(256);

-- Plate comment sections (parsed from Ghidra's plate comment format)
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS plate_summary TEXT;
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS plate_algorithm TEXT;
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS plate_parameters TEXT;
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS plate_returns TEXT;

-- Metadata
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS completeness_score FLOAT;
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS doc_source VARCHAR(32);
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS propagated_from BIGINT;
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS documented_at TIMESTAMP;
ALTER TABLE desctable ADD COLUMN IF NOT EXISTS id_equivalence BIGINT;

-- Add self-referential FK for propagated_from
ALTER TABLE desctable DROP CONSTRAINT IF EXISTS fk_desc_propagated_from;
ALTER TABLE desctable ADD CONSTRAINT fk_desc_propagated_from 
    FOREIGN KEY (propagated_from) REFERENCES desctable(id) ON DELETE SET NULL;

-- ============================================================================
-- STEP 2: Extend exetable with version metadata
-- ============================================================================

ALTER TABLE exetable ADD COLUMN IF NOT EXISTS game_version VARCHAR(16);
ALTER TABLE exetable ADD COLUMN IF NOT EXISTS version_family VARCHAR(16);
ALTER TABLE exetable ADD COLUMN IF NOT EXISTS is_reference BOOLEAN DEFAULT FALSE;

-- ============================================================================
-- STEP 3: Create func_parameters table
-- ============================================================================

CREATE TABLE IF NOT EXISTS func_parameters (
    id BIGSERIAL PRIMARY KEY,
    id_desc BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    param_name VARCHAR(128),
    param_type VARCHAR(256),
    storage VARCHAR(64),
    comment TEXT,
    UNIQUE(id_desc, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_func_params_desc ON func_parameters(id_desc);

COMMENT ON TABLE func_parameters IS 'Function parameters - mirrors Ghidra get_function_documentation() output';
COMMENT ON COLUMN func_parameters.ordinal IS 'Parameter position (0-based)';
COMMENT ON COLUMN func_parameters.storage IS 'Register or stack location, e.g., ECX, Stack[0x4]';

-- ============================================================================
-- STEP 4: Create func_local_variables table
-- ============================================================================

CREATE TABLE IF NOT EXISTS func_local_variables (
    id BIGSERIAL PRIMARY KEY,
    id_desc BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    var_name VARCHAR(128),
    var_type VARCHAR(256),
    storage VARCHAR(64),
    is_parameter BOOLEAN DEFAULT FALSE,
    propagation_confidence VARCHAR(16)
);

CREATE INDEX IF NOT EXISTS idx_func_locals_desc ON func_local_variables(id_desc);

COMMENT ON TABLE func_local_variables IS 'Local variables - best effort propagation (stack layouts may change)';
COMMENT ON COLUMN func_local_variables.propagation_confidence IS 'high/medium/low based on storage match likelihood';

-- ============================================================================
-- STEP 5: Create func_comments table
-- ============================================================================

CREATE TABLE IF NOT EXISTS func_comments (
    id BIGSERIAL PRIMARY KEY,
    id_desc BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    relative_offset INTEGER NOT NULL,
    comment_type VARCHAR(16) NOT NULL,
    comment_text TEXT NOT NULL,
    instruction_bytes BYTEA,
    is_relocatable BOOLEAN DEFAULT TRUE,
    UNIQUE(id_desc, relative_offset, comment_type)
);

CREATE INDEX IF NOT EXISTS idx_func_comments_desc ON func_comments(id_desc);

COMMENT ON TABLE func_comments IS 'Inline comments with relative offsets for cross-version relocation';
COMMENT ON COLUMN func_comments.relative_offset IS 'Bytes from function start address';
COMMENT ON COLUMN func_comments.comment_type IS 'eol, pre, or post';
COMMENT ON COLUMN func_comments.instruction_bytes IS 'Optional: bytes at offset for pattern matching';

-- ============================================================================
-- STEP 6: Create func_tags junction table
-- ============================================================================

CREATE TABLE IF NOT EXISTS func_tags (
    id_desc BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    tag_name VARCHAR(128) NOT NULL,
    added_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (id_desc, tag_name)
);

CREATE INDEX IF NOT EXISTS idx_func_tags_name ON func_tags(tag_name);

COMMENT ON TABLE func_tags IS 'Function tags for categorization and workflow (DOCUMENTED, NEEDS_REVIEW, etc.)';

-- ============================================================================
-- STEP 7: Create version_equivalence table
-- ============================================================================

CREATE TABLE IF NOT EXISTS version_equivalence (
    id BIGSERIAL PRIMARY KEY,
    canonical_name VARCHAR(256) NOT NULL,
    binary_name VARCHAR(128) NOT NULL,
    created_at TIMESTAMP DEFAULT NOW(),
    
    -- One column per D2 version (nullable FK to desctable)
    v1_00 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_01 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_02 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_03 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_04b BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_04c BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_05 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_05b BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_06 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_06b BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_07 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_08 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_09 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_09b BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_09d BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_10 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_11 BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_11b BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_12a BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_13c BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_13d BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_14a BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_14b BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_14c BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    v1_14d BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    
    UNIQUE(canonical_name, binary_name)
);

CREATE INDEX IF NOT EXISTS idx_version_equiv_name ON version_equivalence(canonical_name);
CREATE INDEX IF NOT EXISTS idx_version_equiv_binary ON version_equivalence(binary_name);

COMMENT ON TABLE version_equivalence IS 'Maps equivalent functions across all D2 versions';
COMMENT ON COLUMN version_equivalence.canonical_name IS 'Function name from reference version';
COMMENT ON COLUMN version_equivalence.binary_name IS 'Original DLL name (1.14.x functions live in Game.exe but retain original DLL association)';

-- Add FK constraint from desctable to version_equivalence
ALTER TABLE desctable DROP CONSTRAINT IF EXISTS fk_desc_equivalence;
ALTER TABLE desctable ADD CONSTRAINT fk_desc_equivalence 
    FOREIGN KEY (id_equivalence) REFERENCES version_equivalence(id) ON DELETE SET NULL;

-- ============================================================================
-- STEP 8: Create ordinal_mappings table
-- ============================================================================

CREATE TABLE IF NOT EXISTS ordinal_mappings (
    id SERIAL PRIMARY KEY,
    dll_name VARCHAR(64) NOT NULL,
    ordinal_number INTEGER NOT NULL,
    resolved_name VARCHAR(256),
    signature TEXT,
    description TEXT,
    min_version VARCHAR(16),
    max_version VARCHAR(16),
    
    UNIQUE(dll_name, ordinal_number, min_version)
);

CREATE INDEX IF NOT EXISTS idx_ordinal_dll ON ordinal_mappings(dll_name, ordinal_number);

COMMENT ON TABLE ordinal_mappings IS 'Resolves ordinal imports (e.g., Ordinal_10398) to human-readable names';
COMMENT ON COLUMN ordinal_mappings.min_version IS 'First D2 version with this ordinal';
COMMENT ON COLUMN ordinal_mappings.max_version IS 'Last D2 version (NULL = still valid in latest)';

-- Insert some known ordinal mappings for Storm.dll and Fog.dll
INSERT INTO ordinal_mappings (dll_name, ordinal_number, resolved_name, description) VALUES
    ('Storm.dll', 401, 'SFileOpenArchive', 'Open MPQ archive'),
    ('Storm.dll', 402, 'SFileCloseArchive', 'Close MPQ archive'),
    ('Storm.dll', 403, 'SFileOpenFile', 'Open file from MPQ'),
    ('Storm.dll', 404, 'SFileCloseFile', 'Close MPQ file handle'),
    ('Storm.dll', 405, 'SFileGetFileSize', 'Get file size'),
    ('Storm.dll', 406, 'SFileReadFile', 'Read from MPQ file'),
    ('Storm.dll', 501, 'SMemAlloc', 'Allocate memory'),
    ('Storm.dll', 502, 'SMemFree', 'Free memory'),
    ('Storm.dll', 503, 'SMemReAlloc', 'Reallocate memory'),
    ('Fog.dll', 10000, 'Fog_AllocMem', 'Allocate memory via Fog'),
    ('Fog.dll', 10001, 'Fog_FreeMem', 'Free memory via Fog'),
    ('Fog.dll', 10024, 'Fog_GetErrorHandler', 'Get error handler'),
    ('Fog.dll', 10025, 'Fog_SetErrorHandler', 'Set error handler'),
    ('Fog.dll', 10101, 'Fog_Assert', 'Assert with message')
ON CONFLICT (dll_name, ordinal_number, min_version) DO NOTHING;

-- ============================================================================
-- STEP 9: Create data_types table
-- ============================================================================

CREATE TABLE IF NOT EXISTS data_types (
    id BIGSERIAL PRIMARY KEY,
    type_name VARCHAR(256) NOT NULL,
    category_path VARCHAR(512),
    type_kind VARCHAR(32) NOT NULL,
    size_bytes INTEGER,
    alignment INTEGER,
    definition_json JSONB,
    definition_gdt TEXT,
    source_program VARCHAR(128),
    source_version VARCHAR(16),
    created_at TIMESTAMP DEFAULT NOW(),
    
    UNIQUE(type_name, source_version)
);

CREATE INDEX IF NOT EXISTS idx_data_types_name ON data_types(type_name);

COMMENT ON TABLE data_types IS 'Serialized struct/enum definitions for cross-binary type propagation';
COMMENT ON COLUMN data_types.type_kind IS 'struct, enum, typedef, or union';
COMMENT ON COLUMN data_types.definition_json IS 'JSONB with fields array: [{offset, name, type, size, comment}]';
COMMENT ON COLUMN data_types.definition_gdt IS 'Alternative: Ghidra GDT export format';

-- ============================================================================
-- STEP 10: Create similarity_match_log table
-- ============================================================================

CREATE TABLE IF NOT EXISTS similarity_match_log (
    id BIGSERIAL PRIMARY KEY,
    source_id_desc BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    target_id_desc BIGINT REFERENCES desctable(id) ON DELETE SET NULL,
    similarity_score FLOAT NOT NULL,
    confidence_score FLOAT,
    matched_at TIMESTAMP DEFAULT NOW(),
    propagated_fields TEXT[],
    match_type VARCHAR(32),
    verified BOOLEAN DEFAULT FALSE,
    verification_notes TEXT
);

CREATE INDEX IF NOT EXISTS idx_match_log_source ON similarity_match_log(source_id_desc);
CREATE INDEX IF NOT EXISTS idx_match_log_target ON similarity_match_log(target_id_desc);

COMMENT ON TABLE similarity_match_log IS 'Audit trail for similarity matching and documentation propagation';
COMMENT ON COLUMN similarity_match_log.match_type IS 'identity (>=0.90), similar (>=0.70), or weak (>=0.50)';
COMMENT ON COLUMN similarity_match_log.propagated_fields IS 'Array of field names that were propagated';

-- ============================================================================
-- Create helper views
-- ============================================================================

-- View: Functions with documentation status
CREATE OR REPLACE VIEW v_function_doc_status AS
SELECT 
    d.id,
    d.name_func,
    e.name_exec,
    e.game_version,
    d.return_type,
    d.calling_convention,
    d.completeness_score,
    d.doc_source,
    CASE WHEN d.plate_summary IS NOT NULL THEN TRUE ELSE FALSE END AS has_plate_comment,
    (SELECT COUNT(*) FROM func_parameters p WHERE p.id_desc = d.id) AS param_count,
    (SELECT COUNT(*) FROM func_comments c WHERE c.id_desc = d.id) AS comment_count,
    (SELECT array_agg(tag_name) FROM func_tags t WHERE t.id_desc = d.id) AS tags
FROM desctable d
JOIN exetable e ON d.id_exe = e.id;

COMMENT ON VIEW v_function_doc_status IS 'Summary view of function documentation status';

-- View: Version equivalence with function names filled in
CREATE OR REPLACE VIEW v_version_equivalence_names AS
SELECT 
    ve.id,
    ve.canonical_name,
    ve.binary_name,
    (SELECT name_func FROM desctable WHERE id = ve.v1_00) AS name_1_00,
    (SELECT name_func FROM desctable WHERE id = ve.v1_07) AS name_1_07,
    (SELECT name_func FROM desctable WHERE id = ve.v1_09d) AS name_1_09d,
    (SELECT name_func FROM desctable WHERE id = ve.v1_10) AS name_1_10,
    (SELECT name_func FROM desctable WHERE id = ve.v1_13c) AS name_1_13c,
    (SELECT name_func FROM desctable WHERE id = ve.v1_13d) AS name_1_13d,
    (SELECT name_func FROM desctable WHERE id = ve.v1_14d) AS name_1_14d
FROM version_equivalence ve;

COMMENT ON VIEW v_version_equivalence_names IS 'Version equivalence with resolved function names (subset of versions)';

COMMIT;

-- ============================================================================
-- Verification queries
-- ============================================================================

-- Check all new columns exist
SELECT 'desctable extensions' AS check_type, 
       COUNT(*) AS column_count 
FROM information_schema.columns 
WHERE table_name = 'desctable' 
  AND column_name IN ('return_type', 'calling_convention', 'namespace', 
                      'plate_summary', 'plate_algorithm', 'plate_parameters', 
                      'plate_returns', 'completeness_score', 'doc_source',
                      'propagated_from', 'documented_at', 'id_equivalence');

-- Check new tables exist
SELECT 'new tables' AS check_type,
       table_name 
FROM information_schema.tables 
WHERE table_schema = 'public' 
  AND table_name IN ('func_parameters', 'func_local_variables', 'func_comments',
                     'func_tags', 'version_equivalence', 'ordinal_mappings',
                     'data_types', 'similarity_match_log');

-- Show table summary
SELECT 
    'Schema extension complete' AS status,
    (SELECT COUNT(*) FROM information_schema.columns WHERE table_name = 'desctable') AS desctable_columns,
    (SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = 'public') AS total_tables;
