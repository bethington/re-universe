-- Architecturally Sound BSim Schema Extensions
-- Purpose: Minimal extensions to authentic BSim schema for enhanced analysis
-- Design Principles:
--   1. Extend existing tables instead of creating many new ones
--   2. Use generic relationships, not hard-coded version columns
--   3. Minimize table proliferation - consolidate related data
--   4. Support script requirements with minimal schema changes
--
-- Auto-executed on container initialization via /docker-entrypoint-initdb.d/
-- Runs after: 04-create-bsim-schema.sql (requires base BSim tables to exist)
--
-- Idempotent: Safe to re-run (uses IF NOT EXISTS, ADD COLUMN IF NOT EXISTS)

BEGIN;

-- ============================================================================
-- STEP 0: Create version and executable enumeration tables
-- ============================================================================

-- Game versions table with numeric codes
-- Format: major*1000 + minor*10 + patch_letter_offset
CREATE TABLE IF NOT EXISTS game_versions (
    id SERIAL PRIMARY KEY,
    version_string VARCHAR(10) NOT NULL UNIQUE,
    version_code INTEGER NOT NULL UNIQUE,
    version_family VARCHAR(10) NOT NULL,
    release_order INTEGER NOT NULL,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert all known Diablo 2 versions
INSERT INTO game_versions (version_string, version_code, version_family, release_order, description) VALUES
    ('1.00',  1000, 'Classic', 1,  'Original release'),
    ('1.01',  1010, 'Classic', 2,  'First patch'),
    ('1.02',  1020, 'Classic', 3,  'Bug fixes'),
    ('1.03',  1030, 'Classic', 4,  'Balance changes'),
    ('1.04',  1040, 'Classic', 5,  'Major update'),
    ('1.04b', 1041, 'Classic', 6,  'Bug fix patch'),
    ('1.04c', 1042, 'Classic', 7,  'Bug fix patch'),
    ('1.05',  1050, 'Classic', 8,  'Pre-LoD update'),
    ('1.05b', 1051, 'Classic', 9,  'Bug fix patch'),
    ('1.06',  1060, 'Classic', 10, 'Final Classic-era patch'),
    ('1.06b', 1061, 'Classic', 11, 'Bug fix patch'),
    ('1.07',  1070, 'LoD', 12, 'Lord of Destruction release'),
    ('1.08',  1080, 'LoD', 13, 'LoD patch'),
    ('1.09',  1090, 'LoD', 14, 'Major LoD update'),
    ('1.09b', 1091, 'LoD', 15, 'Bug fix patch'),
    ('1.09d', 1093, 'LoD', 16, 'Bug fix patch'),
    ('1.10',  1100, 'LoD', 17, 'Synergies patch'),
    ('1.10s', 1101, 'LoD', 18, 'Beta/test version'),
    ('1.11',  1110, 'LoD', 19, 'Uber content'),
    ('1.11b', 1111, 'LoD', 20, 'Bug fix patch'),
    ('1.12',  1120, 'LoD', 21, 'No-CD patch'),
    ('1.12a', 1121, 'LoD', 22, 'Bug fix patch'),
    ('1.13',  1130, 'LoD', 23, 'Respec patch'),
    ('1.13c', 1132, 'LoD', 24, 'Bug fix patch'),
    ('1.13d', 1133, 'LoD', 25, 'Final 1.13 patch'),
    ('1.14',  1140, 'LoD', 26, 'Windows 10 compatibility'),
    ('1.14a', 1141, 'LoD', 27, 'Bug fix patch'),
    ('1.14b', 1142, 'LoD', 28, 'Bug fix patch'),
    ('1.14c', 1143, 'LoD', 29, 'Bug fix patch'),
    ('1.14d', 1144, 'LoD', 30, 'Final legacy patch')
ON CONFLICT (version_string) DO NOTHING;

-- Valid executables table - known D2 binaries
CREATE TABLE IF NOT EXISTS valid_executables (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,
    exe_type VARCHAR(16) NOT NULL,
    description TEXT,
    is_core BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW()
);

INSERT INTO valid_executables (name, exe_type, description, is_core) VALUES
    ('Game.exe',       'exe', 'Main game executable', TRUE),
    ('Diablo II.exe',  'exe', 'Alternative main executable', TRUE),
    ('D2Client.dll',   'dll', 'Client-side game logic', TRUE),
    ('D2Common.dll',   'dll', 'Common game utilities', TRUE),
    ('D2Game.dll',     'dll', 'Game server logic', TRUE),
    ('D2Lang.dll',     'dll', 'Language/localization', TRUE),
    ('D2Launch.dll',   'dll', 'Launcher functionality', TRUE),
    ('D2MCPClient.dll','dll', 'Battle.net MCP client', TRUE),
    ('D2Net.dll',      'dll', 'Network functionality', TRUE),
    ('D2Sound.dll',    'dll', 'Sound/audio system', TRUE),
    ('D2Win.dll',      'dll', 'Windows integration', TRUE),
    ('D2CMP.dll',      'dll', 'Compression utilities', TRUE),
    ('D2Multi.dll',    'dll', 'Multiplayer functionality', TRUE),
    ('D2DDraw.dll',    'dll', 'DirectDraw renderer', TRUE),
    ('D2Direct3D.dll', 'dll', 'Direct3D renderer', TRUE),
    ('D2Glide.dll',    'dll', 'Glide renderer', TRUE),
    ('D2gfx.dll',      'dll', 'Graphics utilities', TRUE),
    ('Fog.dll',        'dll', 'Memory/utility library', TRUE),
    ('Storm.dll',      'dll', 'MPQ archive handling', TRUE),
    ('Bnclient.dll',   'dll', 'Battle.net client', TRUE),
    ('ijl11.dll',      'dll', 'Intel JPEG library', FALSE),
    ('SmackW32.dll',   'dll', 'Smacker video playback', FALSE)
ON CONFLICT (name) DO NOTHING;

-- Helper function: Get version code from string
CREATE OR REPLACE FUNCTION get_version_code(version_str TEXT)
RETURNS INTEGER AS $$
BEGIN
    RETURN (SELECT version_code FROM game_versions WHERE version_string = version_str);
END;
$$ LANGUAGE plpgsql;

-- Helper function: Validate executable name
CREATE OR REPLACE FUNCTION is_valid_executable(exe_name TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (SELECT 1 FROM valid_executables WHERE name = exe_name);
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- STEP 1: Extend authentic BSim tables with minimal additions
-- ============================================================================

-- Note: desctable extensions removed per user request
-- Custom fields for desctable have been removed to maintain pure BSim compatibility
-- Enhanced functionality moved to separate extension tables (function_signatures, etc.)

-- Extend exetable (authentic BSim executable table) with version metadata
-- game_version is INTEGER version code (e.g., 1093 for 1.09d)
-- Format: major*1000 + minor*10 + patch_letter_offset
ALTER TABLE exetable ADD COLUMN IF NOT EXISTS game_version INTEGER;
ALTER TABLE exetable ADD COLUMN IF NOT EXISTS version_family VARCHAR(16);
ALTER TABLE exetable ADD COLUMN IF NOT EXISTS sha256 TEXT;
ALTER TABLE exetable ADD COLUMN IF NOT EXISTS is_reference BOOLEAN DEFAULT FALSE;

-- Create index on game_version for efficient version-based queries
CREATE INDEX IF NOT EXISTS idx_exetable_game_version ON exetable(game_version);
CREATE INDEX IF NOT EXISTS idx_exetable_version_family ON exetable(version_family);
CREATE INDEX IF NOT EXISTS idx_exetable_sha256 ON exetable(sha256);

-- ============================================================================
-- STEP 2: Create minimal support tables for data that doesn't fit in BSim core
-- ============================================================================

-- Function parameters (referenced by scripts)
CREATE TABLE IF NOT EXISTS function_parameters (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    ordinal INTEGER NOT NULL,
    param_name VARCHAR(128),
    param_type VARCHAR(256),
    storage_location VARCHAR(64),
    param_comment TEXT,
    UNIQUE(function_id, ordinal)
);

CREATE INDEX IF NOT EXISTS idx_func_params_function ON function_parameters(function_id);

-- Function signatures (populated by Step1)
CREATE TABLE IF NOT EXISTS function_signatures (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    signature_text TEXT,
    parameter_count INTEGER DEFAULT 0,
    return_type VARCHAR(256),
    calling_convention VARCHAR(32),
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id)
);

CREATE INDEX IF NOT EXISTS idx_func_sig_function ON function_signatures(function_id);

-- Enhanced signatures (expected by Step2 and Step5)
CREATE TABLE IF NOT EXISTS enhanced_signatures (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
    signature_hash TEXT,
    signature_data TEXT,
    lsh_vector TEXT,
    confidence_score REAL,
    created_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id)
);

CREATE INDEX IF NOT EXISTS idx_enhanced_sig_function ON enhanced_signatures(function_id);
CREATE INDEX IF NOT EXISTS idx_enhanced_sig_executable ON enhanced_signatures(executable_id);

-- Function similarity matrix (expected by Step4)
CREATE TABLE IF NOT EXISTS function_similarity_matrix (
    id BIGSERIAL PRIMARY KEY,
    source_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    target_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    similarity_score REAL NOT NULL,
    confidence_score REAL,
    match_type VARCHAR(32),
    computed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(source_function_id, target_function_id)
);

CREATE INDEX IF NOT EXISTS idx_sim_matrix_source ON function_similarity_matrix(source_function_id);
CREATE INDEX IF NOT EXISTS idx_sim_matrix_target ON function_similarity_matrix(target_function_id);
CREATE INDEX IF NOT EXISTS idx_sim_matrix_score ON function_similarity_matrix(similarity_score DESC);

-- Function analysis (expected by Step1)
CREATE TABLE IF NOT EXISTS function_analysis (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
    complexity_score INTEGER,
    instruction_count INTEGER,
    basic_block_count INTEGER,
    cyclomatic_complexity INTEGER,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id)
);

CREATE INDEX IF NOT EXISTS idx_func_analysis_function ON function_analysis(function_id);
CREATE INDEX IF NOT EXISTS idx_func_analysis_executable ON function_analysis(executable_id);

-- Function tags (lightweight tagging system)
CREATE TABLE IF NOT EXISTS function_tags (
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
    tag_category VARCHAR(64),
    tag_value VARCHAR(128),
    confidence REAL DEFAULT 1.0,
    auto_generated BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT NOW(),
    PRIMARY KEY (function_id, tag_category, tag_value)
);

CREATE INDEX IF NOT EXISTS idx_func_tags_function ON function_tags(function_id);
CREATE INDEX IF NOT EXISTS idx_func_tags_category ON function_tags(tag_category);

-- ============================================================================
-- STEP 3: Create tables for import/export analysis (populated by Step1)
-- ============================================================================

-- API imports
CREATE TABLE IF NOT EXISTS api_imports (
    id BIGSERIAL PRIMARY KEY,
    executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
    dll_name VARCHAR(128),
    function_name VARCHAR(256),
    ordinal_number INTEGER,
    is_delayed BOOLEAN DEFAULT FALSE,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(executable_id, dll_name, function_name)
);

CREATE INDEX IF NOT EXISTS idx_api_imports_executable ON api_imports(executable_id);
CREATE INDEX IF NOT EXISTS idx_api_imports_dll ON api_imports(dll_name);

-- API exports
CREATE TABLE IF NOT EXISTS api_exports (
    id BIGSERIAL PRIMARY KEY,
    executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
    function_name VARCHAR(256),
    ordinal_number INTEGER,
    rva_address BIGINT,
    is_forwarded BOOLEAN DEFAULT FALSE,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(executable_id, function_name)
);

CREATE INDEX IF NOT EXISTS idx_api_exports_executable ON api_exports(executable_id);
CREATE INDEX IF NOT EXISTS idx_api_exports_function ON api_exports(function_name);

-- Function API usage (links functions to imports/exports)
CREATE TABLE IF NOT EXISTS function_api_usage (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    api_import_id BIGINT REFERENCES api_imports(id) ON DELETE CASCADE,
    usage_type VARCHAR(32) DEFAULT 'call',
    reference_count INTEGER DEFAULT 1,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id, api_import_id, usage_type)
);

CREATE INDEX IF NOT EXISTS idx_api_usage_function ON function_api_usage(function_id);
CREATE INDEX IF NOT EXISTS idx_api_usage_import ON function_api_usage(api_import_id);

-- ============================================================================
-- STEP 4: Create tables for cross-reference analysis (populated by Step1)
-- ============================================================================

-- Function calls
CREATE TABLE IF NOT EXISTS function_calls (
    id BIGSERIAL PRIMARY KEY,
    caller_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    callee_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    call_type VARCHAR(32) DEFAULT 'direct',
    call_count INTEGER DEFAULT 1,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(caller_function_id, callee_function_id, call_type)
);

CREATE INDEX IF NOT EXISTS idx_func_calls_caller ON function_calls(caller_function_id);
CREATE INDEX IF NOT EXISTS idx_func_calls_callee ON function_calls(callee_function_id);

-- Data references
CREATE TABLE IF NOT EXISTS data_references (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    data_address BIGINT,
    reference_type VARCHAR(32),
    access_type VARCHAR(16),
    reference_count INTEGER DEFAULT 1,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id, data_address, reference_type)
);

CREATE INDEX IF NOT EXISTS idx_data_refs_function ON data_references(function_id);
CREATE INDEX IF NOT EXISTS idx_data_refs_address ON data_references(data_address);

-- Call graph metrics
CREATE TABLE IF NOT EXISTS call_graph_metrics (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    incoming_calls INTEGER DEFAULT 0,
    outgoing_calls INTEGER DEFAULT 0,
    unique_callers INTEGER DEFAULT 0,
    unique_callees INTEGER DEFAULT 0,
    is_leaf BOOLEAN DEFAULT FALSE,
    is_entry_point BOOLEAN DEFAULT FALSE,
    computed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id)
);

CREATE INDEX IF NOT EXISTS idx_call_metrics_function ON call_graph_metrics(function_id);

-- ============================================================================
-- STEP 5: Create tables for string analysis (populated by Step1)
-- ============================================================================

-- String references
CREATE TABLE IF NOT EXISTS string_references (
    id BIGSERIAL PRIMARY KEY,
    executable_id INTEGER REFERENCES exetable(id) ON DELETE CASCADE,
    string_address BIGINT,
    string_content TEXT,
    string_length INTEGER,
    encoding_type VARCHAR(16) DEFAULT 'ascii',
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(executable_id, string_address)
);

CREATE INDEX IF NOT EXISTS idx_string_refs_executable ON string_references(executable_id);
CREATE INDEX IF NOT EXISTS idx_string_refs_content ON string_references USING gin(to_tsvector('english', string_content));

-- Function string references (links functions to strings)
CREATE TABLE IF NOT EXISTS function_string_refs (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    string_ref_id BIGINT REFERENCES string_references(id) ON DELETE CASCADE,
    usage_type VARCHAR(32) DEFAULT 'reference',
    reference_count INTEGER DEFAULT 1,
    analyzed_at TIMESTAMP DEFAULT NOW(),
    UNIQUE(function_id, string_ref_id)
);

CREATE INDEX IF NOT EXISTS idx_func_string_refs_function ON function_string_refs(function_id);
CREATE INDEX IF NOT EXISTS idx_func_string_refs_string ON function_string_refs(string_ref_id);

-- ============================================================================
-- STEP 6: Create comments table for Step3a
-- ============================================================================

-- Core comments (simplified from the script's complex requirement)
CREATE TABLE IF NOT EXISTS core_comment (
    id BIGSERIAL PRIMARY KEY,
    entity_type VARCHAR(32) NOT NULL,  -- 'function', 'executable', etc.
    entity_id BIGINT NOT NULL,         -- References desctable.id, exetable.id, etc.
    entity_name VARCHAR(256),          -- For display purposes
    content TEXT NOT NULL,
    content_html TEXT,
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW(),
    is_deleted BOOLEAN DEFAULT FALSE,
    parent_id BIGINT REFERENCES core_comment(id) ON DELETE CASCADE,
    user_id INTEGER  -- Simple user reference
);

CREATE INDEX IF NOT EXISTS idx_core_comment_entity ON core_comment(entity_type, entity_id);
CREATE INDEX IF NOT EXISTS idx_core_comment_user ON core_comment(user_id);

-- Simple user table for comments
CREATE TABLE IF NOT EXISTS auth_user (
    id SERIAL PRIMARY KEY,
    username VARCHAR(150) UNIQUE NOT NULL,
    first_name VARCHAR(30),
    last_name VARCHAR(150),
    email VARCHAR(254),
    password VARCHAR(128),
    is_superuser BOOLEAN DEFAULT FALSE,
    is_staff BOOLEAN DEFAULT FALSE,
    is_active BOOLEAN DEFAULT TRUE,
    date_joined TIMESTAMP DEFAULT NOW()
);

-- Insert default user for comments
INSERT INTO auth_user (username, first_name, last_name, email, is_active, is_staff)
VALUES ('ghidra_script', 'Ghidra', 'Script', 'script@localhost', TRUE, FALSE)
ON CONFLICT (username) DO NOTHING;

-- ============================================================================
-- STEP 7: Single-Match Cross-Version System (Primary Version Focus)
-- ============================================================================

-- Primary version function equivalence (ONE record per function in primary version)
CREATE TABLE IF NOT EXISTS function_equivalence (
    id BIGSERIAL PRIMARY KEY,

    -- Primary version function (center of web table)
    primary_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    primary_version VARCHAR(16) NOT NULL,
    binary_name VARCHAR(128) NOT NULL,
    canonical_name VARCHAR(256) NOT NULL,

    -- Metadata
    created_at TIMESTAMP DEFAULT NOW(),
    last_analyzed TIMESTAMP DEFAULT NOW(),

    -- Constraints to prevent database bloat
    UNIQUE(primary_function_id),
    UNIQUE(binary_name, primary_version) -- Only one primary version per binary
);

-- Single best matches (EXACTLY one match per version per primary function)
CREATE TABLE IF NOT EXISTS function_version_matches (
    id BIGSERIAL PRIMARY KEY,

    -- Links back to primary function
    equivalence_id BIGINT REFERENCES function_equivalence(id) ON DELETE CASCADE,

    -- Target version and function (the match)
    target_function_id BIGINT REFERENCES desctable(id) ON DELETE CASCADE,
    target_version VARCHAR(16) NOT NULL,

    -- Similarity data for color coding
    similarity_score REAL NOT NULL CHECK (similarity_score BETWEEN 0.0 AND 1.0),
    confidence_level VARCHAR(16) NOT NULL CHECK (confidence_level IN ('exact', 'high', 'medium', 'low')),

    -- Analysis metadata
    match_method VARCHAR(32) DEFAULT 'similarity_analysis',
    analyzed_at TIMESTAMP DEFAULT NOW(),

    -- CRITICAL: Exactly one match per version per primary function
    UNIQUE(equivalence_id, target_version),
    -- Prevent target function from matching multiple primary functions
    UNIQUE(target_function_id)
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_equiv_primary_function ON function_equivalence(primary_function_id);
CREATE INDEX IF NOT EXISTS idx_equiv_binary_name ON function_equivalence(binary_name);
CREATE INDEX IF NOT EXISTS idx_equiv_primary_version ON function_equivalence(primary_version);

CREATE INDEX IF NOT EXISTS idx_matches_equivalence ON function_version_matches(equivalence_id);
CREATE INDEX IF NOT EXISTS idx_matches_target_version ON function_version_matches(target_version);
CREATE INDEX IF NOT EXISTS idx_matches_similarity ON function_version_matches(similarity_score DESC);

-- Auto-calculate confidence level from similarity score
CREATE OR REPLACE FUNCTION calculate_confidence_level(score REAL)
RETURNS VARCHAR(16) AS $$
BEGIN
    RETURN CASE
        WHEN score >= 0.98 THEN 'exact'
        WHEN score >= 0.90 THEN 'high'
        WHEN score >= 0.70 THEN 'medium'
        ELSE 'low'
    END;
END;
$$ LANGUAGE plpgsql;

-- Trigger to auto-set confidence level
CREATE OR REPLACE FUNCTION update_confidence_level()
RETURNS TRIGGER AS $$
BEGIN
    NEW.confidence_level = calculate_confidence_level(NEW.similarity_score);
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trigger_update_confidence_level ON function_version_matches;
CREATE TRIGGER trigger_update_confidence_level
    BEFORE INSERT OR UPDATE ON function_version_matches
    FOR EACH ROW
    EXECUTE FUNCTION update_confidence_level();

-- ============================================================================
-- STEP 8: Create compatibility views for script expectations
-- ============================================================================

-- Ensure scripts can find functions with proper joins (desctable kept pure BSim)
CREATE OR REPLACE VIEW v_enhanced_functions AS
SELECT
    d.id as function_id,
    d.name_func,
    d.addr,
    d.flags,
    d.val,
    fs.return_type,
    fs.calling_convention,
    e.id as executable_id,
    e.name_exec,
    e.md5,
    e.game_version,
    ed.architecture,
    ed.name_compiler,
    ed.repository,
    ed.path
FROM desctable d
JOIN exetable e ON d.id_exe = e.id
LEFT JOIN exetable_denormalized ed ON e.id = ed.id
LEFT JOIN function_signatures fs ON d.id = fs.function_id;

COMMENT ON VIEW v_enhanced_functions IS 'Complete function view combining authentic BSim with extensions';

-- Web-optimized cross-version table (your exact requirement)
CREATE OR REPLACE VIEW v_cross_version_web_table AS
SELECT
    fe.canonical_name,
    fe.binary_name,
    fe.primary_version,

    -- Primary function (center column of web table)
    jsonb_build_object(
        'name', primary_d.name_func,
        'id', fe.primary_function_id,
        'addr', primary_d.addr,
        'confidence', 'primary'
    ) as primary_function,

    -- All version matches as JSONB for easy web consumption
    jsonb_object_agg(
        fvm.target_version,
        jsonb_build_object(
            'name', target_d.name_func,
            'id', fvm.target_function_id,
            'addr', target_d.addr,
            'similarity', fvm.similarity_score,
            'confidence', fvm.confidence_level,
            'css_class', CASE
                WHEN fvm.confidence_level = 'exact' THEN 'exact-match'
                WHEN fvm.confidence_level = 'high' THEN 'high-confidence'
                WHEN fvm.confidence_level = 'medium' THEN 'medium-confidence'
                ELSE 'low-confidence'
            END
        )
    ) FILTER (WHERE fvm.target_function_id IS NOT NULL) as version_matches

FROM function_equivalence fe
JOIN desctable primary_d ON fe.primary_function_id = primary_d.id
LEFT JOIN function_version_matches fvm ON fe.id = fvm.equivalence_id
LEFT JOIN desctable target_d ON fvm.target_function_id = target_d.id
GROUP BY fe.id, fe.canonical_name, fe.binary_name, fe.primary_version,
         primary_d.name_func, fe.primary_function_id, primary_d.addr;

COMMENT ON VIEW v_cross_version_web_table IS 'Web-ready cross-version table with primary version focus and color-coding data';

COMMIT;

-- ============================================================================
-- Verification
-- ============================================================================

-- Verify all required tables exist for the scripts
SELECT 'Schema Extension Complete' as status,
    (SELECT COUNT(*) FROM information_schema.tables
     WHERE table_schema = 'public'
     AND table_name IN (
         'function_analysis', 'enhanced_signatures', 'function_similarity_matrix',
         'function_parameters', 'function_signatures', 'api_imports', 'api_exports',
         'function_api_usage', 'function_calls', 'data_references', 'call_graph_metrics',
         'string_references', 'function_string_refs', 'core_comment', 'auth_user',
         'function_equivalence', 'function_version_matches'
     )) as required_tables_created;

SELECT 'Extension Columns Added' as status,
    (SELECT 0) as desc_extensions_removed_per_request,
    (SELECT COUNT(*) FROM information_schema.columns
     WHERE table_name = 'exetable'
     AND column_name IN ('game_version', 'is_reference')) as exe_extensions;