-- ============================================================================
-- VERSION AND EXECUTABLE LOOKUP TABLES
-- ============================================================================
-- Creates enumeration tables for valid game versions and executable names
-- These tables constrain what can be inserted into exetable

-- ============================================================================
-- GAME VERSIONS TABLE
-- ============================================================================
-- Enumerated list of valid Diablo 2 versions with numeric codes
-- Numeric code format: major*1000 + minor*10 + patch_letter_offset
-- Example: 1.04b = 1000 + 40 + 1 = 1041

CREATE TABLE IF NOT EXISTS game_versions (
    id SERIAL PRIMARY KEY,
    version_string VARCHAR(10) NOT NULL UNIQUE,  -- e.g., "1.09d"
    version_code INTEGER NOT NULL UNIQUE,         -- e.g., 1093
    version_family VARCHAR(10) NOT NULL,          -- "Classic" or "LoD"
    release_order INTEGER NOT NULL,               -- Order of release (for sorting)
    description TEXT,                             -- Optional description
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert all known Diablo 2 versions
INSERT INTO game_versions (version_string, version_code, version_family, release_order, description) VALUES
    -- Classic era (1.00 - 1.06b)
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
    -- LoD era (1.07+)
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

-- ============================================================================
-- VALID EXECUTABLES TABLE
-- ============================================================================
-- Known Diablo 2 executable/DLL names that can be added to the database

CREATE TABLE IF NOT EXISTS valid_executables (
    id SERIAL PRIMARY KEY,
    name VARCHAR(64) NOT NULL UNIQUE,      -- e.g., "D2Common.dll"
    exe_type VARCHAR(16) NOT NULL,          -- "dll" or "exe"
    description TEXT,                       -- What this binary does
    is_core BOOLEAN DEFAULT TRUE,           -- Core game file vs optional
    created_at TIMESTAMP DEFAULT NOW()
);

-- Insert known Diablo 2 executables and DLLs
INSERT INTO valid_executables (name, exe_type, description, is_core) VALUES
    -- Core executables
    ('Game.exe',       'exe', 'Main game executable', TRUE),
    ('Diablo II.exe',  'exe', 'Alternative main executable', TRUE),
    -- Core DLLs
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

-- ============================================================================
-- ADD SHA256 COLUMN TO EXETABLE
-- ============================================================================

ALTER TABLE exetable ADD COLUMN IF NOT EXISTS sha256 TEXT;

-- ============================================================================
-- UPDATE GAME_VERSION TO REFERENCE VERSIONS TABLE
-- ============================================================================
-- Note: We keep game_version as an integer that matches version_code
-- This allows direct foreign key relationship

-- First, update any existing game_version text values to version codes
-- (This handles migration from string-based to integer-based)

-- ============================================================================
-- CONVERT GAME_VERSION FROM VARCHAR TO INTEGER
-- ============================================================================
-- First migrate any existing data, then change the column type

DO $$
DECLARE
    col_type TEXT;
BEGIN
    -- Get current column type
    SELECT data_type INTO col_type
    FROM information_schema.columns 
    WHERE table_name = 'exetable' AND column_name = 'game_version';
    
    IF col_type IS NULL THEN
        RAISE NOTICE 'game_version column does not exist - will be created as INTEGER';
    ELSIF col_type = 'integer' THEN
        RAISE NOTICE 'game_version is already INTEGER type';
    ELSE
        -- It's a text/varchar type, need to convert
        RAISE NOTICE 'Converting game_version from % to INTEGER', col_type;
        
        -- Create temporary column
        ALTER TABLE exetable ADD COLUMN IF NOT EXISTS game_version_new INTEGER;
        
        -- Migrate data: convert version strings to version codes
        UPDATE exetable e
        SET game_version_new = gv.version_code
        FROM game_versions gv
        WHERE e.game_version = gv.version_string
          AND e.game_version IS NOT NULL
          AND e.game_version_new IS NULL;
        
        -- Drop old column and rename new
        ALTER TABLE exetable DROP COLUMN game_version;
        ALTER TABLE exetable RENAME COLUMN game_version_new TO game_version;
        
        RAISE NOTICE 'Converted game_version to INTEGER';
    END IF;
END $$;

-- Add the foreign key constraint
DO $$
BEGIN
    -- Check if game_version column exists
    IF EXISTS (
        SELECT 1 FROM information_schema.columns 
        WHERE table_name = 'exetable' AND column_name = 'game_version'
    ) THEN
        -- Try to add foreign key
        IF NOT EXISTS (
            SELECT 1 FROM pg_constraint WHERE conname = 'fk_exetable_game_version'
        ) THEN
            ALTER TABLE exetable 
            ADD CONSTRAINT fk_exetable_game_version 
            FOREIGN KEY (game_version) REFERENCES game_versions(version_code)
            ON DELETE SET NULL;
            RAISE NOTICE 'Added foreign key constraint on exetable.game_version';
        ELSE
            RAISE NOTICE 'Foreign key constraint already exists';
        END IF;
    END IF;
EXCEPTION WHEN OTHERS THEN
    RAISE NOTICE 'Could not add FK constraint: %', SQLERRM;
END $$;

-- ============================================================================
-- ADD UNIQUE CONSTRAINT ON NAME_EXEC
-- ============================================================================
-- Now that we're using plain executable names + version, we need uniqueness
-- on the combination of (name_exec, game_version) instead of just name_exec

DO $$
BEGIN
    -- Drop old name_exec only constraint if exists
    IF EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'exetable_name_exec_key'
    ) THEN
        ALTER TABLE exetable DROP CONSTRAINT exetable_name_exec_key;
        RAISE NOTICE 'Dropped old exetable_name_exec_key constraint';
    END IF;
    
    -- Add new composite unique constraint
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'exetable_name_version_key'
    ) THEN
        ALTER TABLE exetable ADD CONSTRAINT exetable_name_version_key 
        UNIQUE (name_exec, game_version);
        RAISE NOTICE 'Added unique constraint on (name_exec, game_version)';
    END IF;
END $$;

-- ============================================================================
-- HELPER FUNCTION: Get version code from string
-- ============================================================================

CREATE OR REPLACE FUNCTION get_version_code(version_str TEXT)
RETURNS INTEGER AS $$
DECLARE
    v_code INTEGER;
BEGIN
    SELECT version_code INTO v_code
    FROM game_versions
    WHERE version_string = version_str;
    
    RETURN v_code;
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- HELPER FUNCTION: Validate executable name
-- ============================================================================

CREATE OR REPLACE FUNCTION is_valid_executable(exe_name TEXT)
RETURNS BOOLEAN AS $$
BEGIN
    RETURN EXISTS (
        SELECT 1 FROM valid_executables WHERE name = exe_name
    );
END;
$$ LANGUAGE plpgsql;

-- ============================================================================
-- INDEXES
-- ============================================================================

CREATE INDEX IF NOT EXISTS idx_game_versions_code ON game_versions(version_code);
CREATE INDEX IF NOT EXISTS idx_game_versions_family ON game_versions(version_family);
CREATE INDEX IF NOT EXISTS idx_valid_executables_name ON valid_executables(name);
CREATE INDEX IF NOT EXISTS idx_exetable_sha256 ON exetable(sha256);

-- ============================================================================
-- VERIFICATION
-- ============================================================================

SELECT 'Game versions loaded:' as info, COUNT(*) as count FROM game_versions;
SELECT 'Valid executables loaded:' as info, COUNT(*) as count FROM valid_executables;
