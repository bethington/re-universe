-- Fix BSim Schema for Ghidra Scripts Compatibility
-- This adds the missing tables that the Ghidra scripts expect

-- Create function_analysis table (expected by scripts)
CREATE TABLE IF NOT EXISTS function_analysis (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id BIGINT NOT NULL REFERENCES exetable(id) ON DELETE CASCADE,
    function_name VARCHAR(512),
    entry_address BIGINT,
    instruction_count INTEGER,
    basic_block_count INTEGER,
    cyclomatic_complexity INTEGER,
    calls_made INTEGER DEFAULT 0,
    calls_received INTEGER DEFAULT 0,
    has_loops BOOLEAN DEFAULT false,
    has_recursion BOOLEAN DEFAULT false,
    max_depth INTEGER,
    stack_frame_size INTEGER,
    calling_convention VARCHAR(64),
    is_leaf_function BOOLEAN DEFAULT false,
    is_library_function BOOLEAN DEFAULT false,
    is_thunk BOOLEAN DEFAULT false,
    confidence_score DOUBLE PRECISION,
    analysis_timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(function_id, executable_id)
);

-- Create function_tags table (expected by scripts)
-- Note: Keep existing func_tags table for compatibility, add new one for scripts
CREATE TABLE IF NOT EXISTS function_tags (
    id BIGSERIAL PRIMARY KEY,
    function_id BIGINT NOT NULL REFERENCES desctable(id) ON DELETE CASCADE,
    executable_id BIGINT NOT NULL REFERENCES exetable(id) ON DELETE CASCADE,
    tag_category VARCHAR(128) NOT NULL,
    tag_value VARCHAR(256) NOT NULL,
    confidence DOUBLE PRECISION DEFAULT 1.0,
    auto_generated BOOLEAN DEFAULT true,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(function_id, executable_id, tag_category, tag_value)
);

-- Create indexes for performance
CREATE INDEX IF NOT EXISTS idx_function_analysis_function_id ON function_analysis(function_id);
CREATE INDEX IF NOT EXISTS idx_function_analysis_executable_id ON function_analysis(executable_id);
CREATE INDEX IF NOT EXISTS idx_function_analysis_complexity ON function_analysis(cyclomatic_complexity);

CREATE INDEX IF NOT EXISTS idx_function_tags_function_id ON function_tags(function_id);
CREATE INDEX IF NOT EXISTS idx_function_tags_executable_id ON function_tags(executable_id);
CREATE INDEX IF NOT EXISTS idx_function_tags_category ON function_tags(tag_category);
CREATE INDEX IF NOT EXISTS idx_function_tags_value ON function_tags(tag_value);

-- Add comments
COMMENT ON TABLE function_analysis IS 'Detailed function analysis data from Ghidra scripts';
COMMENT ON TABLE function_tags IS 'Function tags from Ghidra analysis (script-compatible format)';

-- Grant permissions
GRANT ALL PRIVILEGES ON function_analysis TO ben;
GRANT ALL PRIVILEGES ON function_tags TO ben;
GRANT USAGE, SELECT ON SEQUENCE function_analysis_id_seq TO ben;
GRANT USAGE, SELECT ON SEQUENCE function_tags_id_seq TO ben;

SELECT 'Schema fixed for Ghidra scripts compatibility' as status;