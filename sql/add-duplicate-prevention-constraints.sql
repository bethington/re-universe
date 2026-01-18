-- ============================================================================
-- DUPLICATE PREVENTION CONSTRAINTS
-- ============================================================================
-- These constraints prevent duplicate data when re-running BSim population scripts
-- Run this migration to enable safer upsert operations in Step1_AddProgramToBSimDatabase.java

-- Add unique constraint on desctable for (id_exe, addr)
-- This ensures one function per address per executable
DO $$
BEGIN
    -- First, remove any existing duplicates (keep the first one by id)
    DELETE FROM desctable a
    USING desctable b
    WHERE a.id > b.id
      AND a.id_exe = b.id_exe
      AND a.addr = b.addr;
    
    -- Add unique constraint if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'desctable_unique_exe_addr'
    ) THEN
        ALTER TABLE desctable 
        ADD CONSTRAINT desctable_unique_exe_addr UNIQUE (id_exe, addr);
        RAISE NOTICE 'Added unique constraint desctable_unique_exe_addr';
    ELSE
        RAISE NOTICE 'Constraint desctable_unique_exe_addr already exists';
    END IF;
END $$;

-- Add unique constraint on exetable for name_exec
-- This ensures one executable per name
DO $$
BEGIN
    -- First, remove any existing duplicates (keep the first one by id)
    DELETE FROM exetable a
    USING exetable b
    WHERE a.id > b.id
      AND a.name_exec = b.name_exec;
    
    -- Add unique constraint if it doesn't exist
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint 
        WHERE conname = 'exetable_unique_name'
    ) THEN
        ALTER TABLE exetable 
        ADD CONSTRAINT exetable_unique_name UNIQUE (name_exec);
        RAISE NOTICE 'Added unique constraint exetable_unique_name';
    ELSE
        RAISE NOTICE 'Constraint exetable_unique_name already exists';
    END IF;
END $$;

-- Verify constraints were added
SELECT 
    tc.constraint_name,
    tc.table_name,
    kcu.column_name,
    tc.constraint_type
FROM information_schema.table_constraints tc
JOIN information_schema.key_column_usage kcu 
    ON tc.constraint_name = kcu.constraint_name
WHERE tc.constraint_type = 'UNIQUE'
  AND tc.table_name IN ('desctable', 'exetable')
ORDER BY tc.table_name, tc.constraint_name;
