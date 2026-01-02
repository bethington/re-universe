-- BSim PostgreSQL Database Initialization Script
-- This script sets up the necessary database structures for Ghidra BSim functionality

-- Create extensions if they don't exist
CREATE EXTENSION IF NOT EXISTS "uuid-ossp";

-- Create BSim-specific schema
CREATE SCHEMA IF NOT EXISTS bsim;

-- Set default search path to include bsim schema
ALTER DATABASE bsim SET search_path TO bsim, public;

-- Grant necessary permissions to bsim_user
GRANT ALL PRIVILEGES ON SCHEMA bsim TO bsim_user;
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA bsim TO bsim_user;
GRANT ALL PRIVILEGES ON ALL SEQUENCES IN SCHEMA bsim TO bsim_user;

-- Set ownership of the bsim schema to bsim_user
ALTER SCHEMA bsim OWNER TO bsim_user;

-- Create a function to grant permissions on future objects
CREATE OR REPLACE FUNCTION grant_permissions_on_new_objects()
RETURNS event_trigger
LANGUAGE plpgsql
AS $$
BEGIN
    GRANT ALL ON ALL TABLES IN SCHEMA bsim TO bsim_user;
    GRANT ALL ON ALL SEQUENCES IN SCHEMA bsim TO bsim_user;
END;
$$;

-- Create event trigger for automatic permission grants
DROP EVENT TRIGGER IF EXISTS grant_permissions_trigger;
CREATE EVENT TRIGGER grant_permissions_trigger
    ON ddl_command_end
    WHEN TAG IN ('CREATE TABLE', 'CREATE SEQUENCE')
    EXECUTE FUNCTION grant_permissions_on_new_objects();

-- Note: The actual BSim tables will be created by Ghidra when connecting to the database
-- This script only sets up the basic infrastructure and permissions