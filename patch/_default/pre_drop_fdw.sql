-- pre_drop_fdw.sql
-- Runs automatically on the temp RDS instance before anonymization.
-- Severs all live connections back to PROD or any foreign server.
-- Directory name must match the FQDN of the temp RDS instance.

-- Drop foreign tables
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT n.nspname AS schema, c.relname AS tbl
    FROM pg_class c
    JOIN pg_namespace n ON n.oid = c.relnamespace
    WHERE c.relkind = 'f'
  LOOP
    EXECUTE format('DROP FOREIGN TABLE IF EXISTS %I.%I CASCADE', r.schema, r.tbl);
  END LOOP;
END $$;

-- Drop user mappings
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN
    SELECT s.srvname, u.usename
    FROM pg_user_mappings u
    JOIN pg_foreign_server s ON s.oid = u.srvid
  LOOP
    EXECUTE format('DROP USER MAPPING IF EXISTS FOR %I SERVER %I', r.usename, r.srvname);
  END LOOP;
END $$;

-- Drop foreign servers
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT srvname FROM pg_foreign_server
  LOOP
    EXECUTE format('DROP SERVER IF EXISTS %I CASCADE', r.srvname);
  END LOOP;
END $$;

-- Drop FDW extensions
DROP EXTENSION IF EXISTS postgres_fdw CASCADE;
DROP EXTENSION IF EXISTS dblink CASCADE;

-- Drop logical replication slots
DO $$
DECLARE r RECORD;
BEGIN
  FOR r IN SELECT slot_name FROM pg_replication_slots WHERE slot_type = 'logical'
  LOOP
    PERFORM pg_drop_replication_slot(r.slot_name);
  END LOOP;
END $$;
