# patch/

This directory holds SQL files used during the anonymization run.

## pre_drop_fdw.sql — tool executes before anonymization

`patch/_default/pre_drop_fdw.sql` is included with the tool. It drops all FDW foreign tables, user mappings, foreign servers, extensions (postgres_fdw, dblink), and logical replication slots on the temp RDS before anonymization begins.

You do not need to create or modify this file. The tool copies it automatically into a run-specific folder at runtime and executes it.

## post_restore_fdw.sql — tool generates, you run manually

After the run, the tool generates `patch/<temp-rds-hostname>/post_restore_fdw.sql` containing the SQL to recreate FDW and dblink on your stage RDS.

This file is not executed automatically. Fill in the `<STAGE_HOST>`, `<STAGE_PORT>`, `<STAGE_DBNAME>`, `<STAGE_USER>`, and `<STAGE_PASSWORD>` placeholders, then run it manually on your stage RDS.
