# patch/

This directory holds SQL files used during the anonymization run.

## pre_drop_fdw.sql — you provide, tool executes

Place a file named `pre_drop_fdw.sql` under `patch/<temp-rds-hostname>/`:

```
patch/<temp-rds-hostname>/pre_drop_fdw.sql
```

The tool executes this on the temp RDS **before anonymization** to drop all FDW/dblink connections back to PROD.

If no host-specific file exists, the tool falls back to `patch/_default/pre_drop_fdw.sql` and copies it into the host-specific folder.

See `patch/_default/pre_drop_fdw.sql` for a template, and `patch/example-temp-rds-hostname/pre_drop_fdw.sql` for an example.

## post_restore_fdw.sql — tool generates, you run manually

After capturing the FDW config, the tool **generates** `patch/<temp-rds-hostname>/post_restore_fdw.sql`.

This file is not executed automatically. Run it manually on your stage RDS after filling in the `<STAGE_HOST>`, `<STAGE_PORT>`, `<STAGE_DBNAME>`, `<STAGE_USER>`, and `<STAGE_PASSWORD>` placeholders to recreate FDW connections.
