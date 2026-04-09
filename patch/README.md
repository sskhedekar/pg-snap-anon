# patch/

This directory holds SQL files used during the anonymization run.

## pre_drop_fdw.sql — you provide, tool executes

Place your file at:

```
patch/_default/pre_drop_fdw.sql
```

The tool executes this on the temp RDS **before anonymization** to drop all FDW/dblink connections back to PROD. The temp RDS hostname is generated at runtime, so you cannot know it in advance — put the file in `_default/` and the tool copies it automatically.

If you run pg-snap-anon against multiple PROD instances that need different teardown SQL, you can place a host-specific override at `patch/<temp-rds-hostname>/pre_drop_fdw.sql`. The tool checks for a host-specific file first and only falls back to `_default/` if none is found.

See `patch/_default/pre_drop_fdw.sql` for a template, and `patch/example-temp-rds-hostname/pre_drop_fdw.sql` for a host-specific override example.

## post_restore_fdw.sql — tool generates, you run manually

After capturing the FDW config, the tool **generates** `patch/<temp-rds-hostname>/post_restore_fdw.sql`.

This file is not executed automatically. Run it manually on your stage RDS after filling in the `<STAGE_HOST>`, `<STAGE_PORT>`, `<STAGE_DBNAME>`, `<STAGE_USER>`, and `<STAGE_PASSWORD>` placeholders to recreate FDW connections.
