#!/usr/bin/env python3
"""pg-snap-anon: Safely anonymize AWS RDS PostgreSQL snapshots."""
from __future__ import annotations

import hashlib
import json
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import boto3
import click
import psycopg2
import yaml
from botocore.exceptions import ClientError
from faker import Faker


_DEFAULTS_PATH = Path(__file__).parent / "defaults.json"


def _load_defaults() -> dict:
    if not _DEFAULTS_PATH.exists():
        click.echo(f"ERROR: defaults.json not found at {_DEFAULTS_PATH}", err=True)
        sys.exit(1)
    with open(_DEFAULTS_PATH) as f:
        return json.load(f)

# All supported Faker rules (ordered list for menu display)
_ALL_FAKER_RULES = [
    "fake.email()",
    "fake.name()",
    "fake.user_name()",
    "fake.phone_number()",
    "fake.company()",
    "fake.job()",
    "fake.street_address()",
    "fake.city()",
    "fake.state()",
    "fake.postcode()",
    "fake.country()",
    "fake.text()",
    "fake.uuid4()",
    "fake.date_of_birth()",
    "fake.ipv4()",
    "fake.url()",
    "fake.iban()",
    "fake.credit_card_number()",
    "fake.ssn()",
    "fake.last_name()",
    "fake.first_name()",
    "fake.date_time()",
]


# Faker rule → compatible PostgreSQL data_type values (from information_schema.columns)
_FAKER_TYPE_COMPAT: dict[str, set[str]] = {
    "fake.email()":               {"character varying", "text", "varchar", "character"},
    "fake.name()":                {"character varying", "text", "varchar", "character"},
    "fake.first_name()":          {"character varying", "text", "varchar", "character"},
    "fake.last_name()":           {"character varying", "text", "varchar", "character"},
    "fake.user_name()":           {"character varying", "text", "varchar", "character"},
    "fake.phone_number()":        {"character varying", "text", "varchar", "character"},
    "fake.company()":             {"character varying", "text", "varchar", "character"},
    "fake.job()":                 {"character varying", "text", "varchar", "character"},
    "fake.street_address()":      {"character varying", "text", "varchar", "character"},
    "fake.city()":                {"character varying", "text", "varchar", "character"},
    "fake.state()":               {"character varying", "text", "varchar", "character"},
    "fake.postcode()":            {"character varying", "text", "varchar", "character"},
    "fake.country()":             {"character varying", "text", "varchar", "character"},
    "fake.text()":                {"character varying", "text", "varchar", "character"},
    "fake.url()":                 {"character varying", "text", "varchar", "character"},
    "fake.iban()":                {"character varying", "text", "varchar", "character"},
    "fake.credit_card_number()":  {"character varying", "text", "varchar", "character"},
    "fake.ssn()":                 {"character varying", "text", "varchar", "character"},
    "fake.ipv4()":                {"character varying", "text", "varchar", "character", "inet"},
    "fake.uuid4()":               {"character varying", "text", "varchar", "character", "uuid"},
    "fake.date_of_birth()":       {"date", "character varying", "text"},
    "fake.date_time()":           {"timestamp without time zone", "timestamp with time zone",
                                   "character varying", "text"},
}


# ── Config & Credentials ──────────────────────────────────────────────────────


def load_env_config() -> dict:
    """Load and validate all PGANONSNAP_* environment variables."""
    required = {
        "PGANONSNAP_SOURCE_RDS_ID": "source_rds_id",
        "PGANONSNAP_S3_BUCKET": "s3_bucket",
        "PGANONSNAP_VPC_SECURITY_GROUP_IDS": "vpc_security_group_ids",
        "PGANONSNAP_DB_SUBNET_GROUP": "db_subnet_group",
    }
    config = {}
    missing = []
    for env_var, key in required.items():
        val = os.environ.get(env_var)
        if not val:
            missing.append(env_var)
        else:
            config[key] = val

    if missing:
        click.echo(f"ERROR: Missing required environment variables: {', '.join(missing)}", err=True)
        sys.exit(1)

    # Split comma-separated security group IDs
    config["vpc_security_group_ids"] = [
        sg.strip() for sg in config["vpc_security_group_ids"].split(",") if sg.strip()
    ]

    # Optional vars with defaults
    config["instance_class"] = os.environ.get("PGANONSNAP_INSTANCE_CLASS", "db.t3.micro")
    config["storage_type"] = os.environ.get("PGANONSNAP_STORAGE_TYPE", "gp2")
    raw = os.environ.get("PGANONSNAP_ALLOCATED_STORAGE", "20")
    try:
        config["allocated_storage"] = int(raw)
    except ValueError:
        click.echo(f"ERROR: PGANONSNAP_ALLOCATED_STORAGE must be an integer, got: {raw!r}", err=True)
        sys.exit(1)
    config["region"] = os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    config["output_snapshot"] = os.environ.get("PGANONSNAP_OUTPUT_SNAPSHOT", "")
    config["db_secret"] = os.environ.get("PGANONSNAP_DB_SECRET", "")
    raw_attempts = os.environ.get("PGANONSNAP_WAITER_MAX_ATTEMPTS", "120")
    try:
        config["waiter_max_attempts"] = int(raw_attempts)
    except ValueError:
        click.echo(
            f"ERROR: PGANONSNAP_WAITER_MAX_ATTEMPTS must be an integer, got: {raw_attempts!r}",
            err=True,
        )
        sys.exit(1)

    return config


def load_db_credentials(config: dict) -> dict:
    """Load DB credentials from Secrets Manager or env vars."""
    if config.get("db_secret"):
        client = boto3.client("secretsmanager", region_name=config["region"])
        response = client.get_secret_value(SecretId=config["db_secret"])
        secret = json.loads(response["SecretString"])
        return {
            "user": secret["username"],
            "password": secret["password"],
            "dbname": secret["dbname"],
            "port": int(secret.get("port", 5432)),
        }

    user = os.environ.get("PGUSER")
    password = os.environ.get("PGPASSWORD")
    dbname = os.environ.get("PGDATABASE")
    raw_port = os.environ.get("PGPORT", "5432")

    if not all([user, password, dbname]):
        click.echo(
            "ERROR: Set PGANONSNAP_DB_SECRET (Secrets Manager) or "
            "PGUSER + PGPASSWORD + PGDATABASE (direct).",
            err=True,
        )
        sys.exit(1)

    try:
        port = int(raw_port)
    except ValueError:
        click.echo(f"ERROR: PGPORT must be an integer, got: {raw_port!r}", err=True)
        sys.exit(1)

    return {"user": user, "password": password, "dbname": dbname, "port": port}


# ── PII Config ────────────────────────────────────────────────────────────────


def load_pii_config(path: str) -> dict:
    """Load and minimally validate pii_config.yaml."""
    p = Path(path)
    if not p.exists():
        click.echo(f"ERROR: pii_config.yaml not found at {path}", err=True)
        sys.exit(1)

    with open(p) as f:
        config = yaml.safe_load(f)

    if not config or "tables" not in config:
        click.echo("ERROR: pii_config.yaml must contain a 'tables' key.", err=True)
        sys.exit(1)

    return config


def validate_pii_approval(pii_config: dict) -> None:
    """Fail fast if pii_config.yaml has not been approved."""
    if not pii_config.get("approved"):
        click.echo(
            "ERROR: pii_config.yaml not approved. "
            "Set approved: true, approved_by, and approved_date, then re-run.",
            err=True,
        )
        sys.exit(1)
    if not str(pii_config.get("approved_by") or "").strip():
        click.echo("ERROR: approved_by is empty in pii_config.yaml.", err=True)
        sys.exit(1)
    if not str(pii_config.get("approved_date") or "").strip():
        click.echo("ERROR: approved_date is empty in pii_config.yaml.", err=True)
        sys.exit(1)


def get_faker_rule_for_column(column_name: str) -> Optional[str]:
    """Return the default Faker rule for a known column name, or None."""
    return _load_defaults().get("columns", {}).get(column_name)


def build_faker_rule_menu() -> str:
    """Return a numbered menu string of all available Faker rules."""
    lines = [f"{i + 1}. {rule}" for i, rule in enumerate(_ALL_FAKER_RULES)]
    return "\n".join(lines)


# ── AWS RDS ───────────────────────────────────────────────────────────────────


def get_latest_automated_snapshot(rds_client, source_rds_id: str) -> str:
    """Return the identifier of the most recent available automated snapshot."""
    paginator = rds_client.get_paginator("describe_db_snapshots")
    pages = paginator.paginate(
        DBInstanceIdentifier=source_rds_id,
        SnapshotType="automated",
    )
    snapshots = [
        s
        for page in pages
        for s in page["DBSnapshots"]
        if s["Status"] == "available"
    ]
    if not snapshots:
        click.echo(
            f"ERROR: No available automated snapshots found for '{source_rds_id}'.",
            err=True,
        )
        sys.exit(1)

    snapshots.sort(key=lambda s: s["SnapshotCreateTime"], reverse=True)
    latest = snapshots[0]
    click.echo(f"Using snapshot: {latest['DBSnapshotIdentifier']} "
               f"(created {latest['SnapshotCreateTime'].isoformat()})")
    return latest["DBSnapshotIdentifier"]


def restore_snapshot_to_temp(
    rds_client, snapshot_id: str, temp_rds_id: str, config: dict
) -> None:
    """Kick off snapshot restore to temp RDS. Does not wait."""
    rds_client.restore_db_instance_from_db_snapshot(
        DBInstanceIdentifier=temp_rds_id,
        DBSnapshotIdentifier=snapshot_id,
        DBInstanceClass=config["instance_class"],
        StorageType=config["storage_type"],
        VpcSecurityGroupIds=config["vpc_security_group_ids"],
        DBSubnetGroupName=config["db_subnet_group"],
        MultiAZ=False,
        PubliclyAccessible=False,
        DeletionProtection=False,
        Tags=[
            {"Key": "managed-by", "Value": "pg-snap-anon"},
            {"Key": "source-rds", "Value": config["source_rds_id"]},
        ],
    )
    click.echo(f"Restore started: {temp_rds_id}")


def wait_for_rds_available(rds_client, temp_rds_id: str, max_attempts: int = 120) -> str:
    """Poll until temp RDS is available. Returns endpoint hostname."""
    click.echo(f"Waiting for {temp_rds_id} to become available (this takes ~10-20 min)...")
    waiter = rds_client.get_waiter("db_instance_available")
    waiter.wait(
        DBInstanceIdentifier=temp_rds_id,
        WaiterConfig={"Delay": 30, "MaxAttempts": max_attempts},
    )
    response = rds_client.describe_db_instances(DBInstanceIdentifier=temp_rds_id)
    endpoint = response["DBInstances"][0]["Endpoint"]["Address"]
    click.echo(f"Temp RDS available: {endpoint}")
    return endpoint


def delete_temp_rds(rds_client, temp_rds_id: str) -> None:
    """Delete temp RDS instance, no final snapshot."""
    rds_client.delete_db_instance(
        DBInstanceIdentifier=temp_rds_id,
        SkipFinalSnapshot=True,
    )
    click.echo(f"Temp RDS deletion initiated: {temp_rds_id}")


# ── S3 Checkpoint ─────────────────────────────────────────────────────────────


def _checkpoint_key(source_rds_id: str) -> str:
    return f"pg-snap-anon/checkpoint-{source_rds_id}.json"


def load_checkpoint(s3_client, bucket: str, source_rds_id: str) -> Optional[dict]:
    """Return checkpoint dict from S3, or None if not found."""
    try:
        response = s3_client.get_object(
            Bucket=bucket, Key=_checkpoint_key(source_rds_id)
        )
        return json.loads(response["Body"].read())
    except ClientError as e:
        if e.response["Error"]["Code"] == "NoSuchKey":
            return None
        raise


def save_checkpoint(s3_client, bucket: str, checkpoint: dict) -> None:
    """Write checkpoint JSON to S3."""
    s3_client.put_object(
        Bucket=bucket,
        Key=_checkpoint_key(checkpoint["source_rds_id"]),
        Body=json.dumps(checkpoint, default=str).encode(),
        ContentType="application/json",
    )


def clear_checkpoint(s3_client, bucket: str, source_rds_id: str) -> None:
    """Delete checkpoint from S3."""
    s3_client.delete_object(Bucket=bucket, Key=_checkpoint_key(source_rds_id))


# ── FDW ───────────────────────────────────────────────────────────────────────

_FDW_CATALOG_QUERY = """
SELECT s.srvname,
       w.fdwname,
       array_to_string(s.srvoptions, ', ') AS server_options,
       u.usename AS mapped_user,
       array_to_string(um.umoptions, ', ') AS user_options
FROM pg_foreign_server s
JOIN pg_foreign_data_wrapper w ON w.oid = s.srvfdw
LEFT JOIN pg_user_mappings um ON um.srvid = s.oid
LEFT JOIN pg_user u ON u.usesysid = um.umuser;
"""

_DBLINK_FUNCTIONS_QUERY = """
SELECT p.proname, pg_get_functiondef(p.oid) AS definition
FROM pg_proc p
JOIN pg_namespace n ON n.oid = p.pronamespace
WHERE n.nspname = 'public'
  AND p.prosrc ILIKE '%dblink%'
ORDER BY p.proname;
"""


def capture_fdw_config(conn, patch_dir: str) -> None:
    """Query pg catalog for FDW and dblink config, write post_restore_fdw.sql."""
    patch_path = Path(patch_dir)
    patch_path.mkdir(parents=True, exist_ok=True)
    out_file = patch_path / "post_restore_fdw.sql"

    with conn.cursor() as cur:
        cur.execute(_FDW_CATALOG_QUERY)
        fdw_rows = cur.fetchall()

        cur.execute("SELECT 1 FROM pg_extension WHERE extname = 'dblink';")
        has_dblink = cur.fetchone() is not None

        dblink_funcs = []
        if has_dblink:
            cur.execute(_DBLINK_FUNCTIONS_QUERY)
            dblink_funcs = cur.fetchall()

    if not fdw_rows and not has_dblink:
        out_file.write_text(
            "-- No FDW or dblink configuration found on this instance.\n"
            "-- Nothing to restore.\n"
        )
        click.echo("FDW capture: no foreign servers or dblink found.")
        return

    lines = [
        "-- post_restore_fdw.sql",
        "-- Auto-generated by pg-snap-anon. Replace <STAGE_HOST> placeholders before running.",
        "",
    ]

    # ── postgres_fdw servers and user mappings ─────────────────────────────────
    seen_servers: set[str] = set()
    for srvname, fdwname, server_options, mapped_user, _user_options in fdw_rows:
        # _user_options not written to output — placeholder credentials used instead
        # to avoid capturing live credentials in the generated SQL file
        mapped_user_str = mapped_user or "PUBLIC"

        if srvname not in seen_servers:
            seen_servers.add(srvname)
            lines += [
                f"-- Server: {srvname} (FDW: {fdwname})",
                f"-- Original server options: {server_options}",
                f"CREATE EXTENSION IF NOT EXISTS {fdwname};",
                f"CREATE SERVER IF NOT EXISTS {srvname} FOREIGN DATA WRAPPER {fdwname}",
                f"  OPTIONS (host '<STAGE_HOST>', port '<STAGE_PORT>', dbname '<STAGE_DBNAME>');",
            ]

        lines += [
            f"CREATE USER MAPPING IF NOT EXISTS FOR {mapped_user_str} SERVER {srvname}",
            f"  OPTIONS (user '<STAGE_USER>', password '<STAGE_PASSWORD>');",
            "",
        ]

    # ── dblink extension and functions ─────────────────────────────────────────
    if has_dblink:
        lines += [
            "-- dblink extension",
            "CREATE EXTENSION IF NOT EXISTS dblink;",
            "",
        ]

        if dblink_funcs:
            lines += [
                "-- Functions that use dblink.",
                "-- Review connection strings inside each function — they may reference PROD.",
                "-- Update host/port/dbname/credentials before running on stage.",
                "",
            ]
            for func_name, definition in dblink_funcs:
                lines += [
                    f"-- Function: {func_name}",
                    definition.rstrip(";") + ";",
                    "",
                ]

    out_file.write_text("\n".join(lines))
    click.echo(f"FDW/dblink config captured → {out_file}")


def execute_pre_drop_fdw(conn, patch_dir: str) -> None:
    """Execute all pre_*.sql files found in patch_dir in sorted order.

    Falls back to patch/_default/ if no files found in patch_dir.
    Warns and continues if no matching files are found in either location.
    """
    patch_path = Path(patch_dir)
    sql_files = sorted(patch_path.glob("pre_*.sql")) if patch_path.exists() else []

    if not sql_files:
        default_path = Path(patch_dir).parent / "_default"
        default_files = sorted(default_path.glob("pre_*.sql")) if default_path.exists() else []
        if default_files:
            # Copy _default pre_*.sql files into the run-specific patch dir
            patch_path.mkdir(parents=True, exist_ok=True)
            for src in default_files:
                dst = patch_path / src.name
                dst.write_text(src.read_text())
            click.echo(f"Copied _default pre_*.sql to {patch_dir}.")
            sql_files = sorted(patch_path.glob("pre_*.sql"))
        else:
            click.echo(f"WARNING: No pre_drop_fdw.sql found in {patch_dir} or _default. "
                       "Continuing — database may not have FDW.")
            return

    for sql_file in sql_files:
        sql = sql_file.read_text()
        with conn.cursor() as cur:
            cur.execute(sql)
        conn.commit()
        click.echo(f"Executed {sql_file.name}")


# ── Schema Validation ─────────────────────────────────────────────────────────


def validate_schema(conn, pii_config: dict) -> list[str]:
    """
    Check each table/column in pii_config exists in the DB schema and that
    the configured Faker rule is type-compatible with the column's data type.
    Returns list of error strings (empty = all valid).
    """
    errors = []
    with conn.cursor() as cur:
        for table, columns in pii_config["tables"].items():
            cur.execute(
                "SELECT column_name, data_type FROM information_schema.columns "
                "WHERE table_name = %s AND table_schema = 'public'",
                (table,),
            )
            rows = cur.fetchall()
            existing_columns = {row[0]: row[1] for row in rows}

            if not existing_columns:
                errors.append(f"Table not found in schema: '{table}'")
                continue

            for col, rule in columns.items():
                if col not in existing_columns:
                    errors.append(f"Column not found: '{table}.{col}'")
                    continue

                # Type compatibility check (advisory — only when rule is in the map)
                col_type = existing_columns[col]
                compatible_types = _FAKER_TYPE_COMPAT.get(rule)
                if compatible_types is not None and col_type not in compatible_types:
                    errors.append(
                        f"Type mismatch: '{table}.{col}' is {col_type!r} "
                        f"but '{rule}' produces text — "
                        f"compatible types: {sorted(compatible_types)}"
                    )

    return errors


# ── Anonymization ─────────────────────────────────────────────────────────────


def resolve_faker_rule(faker: Faker, rule: str) -> str:
    """
    Call the Faker method named in rule string (e.g. 'fake.email()').
    Returns the generated value as a string.
    """
    method_name = rule.strip()
    if method_name.startswith("fake."):
        method_name = method_name[5:]
    if method_name.endswith("()"):
        method_name = method_name[:-2]

    method = getattr(faker, method_name, None)
    if method is None:
        click.echo(f"ERROR: Unknown Faker rule: '{rule}'", err=True)
        sys.exit(1)

    return str(method())


def _get_unique_columns(conn, table: str) -> set[str]:
    """Return column names that have a UNIQUE or PRIMARY KEY constraint on table."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
             AND tc.table_schema = kcu.table_schema
            WHERE tc.table_schema = 'public'
              AND tc.table_name = %s
              AND tc.constraint_type IN ('UNIQUE', 'PRIMARY KEY')
        """, (table,))
        return {row[0] for row in cur.fetchall()}


def _load_existing_values(conn, table: str, cols: set[str]) -> dict[str, set[str]]:
    """Load all existing non-null values for given columns. Used to seed uniqueness tracking.

    Memory tradeoff: loads all values for unique-constrained columns into a Python set.
    Acceptable because only PK-sized identifier columns (email, username) are unique-constrained
    in practice. The set prevents Faker from generating values that collide with unprocessed rows.
    """
    result = {}
    for col in cols:
        with conn.cursor() as cur:
            cur.execute(
                f'SELECT "{col}" FROM "public"."{table}" WHERE "{col}" IS NOT NULL',  # noqa: S608
            )
            result[col] = {str(row[0]) for row in cur.fetchall()}
    return result


def _resolve_unique(faker: Faker, rule: str, seen: set[str]) -> str:
    """Generate a value not in seen. Falls back to appending a hex suffix after 200 attempts."""
    method_name = rule.strip()
    if method_name.startswith("fake."):
        method_name = method_name[5:]
    if method_name.endswith("()"):
        method_name = method_name[:-2]
    method = getattr(faker, method_name)
    for _ in range(200):
        val = str(method())
        if val not in seen:
            seen.add(val)
            return val
    val = f"{str(method())}_{uuid.uuid4().hex[:6]}"
    seen.add(val)
    return val


def _get_pk_columns(conn, table: str) -> list[str]:
    """Return primary key column names for table in key order, or empty list if no PK."""
    with conn.cursor() as cur:
        cur.execute("""
            SELECT a.attname
            FROM pg_index i
            JOIN pg_attribute a ON a.attrelid = i.indrelid
                               AND a.attnum = ANY(i.indkey)
            WHERE i.indrelid = %s::regclass
              AND i.indisprimary
            ORDER BY a.attnum
        """, (f'public."{table}"',))
        return [row[0] for row in cur.fetchall()]


def anonymize_table(
    conn, table: str, columns: dict, faker: Faker, batch_size: int = 1000
) -> int:
    """
    Anonymize declared columns in table using PK-based batch UPDATE.
    Falls back to ctid if no primary key exists (with a warning).
    Returns total rows updated.
    """
    col_names = list(columns.keys())
    total = 0

    # Determine which PII columns have unique constraints and pre-load existing values
    unique_cols = _get_unique_columns(conn, table) & set(col_names)
    unique_seen = _load_existing_values(conn, table, unique_cols)
    if unique_cols:
        click.echo(f"  Unique constraint columns (pre-loading existing values): {sorted(unique_cols)}")

    # Determine row identity strategy
    pk_cols = _get_pk_columns(conn, table)
    use_ctid = not pk_cols
    if use_ctid:
        click.echo(
            f"  WARNING: '{table}' has no primary key — using ctid. "
            "Avoid retrying on failure for this table."
        )

    # Get total row count for progress reporting
    with conn.cursor() as cur:
        cur.execute(f'SELECT COUNT(*) FROM "public"."{table}"')  # noqa: S608
        total_rows = cur.fetchone()[0]
    click.echo(f"  {table}: {total_rows:,} rows to anonymize, columns: {col_names}")

    if total_rows == 0:
        return 0

    # Fetch all row identifiers upfront using a regular cursor.
    # Only PK columns (or ctid) are fetched — far less memory than full rows.
    # Named server-side cursors are NOT used here because conn.commit() would
    # close the server-side cursor mid-iteration, crashing on the second batch.
    if use_ctid:
        with conn.cursor() as cur:
            cur.execute(f'SELECT ctid::text FROM "public"."{table}"')  # noqa: S608
            all_ids = [row[0] for row in cur.fetchall()]
    else:
        pk_select = ", ".join(f'"{c}"::text' for c in pk_cols)
        with conn.cursor() as cur:
            cur.execute(f'SELECT {pk_select} FROM "public"."{table}"')  # noqa: S608
            all_ids = cur.fetchall()  # list of tuples, one per row

    # Build SQL fragments (shared across batches)
    set_clause = ", ".join(f'"{col}" = v."{col}"' for col in col_names)
    fake_col_defs = ", ".join(f'"{col}"' for col in col_names)

    if use_ctid:
        val_col_defs = f"{fake_col_defs}, ctid_val"
        where_clause = f'"public"."{table}".ctid = v.ctid_val::tid'
    else:
        pk_col_defs = ", ".join(f'"{c}"' for c in pk_cols)
        val_col_defs = f"{fake_col_defs}, {pk_col_defs}"
        where_clause = " AND ".join(
            f'"public"."{table}"."{c}"::text = v."{c}"' for c in pk_cols
        )

    with conn.cursor() as update_cur:
        for i in range(0, len(all_ids), batch_size):
            batch = all_ids[i : i + batch_size]
            rows_data = []
            for id_val in batch:
                fake_vals = [
                    _resolve_unique(faker, columns[col], unique_seen[col])
                    if col in unique_cols
                    else resolve_faker_rule(faker, columns[col])
                    for col in col_names
                ]
                if use_ctid:
                    rows_data.append(fake_vals + [id_val])
                else:
                    pk_vals = list(id_val) if len(pk_cols) > 1 else [id_val[0]]
                    rows_data.append(fake_vals + pk_vals)

            placeholders = ", ".join(
                "(" + ", ".join(["%s"] * len(row)) + ")"
                for row in rows_data
            )
            flat_values = [val for row in rows_data for val in row]

            update_cur.execute(
                f'UPDATE "public"."{table}" '  # noqa: S608
                f'SET {set_clause} '
                f'FROM (VALUES {placeholders}) AS v({val_col_defs}) '
                f'WHERE {where_clause}',
                flat_values,
            )
            total += len(batch)
            conn.commit()
            click.echo(f"    {total:,}/{total_rows:,} rows done ({100*total//total_rows}%)")

    return total


# ── Audit Log ─────────────────────────────────────────────────────────────────


def write_audit_log(s3_client, bucket: str, audit: dict) -> None:
    """Write immutable plain-text audit log to S3."""
    run_id = audit["run_id"]
    key = f"pg-snap-anon/logs/run-{run_id}.log"

    tables_section = "\n".join(
        f"  {table}: {info['rows']:,} rows, {info['columns']} columns"
        if isinstance(info["rows"], int)
        else f"  {table}: {info['rows']} rows, {info['columns']} columns"
        for table, info in audit.get("tables_anonymized", {}).items()
    ) or "  (none)"

    body = f"""run_id:             {audit['run_id']}
source_rds:         {audit['source_rds']}
snapshot_used:      {audit['snapshot_used']}
temp_rds:           {audit['temp_rds']}
output_snapshot:    {audit['output_snapshot']}
pii_config_hash:    {audit['pii_config_hash']}
approved_by:        {audit['approved_by']}
approved_date:      {audit['approved_date']}
started_at:         {audit['started_at']}
completed_at:       {audit['completed_at']}

tables_anonymized:
{tables_section}

fdw_captured:       {audit['fdw_captured']}
fdw_dropped:        {audit['fdw_dropped']}
"""

    s3_client.put_object(
        Bucket=bucket,
        Key=key,
        Body=body,
        ContentType="text/plain",
    )
    click.echo(f"Audit log written → s3://{bucket}/{key}")


# ── Retry Helper ─────────────────────────────────────────────────────────────


def _with_retry(fn, *args, retries: int = 3, backoff_base: int = 2, **kwargs):
    """Call fn(*args, **kwargs), retrying up to retries times with exponential backoff on DB errors."""
    for attempt in range(retries):
        try:
            return fn(*args, **kwargs)
        except (psycopg2.OperationalError, psycopg2.InterfaceError) as e:
            if attempt == retries - 1:
                raise
            wait = backoff_base ** (attempt + 1)
            click.echo(f"Connection error: {e}. Retrying in {wait}s...")
            time.sleep(wait)


# ── CLI ───────────────────────────────────────────────────────────────────────

@click.group()
def cli():
    """pg-snap-anon: Anonymize RDS snapshots without touching PROD."""


@cli.command()
@click.option("--output", default="pii_config.yaml", help="Output file path")
def configure(output: str) -> None:
    """Interactive wizard to declare PII scope. Writes pii_config.yaml."""
    click.echo("pg-snap-anon configure — declare which columns contain PII\n")
    tables = {}

    while True:
        table = click.prompt("Table name (or 'done' to finish)").strip()
        if table.lower() == "done":
            break

        raw = click.prompt(f"PII columns for '{table}' (comma-separated)").strip()
        columns_input = [c.strip() for c in raw.split(",") if c.strip()]
        if not columns_input:
            click.echo(f"  No columns entered for '{table}', skipping.")
            continue
        columns = {}

        for col in columns_input:
            suggested = get_faker_rule_for_column(col)
            if suggested:
                while True:
                    rule = click.prompt(
                        f"  '{col}' → suggested: {suggested}\n  Accept or enter different rule",
                        default=suggested,
                    )
                    method_name = rule.strip().removeprefix("fake.").removesuffix("()")
                    if getattr(Faker(), method_name, None) is not None:
                        break
                    click.echo(f"  Invalid Faker rule '{rule}'. Try one from the menu above.")
            else:
                click.echo(f"\n  '{col}' not in defaults. Choose a Faker rule:")
                click.echo(build_faker_rule_menu())
                while True:
                    choice = click.prompt("  Enter number").strip()
                    try:
                        idx = int(choice) - 1
                        if 0 <= idx < len(_ALL_FAKER_RULES):
                            rule = _ALL_FAKER_RULES[idx]
                            break
                    except ValueError:
                        pass
                    click.echo(f"  Invalid choice. Enter 1–{len(_ALL_FAKER_RULES)}.")

            columns[col] = rule
        tables[table] = columns

    pii_config = {
        "tables": tables,
        "approved": False,
        "approved_by": "",
        "approved_date": "",
    }

    with open(output, "w") as f:
        yaml.dump(pii_config, f, default_flow_style=False, sort_keys=False)

    click.echo(f"\nWritten to {output}")
    click.echo("Review it, set approved: true, approved_by, and approved_date, then run --validate.")


@cli.command()
@click.option("--pii-config", default="pii_config.yaml", help="Path to pii_config.yaml")
def validate(pii_config: str) -> None:
    """Validate pii_config.yaml against actual DB schema on a temp RDS restore."""
    pii = load_pii_config(pii_config)
    validate_pii_approval(pii)

    config = load_env_config()
    run_id = datetime.now(timezone.utc).strftime("%Y-%m-%d-%H-%M-%S")
    temp_rds_id = f"pg-snap-anon-temp-{run_id}"

    rds_client = boto3.client("rds", region_name=config["region"])
    credentials = load_db_credentials(config)

    errors = []
    temp_rds_created = False
    try:
        snapshot_id = get_latest_automated_snapshot(rds_client, config["source_rds_id"])
        restore_snapshot_to_temp(rds_client, snapshot_id, temp_rds_id, config)
        temp_rds_created = True
        endpoint = wait_for_rds_available(rds_client, temp_rds_id, config["waiter_max_attempts"])

        conn = psycopg2.connect(
            host=endpoint,
            user=credentials["user"],
            password=credentials["password"],
            dbname=credentials["dbname"],
            port=credentials["port"],
            connect_timeout=30,
            keepalives=1,
            keepalives_idle=60,
            keepalives_interval=10,
            keepalives_count=5,
            sslmode="require",
            options="-c statement_timeout=0",
        )
        try:
            errors = validate_schema(conn, pii)
        finally:
            conn.close()
    finally:
        if temp_rds_created:
            delete_temp_rds(rds_client, temp_rds_id)

    if errors:
        click.echo("\nValidation FAILED:")
        for err in errors:
            click.echo(f"  ✗ {err}")
        sys.exit(1)
    else:
        click.echo("\nValidation PASSED — all tables and columns found in schema.")


@cli.command()
@click.option("--pii-config", default="pii_config.yaml", help="Path to pii_config.yaml")
def run(pii_config: str) -> None:
    """Full anonymization pipeline."""
    pii = load_pii_config(pii_config)
    validate_pii_approval(pii)

    config = load_env_config()
    rds_client = boto3.client("rds", region_name=config["region"])
    s3_client = boto3.client("s3", region_name=config["region"])
    credentials = load_db_credentials(config)

    started_at = datetime.now(timezone.utc)
    run_id = started_at.strftime("%Y-%m-%d-%H-%M-%S")

    # Compute pii_config hash for audit
    with open(pii_config, "rb") as f:
        pii_hash = "sha256:" + hashlib.sha256(f.read()).hexdigest()

    # ── Step 1: Check for existing checkpoint ────────────────────────────────
    checkpoint = load_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])
    temp_rds_id = None
    existing_endpoint = None

    if checkpoint:
        temp_rds_id = checkpoint.get("temp_rds_id")
        created_at_str = checkpoint.get("temp_rds_created_at", "")

        # Check if temp RDS still exists
        try:
            existing_instance = rds_client.describe_db_instances(DBInstanceIdentifier=temp_rds_id)
            existing_endpoint = existing_instance["DBInstances"][0]["Endpoint"]["Address"]
        except rds_client.exceptions.DBInstanceNotFoundFault:
            click.echo("Checkpoint found but temp RDS is gone — starting fresh.")
            clear_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])
            checkpoint = None
            temp_rds_id = None

        if checkpoint:
            if created_at_str:
                created_at = datetime.fromisoformat(created_at_str.replace("Z", "+00:00"))
                age_hours = (datetime.now(timezone.utc) - created_at).total_seconds() / 3600
                if age_hours > 24:
                    click.echo(
                        f"WARNING: Temp RDS is {age_hours:.1f} hours old. "
                        "Data may be stale."
                    )

            completed = checkpoint.get("tables_completed", [])
            click.echo(
                f"Resuming run {checkpoint['run_id']}. "
                f"Already completed: {completed}"
            )
            resume = click.confirm("Resume from checkpoint?", default=True)
            if not resume:
                clear_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])
                checkpoint = None

    # ── Step 2: Restore snapshot if no valid checkpoint ───────────────────────
    if not checkpoint:
        snapshot_id = get_latest_automated_snapshot(rds_client, config["source_rds_id"])
        temp_rds_id = f"pg-snap-anon-temp-{run_id}"

        restore_snapshot_to_temp(rds_client, snapshot_id, temp_rds_id, config)
        endpoint = wait_for_rds_available(rds_client, temp_rds_id, config["waiter_max_attempts"])

        checkpoint = {
            "run_id": run_id,
            "source_rds_id": config["source_rds_id"],
            "snapshot_id": snapshot_id,
            "temp_rds_id": temp_rds_id,
            "temp_rds_endpoint": endpoint,
            "temp_rds_created_at": started_at.isoformat(),
            "fdw_captured": False,
            "fdw_dropped": False,
            "tables_total": len(pii["tables"]),
            "tables_completed": [],
            "tables_remaining": list(pii["tables"].keys()),
            "status": "in_progress",
        }
        save_checkpoint(s3_client, config["s3_bucket"], checkpoint)
    else:
        endpoint = existing_endpoint
        snapshot_id = checkpoint["snapshot_id"]

    conn = psycopg2.connect(
        host=endpoint,
        user=credentials["user"],
        password=credentials["password"],
        dbname=credentials["dbname"],
        port=credentials["port"],
        connect_timeout=30,
        keepalives=1,
        keepalives_idle=60,
        keepalives_interval=10,
        keepalives_count=5,
        sslmode="require",
        options="-c statement_timeout=0",
    )
    schema_valid = False
    tables_anonymized: dict = {}
    try:
        # ── Step 3: FDW handling ──────────────────────────────────────────────────
        patch_dir = str(Path(__file__).parent / "patch" / endpoint.split(".")[0])

        if not checkpoint.get("fdw_captured"):
            capture_fdw_config(conn, patch_dir)
            checkpoint["fdw_captured"] = True
            save_checkpoint(s3_client, config["s3_bucket"], checkpoint)

        if not checkpoint.get("fdw_dropped"):
            execute_pre_drop_fdw(conn, patch_dir)
            checkpoint["fdw_dropped"] = True
            save_checkpoint(s3_client, config["s3_bucket"], checkpoint)

        # ── Step 4: Schema validation ─────────────────────────────────────────────
        errors = validate_schema(conn, pii)
        schema_valid = not errors
        if errors:
            click.echo("Schema validation FAILED — aborting before any anonymization:")
            for err in errors:
                click.echo(f"  ✗ {err}")

        # ── Step 5: Anonymize tables ──────────────────────────────────────────────
        if schema_valid:
            faker = Faker(_load_defaults().get("faker", {}).get("options", ["en_US"]))
            tables_anonymized = {}
            tables_completed = set(checkpoint.get("tables_completed", []))

            # Pre-populate audit entries for tables already done in a prior session
            for table in tables_completed:
                if table in pii["tables"]:
                    tables_anonymized[table] = {
                        "rows": "resumed",
                        "columns": len(pii["tables"][table]),
                    }

            for table, columns in pii["tables"].items():
                if table in tables_completed:
                    click.echo(f"Skipping {table} (already completed)")
                    continue

                click.echo(f"\nAnonymizing {table}...")
                row_count = _with_retry(anonymize_table, conn, table, columns, faker)
                tables_anonymized[table] = {"rows": row_count, "columns": len(columns)}

                tables_completed.add(table)
                checkpoint["tables_completed"] = list(tables_completed)
                checkpoint["tables_remaining"] = [
                    t for t in pii["tables"] if t not in tables_completed
                ]
                save_checkpoint(s3_client, config["s3_bucket"], checkpoint)
                click.echo(f"  ✓ {table}: {row_count:,} rows anonymized")
    finally:
        conn.close()

    if not schema_valid:
        delete_temp_rds(rds_client, temp_rds_id)
        clear_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])
        sys.exit(1)

    # ── Step 6: Create output snapshot ───────────────────────────────────────
    output_snapshot_base = (
        config.get("output_snapshot") or f"pg-snap-anon-{config['source_rds_id']}"
    )
    output_snapshot_id = f"{output_snapshot_base}-{run_id}"
    click.echo(f"\nCreating output snapshot: {output_snapshot_id}")
    rds_client.create_db_snapshot(
        DBSnapshotIdentifier=output_snapshot_id,
        DBInstanceIdentifier=temp_rds_id,
    )
    waiter = rds_client.get_waiter("db_snapshot_available")
    waiter.wait(
        DBSnapshotIdentifier=output_snapshot_id,
        WaiterConfig={"Delay": 30, "MaxAttempts": config["waiter_max_attempts"]},
    )
    click.echo(f"Output snapshot ready: {output_snapshot_id}")

    # ── Step 7: Cleanup and audit ─────────────────────────────────────────────
    delete_temp_rds(rds_client, temp_rds_id)
    clear_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])

    completed_at = datetime.now(timezone.utc)
    audit = {
        "run_id": run_id,
        "source_rds": config["source_rds_id"],
        "snapshot_used": snapshot_id,
        "temp_rds": f"{temp_rds_id} (deleted)",
        "output_snapshot": output_snapshot_id,
        "pii_config_hash": pii_hash,
        "approved_by": pii["approved_by"],
        "approved_date": pii["approved_date"],
        "started_at": started_at.isoformat(),
        "completed_at": completed_at.isoformat(),
        "tables_anonymized": tables_anonymized,
        "fdw_captured": checkpoint["fdw_captured"],
        "fdw_dropped": checkpoint["fdw_dropped"],
    }
    write_audit_log(s3_client, config["s3_bucket"], audit)
    click.echo("\nDone.")


@cli.command()
def cleanup() -> None:
    """Inspect and clean up an abandoned run (temp RDS + checkpoint)."""
    config = load_env_config()
    s3_client = boto3.client("s3", region_name=config["region"])
    rds_client = boto3.client("rds", region_name=config["region"])

    checkpoint = load_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])

    if not checkpoint:
        click.echo("No checkpoint found. Nothing to clean up.")
        return

    click.echo("\nAbandoned run found:")
    click.echo(f"  Run ID:          {checkpoint.get('run_id')}")
    click.echo(f"  Temp RDS:        {checkpoint.get('temp_rds_id')}")
    click.echo(f"  Created at:      {checkpoint.get('temp_rds_created_at')}")
    click.echo(f"  Tables done:     {checkpoint.get('tables_completed', [])}")
    click.echo(f"  Tables left:     {checkpoint.get('tables_remaining', [])}")

    if not click.confirm("\nDelete temp RDS and clear checkpoint?", default=False):
        click.echo("Aborted. Nothing deleted.")
        return

    temp_rds_id = checkpoint.get("temp_rds_id")
    if temp_rds_id:
        try:
            delete_temp_rds(rds_client, temp_rds_id)
        except Exception as e:
            click.echo(f"WARNING: Could not delete temp RDS ({e}). Clearing checkpoint anyway.")
    else:
        click.echo("WARNING: No temp_rds_id in checkpoint; skipping RDS deletion.")

    clear_checkpoint(s3_client, config["s3_bucket"], config["source_rds_id"])
    click.echo("Cleaned up.")


if __name__ == "__main__":
    cli()
