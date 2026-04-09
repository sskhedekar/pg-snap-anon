# pg-snap-anon

Safely anonymize AWS RDS PostgreSQL snapshots without ever connecting to live PROD.

## What it does

1. Finds the latest automated snapshot of your PROD RDS instance
2. Restores it to a temporary RDS instance (inside your VPC)
3. Captures and drops all FDW/dblink connections (no live PROD links remain)
4. Anonymizes PII columns declared in `pii_config.yaml` using Faker
5. Creates an anonymized output snapshot
6. Deletes the temp RDS
7. Writes an audit log to S3

PROD is never connected to. Every step is checkpointed to S3 — if the run fails, re-run to resume from the last completed table.

---

## Requirements

- Python 3.8+
- Must run from within the same VPC as the RDS instances (e.g. an EC2 bastion)
- AWS credentials with the permissions listed below

```bash
pip install -r requirements.txt
```

---

## Setup

### 1. Configure environment variables

```bash
export AWS_DEFAULT_REGION=<region>
export PGANONSNAP_SOURCE_RDS_ID=<prod-rds-id>
export PGANONSNAP_S3_BUCKET=<s3-bucket>
export PGANONSNAP_VPC_SECURITY_GROUP_IDS=<sg-id>
export PGANONSNAP_DB_SUBNET_GROUP=<subnet-group>
export PGANONSNAP_DB_SECRET=<secrets-manager-secret-name>   # or use PGUSER/PGPASSWORD/PGDATABASE
export PGANONSNAP_STORAGE_TYPE=gp3
```

All supported variables:

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `AWS_DEFAULT_REGION` | Yes | — | AWS region |
| `PGANONSNAP_SOURCE_RDS_ID` | Yes | — | PROD RDS instance identifier |
| `PGANONSNAP_S3_BUCKET` | Yes | — | S3 bucket for checkpoints and audit logs |
| `PGANONSNAP_VPC_SECURITY_GROUP_IDS` | Yes | — | Comma-separated SG IDs for temp RDS |
| `PGANONSNAP_DB_SUBNET_GROUP` | Yes | — | Subnet group for temp RDS |
| `PGANONSNAP_DB_SECRET` | Prod | — | Secrets Manager secret (priority over PGUSER/PGPASSWORD) |
| `PGUSER` / `PGPASSWORD` / `PGDATABASE` | Dev | — | Direct DB credentials (if no DB_SECRET) |
| `PGANONSNAP_INSTANCE_CLASS` | No | `db.t3.micro` | Temp RDS instance class |
| `PGANONSNAP_STORAGE_TYPE` | No | `gp2` | Temp RDS storage type |
| `PGANONSNAP_ALLOCATED_STORAGE` | No | `20` | Temp RDS storage in GB |
| `PGANONSNAP_WAITER_MAX_ATTEMPTS` | No | `120` | Max waiter attempts (120 × 30s = 60 min) |
| `PGANONSNAP_OUTPUT_SNAPSHOT` | No | `pg-snap-anon-<source-rds-id>` | Output snapshot base name |

### 2. Declare PII scope

```bash
python3 pg_snap_anon.py configure
```

This runs an interactive wizard and writes `pii_config.yaml`. Review the file, then set:

```yaml
approved: true
approved_by: "Your Name"
approved_date: "YYYY-MM-DD"
```

See `example_pii_config.yaml` for a full example.

### 3. Validate against real schema

```bash
python3 pg_snap_anon.py validate
```

Restores a snapshot, checks every declared table and column exists and is type-compatible with the Faker rule, then deletes the temp RDS. Run this after first setup or after schema changes.

> **Note:** Validate restores a full snapshot — it takes the same time and incurs the same cost as a run.

### 4. Run anonymization

Always run inside `screen` to survive SSH disconnection:

```bash
screen -S pg-anon
python3 pg_snap_anon.py run 2>&1 | tee run.log
```

If SSH drops, reconnect and reattach:

```bash
screen -r pg-anon
```

Output snapshot will be named: `pg-snap-anon-<source-rds-id>-<run-id>`

Monitor from a second terminal:

```bash
tail -f run.log
```

### 5. Clean up an abandoned run

```bash
python3 pg_snap_anon.py cleanup
```

Deletes orphaned temp RDS and clears the S3 checkpoint.

---

## FDW / dblink handling

If your database has foreign servers, place a `pre_drop_fdw.sql` in:

```
patch/<temp-rds-hostname>/pre_drop_fdw.sql
```

If no host-specific file is found, the tool automatically falls back to `patch/_default/pre_drop_fdw.sql` and copies it into the run-specific folder.

See `patch/example-temp-rds-hostname/pre_drop_fdw.sql` for a template that drops all foreign tables, user mappings, servers, extensions and replication slots.

After the run, `patch/<temp-rds-hostname>/post_restore_fdw.sql` is auto-generated with placeholders:

```sql
CREATE SERVER IF NOT EXISTS my_server FOREIGN DATA WRAPPER postgres_fdw
  OPTIONS (host '<STAGE_HOST>', port '<STAGE_PORT>', dbname '<STAGE_DBNAME>');
CREATE USER MAPPING IF NOT EXISTS FOR myuser SERVER my_server
  OPTIONS (user '<STAGE_USER>', password '<STAGE_PASSWORD>');
```

Fill in placeholders and run on your stage RDS to reconnect FDW.

---

## Limitations

The tool anonymizes data via in-place `UPDATE` — it never deletes or inserts rows.

**Handled automatically:**

| Object | Detail |
|--------|--------|
| Primary keys | Used to identify rows, never modified |
| Sequences | No INSERT/DELETE so sequences are untouched |
| Foreign keys | UPDATE in-place doesn't violate FK constraints |
| UNIQUE constraints | Pre-loads existing values, retries until unique, UUID suffix fallback |
| NOT NULL constraints | Faker always returns a non-null value |
| Indexes on anonymized columns | PostgreSQL auto-maintains indexes on UPDATE |

**Not handled — check before running:**

| Object | Risk |
|--------|------|
| CHECK constraints | UPDATE will fail if Faker value doesn't satisfy the constraint |
| Triggers on UPDATE | Will fire — may write to audit tables or call external systems |
| Generated columns | Cannot be updated directly — will crash if declared in `pii_config.yaml` |
| Row-level security (RLS) | Rows hidden by RLS policies will be silently skipped |

See [docs/limitations.md](docs/limitations.md) for diagnostic SQL queries to detect these before running.

---

## Required AWS IAM permissions

```json
{
  "RDS": [
    "rds:DescribeDBSnapshots",
    "rds:DescribeDBInstances",
    "rds:RestoreDBInstanceFromDBSnapshot",
    "rds:CreateDBSnapshot",
    "rds:DeleteDBInstance",
    "rds:AddTagsToResource",
    "rds:ListTagsForResource",
    "rds:ModifyDBInstance"
  ],
  "S3": [
    "s3:GetObject",
    "s3:PutObject",
    "s3:DeleteObject",
    "s3:ListBucket"
  ],
  "SecretsManager": [
    "secretsmanager:GetSecretValue"
  ]
}
```

---

## S3 layout

```
s3://<bucket>/pg-snap-anon/
  checkpoint-<source-rds-id>.json   — resume state (deleted on success)
  logs/
    run-<timestamp>.log             — immutable audit log per run
```

---

## pii_config.yaml format

```yaml
tables:
  users:
    email: fake.email()
    full_name: fake.name()
    phone_number: fake.phone_number()
  organizations:
    company_name: fake.company()

approved: true
approved_by: "DBA Name"
approved_date: "YYYY-MM-DD"
```

Only columns listed here are anonymized. Everything else is untouched.

---

## Supported Faker rules

| Rule | Output |
|------|--------|
| `fake.email()` | Email address |
| `fake.name()` | Full name |
| `fake.first_name()` | First name |
| `fake.last_name()` | Last name |
| `fake.user_name()` | Username |
| `fake.phone_number()` | Phone number |
| `fake.company()` | Company name |
| `fake.job()` | Job title |
| `fake.street_address()` | Street address |
| `fake.city()` | City |
| `fake.state()` | State |
| `fake.postcode()` | Postal code |
| `fake.country()` | Country |
| `fake.text()` | Random text |
| `fake.uuid4()` | UUID |
| `fake.date_of_birth()` | Date |
| `fake.date_time()` | Timestamp |
| `fake.ipv4()` | IP address |
| `fake.url()` | URL |
| `fake.iban()` | IBAN |
| `fake.credit_card_number()` | Credit card number |
| `fake.ssn()` | Social security number |
| `fake.sha256()` | SHA256 hash |
