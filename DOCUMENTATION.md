# BlockListManager — Firewall Blocklist Manager

A command-line tool for managing firewall IP block and allow rules in a local SQLite database, with audit logging, expiration support, whitelist protection, and rule export.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Directory Structure](#directory-structure)
4. [Configuration](#configuration)
5. [Whitelist](#whitelist)
6. [Usage](#usage)
   - [block / deny](#block--deny)
   - [allow](#allow)
   - [remove](#remove)
   - [search](#search)
   - [export](#export)
   - [list](#list)
   - [report](#report)
   - [purge](#purge)
7. [Input Formats](#input-formats)
8. [Expiration](#expiration)
9. [Redundancy & Optimization](#redundancy--optimization)
10. [Backup Behavior](#backup-behavior)
11. [Audit Logging](#audit-logging)
12. [Database Schema](#database-schema)

---

## Requirements

- Python 3.8+
- `python-dotenv`
- `colorama`

Install dependencies:

```
pip install python-dotenv colorama
```

---

## Installation

No installation required. Run directly:

```
python BlockListManager.py <command> [target] [options]
```

---

## Directory Structure

The tool creates the following directories automatically on first run, relative to the current working directory:

```
database/    SQLite database file
logs/        Audit log (audit.log)
rules/       Exported rule files
reports/     CSV audit reports
backups/     Pre-export backups of rule files
```

`config.env` is loaded from the same directory as `BlockListManager.py`.

---

## Configuration

Create a `config.env` file next to `BlockListManager.py`. All values are optional and fall back to defaults if not set.

| Key               | Type      | Default | Description                                                                 |
|-------------------|-----------|---------|-----------------------------------------------------------------------------|
| `DENY_ONLY`       | TRUE/FALSE | TRUE   | When TRUE, the `allow` command is disabled.                                 |
| `DEFAULT_EXPIRY`  | integer   | 30      | Default expiration in days when the operator presses Enter at the prompt.   |
| `FILE_OUTPUT_DENY` | path     | `rules/block.txt` | Output path for the exported BLOCK list.                       |
| `FILE_OUTPUT_ALLOW`| path     | `rules/allow.txt` | Output path for the exported ALLOW list.                       |

Example `config.env`:

```
DENY_ONLY=TRUE
DEFAULT_EXPIRY=30
FILE_OUTPUT_DENY=/etc/firewall/blocklist.txt
FILE_OUTPUT_ALLOW=/etc/firewall/allowlist.txt
```

---

## Whitelist

If a `whitelist.txt` file exists in the working directory, any `block` or `deny` command targeting an IP or range that overlaps a whitelisted entry will be rejected immediately — no prompts, no database write.

### File Format

- One IP, CIDR, or dash range per line
- Lines beginning with `#` are full-line comments and are ignored
- Inline comments are supported: everything from `#` onward is stripped
- Blank lines are ignored
- Invalid entries produce a warning and are skipped

### Example `whitelist.txt`

```
# Core infrastructure — never block
203.0.113.0/24      # NOC uplink
198.51.100.10       # monitoring host
2001:db8::/32       # IPv6 management range
10.0.0.1-10.0.0.50  # internal management range
```

---

## Usage

```
python BlockListManager.py COMMAND [TARGET] [OPTIONS]
```

### block / deny

Add a BLOCK rule for the given IP, CIDR, or dash range.

```
python BlockListManager.py block <target>
python BlockListManager.py deny <target>
```

`deny` is an alias for `block`. Behavior is identical.

**Behavior:**
- If the target is already covered by an existing BLOCK rule, the operator is offered the option to extend its expiration. No duplicate is added.
- If the target overlaps an existing ALLOW rule, the operator is prompted to confirm the exception before proceeding.
- If the target overlaps a whitelisted network, the entry is rejected immediately.
- For dash ranges that expand to multiple CIDRs, each is processed individually.

**Prompts:** Incident/Ticket ID, operator comment, expiration.

---

### allow

Add an ALLOW rule for the given IP, CIDR, or dash range.

```
python BlockListManager.py allow <target>
```

Behavior mirrors `block` but for the ALLOW policy. May be disabled via `DENY_ONLY=TRUE` in `config.env`.

**Prompts:** Incident/Ticket ID, operator comment, expiration.

---

### remove

Remove an active BLOCK or ALLOW rule.

```
python BlockListManager.py remove <target>
```

**Behavior:**
- If the target is not found as an exact active rule, the tool checks whether it is covered by a broader rule and hints the operator.
- If both a BLOCK and ALLOW rule exist for the same CIDR, the operator is presented with a list and asked to choose which to remove.
- When a covering rule is removed, any non-expired child ranges that were marked redundant under it are automatically reactivated under the new incident ID.

**Prompts:** Confirmation, Incident/Ticket ID, operator comment.

---

### search

Look up whether an IP address is covered by any active rule.

```
python BlockListManager.py search <target>
```

Displays policy, CIDR range, author, creation date, expiration, and incident ID for every matching rule. Does not require a globally routable address (useful for searching RFC 1918 or other special-use addresses).

---

### export

Export all active, non-redundant, non-expired rules to flat text files.

```
python BlockListManager.py export
```

Output paths are determined by `FILE_OUTPUT_DENY` and `FILE_OUTPUT_ALLOW` in `config.env`. If not configured, defaults to:

```
rules/block.txt
rules/allow.txt
```

If an output file already exists, it is backed up to `backups/` with a timestamp suffix before being overwritten. The backup is verified via SHA-256 hash. If the backup fails integrity verification, the operator is prompted to confirm overwriting without a backup.

---

### list

Print all active, non-redundant, non-expired rules to the screen.

```
python BlockListManager.py list
```

Output is a formatted table showing policy, CIDR, creation date, expiration, author, and incident ID.

---

### report

Generate a full CSV audit export of every record in the database.

```
python BlockListManager.py report
```

Includes all records — active, redundant, and expired. Output is written to:

```
reports/ip_audit_report_YYYYMMDD_HHMMSS.csv
```

Columns: IP/CIDR, Policy, Version, Incident ID, Author, Created, Expires, Is Redundant.

---

### purge

Permanently delete redundant (swallowed) records from the database.

```
python BlockListManager.py purge [--days N]
```

| Option    | Description                                              |
|-----------|----------------------------------------------------------|
| `--days N` | Only purge redundant records older than N days. Omit to purge all redundant records. |

Redundant records are created automatically when a broader range supersedes a narrower one. They are kept by default so the full history is preserved in reports. Use `purge` to reclaim space.

**Prompts:** Confirmation before proceeding.

---

## Input Formats

| Format              | Example                  | Treated as                  |
|---------------------|--------------------------|-----------------------------|
| Plain IPv4          | `1.2.3.4`                | `/32` host rule             |
| IPv4 CIDR           | `1.2.3.0/24`             | Exact CIDR                  |
| Plain IPv6          | `2001:db8::1`            | `/64` network rule          |
| IPv6 CIDR           | `2001:db8::/32`          | Exact CIDR                  |
| IPv4 dash range     | `1.2.3.10-1.2.3.20`      | Expanded to minimal CIDRs   |

**Notes:**
- Plain IPv4 addresses are automatically treated as `/32`.
- Plain IPv6 addresses are automatically expanded to `/64`. Use `/128` to target a single host.
- Dash ranges are expanded into the minimal set of CIDRs needed to cover the range (equivalent to `summarize_address_range`).
- Only globally routable addresses are accepted for `block`, `allow`, and `remove`. The `search` command accepts any address.
- Dash ranges that cross a `/24` boundary trigger a confirmation prompt showing the full expansion before proceeding.

---

## Expiration

All rules can optionally expire. At the expiration prompt:

| Input     | Result                              |
|-----------|-------------------------------------|
| Enter     | Use the default (from `DEFAULT_EXPIRY` in config, default 30 days) |
| `0`       | Rule never expires (indefinite)     |
| `N` (integer > 0) | Rule expires N days from now |

Expired rules are excluded from `search`, `list`, `export`, and child-range restoration on `remove`. They remain in the database and appear in `report`.

When a matching rule already exists, the operator is offered the option to extend the expiration:

| Input     | Result                                      |
|-----------|---------------------------------------------|
| Enter     | Keep current expiration unchanged           |
| `0`       | Make the rule indefinite                    |
| `N` (integer > 0) | Add N days to the current expiration |

---

## Redundancy & Optimization

When a new rule is added that covers one or more existing rules of the same policy, those smaller rules are automatically marked `is_redundant = 1`. This prevents duplicate matches and keeps exports clean.

When a covering rule is removed, non-expired redundant child ranges of the same policy are automatically reactivated (`is_redundant = 0`) and assigned the incident ID from the removal operation.

Redundant records are retained in the database for audit purposes until explicitly removed with `purge`.

---

## Backup Behavior

Before overwriting an export file, the tool:

1. Computes the SHA-256 hash of the existing file.
2. Copies the file to `backups/<filename>-YYYY-DD-MM_HH_MM_SS.txt`.
3. Computes the SHA-256 hash of the backup.
4. Compares the two hashes.

If the hashes match, the export proceeds and the backup is confirmed with `(verified)`.

If the hashes do not match (copy corruption), the backup is deleted and the operator is prompted:

```
[!] INTEGRITY ISSUE: couldn't back up existing block.txt.
Overwrite without backup? (y/n):
```

Answering `n` skips the export for that policy. The other policy continues normally.

---

## Audit Logging

All write operations are recorded in two places:

**SQLite `audit_history` table** — queryable record of every ADD, REMOVE, EXTEND, and PURGE event, including the operator, target CIDR, incident ID, comment, and timestamp.

**`logs/audit.log`** — append-only flat log file in the format:

```
YYYY-MM-DD HH:MM:SS [INFO] USER: <username> | ACTION: <event> | TARGET: <cidr> | ID: <incident> | EXPIRES: <date> | COMMENT: <text>
```

---

## Database Schema

### `ip_ranges`

| Column           | Type      | Description                                           |
|------------------|-----------|-------------------------------------------------------|
| `id`             | INTEGER   | Primary key                                           |
| `original_input` | TEXT      | The raw input string provided by the operator         |
| `cidr`           | TEXT      | Normalized CIDR notation                              |
| `version`        | INTEGER   | IP version (4 or 6)                                   |
| `start_blob`     | BLOB      | Packed start address (for range queries)              |
| `end_blob`       | BLOB      | Packed end address (for range queries)                |
| `incident_id`    | TEXT      | Incident or ticket ID provided at time of entry       |
| `is_redundant`   | INTEGER   | 1 if superseded by a broader rule, 0 if active        |
| `policy`         | TEXT      | `BLOCK` or `ALLOW`                                    |
| `created_by`     | TEXT      | OS username of the operator who created the rule      |
| `created_at`     | TIMESTAMP | Creation timestamp                                    |
| `expires_at`     | TIMESTAMP | Expiration timestamp, or NULL for indefinite          |

### `audit_history`

| Column        | Type      | Description                              |
|---------------|-----------|------------------------------------------|
| `id`          | INTEGER   | Primary key                              |
| `event_type`  | TEXT      | `ADDED_BLOCK`, `ADDED_ALLOW`, `REMOVED`, `EXTENDED`, `PURGE` |
| `target_cidr` | TEXT      | The CIDR or description that was affected |
| `user`        | TEXT      | OS username of the operator              |
| `incident_id` | TEXT      | Incident or ticket ID                    |
| `comment`     | TEXT      | Operator comment                         |
| `expires_at`  | TIMESTAMP | Expiration at time of event              |
| `timestamp`   | TIMESTAMP | When the event occurred                  |
