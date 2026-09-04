# BlocklistManager — Firewall Blocklist Manager

One authoritative IP blocklist for hybrid environments, enforced at the network edge and in cloud identity from a single source of truth.

Rules live in a local SQLite database with full audit history, expiration and whitelist protection. The same rule set publishes to flat files for firewall ingestion and to a Microsoft Entra Conditional Access Named Location. Publishing is separate from rule management, so further targets can be added without changing how rules are written, reviewed or audited.

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
   - [carve](#carve)
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

- Python 3.10+
- `colorama`
- `microsoft_graph_helpers` (only needed for `sync`, and the reason the floor
  is 3.10 rather than 3.8)

Install dependencies:

```
pip install -r requirements.txt
```

---

## Installation

No installation required. Run directly:

```
python src/BlocklistManager.py <command> [target] [options]
```

---

## Directory Structure

The tool creates the following directories automatically on first run, relative to the project root:

```
data/        SQLite database file (see DATABASE_PATH)
logs/        Audit log (audit.log)
rules/       Exported rule files
reports/     CSV audit reports
backups/     Pre-export backups of rule files
```

`config.txt` is loaded from the project root, one level up from `src/`.

Source lives under `src/`:

```
src/BlocklistManager.py    The tool itself
src/modules/               Supporting modules
src/modules/envfile.py     Parser for config.txt
```

`src/` goes on the import path, so a supporting module is reached as
`from modules.envfile import load_config`. New helpers go in `src/modules/` and
are imported from their own file rather than re-exported from the package.

---

## Configuration

Create a `config.txt` file in the project root, beside `src/` and not inside it. All values are optional and fall back to defaults if not set.

| Key               | Type      | Default | Description                                                                 |
|-------------------|-----------|---------|-----------------------------------------------------------------------------|
| `DENY_ONLY`       | TRUE/FALSE | TRUE   | When TRUE, the `allow` command is disabled.                                 |
| `DEFAULT_EXPIRY`  | integer   | 30      | Default expiration in days when the operator presses Enter at the prompt.   |
| `DATABASE_PATH`   | path      | `data/BlocklistManager.sqlite` | Where the SQLite database lives. Relative paths resolve against the project root; absolute paths are used as given. Missing directories are created. |
| `MAX_EXPIRY`      | integer   | unset   | Optional cap on rule lifetime. When set, longer expirations and indefinite (`0`) rules are refused. |
| `FILE_OUTPUT_DENY` | path     | `rules/block.txt` | Output path for the exported BLOCK list.                       |
| `FILE_OUTPUT_ALLOW`| path     | `rules/allow.txt` | Output path for the exported ALLOW list.                       |
| `TENANT_ID`       | string    | —       | Azure AD tenant ID. Required for `sync`.                                    |
| `CLIENT_ID`       | string    | —       | App registration client ID. Required for `sync`.                            |
| `SECRET`          | string    | —       | App registration client secret. Required for `sync`.                        |
| `WHITELIST_PATH`  | path      | `whitelist.txt` | Where the whitelist lives. Relative paths resolve against the project root; absolute paths are used as given, so it can sit in `/etc` with your other config. |
| `BLOCKLIST_NAMED_LOCATION_ID` | string | — | UUID of the Entra Named Location to update. Required for `sync`.       |

`config.txt` holds a client secret and is gitignored. Copy `config.txt.example` to `config.txt` and fill it in.

Example `config.txt`:

```
DENY_ONLY=TRUE
DEFAULT_EXPIRY=30
FILE_OUTPUT_DENY=/etc/firewall/blocklist.txt
FILE_OUTPUT_ALLOW=/etc/firewall/allowlist.txt
```

### File format

One `KEY=VALUE` per line. Blank lines are ignored, as is anything after a `#`
that follows whitespace, so `DEFAULT_EXPIRY=30 # days` sets `30` while a secret
containing `abc#def` keeps its `#`.

Values may be quoted to preserve leading or trailing spaces, and a quoted value
may span several lines:

```
SECRET="  padded value  "
LITERAL='no \n escapes here'
IDS="11111111-2222-3333-4444-555555555555
66666666-7777-8888-9999-000000000000"
```

Double quotes process `\n`, `\t`, `\r`, `\\` and `\"`; single quotes are
literal. `${VAR}` is **not** expanded. Values are passed through exactly as
written, since a client secret can legitimately contain a `$` or a brace.

This is the standard env-file format, which means `config.txt` can also be fed
straight to systemd's `EnvironmentFile=` or `docker --env-file` if you would
rather inject `SECRET` from a vault than write it to disk.

A syntax error is fatal: the tool reports the file and line number and exits
rather than running with a silently misread configuration.

### Entra setup for `sync`

`sync` authenticates as an application, with no user context, so it needs an
Entra app registration:

1. Register an application in Entra ID and note its **Application (client) ID**
   and your **Directory (tenant) ID**.
2. Under **API permissions**, add both Microsoft Graph **application**
   permissions: `Policy.Read.All` and `Policy.ReadWrite.ConditionalAccess`.
   Microsoft lists both as required to update a Named Location: the read is
   used to fetch current state for the backup, and the write to replace the
   ranges. Application permissions cannot be granted by a user, so a Global
   Administrator or Privileged Role Administrator must click **Grant admin
   consent** afterwards.
3. Under **Certificates & secrets**, create a client secret and copy the value
   immediately. Entra shows it once.
4. Put the tenant ID, client ID and secret into `config.txt` as `TENANT_ID`,
   `CLIENT_ID` and `SECRET`.

The Named Location must already exist. Entra will not accept one with no
entries, so create it by hand with a single placeholder CIDR, then open it and
copy the UUID from the address bar into `BLOCKLIST_NAMED_LOCATION_ID`.

`sync` is authoritative, not additive. It sends the full list of active BLOCK
rules and Graph replaces the entire `ipRanges` collection, so anything not in
the database is removed from the Named Location. Entries added by hand in the
portal will be wiped on the next run. The previous state is written to
`backups/` as JSON first.

If the permission or consent is missing, `sync` exits after the file export
with the required permission named in the error.

---

## Rule Breadth

Rules are gated on how much address space they cover, so a single mistyped
prefix cannot lock out a tenant.

| Family | Size | Behavior |
|--------|------|----------|
| IPv4 | `/24` or narrower | Proceeds normally |
| IPv4 | `/23` – `/16` | Red warning; the operator must **retype the range exactly** to confirm |
| IPv4 | wider than `/16` | Refused outright — cannot be forced |
| IPv6 | `/48` or narrower | Proceeds normally |
| IPv6 | `/47` – `/32` | Red warning; retype to confirm |
| IPv6 | wider than `/32` | Refused outright |

Confirmation deliberately does not accept `y`. A destructive rule should not be
one reflex keystroke away, so the range must be retyped character for character.

The IPv6 thresholds track the equivalent operational units — a site is a `/48`,
a large allocation a `/32` — so an ordinary `/64` host block never trips the
guard. The gate applies to both `block` and `allow`.

If a rule genuinely needs to be wider than the refusal threshold, split it into
permitted blocks. The limits live in `IPDatabase.SIZE_LIMITS`.

---

## Whitelist

Any `block` or `deny` command targeting an IP or range that overlaps a
whitelisted entry is rejected immediately: no prompts, no database write.
Overlap is checked in both directions, so a `/16` that merely contains one
whitelisted `/32` is rejected too.

**The whitelist file is required.** `block`, `deny`, `allow` and `remove` refuse
to run until it exists, and exit non-zero. Reading and publishing commands
(`list`, `search`, `report`, `export`, `sync`) still work without it, since
those rules were already checked against the whitelist when they were added.

An empty file is accepted. The requirement is not that you have something to
protect, it is that an administrator consciously decided what must never be
blocked instead of the question never being asked. Copy
`whitelist.txt.example` to `whitelist.txt` and edit it, or create it empty if
you genuinely have nothing to list.

By default it sits in the project root beside `config.txt`. Set `WHITELIST_PATH`
to move it, including to an absolute path outside the install.

Replace the placeholder entries with your own infrastructure before adding any rules. `whitelist.txt` is gitignored so each deployment keeps its own.

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
python src/BlocklistManager.py COMMAND [TARGET] [OPTIONS]
```

### block / deny

Add a BLOCK rule for the given IP, CIDR, or dash range.

```
python src/BlocklistManager.py block <target>
python src/BlocklistManager.py deny <target>
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
python src/BlocklistManager.py allow <target>
```

Behavior mirrors `block` but for the ALLOW policy. May be disabled via `DENY_ONLY=TRUE` in `config.txt`.

**Prompts:** Incident/Ticket ID, operator comment, expiration.

---

### remove

Remove an active BLOCK or ALLOW rule.

```
python src/BlocklistManager.py remove <target>
```

**Behavior:**
- If the target is not found as an exact active rule, the tool checks whether it is covered by a broader rule and hints the operator.
- If both a BLOCK and ALLOW rule exist for the same CIDR, the operator is presented with a list and asked to choose which to remove.
- When a covering rule is removed, any non-expired child ranges that were marked redundant under it are automatically reactivated under the new incident ID.

**Prompts:** Confirmation, Incident/Ticket ID, operator comment.

#### Carve-out

Removing a range that sits inside a broader rule offers to carve it out, and
`carve` goes straight there. The
covering rule is deleted and replaced by the CIDRs covering everything except
the carved range, keeping the covering rule's policy and expiration. Carving
`45.33.32.50` out of a `45.33.32.0/24` block leaves 8 BLOCK rules and a hole.

Carving out of a BLOCK also writes an **ALLOW record** for the carved range,
inheriting the covering rule's expiration so the exception cannot outlive the
block it came from. It is a record, not an instruction. The three publishing
targets see it differently:

| Target | What it gets |
|---|---|
| Block list (`FILE_OUTPUT_DENY`) | The replacement CIDRs. The carved range is simply absent. |
| Named Location (`sync`) | The same replacement CIDRs. Entra has no allow concept, and `sync` only ever publishes BLOCK rules. |
| Allow list (`FILE_OUTPUT_ALLOW`) | The carved range, as a record of what was deliberately let through. |

The allow list is documentation here rather than enforcement: the block list
and the Named Location already express the exception by leaving the range out.
Nothing depends on your firewall evaluating a specific allow ahead of a broader
block.

This works while `DENY_ONLY` is TRUE. The `allow` command stays disabled in
that mode, so a carve-out is the only way an ALLOW entry comes into existence.

Carving out of an ALLOW rule writes no such record. Subtracting from a hole
does not produce a rule worth publishing.

Only one carve is offered per `remove`.

##### Lifetime of the ALLOW record

**The allow list is a historical record of exceptions, not a current-state
view.** Read it as "these ranges were deliberately let through," not as "these
ranges are currently holes in a live block."

When the carve-out expires it takes the ALLOW record with it, since the record
inherits the covering rule's expiration and the replacement blocks carry the
same one. That is the ordinary path and needs no attention.

Removing the replacement blocks by hand is different. The ALLOW record is not
removed with them, so an allow list can name a range whose surrounding blocks
are gone:

```
block list: 0 entries
allow list: 45.33.32.1/32
```

This is deliberate. The record is audit evidence that somebody authorised an
exception, under a specific incident ID, and it does not evaporate because the
blocks around it were later cleaned up. It also cannot cause harm on its own,
since nothing enforces the allow list: the block list and the Named Location
carry the enforcement, and neither mentions the range.

Clean it up by hand when you want it gone:

```
blocklist remove 45.33.32.1
```

`remove` finds the ALLOW as an exact target and deletes it like any other rule.
`report` shows every record including expired and redundant ones, which is the
place to audit what is still on the books.

---

### carve

Punch a hole in a broader rule: carve a range out of whatever covers it.

```
blocklist carve <target>
```

This is what you want when an address sits inside a block and you need to let
it through. `remove` reaches the same place, but only after a `NOT FOUND` error
that reads like a failure, so `carve` says what you meant.

**Behavior:**
- Finds the active rule covering the target, checking BLOCK before ALLOW.
- Shows the replacement CIDRs and asks to confirm before writing anything.
- Carving out of a BLOCK also writes an ALLOW record for the carved range. See
  [Carve-out](#carve-out) for what each publishing target receives.
- Works while `DENY_ONLY` is TRUE. That setting disables the standalone `allow`
  command, not carving, and a carve-out is the only way an ALLOW entry is
  created in that mode.
- If the target is already a rule of its own, there is nothing broader to carve
  it out of, and the tool points at `remove` instead.
- If nothing covers the target, the address is already unblocked, and the tool
  points at `block`.

**Prompts:** Confirmation, Incident/Ticket ID, operator comment, then a second
confirmation showing the replacement rules.

Attempting `allow` on an address inside a block while `DENY_ONLY` is set names
this command in the refusal:

```
[!] ACCESS DENIED: DENY_ONLY_MODE is set, 'allow' is disabled.
    45.33.32.50/32 is covered by an active BLOCK rule for 45.33.32.0/24.
    To punch a hole in that rule instead:
        blocklist carve 45.33.32.50
```

---

### search

Look up whether an IP address is covered by any active rule.

```
python src/BlocklistManager.py search <target>
```

Displays policy, CIDR range, author, creation date, expiration, and incident ID for every matching rule. Does not require a globally routable address (useful for searching RFC 1918 or other special-use addresses).

---

### export

Export all active, non-redundant, non-expired rules to flat text files.

```
python src/BlocklistManager.py export
```

Output paths are determined by `FILE_OUTPUT_DENY` and `FILE_OUTPUT_ALLOW` in `config.txt`. If not configured, defaults to:

```
rules/block.txt
rules/allow.txt
```

If an output file already exists, it is backed up to `backups/` with a timestamp suffix before being overwritten. The backup is verified via SHA-256 hash. If the backup fails integrity verification, the operator is prompted to confirm overwriting without a backup.

---

### list

Print all active, non-redundant, non-expired rules to the screen.

```
python src/BlocklistManager.py list
```

Output is a formatted table showing policy, CIDR, creation date, expiration, author, and incident ID.

---

### report

Generate a full CSV audit export of every record in the database.

```
python src/BlocklistManager.py report
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
python src/BlocklistManager.py purge [--days N]
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

Redundancy is always reversible, in both directions:

- **Covering rule removed** — non-expired redundant child ranges of the same policy are reactivated (`is_redundant = 0`) and assigned the incident ID from the removal operation.
- **Covering rule expires** — the same children are reactivated on the next run, with a `REACTIVATED` entry in the audit history. Without this, a temporary wide sweep would permanently suppress a narrower rule that had no expiration of its own, and that rule would silently vanish from every export.

Reactivation is policy-scoped: an active BLOCK rule never suppresses an orphaned ALLOW child, or vice versa. Nested rules are re-checked broadest-first, so a reactivated parent continues to suppress its own children.

Redundant records are retained in the database for audit purposes until explicitly removed with `purge`. Because purging is permanent, `purge` warns first if any of the records it would delete have no expiration — those would otherwise return automatically once their covering rule lapsed.

---

## Backup Behavior

Before overwriting an export file, the tool:

1. Computes the SHA-256 hash of the existing file.
2. Copies the file to `backups/YYYY-MM-DD_HH_MM_SS-<filename>.txt`.
3. Computes the SHA-256 hash of the backup.
4. Compares the two hashes.

Empty files are not backed up — there is nothing to restore. In `DENY_ONLY`
mode the allow list is always empty, so it would otherwise accumulate a useless
backup on every single export.

The check is on the **existing** file, not the new content. Replacing a
populated block list with an empty one still takes a backup first; that is the
case where losing the previous contents would hurt most.

### Backup filenames

Backups lead with the timestamp, so a plain alphabetical listing in Finder or
any file browser is also chronological:

```
2026-09-03_08_01_16-palo-blocks.txt
2026-09-03_08_01_16-Campus-Blocklist-0e697235.json
```

`sync` names its Named Location backup after the location itself, followed by
the first block of the location's UUID:

```
YYYY-MM-DD_HH_MM_SS-<display name>-<uuid prefix>.json
```

The UUID prefix is there because a single Named Location holds at most 2000
CIDRs; past that a tenant needs a second one, and its backups have to stay
distinguishable even if both lists are given the same display name. Display
names are free text, so spaces become `-`, path separators and other awkward
characters are dropped, and the name is capped at 60 characters. A location
with no usable display name falls back to `named_location`.

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
