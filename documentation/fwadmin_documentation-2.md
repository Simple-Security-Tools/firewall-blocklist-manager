# Firewall Block List Manager (`fwadmin.py`)

## Overview
`fwadmin.py` is a command-line tool for managing an IP-based firewall block list with full audit history.
It supports IPv4 and IPv6 addresses and CIDR ranges, tracks incidents and comments, prevents redundant entries,
and exports clean block lists for firewall ingestion.

The tool stores all data in a local SQLite database and is designed to be:
- **Auditable** (incident IDs, comments, timestamps)
- **Safe** (prevents duplicate or redundant blocks)
- **Firewall-friendly** (exports only active ranges)

---

## Features
- Add IPv4 / IPv6 addresses or CIDR ranges
- Automatic `/64` normalization for bare IPv6 addresses
- Redundancy detection and marking
- Search which incidents cover a given IP
- Export active (non-redundant) ranges for firewall use
- Generate full CSV audit reports

---

## Requirements
- Python 3.8+
- Standard library only:
  - `sqlite3`
  - `ipaddress`
  - `csv`
  - `datetime`

No third-party dependencies.

---

## Installation
1. Copy `fwadmin.py` to the desired system.
2. Ensure Python 3 is available:
   ```bash
   python3 --version
   ```
3. Make executable (optional):
   ```bash
   chmod +x BlockListAdmin.py
   ```

The SQLite database (`ip_manager.db`) will be created automatically on first run.

---

## Usage Guide

### Command Summary
```bash
python BlockListAdmin.py add <ip-or-cidr>
python BlockListAdmin.py remove <original-input>
python BlockListAdmin.py search <ip>
python BlockListAdmin.py export
python BlockListAdmin.py report
```

---

### Add an IP or Network
```bash
python BlockListAdmin.py add 203.0.113.45
python BlockListAdmin.py add 203.0.113.0/24
python BlockListAdmin.py add 2001:db8::1
```

Behavior:
- Prompts for **Incident ID** and **Comment**
- Rejects entries already covered by an existing active range
- Marks smaller existing ranges as *redundant* if swallowed by the new range

Example prompt:
```
--- Metadata for 203.0.113.0/24 ---
Enter Incident ID: INC-2026-041
Enter Comment: Botnet traffic observed
```

---

### Remove an Entry
Removes by *exact original input string*:
```bash
python BlockListAdmin.py remove 203.0.113.0/24
```

⚠️ This permanently deletes the entry.

---

### Search an IP
Find all ranges (active and redundant) covering an IP:
```bash
python BlockListAdmin.py search 203.0.113.45
```

Output includes:
- Matching range
- Incident ID
- Comment
- Timestamp
- Redundancy status

---

### Export Firewall Block List
Exports **only active (non-redundant)** ranges:
```bash
python BlockListAdmin.py export
```

Output:
- `blocklist.txt`
- One IP/CIDR per line
- Sorted for firewall ingestion

---

### Generate Audit Report
Exports the full database to CSV:
```bash
python BlockListAdmin.py report
```

Output:
- `ip_audit_report.csv`
- Includes redundant entries for compliance and audits

---

## Database Design

### Table: `ip_ranges`
| Column | Description |
|------|------------|
| `id` | Auto-increment primary key |
| `original_input` | User-entered IP/CIDR |
| `version` | IP version (4 or 6) |
| `start_blob` | Binary start address |
| `end_blob` | Binary end address |
| `incident_id` | Incident reference |
| `comment` | Analyst notes |
| `created_at` | Timestamp |
| `is_redundant` | 0 = active, 1 = redundant |

Binary storage enables efficient IP range comparisons.

---

## IPv6 Handling
- Bare IPv6 addresses (no CIDR) are automatically treated as `/64`
- This aligns with common IPv6 operational practices

Example:
```
2001:db8::1  →  2001:db8::/64
```

---

## Developer Guide

### Code Structure
- `IPDatabase`
  - Handles all database operations
  - Encapsulates IP parsing and normalization
- CLI logic is contained under `if __name__ == "__main__"`

---

### Adding New Commands
1. Implement method in `IPDatabase`
2. Add CLI dispatch in the main block
3. Keep output human-readable (this is an operator tool)

---

### Modifying Redundancy Logic
Redundancy is determined by:
```sql
start_blob >= new_start AND end_blob <= new_end
```
and filtered by IP version.

⚠️ Any change here affects firewall correctness.

---

### Database Migration Notes
- SQLite schema is created automatically
- If schema changes are required:
  - Version the database file
  - Or implement a migration routine before `_create_table()`

---

### Safety & Operational Notes
- The database file is authoritative; back it up regularly
- Exported firewall lists should be treated as **generated artifacts**
- Always regenerate exports after add/remove operations

---

## Example Workflow
1. Analyst detects malicious IP
2. `fwadmin.py add <ip>`
3. Incident ID recorded
4. Firewall list exported
5. Firewall reloads block list
6. Audit report generated as needed

---

## License / Internal Use
This script is intended for internal security operations.
Review and adapt as needed for your environment.
