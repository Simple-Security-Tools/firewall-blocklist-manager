# IP Range Manager (SQLite3 & ArgParse)

A high-performance security utility for managing network `ALLOW` and `BLOCK` lists. This tool specifically addresses the limitations of SQLite's 64-bit integer ceiling by utilizing binary BLOB indexing for 128-bit IPv6 address spaces.

## 🌟 Key Features
* **Dual-Policy Architecture:** Manage allowlists and blocklists within a single unified database.
* **IPv6 Intelligence:** Automatic expansion of single IPv6 addresses to standard `/64` subnets.
* **Redundancy Management:** Intelligent "swallowing" logic marks smaller ranges as redundant when a larger parent network is added, keeping firewall exports lean.
* **Conflict Detection:** Real-time checking to prevent accidental "friendly fire" (e.g., blocking an IP that is already in the allowlist).
* **Audit Ready:** Every entry captures Incident IDs, timestamps, and custom operator comments.

---

## 🚀 Usage Guide

The tool utilizes subcommands for all operations. You can access the built-in help at any time using `python ip_manager.py --help`.

### Core Commands
| Command | Usage Example | Purpose |
| :--- | :--- | :--- |
| **Block** | `python ip_manager.py block 1.2.3.4` | Adds a range to the blocklist. |
| **Allow** | `python ip_manager.py allow 192.168.1.0/24` | Adds a range to the allowlist. |
| **Search** | `python ip_manager.py search 1.2.3.4` | Queries the DB for all incidents covering this IP. |
| **Remove** | `python ip_manager.py remove 1.2.3.4` | Deletes a record by its original input string. |
| **Export** | `python ip_manager.py export` | Generates `.txt` files for firewall consumption. |
| **Report** | `python ip_manager.py report` | Generates a full `.csv` audit trail. |

---

## 🏗 Developer Documentation

### Binary Range Storage Strategy
Because SQLite lacks a native `INET` type, this tool mimics enterprise database behavior by converting IPs into **Network Byte Order (Big-Endian) Blobs**.



By storing the start and end of a CIDR range as 16-byte (IPv6) or 4-byte (IPv4) blobs, SQLite can utilize its standard B-Tree index to perform range comparisons using the `BETWEEN` operator. This ensures that lookups remain $O(\log n)$ even as the database grows to thousands of entries.

### Logical Overlap & Swallowing
When a new range is added, the script performs two checks:
1. **Containment:** If the new range is already inside an existing **Active** range of the same policy, the new entry is discarded to prevent bloat.
2. **Swallowing:** If the new range is a "Superset" of existing entries, the smaller existing entries are flagged with `is_redundant = 1`.


### Reciprocity (Un-swallowing) Logic

The system maintains data integrity during deletion. If a broad CIDR range (the parent) is removed, the system automatically identifies any narrower ranges (the children) that were previously "swallowed" (marked is_redundant = 1). These child ranges are restored to is_redundant = 0 so they appear in the next firewall export.

This ensures that your security posture is not inadvertently weakened by removing a large block while smaller, still-relevant blocks exist underneath it.

Redundant entries are excluded from firewall `.txt` exports but remain in the database for historical audit purposes.

### Database Schema


---

## 📝 Maintenance & Context Recovery
*If returning to this project after a break or transferring to a new environment:*

* **Environment:** Python 3.3+ required. No external dependencies.
* **Data Integrity:** Always filter by `version` (4 or 6) in SQL queries to avoid binary length mismatches.
* **Policy Precedence:** While this tool exports both lists, your firewall should always be configured to process the `ip_allowlist.txt` **before** the `ip_blocklist.txt`.
* **Database File:** The system state is entirely contained within `ip_manager.db`.