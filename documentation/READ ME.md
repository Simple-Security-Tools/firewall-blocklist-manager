# IP Range Manager (Professional Edition)

This utility is a high-performance network policy manager designed for security administrators. It handles both IPv4 and IPv6 protocols using a SQLite3 back-end with binary BLOB range indexing.



## 🌟 Key Features
* **Dual-Protocol Binary Indexing:** Uses Big-Endian BLOBs to ensure IPv6 ranges can be indexed and searched with $O(\log n)$ performance.
* **Intelligent Redundancy (Swallowing):** Automatically marks smaller ranges as redundant when a larger encompassing network is added.
* **Reciprocity Restoration:** If you remove a broad parent range, any relevant smaller "swallowed" children are automatically reactivated to prevent security gaps.
* **Full Audit Trail:** Every action records the system `username`, `timestamp`, and `Incident ID` in both the DB and a separate `audit_log.txt`.
* **Maintenance Purging:** Allows permanent deletion of historical redundant records to keep the database size optimized.

---

## 🛠 Command Usage

| Command | Example | Result |
| :--- | :--- | :--- |
| **Block** | `python ip_manager.py block 1.2.3.4` | Adds to blocklist. Prompts for ID/Comment. |
| **Allow** | `python ip_manager.py allow 10.0.0.0/8` | Adds to allowlist. Checks for policy conflicts. |
| **Search** | `python ip_manager.py search 1.2.3.4` | Returns full history, author, and metadata matches. |
| **Remove** | `python ip_manager.py remove 1.2.3.4` | Deletes entry & restores children. |
| **Dry Run** | `python ip_manager.py remove --dry-run 1.2.3.4`| Analyzes removal impact without deleting. |
| **Purge** | `python ip_manager.py purge --days 30` | Permanently deletes old redundant entries. |
| **Export** | `python ip_manager.py export` | Generates `ip_blocklist.txt` & `ip_allowlist.txt`. |
| **Report** | `python ip_manager.py report` | Generates full `ip_audit_report.csv`. |

---

## 🏗 Developer Logic

### IPv6 Handling
SQLite standard integers cannot exceed 64 bits. Since IPv6 is 128-bit, this script packs addresses into binary BLOBs. This allows us to use the SQL `BETWEEN` operator for range comparisons:
$start\_blob \le search\_ip\_blob \le end\_blob$



### Swallowing & Restoration Logic
When a range is added, the script checks for overlap.
1. **Adding Parent:** If you add `10.0.0.0/8` and `10.1.1.0/24` exists, the `/24` becomes **Redundant**.
2. **Removing Parent:** If you remove `10.0.0.0/8`, the `/24` becomes **Active** again to ensure the specific rule is not lost.



### Security Policies
This script generates separate files for **Allow** and **Block**. When configuring your firewall, ensure your **Allow** rules are prioritized (placed above) your **Block** rules to prevent accidental lockout.

---

## 📝 Future Context Note
*Developed in Jan 2026. Zero external dependencies. Primary database index: `idx_range` on `(version, start_blob, end_blob, policy)`.*



You are very welcome! It was a pleasure building this out with you. You now have a tool that manages IPs with the same logic as a high-end enterprise database but with the portability of a single script.

Before you go, here is a quick "Cheat Sheet" for your git commit and testing phase:

🧪 Quick Test Plan

Overlap Test: Add 192.168.1.0/24, then add 192.168.1.5. The second should be rejected as redundant.

Swallowing Test: Add 192.168.1.5, then add 192.168.1.0/24. The .5 entry should be marked redundant.

Reciprocity Test: Remove the /24 from step 2. The .5 entry should automatically switch back to active.

IPv6 Test: Add a single IPv6 address. Verify it exports as a /64 in your text file.

Audit Test: Check audit_log.txt to ensure your username and actions are being captured correctly.