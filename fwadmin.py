import sqlite3
import ipaddress
import argparse
import csv
import getpass
import logging
import sys
from pathlib import Path
from datetime import datetime, timedelta


class IPDatabase:
    def __init__(self, db_name="ip_manager.db"):
        # Ensure required directories exist
        Path("database").mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
        Path("rules").mkdir(exist_ok=True)
        Path("reports").mkdir(exist_ok=True)

        # Setup Python Logging Module
        log_file = Path("logs") / "audit.log"
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s [%(levelname)s] USER: %(user)s | %(message)s',
            handlers=[logging.FileHandler(log_file)]
        )
        self.logger = logging.getLogger("FWAdmin")

        # Initialize Database
        db_path = Path("database") / db_name
        self.conn = sqlite3.connect(db_path)
        self.conn.row_factory = sqlite3.Row
        self._create_table()

    def _create_table(self):
        # Initializes the database schema
        self.conn.execute("""
                          CREATE TABLE IF NOT EXISTS ip_ranges
                          (
                              id INTEGER PRIMARY KEY AUTOINCREMENT,
                              original_input TEXT,
                              cidr TEXT,
                              version INTEGER,
                              start_blob BLOB,
                              end_blob BLOB,
                              incident_id TEXT,
                              created_at TIMESTAMP,
                              is_redundant INTEGER DEFAULT 0,
                              policy TEXT DEFAULT 'BLOCK',
                              added_by TEXT
                          );
                          """)
        self.conn.execute("CREATE INDEX IF NOT EXISTS idx_range ON ip_ranges (version, start_blob, end_blob, policy);")
        self.conn.commit()

        self.conn.execute("""
                          CREATE TABLE IF NOT EXISTS audit_history
                          (
                              id
                              INTEGER PRIMARY KEY AUTOINCREMENT,
                              event_type TEXT, -- ADD, REMOVE, PURGE
                              target_cidr TEXT,
                              user TEXT,
                              incident_id TEXT,
                              comment TEXT,
                              timestamp TIMESTAMP
                          );
                          """)
        self.conn.commit()

    def _log_event(self, event_type, target_cidr, incident_id="N/A", comment=""):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user = getpass.getuser()

        # Create the named mapping
        log_data = {
            "event_type": event_type,
            "target": target_cidr,
            "user": user,
            "inc": incident_id,
            "msg": comment,
            "ts": timestamp
        }

        try:
            with self.conn:
                self.conn.execute("""
                                  INSERT INTO audit_history (event_type, target_cidr, user, incident_id, comment, timestamp)
                                  VALUES (:event_type, :target, :user, :inc, :msg, :ts)
                                  """, log_data)

            self.logger.info(
                f"ACTION: {event_type} | TARGET: {target_cidr} | ID: {incident_id} | COMMENT: {comment}",
                extra={'user': user}
            )
        except Exception as e:
            print(f"[-] AUDIT LOGGING ERROR: {e}")

    def _get_parent_range(self, version, start, end, policy):
        """Returns the CIDR of an active range that covers the provided range."""
        params = {
            "v": version,
            "s": start,
            "e": end,
            "p": policy
        }

        query = """
                SELECT cidr \
                FROM ip_ranges
                WHERE version = :v \
                  AND start_blob <= :s \
                  AND end_blob >= :e
                  AND policy = :p \
                  AND is_redundant = 0
                """
        result = self.conn.execute(query, params).fetchone()
        return result['cidr'] if result else None

    def parse_inputs(self):
        inc_id = input("\nEnter Incident/Ticket ID: ").strip()
        comment = input("Enter Operator Comment: ").strip()

        return inc_id, comment

    def normalize_cidr(self, ip_input):
        """
        Handles IPv4/IPv6 parsing.
        Converts plain IPs: IPv4 -> /32, IPv6 -> /64.
        """
        # Logic for IPv6 expansion vs IPv4 host conversion
        if ":" in ip_input:  # IPv6
            if "/" not in ip_input:
                net = ipaddress.ip_network(f"{ip_input}/64", strict=False)
            else:
                net = ipaddress.ip_network(ip_input, strict=False)
        else:  # IPv4
            if "/" not in ip_input:
                net = ipaddress.ip_network(f"{ip_input}/32", strict=False)
            else:
                net = ipaddress.ip_network(ip_input, strict=False)

        cidr_val = str(net)
        return net, net.version, net.network_address.packed, net.broadcast_address.packed, cidr_val

    def add_entry(self, ip_input, inc_id='N/A', comment='', policy='BLOCK'):
        try:
            net_obj, version, start, end, cidr_val = self.normalize_cidr(ip_input)
            current_user = getpass.getuser()
            ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Determine opposite policy for conflict checks without overwriting 'policy'
            other_policy = 'ALLOW' if policy == 'BLOCK' else 'BLOCK'

            # Unified data dictionary for named placeholders
            params = {
                "version": version,
                "start_blob": start,
                "end_blob": end,
                "policy": policy,
                "other_policy": other_policy,
                "orig": ip_input,
                "cidr": cidr_val,
                "inc": inc_id,
                "ts": ts,
                "user": current_user
            }

            # CONFLICT CHECK (Checking against the OPPOSITE policy)
            conflict = self._get_parent_range(version, start, end, other_policy)

            if conflict:
                # Safer access using the column name 'cidr'
                print(f"\nEXCEPTION DETECTED: {ip_input} overlaps an existing {other_policy} rule ({conflict})")
                if input(f"Confirm adding this {policy} exception? (y/n): ").lower() != 'y':
                    return

            # REDUNDANCY CHECK (Checking against the SAME policy)
            existing = self._get_parent_range(version, start, end, policy)

            if existing:
                print(f"\n{ip_input} is already covered by active range: {existing}")
                return

            with self.conn:
                # Mark smaller ranges as redundant
                cursor = self.conn.execute("""
                                           UPDATE ip_ranges
                                           SET is_redundant = 1
                                           WHERE version = :version
                                             AND start_blob >= :start_blob
                                             AND end_blob <= :end_blob
                                             AND policy = :policy
                                           """, params)

                if cursor.rowcount > 0:
                    print(f"Optimization: {cursor.rowcount} existing ranges marked redundant.")

                # INSERT using named placeholders
                self.conn.execute("""
                                  INSERT INTO ip_ranges
                                  (original_input, cidr, version, start_blob, end_blob, incident_id, created_at, policy,
                                   added_by)
                                  VALUES (:orig, :cidr, :version, :start_blob, :end_blob, :inc, :ts, :policy, :user)
                                  """, params)

            print(f"SUCCESS: {policy} rule for {cidr_val} committed.")
            self._log_event(f"ADDED {policy}", cidr_val, inc_id, comment)

        except Exception as e:
            print(f"[-] ERROR: {e}")

    def remove_entry(self, ip_input, dry_run=False):
        try:
            # Normalize input to find the correct record
            net_obj, version, start, end, cidr_val = self.normalize_cidr(ip_input)

            # Get Incident and Comment for the audit trail
            inc_id, comment = self.parse_inputs()

            params = {
                'version': version,
                'start_blob': start,
                'end_blob': end
            }

            # Identify children that would be "un-swallowed"
            to_restore = self.conn.execute("""
                                           SELECT original_input, incident_id, added_by
                                           FROM ip_ranges
                                           WHERE version = :version
                                             AND start_blob >= :start_blob
                                             AND end_blob <= :end_blob
                                             AND is_redundant = 1
                                           """, params).fetchall()

            if dry_run:
                print(f"\n[DRY RUN] Removing: {cidr_val}")
                if to_restore:
                    print(f"This will ACTIVATE {len(to_restore)} children with new INC ID: {inc_id}")
                return

            with self.conn:
                params = {
                    'incident_id': inc_id,
                    'version': version,
                    'start_blob': start,
                    'end_blob': end
                }

                # Update restored children to the NEW Incident ID authorizing their reactivation
                self.conn.execute("""
                                  UPDATE ip_ranges
                                  SET is_redundant = 0,
                                      incident_id  = :incident_id
                                  WHERE version = :version
                                    AND start_blob >= :start_blob
                                    AND end_blob <= :end_blob
                                    AND is_redundant = 1
                                  """, params)

                # Remove the actual record
                params = {
                    'cidr': cidr_val,
                }
                c = self.conn.execute("DELETE FROM ip_ranges WHERE cidr = :cidr", params)

                if c.rowcount > 0:
                    # Log to database and text file
                    self._log_event("REMOVED", cidr_val, inc_id, comment)
                    print(f"\nSUCCESS: '{cidr_val}' removed.")
                    if to_restore:
                        print(f"Reciprocity: {len(to_restore)} child ranges reactivated under INC {inc_id}.")
                else:
                    print(f"\n[-] NOT FOUND: No record matching '{cidr_val}' exists.")
        except Exception as e:
            print(f"[-] ERROR during removal: {e}")

    def purge_redundant(self, days=None):
        # Permanently deletes redundant (swallowed) records from the database.
        try:
            query = "DELETE FROM ip_ranges WHERE is_redundant = 1"
            params = []

            if days:
                cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at < ?"
                params.append(cutoff)

            # Confirm with count first
            count_query = query.replace("DELETE", "SELECT COUNT(*) as total")
            total_to_purge = self.conn.execute(count_query, params).fetchone()['total']

            if total_to_purge == 0:
                print("\nNo redundant records found to purge.")
                return

            print(f"\n--- Database Purge ---")
            print(f"Found {total_to_purge} redundant records older than {days if days else 'all'} days.")
            confirm = input("This action is PERMANENT. Proceed? (y/n): ")

            if confirm.lower() == 'y':
                with self.conn:
                    self.conn.execute(query, params)
                self._log_event("PURGE", f"{total_to_purge} records")
                print(f"SUCCESS: Permanently purged {total_to_purge} records from database.")
            else:
                print("Purge aborted.")
        except Exception as e:
            print(f"[-] ERROR during purge: {e}")

    def search_ip(self, search_ip):
        try:
            ip_obj = ipaddress.ip_address(search_ip)

            # Search using named placeholder :val
            query = """
                    SELECT *
                    FROM ip_ranges
                    WHERE version = :ver
                      AND :packed BETWEEN start_blob AND end_blob
                    ORDER BY created_at DESC
                    """
            params = {"ver": ip_obj.version, "packed": ip_obj.packed}
            results = self.conn.execute(query, params).fetchall()

            if results:
                print(f"\n--- Full Audit Report for {search_ip} ---")
                for r in results:
                    # Accessing by column name via sqlite3.Row
                    status = "[REDUNDANT]" if r['is_redundant'] == 1 else "[ACTIVE]"
                    print(f" POLICY: {r['policy']} {status}")
                    print(f" RANGE:  {r['cidr']}")
                    print(f" AUTHOR: {r['added_by']} | DATE: {r['created_at']}")
                    print(f" ID:     {r['incident_id']}\n")
            else:
                print(f"\n[-] NO MATCH: The address {search_ip} is not covered by any policy.")
        except Exception as e:
            print(f"[-] SEARCH ERROR: {e}")

    def export_lists(self):
        for p in ['BLOCK', 'ALLOW']:
            fname = f"ip_{p.lower()}list.txt"

            params = {
                'policy': p
            }

            rows = self.conn.execute("""
                SELECT cidr 
                FROM ip_ranges
                WHERE policy = :policy
                  AND is_redundant = 0
                ORDER BY version ASC, 
                         start_blob ASC
            """, params).fetchall()

            with open(Path("rules") / fname, "w") as f:
                for r in rows:
                    f.write(f"{r['cidr']}\n")
            print(f"[+] EXPORTED: {len(rows)} rules to {fname}")

    def dump_to_screen(self):
        rows = self.conn.execute("""
                                 SELECT policy,
                                        cidr,
                                        created_at,
                                        added_by,
                                        incident_id
                                 FROM ip_ranges
                                 WHERE is_redundant = 0
                                 ORDER BY created_at DESC
                                 """).fetchall()

        if not rows:
            print("\nNo active entries found.")
            return

        print(f"\n{'POLICY':<6} | {'CIDR':<38} | {'CREATED_AT':<19} | {'ADDED BY':<12} | {'INCIDENT'}")
        print("-" * 96)

        for r in rows:
            # Using f-string padding (<18 means 18 characters wide, left-aligned)
            print(f"{r['policy']:<6} | {r['cidr']:<38} | {r['created_at']:19} | {r['added_by']:<12} | {r['incident_id']}")

        print("-" * 96 + "\n")


    def generate_report(self):
        """Generates a comprehensive CSV of the entire database state."""
        fname = "ip_audit_report.csv"
        rows = self.conn.execute("""
                                 SELECT original_input,
                                        policy,
                                        version,
                                        incident_id,
                                        added_by,
                                        created_at,
                                        is_redundant
                                 FROM ip_ranges
                                 ORDER BY created_at DESC
                                 """).fetchall()

        with open(Path("reports") / fname, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(
                ["IP/CIDR", "Policy", "Version", "Incident ID", "Author", "Timestamp", "Is Redundant"])
            writer.writerows(rows)
        print(f"[+] CSV GENERATED: {fname} (Full Database Audit Export)")


def main():
    parser = argparse.ArgumentParser(description="Simple Firewall Blocklist Manager")
    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Add/Search Commands
    for cmd in ["block", "deny", "allow", "search"]:
        p = subparsers.add_parser(cmd)
        p.add_argument("target", help="The IP or CIDR to process")

    # Remove Command
    rem = subparsers.add_parser("remove")
    rem.add_argument("target", help="Exact IP/CIDR to remove")
    rem.add_argument("--dry-run", action="store_true", help="Analyze child restoration without deleting")

    # Purge Command
    purge = subparsers.add_parser("purge")
    purge.add_argument("--days", type=int, help="Purge redundant records older than X days")

    # Utility Commands
    subparsers.add_parser("export", help="Export active rules to .txt files")
    subparsers.add_parser("report", help="Generate full CSV database audit")
    subparsers.add_parser("dump", help="Display all active entries on screen as CSV")

    args = parser.parse_args()

    #  Validation
    try:
        ipaddress.ip_address(args.target)
    except ValueError:
        print("Invalid IP or CIDR entered")
        exit(0)

    # Do not block private IPs
    if ipaddress.IPv4Address(args.target).is_global is False:
        print("private IP, won't take action")
        exit(0)
        
    db = IPDatabase()

    if args.command in [ "block", "deny" ]:
        incident_id, comment = db.parse_inputs()
        db.add_entry(
            args.target,
            policy='BLOCK',
            inc_id=incident_id,
            comment=comment
        )
    elif args.command == "allow":
        incident_id, comment = db.parse_inputs()
        db.add_entry(
            args.target,
            policy='ALLOW',
            inc_id=incident_id,
            comment=comment
        )
    elif args.command == "remove":
        db.remove_entry(args.target, dry_run=args.dry_run)
    elif args.command == "purge":
        db.purge_redundant(days=args.days)
    elif args.command == "search":
        db.search_ip(args.target)
    elif args.command == "export":
        db.export_lists()
    elif args.command == "report":
        db.generate_report()
    elif args.command == "dump":
        db.dump_to_screen()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()