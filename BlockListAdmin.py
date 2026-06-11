import hashlib
import sqlite3
import ipaddress
import argparse
import csv
import getpass
import logging
import shutil
import sys
from pathlib import Path
from datetime import datetime, timedelta
from dotenv import dotenv_values

from colorama import init, Fore, Style
init(autoreset=True)

def err(msg):
    """Print an error message in red to stderr."""
    print(Fore.RED + msg, file=sys.stderr)

def warn(msg):
    """Print a warning message in yellow to stderr."""
    print(Fore.YELLOW + msg, file=sys.stderr)

def ok(msg):
    """Print a success message in green."""
    print(Fore.GREEN + msg)


class IPDatabase:
    def __init__(self, db_name="ip_manager.db"):
        self.config = dotenv_values("config.env")

        self.deny_mode = ( self.config.get("DENY_ONLY", "TRUE").upper().strip() == "TRUE" )

        # Ensure required directories exist
        Path("database").mkdir(exist_ok=True)
        Path("logs").mkdir(exist_ok=True)
        Path("rules").mkdir(exist_ok=True)
        Path("reports").mkdir(exist_ok=True)
        Path("backups").mkdir(exist_ok=True)

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
        self.whitelist = self._load_whitelist()

    def close(self):
        self.conn.close()

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
                              is_redundant INTEGER DEFAULT 0,
                              policy TEXT DEFAULT 'BLOCK',
                              created_by TEXT,
                              created_at TIMESTAMP,
                              expires_at TIMESTAMP
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
                              expires_at TIMESTAMP,
                              timestamp TIMESTAMP
                          );
                          """)
        self.conn.commit()

    def _log_event(self, event_type, target_cidr, incident_id="N/A", comment="", expires_at=None):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        user = getpass.getuser()

        # Create the named mapping
        log_data = {
            "event_type": event_type,
            "target": target_cidr,
            "user": user,
            "inc": incident_id,
            "msg": comment,
            "expires_at": expires_at,
            "ts": timestamp
        }

        try:
            with self.conn:
                self.conn.execute("""
                                  INSERT INTO audit_history (event_type, target_cidr, user, incident_id, comment, expires_at, timestamp)
                                  VALUES (:event_type, :target, :user, :inc, :msg, :expires_at, :ts)
                                  """, log_data)

            self.logger.info(
                f"ACTION: {event_type} | TARGET: {target_cidr} | ID: {incident_id} | EXPIRES: {expires_at} | COMMENT: {comment}",
                extra={'user': user}
            )
        except Exception as e:
            err(f"[-] AUDIT LOGGING ERROR: {e}")

    def _get_parent_range(self, version, start, end, policy):
        """Returns the CIDR of an active range that covers the provided range."""
        row = self._get_covering_rule(version, start, end, policy)
        return row['cidr'] if row else None

    def _get_covering_rule(self, version, start, end, policy):
        """Returns the full row of an active range that covers the provided range, or None."""
        params = {
            "v": version,
            "s": start,
            "e": end,
            "p": policy,
            "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        query = """
                SELECT *
                FROM ip_ranges
                WHERE version = :v
                  AND start_blob <= :s
                  AND end_blob >= :e
                  AND policy = :p
                  AND is_redundant = 0
                  AND (expires_at > :now OR expires_at IS NULL)
                """
        return self.conn.execute(query, params).fetchone()

    def _load_whitelist(self, path="whitelist.txt"):
        """
        Loads whitelist.txt and returns a list of ip_network objects.
        - Lines starting with # are full-line comments and are skipped.
        - Inline comments: everything from # onward is stripped before parsing.
        - Blank lines are skipped.
        - Supports plain IPs, CIDR notation, and dash ranges (e.g. 1.1.1.1-1.1.1.26).
          Dash ranges are expanded into the minimal set of covering CIDRs.
        - Invalid entries are warned about and skipped.
        """
        whitelist = []
        wl_path = Path(path)

        if not wl_path.exists():
            return whitelist

        with open(wl_path) as f:
            for lineno, raw in enumerate(f, start=1):
                # Strip inline comment and surrounding whitespace
                line = raw.split("#")[0].strip()
                if not line:
                    continue
                try:
                    if '-' in line:
                        # Dash range: split into start and end, expand to CIDRs
                        start_str, end_str = [p.strip() for p in line.split('-', 1)]
                        start_ip = ipaddress.ip_address(start_str)
                        end_ip   = ipaddress.ip_address(end_str)
                        if end_ip < start_ip:
                            raise ValueError(f"end address {end_ip} is less than start {start_ip}")
                        whitelist.extend(ipaddress.summarize_address_range(start_ip, end_ip))
                    else:
                        whitelist.append(ipaddress.ip_network(line, strict=False))
                except ValueError as e:
                    warn(f"[!] WHITELIST WARNING: Invalid entry on line {lineno}: '{line}' — {e} — skipped.")

        return whitelist

    def _check_whitelist(self, net_obj):
        """
        Returns the whitelisted network (as a string) that overlaps net_obj,
        or None if no overlap is found.
        """
        for protected in self.whitelist:
            if net_obj.overlaps(protected):
                return str(protected)
        return None

    @staticmethod
    def _confirm_large_range(start_ip, end_ip, cidrs):
        """
        Warns and prompts for confirmation if a dash range crosses a /24
        boundary. Returns True if the operator confirms, False to abort.
        """
        start_octets = str(start_ip).split('.')
        end_octets   = str(end_ip).split('.')

        if start_octets[:3] == end_octets[:3]:
            return True

        total_ips = sum(net.num_addresses for net in cidrs)
        warn(f"\n[!] WARNING: This range crosses a /24 boundary.")
        warn(f"    Start : {start_ip}")
        warn(f"    End   : {end_ip}")
        warn(f"    Expands to {len(cidrs)} CIDRs ({total_ips:,} IPs):")
        for net in cidrs:
            warn(f"      {net}  ({net.num_addresses:,} IPs)")
        confirm = input("\nAre you sure you want to continue? (yes/no): ").strip().lower()
        return confirm == 'yes'

    @staticmethod
    def expand_range(ip_input):
        """
        Accepts a plain IP, CIDR, or dash range (e.g. 192.168.1.15-192.168.1.20).
        Returns (list of ip_network objects, start_ip or None, end_ip or None).
        Ranges are expanded into the minimal set of covering CIDRs, since
        Microsoft Named Locations and most firewall APIs only accept IPs/CIDRs.
        Raises ValueError on invalid input.
        """
        if '-' in ip_input:
            start_str, end_str = [p.strip() for p in ip_input.split('-', 1)]
            start_ip = ipaddress.ip_address(start_str)
            end_ip   = ipaddress.ip_address(end_str)
            if end_ip < start_ip:
                raise ValueError(f"End address {end_ip} is less than start address {start_ip}")
            return list(ipaddress.summarize_address_range(start_ip, end_ip)), start_ip, end_ip
        else:
            return [ipaddress.ip_network(ip_input, strict=False)], None, None

    def is_input_ip_address(self, ip_input):
        try:
            self.expand_range(ip_input)
            return True
        except ValueError:
            return False

    def is_ip_address_routable(self, ip_input):
        try:
            nets, _, _ = self.expand_range(ip_input)
            return all(net.is_global for net in nets)
        except ValueError:
            return False

    def parse_inputs(self):
        inc_id = input("\nEnter Incident/Ticket ID: ").strip()
        comment = input("Enter Operator Comment: ").strip()
        expires_at = self.expiration_date_prompt()
        return inc_id, comment, expires_at

    def parse_removal_inputs(self):
        inc_id = input("\nEnter Incident/Ticket ID: ").strip()
        comment = input("Enter Operator Comment: ").strip()
        return inc_id, comment

    def prompt_extend_expiration(self, row, policy='BLOCK'):
        """
        Displays the existing rule details and prompts the operator to optionally
        extend the expiration.
          Enter  — keep current expiration unchanged
          0      — make indefinite (NULL)
          N > 0  — add N days to the current expiration
        Returns the new expires_at string, or the original value if unchanged.
        If the rule is already indefinite, prints a notice and returns None immediately.
        """
        warn(f"\nMatching rule already exists.")

        print(f"  {row['cidr']}  |  {policy}  |  Added: {row['created_at']}  |  Expires: {row['expires_at'] or 'never'}  |  Incident: {row['incident_id']}")

        if row['expires_at'] is None:
            print("Rule is already indefinite. No expiration to extend.")
            return None

        user_input = input(
            "\nExtend expiration? "
            "([Enter] keep current / 0 = indefinite / N = add N days): "
        ).strip()

        if user_input == "":
            return row['expires_at']  # unchanged

        try:
            days = int(user_input)
        except ValueError:
            err("Invalid input — expiration unchanged.")
            return row['expires_at']

        if days == 0:
            return None  # indefinite

        if days < 0:
            err("Must be a positive integer — expiration unchanged.")
            return row['expires_at']

        # Base the extension on the current expiry, or from now if indefinite
        if row['expires_at']:
            base = datetime.strptime(row['expires_at'], "%Y-%m-%d %H:%M:%S")
        else:
            base = datetime.now()

        new_expiry = (base + timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
        ok(f"Expiration updated to {new_expiry}.")
        return new_expiry

    def expiration_date_prompt(self):
        now = datetime.now()
        default_expiry_days = int(self.config.get("DEFAULT_EXPIRY", 30))

        while True:
            user_input = input(
                f"Enter expiration days (1+, 0=indefinite) "
                f"[{default_expiry_days}]: "
            ).strip()

            if user_input == "":
                expiry_days = default_expiry_days
            else:
                try:
                    expiry_days = int(user_input)
                except ValueError:
                    err("Invalid input: must be an integer. Please try again.")
                    continue

            if expiry_days == 0:
                return None
            elif expiry_days >= 1:
                return (now + timedelta(days=expiry_days)).strftime("%Y-%m-%d %H:%M:%S")
            else:
                err("Must be 0 (indefinite) or a positive integer. Please try again.")
                continue

    def normalize_cidr(self, ip_input, notify=False):
        """
        Handles IPv4/IPv6 parsing.
        Converts plain IPs: IPv4 -> /32, IPv6 -> /64.
        Pass notify=True to print an informational message when a plain IPv6
        address is auto-expanded to /64 (appropriate for add operations only).
        """
        # Logic for IPv6 expansion vs IPv4 host conversion
        if ":" in ip_input:  # IPv6
            if "/" not in ip_input:
                net = ipaddress.ip_network(f"{ip_input}/64", strict=False)
                if notify:
                    print(f"Note: plain IPv6 address expanded to /64 ({net}). To target a single host, use /128.")
            else:
                net = ipaddress.ip_network(ip_input, strict=False)
        else:  # IPv4
            if "/" not in ip_input:
                net = ipaddress.ip_network(f"{ip_input}/32", strict=False)
            else:
                net = ipaddress.ip_network(ip_input, strict=False)

        cidr_val = str(net)
        return net, net.version, net.network_address.packed, net.broadcast_address.packed, cidr_val

    def add_entry(self, ip_input, inc_id='N/A', comment='', expires_at=None, policy='BLOCK'):
        try:
            net_obj, version, start, end, cidr_val = self.normalize_cidr(ip_input, notify=True)
            current_user = getpass.getuser()
            created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

            # Safety Gate: Stop execution if ALLOW is attempted in DENY_MODE
            if self.deny_mode and policy.upper() == "ALLOW":
                err("[!] ACCESS DENIED: The system is in DENY_ONLY_MODE. 'allow' commands are disabled.")
                sys.exit(1)

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
                "created_by": current_user,
                "created_at": created_at,
                "expires_at": expires_at
            }

            # CONFLICT CHECK (Checking against the OPPOSITE policy)
            conflict = self._get_parent_range(version, start, end, other_policy)

            if conflict:
                # Safer access using the column name 'cidr'
                warn(f"\nEXCEPTION DETECTED: {ip_input} overlaps an existing {other_policy} rule ({conflict})")
                if input(f"Confirm adding this {policy} exception? (y/n): ").lower() != 'y':
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
                                  (original_input, cidr, version, start_blob, end_blob, incident_id, policy, created_by, created_at, expires_at)
                                  VALUES (:orig, :cidr, :version, :start_blob, :end_blob, :inc, :policy, :created_by, :created_at, :expires_at)
                                  """, params)

            ok(f"SUCCESS: {policy} rule for {cidr_val} committed.")
            self._log_event(f"ADDED_{policy}", cidr_val, inc_id, comment, expires_at)

        except Exception as e:
            err(f"[-] ERROR: {e}")

    def remove_entry(self, ip_input):
        try:
            # Normalize input to find the correct record
            net_obj, version, start, end, cidr_val = self.normalize_cidr(ip_input)

            # Locate the target record(s) by exact CIDR — may be multiple (different policies)
            lookup_params = {
                'version': version,
                'start_blob': start,
                'end_blob': end
            }
            targets = self.conn.execute("""
                                        SELECT id, cidr, policy
                                        FROM ip_ranges
                                        WHERE version = :version
                                          AND start_blob = :start_blob
                                          AND end_blob = :end_blob
                                          AND is_redundant = 0
                                        """, lookup_params).fetchall()

            if not targets:
                err(f"\n[-] NOT FOUND: No active record matching '{cidr_val}' exists.")
                # Check if it's covered by a broader rule and hint the operator
                for policy_check in ('BLOCK', 'ALLOW'):
                    parent = self._get_parent_range(version, start, end, policy_check)
                    if parent:
                        warn(f"[i] NOTE: This address is covered by an active {policy_check} rule for {parent}.")
                return

            # If multiple policies match, show them and ask which to remove
            if len(targets) > 1:
                print(f"\nMultiple active records found for '{cidr_val}':")
                for i, t in enumerate(targets):
                    print(f"  [{i}] id={t['id']}  policy={t['policy']}")
                choice = input("Enter index to remove: ").strip()
                try:
                    target_row = targets[int(choice)]
                except (ValueError, IndexError):
                    err("[-] Invalid selection. Aborting.")
                    return
            else:
                target_row = targets[0]

            print(f"\nAbout to remove: {target_row['policy']} rule for '{cidr_val}' (id={target_row['id']})")
            if input("Confirm removal? (y/n): ").lower() != 'y':
                print("Removal aborted.")
                return

            # Get Incident and Comment for the audit trail
            inc_id, comment = self.parse_removal_inputs()

            target_policy = target_row['policy']
            target_id = target_row['id']

            # Identify children that would be "un-swallowed" — same policy only
            child_params = {
                'version': version,
                'start_blob': start,
                'end_blob': end,
                'policy': target_policy
            }
            to_restore = self.conn.execute("""
                                           SELECT original_input, incident_id, created_by
                                           FROM ip_ranges
                                           WHERE version = :version
                                             AND start_blob >= :start_blob
                                             AND end_blob <= :end_blob
                                             AND policy = :policy
                                             AND is_redundant = 1
                                             AND (expires_at > :now OR expires_at IS NULL)
                                           """, {**child_params, 'now': datetime.now().strftime("%Y-%m-%d %H:%M:%S")}).fetchall()

            with self.conn:
                restore_params = {
                    'incident_id': inc_id,
                    'version': version,
                    'start_blob': start,
                    'end_blob': end,
                    'policy': target_policy
                }

                # Update restored children to the NEW Incident ID authorizing their reactivation
                self.conn.execute("""
                                  UPDATE ip_ranges
                                  SET is_redundant = 0,
                                      incident_id  = :incident_id
                                  WHERE version = :version
                                    AND start_blob >= :start_blob
                                    AND end_blob <= :end_blob
                                    AND policy = :policy
                                    AND is_redundant = 1
                                    AND (expires_at > :now OR expires_at IS NULL)
                                  """, {**restore_params, 'now': datetime.now().strftime("%Y-%m-%d %H:%M:%S")})

                # Remove the specific record by primary key
                c = self.conn.execute("DELETE FROM ip_ranges WHERE id = :id", {'id': target_id})

                if c.rowcount > 0:
                    self._log_event("REMOVED", cidr_val, inc_id, comment)
                    ok(f"\nSUCCESS: '{cidr_val}' ({target_policy}) removed.")
                    if to_restore:
                        print(f"Reciprocity: {len(to_restore)} child ranges reactivated under INC {inc_id}.")
                else:
                    err(f"\n[-] NOT FOUND: No record matching '{cidr_val}' exists.")
        except Exception as e:
            err(f"[-] ERROR during removal: {e}")

    def purge_redundant(self, days=None):
        # Permanently deletes redundant (swallowed) records from the database.
        try:
            query = "DELETE FROM ip_ranges WHERE is_redundant = 1"
            params = {}

            if days:
                cutoff = (datetime.now() - timedelta(days=days)).strftime("%Y-%m-%d %H:%M:%S")
                query += " AND created_at < :cutoff"
                params['cutoff'] = cutoff

            # Confirm with count first
            if days:
                count_query = "SELECT COUNT(*) as total FROM ip_ranges WHERE is_redundant = 1 AND created_at < :cutoff"
            else:
                count_query = "SELECT COUNT(*) as total FROM ip_ranges WHERE is_redundant = 1"
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
                ok(f"SUCCESS: Permanently purged {total_to_purge} records from database.")
            else:
                print("Purge aborted.")
        except Exception as e:
            err(f"[-] ERROR during purge: {e}")

    def search_ip(self, search_ip):
        try:
            ip_obj = ipaddress.ip_address(search_ip)

            params = {
                "ver": ip_obj.version,
                "packed": ip_obj.packed,
                "now": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

            # Search using named placeholder :val
            query = """
                    SELECT *
                    FROM ip_ranges
                    WHERE version = :ver
                      AND :packed BETWEEN start_blob AND end_blob
                      AND is_redundant = 0
                      AND (expires_at > :now OR expires_at IS NULL)
                    ORDER BY created_at DESC
                    """
            results = self.conn.execute(query, params).fetchall()

            if results:
                print(f"\n--- Full Audit Report for {search_ip} ---")
                for r in results:
                    print(f" POLICY:   {r['policy']}")
                    print(f" RANGE:    {r['cidr']}")
                    print(f" AUTHOR:   {r['created_by']}")
                    print(f" CREATED:  {r['created_at']}")
                    print(f" EXPIRES:  {r['expires_at'] or 'never'}")
                    print(f" INCIDENT: {r['incident_id']}\n")
            else:
                warn(f"\n[-] NO MATCH: The address {search_ip} is not covered by any policy.")
        except Exception as e:
            err(f"[-] SEARCH ERROR: {e}")

    def export_lists(self):
        output_paths = {
            'BLOCK': self.config.get("FILE_OUTPUT_DENY") or str(Path("rules") / "block.txt"),
            'ALLOW': self.config.get("FILE_OUTPUT_ALLOW") or str(Path("rules") / "allow.txt"),
        }

        for p in ['BLOCK', 'ALLOW']:
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            params = {'policy': p, 'now': now}

            rows = self.conn.execute("""
                                     SELECT cidr
                                     FROM ip_ranges
                                     WHERE policy = :policy
                                       AND is_redundant = 0
                                       AND (expires_at > :now OR expires_at IS NULL)
                                     ORDER BY version ASC,
                                              start_blob ASC
                                     """, params).fetchall()

            out_path = Path(output_paths[p])
            out_path.parent.mkdir(parents=True, exist_ok=True)

            if out_path.exists():
                timestamp = datetime.now().strftime("%Y-%d-%m_%H_%M_%S")
                backup_name = f"{out_path.stem}-{timestamp}{out_path.suffix}"
                backup_path = Path("backups") / backup_name
                backup_ok = False

                try:
                    src_hash = self._sha256(out_path)
                    shutil.copy2(out_path, backup_path)
                    dst_hash = self._sha256(backup_path)
                    if src_hash == dst_hash:
                        backup_ok = True
                    else:
                        backup_path.unlink(missing_ok=True)
                except Exception:
                    backup_path.unlink(missing_ok=True)

                if backup_ok:
                    print(f"[+] BACKUP: {out_path.name} -> backups/{backup_name} (verified)")
                else:
                    err(f"[!] INTEGRITY ISSUE: couldn't back up existing {out_path.name}.")
                    if input("Overwrite without backup? (y/n): ").strip().lower() != 'y':
                        warn(f"Skipping export for {p}.")
                        continue

            with open(out_path, "w") as f:
                for r in rows:
                    f.write(f"{r['cidr']}\n")
            print(f"[+] EXPORTED: {len(rows)} rules to {out_path}")

    @staticmethod
    def _sha256(path):
        h = hashlib.sha256()
        with open(path, "rb") as fh:
            for chunk in iter(lambda: fh.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def list_active(self):
        params = {
            'now': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
        rows = self.conn.execute("""
                                 SELECT policy,
                                        cidr,
                                        created_at,
                                        expires_at,
                                        created_by,
                                        incident_id
                                 FROM ip_ranges
                                 WHERE is_redundant = 0
                                     AND (expires_at > :now OR expires_at IS NULL)
                                 ORDER BY created_at DESC
                                 """, params).fetchall()

        if not rows:
            print("\nNo active entries found.")
            return

        print(f"\n{'POLICY':<6} | {'CIDR':<38} | {'CREATED_AT':<19} | {'EXPIRES_AT':<19} | {'CREATED BY':<12} | {'INCIDENT'}")
        print("-" * 96)

        for r in rows:
            # Using f-string padding (<18 means 18 characters wide, left-aligned)
            print(f"{r['policy']:<6} | {r['cidr']:<38} | {r['created_at']:19} | {str(r['expires_at'] or 'never'):<19} | {r['created_by']:<12} | {r['incident_id']}")

        print("-" * 96 + "\n")


    def generate_report(self):
        """Generates a comprehensive CSV of the entire database state."""
        fname = f"ip_audit_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        rows = self.conn.execute("""
                                 SELECT original_input,
                                        policy,
                                        version,
                                        incident_id,
                                        created_by,
                                        created_at,
                                        expires_at,
                                        is_redundant
                                 FROM ip_ranges
                                 ORDER BY created_at DESC
                                 """).fetchall()

        with open(Path("reports") / fname, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(
                ["IP/CIDR", "Policy", "Version", "Incident ID", "Author", "Created", "Expires", "Is Redundant"])
            writer.writerows(rows)
        print(f"[+] CSV GENERATED: {fname} (Full Database Audit Export)")


def main():
    # Custom Help Text Block
    custom_help = """
Firewall Admin Tool (FWAdmin)
=========================================
Usage: python BlockListAdmin.py COMMAND [TARGET] [OPTIONS]

TARGET may be a plain IP address, a CIDR range, or a dash range (e.g. 1.2.3.4,
1.2.3.0/24, or 1.2.3.10-1.2.3.20). Plain IPv4 addresses are treated as /32;
plain IPv6 addresses are treated as /64. Only globally routable addresses are
accepted. Dash ranges are automatically expanded to the minimal set of CIDRs
required to cover them, since firewall APIs and Microsoft Named Locations only
accept IPs and CIDRs.

--- Rule Commands ---

  block  <target>     Add a BLOCK rule for the given IP or CIDR range.
                      If the target overlaps a larger existing BLOCK rule it is
                      already covered and will not be added. If it overlaps an
                      ALLOW rule you will be prompted to confirm the exception.
                      Prompts for: Incident/Ticket ID, comment, expiration.
                      Blocked by whitelist.txt if the target overlaps a
                      protected network (see Whitelist section below).

  deny   <target>     Alias for block. Identical behavior.

  allow  <target>     Add an ALLOW rule for the given IP or CIDR range.
                      Behavior mirrors block but for the ALLOW policy.
                      May be disabled via DENY_ONLY=TRUE in config.env to
                      maintain compatibility with Entra Conditional Access
                      Policy block lists.
                      Prompts for: Incident/Ticket ID, comment, expiration.

  remove <target>     Remove an active BLOCK or ALLOW rule for the given IP
                      or CIDR. If the removed range was covering smaller
                      (redundant) ranges of the same policy, those child
                      ranges are automatically reactivated.
                      Prompts for: Incident/Ticket ID, comment.

  search <target>     Look up whether an IP address is covered by any active
                      rule in the database. Displays policy, range, author,
                      creation date, expiration, and incident ID for every
                      matching entry. Does not require a routable address.

--- Maintenance Commands ---

  export              Export all active, non-redundant rules to flat text
                      files. Output paths are configured via FILE_OUTPUT_DENY
                      and FILE_OUTPUT_ALLOW in config.env. If not set, defaults
                      to:
                        rules/block.txt
                        rules/allow.txt
                      Suitable for ingestion by external firewall tooling.

  list                Print all active, non-redundant rules to the screen in
                      a formatted table showing policy, CIDR, dates, author,
                      and incident ID.

  report              Generate a full CSV audit export of every rule in the
                      database (including redundant/expired entries) to:
                        reports/ip_audit_report_YYYYMMDD_HHMMSS.csv

  purge               Permanently delete redundant (swallowed) records from
                      the database. Redundant records are created automatically
                      when a broader range supersedes a narrower one.
                        --days N    Only purge records older than N days.
                                    Omit to purge all redundant records.

--- Whitelist ---

  If whitelist.txt exists in the working directory, any block/deny command
  targeting a network that overlaps a whitelisted entry will be rejected
  immediately — no prompts, no database write.

  File format:
    - One IP or CIDR per line
    - Lines beginning with # are comments and are ignored
    - Inline comments are supported: everything from # onward is stripped
    - Blank lines are ignored
    - Invalid entries produce a warning and are skipped

  Example whitelist.txt:
    # Core infrastructure — never block
    203.0.113.0/24      # NOC uplink
    198.51.100.10       # monitoring host
    2001:db8::/32       # IPv6 management range

--- Configuration (config.env) ---

  DENY_ONLY      TRUE/FALSE  Disables the allow command when TRUE (default TRUE)
  DEFAULT_EXPIRY days        Default expiration if operator presses Enter (default 30)

--- Examples ---

  python BlockListAdmin.py block 1.2.3.4
  python BlockListAdmin.py block 10.10.0.0/16
  python BlockListAdmin.py block 10.10.0.15-10.10.0.20
  python BlockListAdmin.py allow 203.0.113.50
  python BlockListAdmin.py remove 1.2.3.4
  python BlockListAdmin.py search 1.2.3.4
  python BlockListAdmin.py purge --days 90
  python BlockListAdmin.py export
  python BlockListAdmin.py list
  python BlockListAdmin.py report
    """

    # 2. Add add_help=False to stop argparse from auto-generating help
    parser = argparse.ArgumentParser(add_help=False)

    # Manually handle -h/--help to print your block
    parser.add_argument("-h", "--help", action="store_true")

    subparsers = parser.add_subparsers(dest="command")

    # Setup the commands (keeping argument logic intact)
    for cmd in ["block", "deny", "allow", "search", "remove"]:
        p = subparsers.add_parser(cmd)
        p.add_argument("target")

    subparsers.add_parser("export")
    subparsers.add_parser("report")
    subparsers.add_parser("list")

    purge = subparsers.add_parser("purge")
    purge.add_argument("--days", type=int)

    args = parser.parse_args()

    # Check for help flag OR no command
    if args.help or not args.command:
        print(custom_help)
        sys.exit(0)

    db = IPDatabase()

    try:
        # Validation
        if args.command in ["block", "deny", "allow", "search", "remove"]:
            if db.is_input_ip_address(args.target) is False:
                err("[-] Invalid IP or CIDR")
                sys.exit(1)
            if args.command != "search" and db.is_ip_address_routable(args.target) is False:
                err("[-] Non-routable IP")
                sys.exit(1)

        # Command Routing
        if args.command in ["block", "deny"]:
            targets, start_ip, end_ip = db.expand_range(args.target)
            if start_ip and not db._confirm_large_range(start_ip, end_ip, targets):
                err("Aborted.")
                sys.exit(1)
            if len(targets) > 1:
                print(f"Range expanded to {len(targets)} CIDRs.")
            # Pre-flight: resolve whitelist and DB coverage before prompting for input
            actionable = []
            for net_obj in targets:
                cidr_val = str(net_obj)
                protected = db._check_whitelist(net_obj)
                if protected:
                    err(f"[!] BLOCKED BY WHITELIST: {cidr_val} overlaps protected network {protected} in whitelist.txt. Skipping.")
                    continue
                _, version, start, end, _ = db.normalize_cidr(cidr_val)
                existing_row = db._get_covering_rule(version, start, end, 'BLOCK')
                if existing_row:
                    new_expiry = db.prompt_extend_expiration(existing_row, policy='BLOCK')
                    if new_expiry != existing_row['expires_at']:
                        with db.conn:
                            db.conn.execute(
                                "UPDATE ip_ranges SET expires_at = :exp WHERE id = :id",
                                {'exp': new_expiry, 'id': existing_row['id']}
                            )
                        db._log_event("EXTENDED", existing_row['cidr'], comment=f"Expiry updated to {new_expiry or 'indefinite'}")
                    continue
                actionable.append(net_obj)
            if not actionable:
                warn("Nothing to add.")
                sys.exit(0)
            inc, msg, expires_at = db.parse_inputs()
            for net_obj in actionable:
                db.add_entry(str(net_obj), policy='BLOCK', inc_id=inc, expires_at=expires_at, comment=msg)
        elif args.command == "allow":
            targets, start_ip, end_ip = db.expand_range(args.target)
            if start_ip and not db._confirm_large_range(start_ip, end_ip, targets):
                err("Aborted.")
                sys.exit(1)
            if len(targets) > 1:
                print(f"Range expanded to {len(targets)} CIDRs.")
            # Pre-flight: check DB coverage before prompting for input
            actionable = []
            for net_obj in targets:
                cidr_val = str(net_obj)
                _, version, start, end, _ = db.normalize_cidr(cidr_val)
                existing_row = db._get_covering_rule(version, start, end, 'ALLOW')
                if existing_row:
                    new_expiry = db.prompt_extend_expiration(existing_row, policy='ALLOW')
                    if new_expiry != existing_row['expires_at']:
                        with db.conn:
                            db.conn.execute(
                                "UPDATE ip_ranges SET expires_at = :exp WHERE id = :id",
                                {'exp': new_expiry, 'id': existing_row['id']}
                            )
                        db._log_event("EXTENDED", existing_row['cidr'], comment=f"Expiry updated to {new_expiry or 'indefinite'}")
                    continue
                actionable.append(net_obj)
            if not actionable:
                warn("Nothing to add.")
                sys.exit(0)
            inc, msg, expires_at = db.parse_inputs()
            for net_obj in actionable:
                db.add_entry(str(net_obj), policy='ALLOW', inc_id=inc, expires_at=expires_at, comment=msg)
        elif args.command == "remove":
            db.remove_entry(args.target)
        elif args.command == "purge":
            db.purge_redundant(days=args.days)
        elif args.command == "search":
            db.search_ip(args.target)
        elif args.command == "export":
            db.export_lists()
        elif args.command == "report":
            db.generate_report()
        elif args.command == "list":
            db.list_active()
        else:
            print(custom_help)
    finally:
        db.close()


if __name__ == "__main__":
    main()