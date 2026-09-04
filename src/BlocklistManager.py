import hashlib
import json
import sqlite3
import ipaddress
import argparse
import csv
import getpass
import logging
import re
import shutil
import sys
from pathlib import Path
from datetime import datetime, timedelta
from modules.envfile import ConfigError, load_config
from microsoft_graph_helpers import get_bearer_token, get_named_location, update_named_location

from colorama import init, Fore, Back, Style
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
    #: Where the database lives when DATABASE_PATH is not set in config.txt.
    DEFAULT_DATABASE_PATH = "data/BlocklistManager.sqlite"

    #: Where the whitelist lives when WHITELIST_PATH is not set. It sits beside
    #: config.txt rather than in data/, because it is hand-edited operator input
    #: and not state the tool rewrites.
    DEFAULT_WHITELIST_PATH = "whitelist.txt"

    #: Commands that put rules into the database. These refuse to run without a
    #: whitelist file, so nothing is ever blocked before an admin has made the
    #: deliberate choice about what must never be blocked. An empty file counts:
    #: it says the decision was made, not skipped.
    RULE_WRITING_COMMANDS = ("block", "deny", "allow", "remove")

    def __init__(self, db_path=None, base_dir=None):
        # Everything this tool owns — database, logs, rules, reports, backups,
        # config and whitelist — lives at the project root, not in whatever
        # directory it happens to be invoked from. Otherwise running it from
        # elsewhere silently creates a second, empty database and finds no
        # whitelist, which is exactly what a launcher on PATH would do.
        #
        # The module sits in src/, so the root is one level UP from this file.
        # Using the file's own directory would bury data/, logs/ and config.txt
        # inside src/ — a working install that finds no config and no rules.
        self.base_dir = Path(base_dir) if base_dir else Path(__file__).resolve().parent.parent

        config_path = self.base_dir / "config.txt"
        if not config_path.exists():
            warn(f"[!] config.txt not found at {config_path} — using defaults.")
        try:
            self.config = load_config(config_path)
        except ConfigError as e:
            err(f"[!] Cannot parse config.txt: {e}")
            sys.exit(1)

        self.deny_mode = ( self.config.get("DENY_ONLY", "TRUE").upper().strip() == "TRUE" )

        # Ensure required directories exist
        for d in ("logs", "rules", "reports", "backups"):
            (self.base_dir / d).mkdir(exist_ok=True)

        # Setup Python Logging Module
        log_file = self.base_dir / "logs" / "audit.log"
        self.logger = logging.getLogger("BlocklistManager")
        self.logger.setLevel(logging.INFO)
        self.logger.propagate = False
        if not self.logger.handlers:
            handler = logging.FileHandler(log_file)
            handler.setFormatter(logging.Formatter('%(asctime)s [%(levelname)s] USER: %(user)s | %(message)s'))
            self.logger.addHandler(handler)

        # Initialize Database. DATABASE_PATH may be relative (anchored to the
        # project root) or absolute, so a deployment can put the database under
        # /var/lib or /opt without moving anything else. The parent directory is
        # created if missing, including intermediate levels.
        # Strip before falling back, so DATABASE_PATH set to blank or whitespace
        # uses the default rather than resolving to the project root itself.
        configured = str(db_path or self.config.get("DATABASE_PATH") or "").strip()
        self.db_path = self._resolve(configured or self.DEFAULT_DATABASE_PATH)
        try:
            self.db_path.parent.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            err(f"[!] Cannot create database directory {self.db_path.parent}: {e}")
            err(f"    Check DATABASE_PATH in config.txt, or the permissions on that path.")
            sys.exit(1)

        try:
            self.conn = sqlite3.connect(self.db_path)
        except sqlite3.OperationalError as e:
            err(f"[!] Cannot open database at {self.db_path}: {e}")
            err(f"    Check DATABASE_PATH in config.txt, or the permissions on that file.")
            sys.exit(1)
        self.conn.row_factory = sqlite3.Row
        self._create_table()
        # Set before loading so the attributes exist even if _load_whitelist is
        # stubbed out, which the test suite does.
        self.whitelist_path = None
        self.whitelist_exists = False
        self.whitelist = self._load_whitelist()

        # A rule is only redundant for as long as the broader rule that swallowed
        # it is still active. Re-check that on every run, before anything reads
        # or writes the rule set.
        self.reactivate_uncovered()

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
                              id INTEGER PRIMARY KEY AUTOINCREMENT,
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

    def reactivate_uncovered(self, verbose=True):
        """
        Restores rules that were marked redundant by a broader rule which has
        since expired.

        Without this, a temporary wide rule permanently suppresses the narrower
        rules it swallowed: when it expires those rules stay is_redundant = 1
        forever and silently drop out of every export, even if they were created
        with no expiration of their own. remove_entry() already reactivates
        children when a covering rule is deleted; this is the same guarantee for
        covering rules that lapse instead.

        Candidates are processed broadest-first so a rule that is itself
        reactivated continues to suppress its own children in the same pass.
        Returns the list of reactivated rows.
        """
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        candidates = self.conn.execute("""
                                       SELECT id, cidr, version, start_blob, end_blob, policy
                                       FROM ip_ranges
                                       WHERE is_redundant = 1
                                         AND (expires_at > :now OR expires_at IS NULL)
                                       """, {'now': now}).fetchall()

        if not candidates:
            return []

        def span(row):
            return (int.from_bytes(row['end_blob'], 'big')
                    - int.from_bytes(row['start_blob'], 'big'))

        revived = []
        with self.conn:
            for row in sorted(candidates, key=span, reverse=True):
                covering = self.conn.execute("""
                                             SELECT 1
                                             FROM ip_ranges
                                             WHERE version = :version
                                               AND start_blob <= :start_blob
                                               AND end_blob >= :end_blob
                                               AND policy = :policy
                                               AND is_redundant = 0
                                               AND id != :id
                                               AND (expires_at > :now OR expires_at IS NULL)
                                             LIMIT 1
                                             """, {
                                                 'version': row['version'],
                                                 'start_blob': row['start_blob'],
                                                 'end_blob': row['end_blob'],
                                                 'policy': row['policy'],
                                                 'id': row['id'],
                                                 'now': now,
                                             }).fetchone()

                if covering:
                    continue

                self.conn.execute("UPDATE ip_ranges SET is_redundant = 0 WHERE id = :id",
                                  {'id': row['id']})
                revived.append(row)

        for row in revived:
            self._log_event("REACTIVATED", row['cidr'],
                            comment="Covering rule expired; rule re-enforced")
            if verbose:
                warn(f"[i] REACTIVATED: {row['cidr']} ({row['policy']}) — its covering rule expired.")

        return revived

    def _load_whitelist(self, path=None):
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
        # WHITELIST_PATH works like DATABASE_PATH: relative to the project root,
        # or absolute so a deployment can keep it under /etc with its other
        # config. Defaults to whitelist.txt beside config.txt.
        configured = str(path or self.config.get("WHITELIST_PATH") or "").strip()
        wl_path = self._resolve(configured or self.DEFAULT_WHITELIST_PATH)

        # Commands that write rules refuse to run without this file. Record
        # whether it was there so they can check, rather than having them
        # re-stat the path themselves.
        self.whitelist_path = wl_path
        self.whitelist_exists = wl_path.exists()

        # No warning here on purpose. The whitelist only ever gates rule entry,
        # and those commands now refuse outright with a message that says what
        # to do about it. Warning again on list or report would be noise on
        # commands the whitelist does not affect, and a yellow line people learn
        # to scroll past is one they will also scroll past when it matters.
        if not self.whitelist_exists:
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
        try:
            default_expiry_days = int(self.config.get("DEFAULT_EXPIRY", 30))
        except ValueError:
            warn("[!] config.txt: DEFAULT_EXPIRY is not a valid integer — falling back to 30 days.")
            default_expiry_days = 30

        max_expiry = self.config.get("MAX_EXPIRY")
        if max_expiry:
            try:
                max_expiry = int(max_expiry)
            except ValueError:
                warn("[!] config.txt: MAX_EXPIRY is not a valid integer — no cap applied.")
                max_expiry = None

        while True:
            rules_hint = f"1-{max_expiry}" if max_expiry else "1+, 0=indefinite"
            user_input = input(
                f"Enter expiration days ({rules_hint}) "
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

            if max_expiry and expiry_days > max_expiry:
                err(f"Exceeds MAX_EXPIRY of {max_expiry} days. Please try again.")
                continue

            if expiry_days == 0:
                if max_expiry:
                    err(f"Indefinite rules are disabled while MAX_EXPIRY is set "
                        f"({max_expiry} days). Please try again.")
                    continue
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
            conflict_row = self._get_covering_rule(version, start, end, other_policy)

            if conflict_row:
                warn(f"\nEXCEPTION DETECTED: {ip_input} overlaps an existing {other_policy} rule ({conflict_row['cidr']})")
                if input(f"Confirm adding this {policy} exception? (y/n): ").lower() != 'y':
                    return True

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
            return True

        except Exception as e:
            err(f"[-] ERROR: {e}")
            return False

    def _carve_out(self, net_obj, covering_row, inc_id, comment):
        """Subtract net_obj from a covering rule, replacing it with the remaining CIDRs."""
        covering_net = ipaddress.ip_network(covering_row['cidr'])
        remaining = sorted(covering_net.address_exclude(net_obj), key=lambda n: n.network_address)

        print(f"\nResulting BLOCK rules after carving {net_obj} out of {covering_net}:")
        for r in remaining:
            print(f"  {r}")

        if input(f"\nApply ({len(remaining)} replacement rules)? (y/n): ").strip().lower() != 'y':
            print("Aborted.")
            return

        current_user = getpass.getuser()
        created_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        with self.conn:
            self.conn.execute("DELETE FROM ip_ranges WHERE id = :id", {'id': covering_row['id']})
            for cidr in remaining:
                _, version, start, end, cidr_val = self.normalize_cidr(str(cidr))
                self.conn.execute("""
                                  INSERT INTO ip_ranges
                                  (original_input, cidr, version, start_blob, end_blob, incident_id, policy, created_by, created_at, expires_at)
                                  VALUES (:orig, :cidr, :version, :start_blob, :end_blob, :inc, :policy, :created_by, :created_at, :expires_at)
                                  """, {
                    'orig': str(cidr),
                    'cidr': cidr_val,
                    'version': version,
                    'start_blob': start,
                    'end_blob': end,
                    'inc': inc_id,
                    'policy': covering_row['policy'],
                    'created_by': current_user,
                    'created_at': created_at,
                    'expires_at': covering_row['expires_at'],
                })

        self._log_event("CARVED", f"{net_obj} from {covering_net}", inc_id, comment)
        ok(f"SUCCESS: {net_obj} carved out of {covering_net}. {len(remaining)} replacement rules active.")

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
                for policy_check in ('BLOCK', 'ALLOW'):
                    covering_row = self._get_covering_rule(version, start, end, policy_check)
                    if covering_row:
                        warn(f"[i] NOTE: {cidr_val} is covered by an active {policy_check} rule for {covering_row['cidr']}.")
                        if input(f"Carve {cidr_val} out of {covering_row['cidr']}? (y/n): ").strip().lower() == 'y':
                            inc_id, comment = self.parse_removal_inputs()
                            self._carve_out(net_obj, covering_row, inc_id, comment)
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
                                           SELECT id
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
            if days:
                print(f"Found {total_to_purge} redundant records older than {days} days.")
            else:
                print(f"Found {total_to_purge} redundant records (no age limit).")

            # Redundant-but-indefinite rules would come back on their own once the
            # covering rule expires (see reactivate_uncovered). Purging destroys
            # that, so call it out before the operator confirms.
            indefinite_query = count_query.replace(
                "WHERE is_redundant = 1", "WHERE is_redundant = 1 AND expires_at IS NULL"
            )
            indefinite = self.conn.execute(indefinite_query, params).fetchone()['total']
            if indefinite:
                warn(f"[!] {indefinite} of these have NO expiration and would be re-enforced "
                     f"automatically once their covering rule lapses.")
                warn("    Purging them removes that protection permanently.")

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
        # A relative FILE_OUTPUT_* is relative to the install, not the caller's
        # cwd. Absolute paths (/etc/firewall/...) are left alone.
        output_paths = {k: self._resolve(v) for k, v in output_paths.items()}

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

            # Only back up a file that actually holds something. An empty list —
            # allow.txt in DENY_ONLY mode, say — is re-exported on every run and
            # would otherwise pile up empty backups with nothing to restore.
            # The test is on the EXISTING file, not the new content: overwriting
            # a populated list with an empty one is exactly when a backup matters.
            if out_path.exists() and out_path.stat().st_size > 0:
                backup_name = self._backup_name(out_path.stem, out_path.suffix)
                backup_path = self.base_dir / "backups" / backup_name
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

            publishable, dropped = self._routable_only([r['cidr'] for r in rows])
            if dropped:
                warn(f"[!] SKIPPED {len(dropped)} non-routable {p} rule(s) — not written to {out_path.name}:")
                for c in dropped:
                    warn(f"      {c}")
                warn("    These are inside your perimeter and cannot match a public source address.")

            with open(out_path, "w") as f:
                for c in publishable:
                    f.write(f"{c}\n")
            print(f"[+] EXPORTED: {len(publishable)} rules to {out_path}\n")

    def sync_named_location(self):
        """Export block list to file, then push CIDRs to the configured Entra Named Location."""
        required = ["TENANT_ID", "CLIENT_ID", "SECRET", "BLOCKLIST_NAMED_LOCATION_ID"]
        missing = [k for k in required if not self.config.get(k)]
        if missing:
            err(f"[!] Missing required config.txt keys for sync: {', '.join(missing)}")
            err("    These come from an Entra app registration holding the Graph APPLICATION")
            err("    permissions Policy.Read.All and Policy.ReadWrite.ConditionalAccess.")
            sys.exit(1)

        # Export files first (includes backup logic)
        self.export_lists()

        # Fetch active BLOCK CIDRs
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        rows = self.conn.execute("""
                                 SELECT cidr FROM ip_ranges
                                 WHERE policy = 'BLOCK'
                                   AND is_redundant = 0
                                   AND (expires_at > :now OR expires_at IS NULL)
                                 ORDER BY version ASC, start_blob ASC
                                 """, {'now': now}).fetchall()

        cidrs, dropped = self._routable_only([r['cidr'] for r in rows])
        if dropped:
            warn(f"[!] SKIPPED {len(dropped)} non-routable rule(s) — not sent to Entra:")
            for c in dropped:
                warn(f"      {c}")
            warn("    Entra would accept these silently, but they can never match a")
            warn("    public source address. Remove them from the database.")

        if not cidrs:
            warn("[!] No active BLOCK rules to sync.")
            return

        try:
            token = get_bearer_token(
                tenant_id=self.config["TENANT_ID"],
                client_id=self.config["CLIENT_ID"],
                client_secret=self.config["SECRET"],
            )
        except Exception as e:
            err(f"[!] Failed to obtain Azure token: {e}")
            sys.exit(1)

        # Backup the current Named Location state before overwriting
        location_id = self.config["BLOCKLIST_NAMED_LOCATION_ID"]
        existing = get_named_location(bearer_token=token, uuid=location_id)
        if existing:
            # Name the backup after the location itself, plus the first block of
            # its UUID. A tenant needs more than one Named Location once a list
            # passes the 2000-CIDR cap, and these filenames stay distinct.
            label = self._safe_label(existing.get("displayName"))
            backup_name = self._backup_name(f"{label}-{location_id.split('-')[0]}", ".json")
            backup_path = self.base_dir / "backups" / backup_name
            with open(backup_path, "w") as f:
                json.dump(existing, f, indent=2)
            print(f"[+] BACKUP: Named Location -> backups/{backup_name}")
        else:
            warn("[!] Could not retrieve current Named Location state — proceeding without backup.")

        success = update_named_location(
            bearer_token=token,
            uuid=location_id,
            type="ipRanges",
            values=cidrs,
        )

        if success:
            print(f"[+] EXPORTED: {len(cidrs)} rules to Named Location {location_id}\n")
            self._log_event("SYNC", f"{len(cidrs)} CIDRs -> Named Location {location_id}")
        else:
            err("[!] Named Location update failed. File export completed but Entra was not updated.")
            err("    Most often this is permissions. The app registration needs the Graph")
            err("    APPLICATION permissions Policy.Read.All and")
            err("    Policy.ReadWrite.ConditionalAccess, with admin consent granted.")
            err("    The Graph status code is in the error logged just above.")
            sys.exit(1)

    @staticmethod
    def _backup_name(label, suffix=""):
        """
        Builds a backup filename with the timestamp first, e.g.
        2026-08-04_11_35_59-block.txt. The format is fixed-width and
        zero-padded, so an alphabetical listing in Finder or any file browser
        is also chronological.
        """
        return f"{datetime.now().strftime('%Y-%m-%d_%H_%M_%S')}-{label}{suffix}"

    # Prefix lengths at which a rule stops being routine. A rule WIDER than
    # 'confirm' demands a typed confirmation; wider than 'refuse' is rejected
    # outright and cannot be forced.
    #
    # IPv4 mirrors the operational units: /24 is the smallest normally-routed
    # block, /16 the widest anyone should ever need to block in one go. IPv6
    # uses the analogous units — /48 is a site, /32 a large allocation — so an
    # ordinary /64 host block stays frictionless rather than tripping a guard
    # calibrated for IPv4 arithmetic.
    SIZE_LIMITS = {
        4: {"confirm": 24, "refuse": 16},
        6: {"confirm": 48, "refuse": 32},
    }

    def _size_verdict(self, net_obj):
        """Returns 'ok', 'confirm' or 'refuse' for the breadth of net_obj."""
        limits = self.SIZE_LIMITS[net_obj.version]
        if net_obj.prefixlen < limits["refuse"]:
            return "refuse"
        if net_obj.prefixlen < limits["confirm"]:
            return "confirm"
        return "ok"

    def _confirm_oversized(self, net_obj, policy):
        """
        Loud, unmissable prompt for a rule wider than the confirm threshold.
        Requires the operator to retype the range exactly — a bare 'y' is too
        easy to hit by reflex on something this destructive.
        """
        banner = f"  !!  LARGE {policy} RANGE  —  {net_obj}  covers {net_obj.num_addresses:,} addresses  !!  "
        edge = " " * len(banner)
        loud = Back.RED + Fore.WHITE + Style.BRIGHT
        print("")
        print(loud + edge + Style.RESET_ALL)
        print(loud + banner + Style.RESET_ALL)
        print(loud + edge + Style.RESET_ALL)
        warn(f"\nThis will {policy.lower()} every address in {net_obj}.")
        warn("Check the prefix length carefully — /16 is 256x wider than /24.")

        typed = input(f"\nType the range exactly to confirm (or anything else to abort): ").strip()
        if typed != str(net_obj):
            err("Aborted — input did not match.")
            return False
        return True

    def _routable_only(self, cidrs):
        """
        Splits CIDRs into (publishable, rejected).

        Non-routable space must never reach a firewall or a Named Location. It
        sits inside the perimeter already, it can never match a public source
        address, and Entra accepts it silently rather than refusing it — so
        nothing downstream will catch the mistake. add_entry's callers reject it
        at entry, but rows predating that check can still be in the database, so
        it is enforced again here at publish time.
        """
        keep, dropped = [], []
        for c in cidrs:
            try:
                net = ipaddress.ip_network(c, strict=False)
            except ValueError:
                dropped.append(c)
                continue
            (keep if net.is_global else dropped).append(c)
        return keep, dropped

    def _resolve(self, path):
        """Anchors a relative path to the install directory; leaves absolute ones alone."""
        p = Path(path)
        return p if p.is_absolute() else self.base_dir / p

    @staticmethod
    def _safe_label(text, fallback="named_location", limit=60):
        """
        Reduces an Entra display name to something usable in a filename:
        whitespace becomes '-', and path separators and other awkward
        characters are dropped. Returns the fallback if nothing usable is left,
        so a location with an empty or emoji-only name still produces a valid
        backup path.
        """
        cleaned = re.sub(r"\s+", "-", (text or "").strip())
        cleaned = re.sub(r"[^A-Za-z0-9._-]", "", cleaned)
        cleaned = re.sub(r"-{2,}", "-", cleaned).strip("-._")
        return cleaned[:limit] or fallback

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

        with open(self.base_dir / "reports" / fname, "w", newline='') as f:
            writer = csv.writer(f)
            writer.writerow(
                ["IP/CIDR", "Policy", "Version", "Incident ID", "Author", "Created", "Expires", "Is Redundant"])
            writer.writerows(rows)
        print(f"[+] CSV GENERATED: {fname} (Full Database Audit Export)")


def main():
    # Custom Help Text Block
    custom_help = """
BlocklistManager — Firewall Blocklist Manager
=============================================
Usage: python src/BlocklistManager.py COMMAND [TARGET] [OPTIONS]

One authoritative IP blocklist for hybrid environments, enforced at the network
edge and in cloud identity from a single source of truth. Rules are held in a
local SQLite database with full audit history; the same rule set publishes to
flat files for firewall ingestion and to an Entra Conditional Access Named
Location, so the two cannot drift apart.

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
                      May be disabled via DENY_ONLY=TRUE in config.txt to
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
                      and FILE_OUTPUT_ALLOW in config.txt. If not set, defaults
                      to:
                        rules/block.txt
                        rules/allow.txt
                      Suitable for ingestion by external firewall tooling.

  sync                Export rules to file (same as export), then push all
                      active BLOCK CIDRs to the Entra Named Location specified
                      by BLOCKLIST_NAMED_LOCATION_ID in config.txt. Requires
                      Azure credentials in config.txt (see Configuration).
                      Backs up the current Named Location state to backups/
                      as JSON before overwriting it.

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
                      Warns first if any of the records have no expiration,
                      since those would otherwise be re-enforced automatically
                      once their covering rule lapses.

--- Redundancy ---

  Adding a rule that covers narrower existing rules of the same policy marks
  those as redundant so exports stay compact. This is reversible in both
  directions: removing the covering rule reactivates its children under the new
  incident ID, and letting the covering rule EXPIRE reactivates them on the next
  run with a REACTIVATED audit entry. A temporary wide sweep therefore never
  silently cancels a narrower permanent block.

--- Rule Breadth ---

  Rules are gated on how much of the internet they cover, so one mistyped
  prefix cannot lock out a tenant:

    IPv4   /24 or narrower   proceeds normally
           /23 to /16        requires retyping the range to confirm
           wider than /16    refused outright, cannot be forced

    IPv6   /48 or narrower   proceeds normally
           /47 to /32        requires retyping the range to confirm
           wider than /32    refused outright, cannot be forced

  The IPv6 thresholds track the equivalent operational units (a site is a /48,
  a large allocation a /32), so an ordinary /64 host block is unaffected.
  The guard applies to both block and allow.

--- Whitelist ---

  Any block/deny command targeting a network that overlaps a whitelisted entry
  is rejected immediately: no prompts, no database write.

  The whitelist file is REQUIRED. block, deny, allow and remove refuse to run
  until it exists; list, search, report, export and sync still work without it.
  An empty file is accepted. The point is that an admin decided what must
  never be blocked, not that the list has entries. Its location comes from
  WHITELIST_PATH, defaulting to whitelist.txt in the project root.

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

--- Configuration (config.txt) ---

  One KEY=VALUE per line, in the project root. Text after a " #" is a comment.
  Quote a value to keep surrounding spaces or to spread it across lines.

  DENY_ONLY                    TRUE/FALSE  Disables the allow command when TRUE (default TRUE)
  DEFAULT_EXPIRY                days       Default expiration if operator presses Enter (default 30)
  DATABASE_PATH                 path       SQLite database location. Relative to the project
                                           root, or absolute for /var, /opt etc. Missing
                                           directories are created.
                                           (default data/BlocklistManager.sqlite)
  WHITELIST_PATH                path       Whitelist location. Relative to the project
                                           root, or absolute for /etc etc.
                                           (default whitelist.txt)
  MAX_EXPIRY                    days       Optional cap on rule lifetime. When set, longer
                                           expirations and indefinite (0) rules are refused.
                                           Unset by default.
  FILE_OUTPUT_DENY               path      Output path for exported BLOCK list (default rules/block.txt)
  FILE_OUTPUT_ALLOW              path      Output path for exported ALLOW list (default rules/allow.txt)
  TENANT_ID                     string     Azure AD tenant ID (required for sync)
  CLIENT_ID                     string     App registration client ID (required for sync)
  SECRET                        string     App registration client secret (required for sync)
  BLOCKLIST_NAMED_LOCATION_ID   string     UUID of the Entra Named Location to update (required for sync)

  sync needs an Entra app registration holding the Microsoft Graph application
  permissions Policy.Read.All and Policy.ReadWrite.ConditionalAccess, with
  admin consent granted.
  It replaces the whole Named Location list, so entries added by hand in the
  portal are removed on the next run.
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
    subparsers.add_parser("sync")
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
                err("[-] REFUSED: not a globally routable address.")
                err("    Private, loopback, link-local and reserved ranges are inside your\n    perimeter already; blocking them at the edge or in Conditional Access\n    achieves nothing. Entra accepts them silently, which makes it worse.")
                sys.exit(1)

        # Hard fail rather than warn. The whitelist is the only thing standing
        # between a typo and blocking your own infrastructure, and an admin who
        # has not created the file has not yet made that decision. Reading and
        # publishing still work, since those rules were already vetted on entry.
        if args.command in IPDatabase.RULE_WRITING_COMMANDS and not db.whitelist_exists:
            err(f"[!] REFUSED: no whitelist at {db.whitelist_path}")
            err("    Rules cannot be added or removed until this file exists. It lists the")
            err("    networks that must never be blocked, and creating it is a deliberate")
            err("    step, not a default.")
            err("")
            err("    cp whitelist.txt.example whitelist.txt   # then edit it")
            err("")
            err("    An empty file is accepted if you genuinely have nothing to protect.")
            err("    Set WHITELIST_PATH in config.txt to keep it somewhere else.")
            sys.exit(1)

        def run_add(policy):
            # Refuse before prompting for incident ID, comment and expiration —
            # add_entry() also enforces this, but only after the operator has
            # already typed all three.
            if db.deny_mode and policy == 'ALLOW':
                err("[!] ACCESS DENIED: The system is in DENY_ONLY_MODE. 'allow' commands are disabled.")
                sys.exit(1)

            targets, start_ip, end_ip = db.expand_range(args.target)

            # Breadth gate, before anything is written or any detail prompted
            # for. Refusals are checked across every expanded CIDR first, so an
            # oversized range is rejected outright rather than after the
            # operator has already confirmed some of its parts.
            for net_obj in targets:
                if db._size_verdict(net_obj) == "refuse":
                    limit = db.SIZE_LIMITS[net_obj.version]["refuse"]
                    err(f"[!] REFUSED: {net_obj} is wider than /{limit} "
                        f"({net_obj.num_addresses:,} addresses).")
                    err(f"    Rules this broad are not permitted. Split it into /{limit} "
                        f"or narrower blocks if this is genuinely intended.")
                    sys.exit(1)
            for net_obj in targets:
                if db._size_verdict(net_obj) == "confirm" and not db._confirm_oversized(net_obj, policy):
                    sys.exit(1)

            if start_ip and not db._confirm_large_range(start_ip, end_ip, targets):
                err("Aborted.")
                sys.exit(1)
            if len(targets) > 1:
                print(f"Range expanded to {len(targets)} CIDRs.")
            actionable = []
            # One dash range can expand to many CIDRs that are all covered by the
            # same existing rule. Prompt once per covering rule, not once per
            # CIDR — otherwise the operator answers the identical question
            # repeatedly and each answer compounds the extension.
            prompted = set()
            for net_obj in targets:
                cidr_val = str(net_obj)
                if policy == 'BLOCK':
                    protected = db._check_whitelist(net_obj)
                    if protected:
                        err(f"[!] BLOCKED BY WHITELIST: {cidr_val} overlaps protected network {protected} in whitelist.txt. Skipping.")
                        continue
                _, version, start, end, _ = db.normalize_cidr(cidr_val)
                existing_row = db._get_covering_rule(version, start, end, policy)
                if existing_row:
                    if existing_row['id'] in prompted:
                        continue
                    prompted.add(existing_row['id'])
                    new_expiry = db.prompt_extend_expiration(existing_row, policy=policy)
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
                if not db.add_entry(str(net_obj), policy=policy, inc_id=inc, expires_at=expires_at, comment=msg):
                    sys.exit(1)

        # Command Routing
        if args.command in ["block", "deny"]:
            run_add('BLOCK')
        elif args.command == "allow":
            run_add('ALLOW')
        elif args.command == "remove":
            db.remove_entry(args.target)
        elif args.command == "purge":
            db.purge_redundant(days=args.days)
        elif args.command == "search":
            db.search_ip(args.target)
        elif args.command == "export":
            db.export_lists()
        elif args.command == "sync":
            db.sync_named_location()
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