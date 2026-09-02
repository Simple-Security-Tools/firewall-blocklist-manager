import unittest
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta
import sqlite3
import ipaddress
import shutil
import sys
import os
import tempfile

# Ensure the project root is on the path
sys.path.insert(0, os.path.dirname(__file__))

from BlockListManager import IPDatabase


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_db():
    """
    Returns an IPDatabase instance backed by an in-memory SQLite database,
    with config and whitelist mocked out so no files are needed.
    """
    with patch("BlockListManager.dotenv_values", return_value={"DENY_ONLY": "FALSE", "DEFAULT_EXPIRY": "30"}), \
         patch("BlockListManager.Path.mkdir"), \
         patch.object(IPDatabase, "_load_whitelist", return_value=[]):
        db = IPDatabase.__new__(IPDatabase)
        db.config = {"DENY_ONLY": "FALSE", "DEFAULT_EXPIRY": "30"}
        db.deny_mode = False
        db.whitelist = []
        db.logger = MagicMock()
        db.conn = sqlite3.connect(":memory:")
        db.conn.row_factory = sqlite3.Row
        db._create_table()
        return db


# ---------------------------------------------------------------------------
# normalize_cidr
# ---------------------------------------------------------------------------

class TestNormalizeCidr(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def test_ipv4_plain_becomes_32(self):
        net, version, start, end, cidr = self.db.normalize_cidr("1.2.3.4")
        self.assertEqual(cidr, "1.2.3.4/32")
        self.assertEqual(version, 4)

    def test_ipv4_cidr_preserved(self):
        _, _, _, _, cidr = self.db.normalize_cidr("10.0.0.0/8")
        self.assertEqual(cidr, "10.0.0.0/8")

    def test_ipv6_plain_becomes_64(self):
        _, version, _, _, cidr = self.db.normalize_cidr("2001:db8::1")
        self.assertEqual(version, 6)
        self.assertTrue(cidr.endswith("/64"))

    def test_ipv6_explicit_prefix_preserved(self):
        _, _, _, _, cidr = self.db.normalize_cidr("2001:db8::1/128")
        self.assertEqual(cidr, "2001:db8::1/128")

    def test_notify_false_no_print(self):
        with patch("builtins.print") as mock_print:
            self.db.normalize_cidr("2001:db8::1", notify=False)
            mock_print.assert_not_called()

    def test_notify_true_prints(self):
        with patch("builtins.print") as mock_print:
            self.db.normalize_cidr("2001:db8::1", notify=True)
            mock_print.assert_called_once()


# ---------------------------------------------------------------------------
# expand_range
# ---------------------------------------------------------------------------

class TestExpandRange(unittest.TestCase):

    def test_plain_ipv4(self):
        nets, start, end = IPDatabase.expand_range("1.2.3.4")
        self.assertEqual(len(nets), 1)
        self.assertIsNone(start)

    def test_cidr(self):
        nets, start, end = IPDatabase.expand_range("10.0.0.0/24")
        self.assertEqual(len(nets), 1)
        self.assertEqual(str(nets[0]), "10.0.0.0/24")

    def test_dash_range(self):
        nets, start, end = IPDatabase.expand_range("10.0.0.1-10.0.0.4")
        self.assertIsNotNone(start)
        self.assertIsNotNone(end)
        # All CIDRs must lie within the range
        for net in nets:
            self.assertGreaterEqual(net.network_address, start)
            self.assertLessEqual(net.broadcast_address, end)

    def test_invalid_raises(self):
        with self.assertRaises(ValueError):
            IPDatabase.expand_range("not-an-ip")

    def test_reversed_dash_range_raises(self):
        with self.assertRaises(ValueError):
            IPDatabase.expand_range("10.0.0.10-10.0.0.1")


# ---------------------------------------------------------------------------
# is_input_ip_address / is_ip_address_routable
# ---------------------------------------------------------------------------

class TestValidation(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def test_valid_ip(self):
        self.assertTrue(self.db.is_input_ip_address("1.2.3.4"))

    def test_invalid_input(self):
        self.assertFalse(self.db.is_input_ip_address("not-an-ip"))

    def test_global_ip_routable(self):
        self.assertTrue(self.db.is_ip_address_routable("8.8.8.8"))

    def test_private_ip_not_routable(self):
        self.assertFalse(self.db.is_ip_address_routable("192.168.1.1"))

    def test_loopback_not_routable(self):
        self.assertFalse(self.db.is_ip_address_routable("127.0.0.1"))


# ---------------------------------------------------------------------------
# whitelist
# ---------------------------------------------------------------------------

class TestWhitelist(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.db.whitelist = [ipaddress.ip_network("203.0.113.0/24")]

    def test_overlapping_ip_blocked(self):
        net = ipaddress.ip_network("203.0.113.50/32")
        result = self.db._check_whitelist(net)
        self.assertEqual(result, "203.0.113.0/24")

    def test_non_overlapping_ip_allowed(self):
        net = ipaddress.ip_network("1.2.3.4/32")
        self.assertIsNone(self.db._check_whitelist(net))


# ---------------------------------------------------------------------------
# add_entry / _get_covering_rule
# ---------------------------------------------------------------------------

class TestAddEntry(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def _add(self, cidr, policy="BLOCK", inc_id="INC001", expires_at=None):
        self.db.add_entry(cidr, inc_id=inc_id, policy=policy, expires_at=expires_at)

    def test_add_block_rule(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self._add("1.2.3.4/32")
        rows = self.db.conn.execute("SELECT * FROM ip_ranges").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["policy"], "BLOCK")

    def test_redundant_smaller_range_marked(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self._add("1.2.3.4/32")
            self._add("1.2.3.0/24")  # broader range — should mark /32 redundant
        active = self.db.conn.execute(
            "SELECT * FROM ip_ranges WHERE is_redundant = 0"
        ).fetchall()
        self.assertEqual(len(active), 1)
        self.assertEqual(active[0]["cidr"], "1.2.3.0/24")

    def test_deny_mode_blocks_allow(self):
        self.db.deny_mode = True
        with self.assertRaises(SystemExit):
            self._add("1.2.3.4/32", policy="ALLOW")

    def test_conflict_check_prompts(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self._add("1.2.3.4/32", policy="ALLOW")
        with patch("builtins.input", return_value="y"), \
             patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self._add("1.2.3.4/32", policy="BLOCK")
        rows = self.db.conn.execute(
            "SELECT * FROM ip_ranges WHERE is_redundant = 0"
        ).fetchall()
        policies = {r["policy"] for r in rows}
        self.assertIn("BLOCK", policies)
        self.assertIn("ALLOW", policies)


# ---------------------------------------------------------------------------
# remove_entry
# ---------------------------------------------------------------------------

class TestRemoveEntry(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.3.4/32", inc_id="INC001")

    def test_remove_existing(self):
        with patch("builtins.input", side_effect=["y", "INC002", "removing"]), \
             patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.remove_entry("1.2.3.4")
        rows = self.db.conn.execute("SELECT * FROM ip_ranges").fetchall()
        self.assertEqual(len(rows), 0)

    def test_remove_nonexistent_prints_error(self):
        with patch("BlockListManager.err") as mock_err:
            self.db.remove_entry("9.9.9.9")
        mock_err.assert_called()

    def test_remove_aborted_on_no(self):
        with patch("builtins.input", return_value="n"):
            self.db.remove_entry("1.2.3.4")
        rows = self.db.conn.execute("SELECT * FROM ip_ranges").fetchall()
        self.assertEqual(len(rows), 1)


# ---------------------------------------------------------------------------
# search_ip
# ---------------------------------------------------------------------------

class TestSearchIp(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.3.0/24", inc_id="INC001")

    def test_search_covered_ip_returns_result(self):
        with patch("builtins.print") as mock_print:
            self.db.search_ip("1.2.3.50")
        output = " ".join(str(c) for c in mock_print.call_args_list)
        self.assertIn("1.2.3.0/24", output)

    def test_search_uncovered_ip_warns(self):
        with patch("BlockListManager.warn") as mock_warn:
            self.db.search_ip("8.8.8.8")
        mock_warn.assert_called()

    def test_search_excludes_redundant(self):
        # Add a broader range to make the /24 redundant
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.0.0/16", inc_id="INC002")
        results = self.db.conn.execute(
            "SELECT * FROM ip_ranges WHERE is_redundant = 0"
        ).fetchall()
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["cidr"], "1.2.0.0/16")


# ---------------------------------------------------------------------------
# expiration_date_prompt
# ---------------------------------------------------------------------------

class TestExpirationPrompt(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def test_default_on_enter(self):
        with patch("builtins.input", return_value=""):
            result = self.db.expiration_date_prompt()
        expected = (datetime.now() + timedelta(days=30)).strftime("%Y-%m-%d")
        self.assertTrue(result.startswith(expected))

    def test_zero_returns_none(self):
        with patch("builtins.input", return_value="0"):
            result = self.db.expiration_date_prompt()
        self.assertIsNone(result)

    def test_positive_integer(self):
        with patch("builtins.input", return_value="7"):
            result = self.db.expiration_date_prompt()
        expected = (datetime.now() + timedelta(days=7)).strftime("%Y-%m-%d")
        self.assertTrue(result.startswith(expected))

    def test_invalid_then_valid(self):
        # First input is bad, second is valid — should retry, not exit
        with patch("builtins.input", side_effect=["abc", "5"]):
            result = self.db.expiration_date_prompt()
        expected = (datetime.now() + timedelta(days=5)).strftime("%Y-%m-%d")
        self.assertTrue(result.startswith(expected))

    def test_negative_then_valid(self):
        with patch("builtins.input", side_effect=["-1", "10"]):
            result = self.db.expiration_date_prompt()
        expected = (datetime.now() + timedelta(days=10)).strftime("%Y-%m-%d")
        self.assertTrue(result.startswith(expected))


# ---------------------------------------------------------------------------
# prompt_extend_expiration
# ---------------------------------------------------------------------------

class TestPromptExtendExpiration(unittest.TestCase):

    def setUp(self):
        self.db = make_db()

    def _make_row(self, expires_at):
        row = MagicMock()
        row.__getitem__ = lambda self, key: {
            "cidr": "1.2.3.4/32",
            "created_by": "testuser",
            "created_at": "2026-01-01 00:00:00",
            "expires_at": expires_at,
            "incident_id": "INC001",
        }[key]
        return row

    def test_indefinite_returns_none_no_prompt(self):
        row = self._make_row(None)
        with patch("builtins.input") as mock_input:
            result = self.db.prompt_extend_expiration(row)
        mock_input.assert_not_called()
        self.assertIsNone(result)

    def test_enter_keeps_current(self):
        row = self._make_row("2026-12-01 00:00:00")
        with patch("builtins.input", return_value=""):
            result = self.db.prompt_extend_expiration(row)
        self.assertEqual(result, "2026-12-01 00:00:00")

    def test_zero_makes_indefinite(self):
        row = self._make_row("2026-12-01 00:00:00")
        with patch("builtins.input", return_value="0"):
            result = self.db.prompt_extend_expiration(row)
        self.assertIsNone(result)

    def test_positive_extends_from_current_expiry(self):
        row = self._make_row("2026-12-01 00:00:00")
        with patch("builtins.input", return_value="30"):
            result = self.db.prompt_extend_expiration(row)
        expected = (datetime(2026, 12, 1) + timedelta(days=30)).strftime("%Y-%m-%d %H:%M:%S")
        self.assertEqual(result, expected)


# ---------------------------------------------------------------------------
# reactivate_uncovered
# ---------------------------------------------------------------------------

class TestReactivateUncovered(unittest.TestCase):
    """
    A rule is only redundant while the rule that swallowed it is still active.
    When the covering rule expires, the narrower rule must be re-enforced —
    otherwise a temporary wide sweep silently cancels a permanent block.
    """

    def setUp(self):
        self.db = make_db()

    def _expire(self, cidr, policy=None):
        query = "UPDATE ip_ranges SET expires_at = :past WHERE cidr = :cidr"
        params = {'past': (datetime.now() - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S"),
                  'cidr': cidr}
        if policy:
            query += " AND policy = :policy"
            params['policy'] = policy
        self.db.conn.execute(query, params)
        self.db.conn.commit()

    def _state(self):
        return dict(self.db.conn.execute(
            "SELECT cidr, is_redundant FROM ip_ranges").fetchall())

    def test_indefinite_child_returns_when_covering_rule_expires(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("5.5.5.5/32", inc_id="INC001", expires_at=None)
            self.db.add_entry("5.5.0.0/16", inc_id="INC002",
                              expires_at=(datetime.now() + timedelta(days=2)).strftime("%Y-%m-%d %H:%M:%S"))

        self.assertEqual(self._state()["5.5.5.5/32"], 1)

        self._expire("5.5.0.0/16")
        revived = self.db.reactivate_uncovered(verbose=False)

        self.assertEqual([r['cidr'] for r in revived], ["5.5.5.5/32"])
        self.assertEqual(self._state()["5.5.5.5/32"], 0)

    def test_child_stays_redundant_while_covering_rule_is_active(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("5.5.5.5/32", inc_id="INC001")
            self.db.add_entry("5.5.0.0/16", inc_id="INC002")

        self.assertEqual(self.db.reactivate_uncovered(verbose=False), [])
        self.assertEqual(self._state()["5.5.5.5/32"], 1)

    def test_nested_reactivation_keeps_grandchild_suppressed(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("6.6.6.6/32", inc_id="INC001")
            self.db.add_entry("6.6.6.0/24", inc_id="INC002")
            self.db.add_entry("6.6.0.0/16", inc_id="INC003")

        self._expire("6.6.0.0/16")
        revived = self.db.reactivate_uncovered(verbose=False)

        # Only the /24 comes back; the /32 is still covered by it.
        self.assertEqual([r['cidr'] for r in revived], ["6.6.6.0/24"])
        state = self._state()
        self.assertEqual(state["6.6.6.0/24"], 0)
        self.assertEqual(state["6.6.6.6/32"], 1)

    def test_does_not_reactivate_across_policies(self):
        # The BLOCK /16 overlaps an existing ALLOW rule, so add_entry() raises a
        # conflict prompt — answer it, or the row is never inserted and this
        # test silently stops testing anything.
        with patch("BlockListManager.getpass.getuser", return_value="testuser"), \
             patch("builtins.input", return_value="y"):
            self.assertTrue(self.db.add_entry("7.7.7.7/32", inc_id="INC001", policy="ALLOW"))
            self.assertTrue(self.db.add_entry("7.7.0.0/16", inc_id="INC002", policy="ALLOW"))
            self.assertTrue(self.db.add_entry("7.7.0.0/16", inc_id="INC003", policy="BLOCK"))

        self.assertEqual(
            self.db.conn.execute(
                "SELECT COUNT(*) FROM ip_ranges WHERE policy = 'BLOCK'").fetchone()[0], 1)

        # Expire only the ALLOW /16. The BLOCK /16 stays active and covers the
        # same addresses — it must not suppress the orphaned ALLOW child.
        self._expire("7.7.0.0/16", policy="ALLOW")

        revived = self.db.reactivate_uncovered(verbose=False)
        self.assertEqual(
            [(r['cidr'], r['policy']) for r in revived], [("7.7.7.7/32", "ALLOW")],
            "an ALLOW child must not be held down by an active BLOCK rule")

    def test_expired_child_is_not_reactivated(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("8.8.8.8/32", inc_id="INC001")
            self.db.add_entry("8.8.0.0/16", inc_id="INC002")

        self._expire("8.8.8.8/32")
        self._expire("8.8.0.0/16")

        self.assertEqual(self.db.reactivate_uncovered(verbose=False), [])

    def test_reactivation_is_audited(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("9.9.9.9/32", inc_id="INC001")
            self.db.add_entry("9.9.0.0/16", inc_id="INC002")

        self._expire("9.9.0.0/16")
        self.db.reactivate_uncovered(verbose=False)

        events = [r[0] for r in self.db.conn.execute(
            "SELECT event_type FROM audit_history").fetchall()]
        self.assertIn("REACTIVATED", events)


# ---------------------------------------------------------------------------
# purge_redundant
# ---------------------------------------------------------------------------

class TestPurgeRedundant(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        # Add a broader range to create a redundant record
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.3.4/32", inc_id="INC001")
            self.db.add_entry("1.2.3.0/24", inc_id="INC002")

    def test_purge_removes_redundant(self):
        with patch("builtins.input", return_value="y"):
            self.db.purge_redundant()
        rows = self.db.conn.execute(
            "SELECT * FROM ip_ranges WHERE is_redundant = 1"
        ).fetchall()
        self.assertEqual(len(rows), 0)

    def test_purge_aborted_leaves_redundant(self):
        with patch("builtins.input", return_value="n"):
            self.db.purge_redundant()
        rows = self.db.conn.execute(
            "SELECT * FROM ip_ranges WHERE is_redundant = 1"
        ).fetchall()
        self.assertEqual(len(rows), 1)

    def test_purge_with_days_filter(self):
        # Set the redundant record's created_at to 100 days ago
        self.db.conn.execute(
            "UPDATE ip_ranges SET created_at = ? WHERE is_redundant = 1",
            [(datetime.now() - timedelta(days=100)).strftime("%Y-%m-%d %H:%M:%S")]
        )
        self.db.conn.commit()
        with patch("builtins.input", return_value="y"):
            self.db.purge_redundant(days=90)
        rows = self.db.conn.execute(
            "SELECT * FROM ip_ranges WHERE is_redundant = 1"
        ).fetchall()
        self.assertEqual(len(rows), 0)


# ---------------------------------------------------------------------------
# _carve_out (via remove_entry)
# ---------------------------------------------------------------------------

class TestCarveOut(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("192.168.0.0/24", inc_id="INC001")

    def test_carve_single_host_out_of_block(self):
        with patch("builtins.input", side_effect=["y", "INC002", "exempt host", "y"]), \
             patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.remove_entry("192.168.0.25/32")

        rows = self.db.conn.execute(
            "SELECT cidr FROM ip_ranges WHERE is_redundant = 0"
        ).fetchall()
        cidrs = {r["cidr"] for r in rows}

        # The original /24 should be gone, replaced by smaller CIDRs
        self.assertNotIn("192.168.0.0/24", cidrs)
        self.assertGreater(len(cidrs), 1)

        # The carved address itself should not be covered by any remaining CIDR
        carved = ipaddress.ip_network("192.168.0.25/32")
        self.assertFalse(any(
            carved.subnet_of(ipaddress.ip_network(c)) for c in cidrs
        ))

        # Every other address in the original /24 should still be covered
        parent = ipaddress.ip_network("192.168.0.0/24")
        sample_ips = [ip for ip in (parent.network_address + 1, parent.network_address + 100)
                      if ip != ipaddress.ip_address("192.168.0.25")]
        for ip in sample_ips:
            covered = any(ip in ipaddress.ip_network(c) for c in cidrs)
            self.assertTrue(covered, f"{ip} should still be covered after carve-out")

    def test_carve_declined_at_offer_leaves_parent_intact(self):
        with patch("builtins.input", side_effect=["n"]):
            self.db.remove_entry("192.168.0.25/32")
        rows = self.db.conn.execute("SELECT cidr FROM ip_ranges").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cidr"], "192.168.0.0/24")

    def test_carve_declined_at_apply_leaves_parent_intact(self):
        with patch("builtins.input", side_effect=["y", "n"]):
            self.db.remove_entry("192.168.0.25/32")
        rows = self.db.conn.execute("SELECT cidr FROM ip_ranges").fetchall()
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["cidr"], "192.168.0.0/24")

    def test_carve_logs_audit_event(self):
        with patch("builtins.input", side_effect=["y", "INC002", "exempt host", "y"]), \
             patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.remove_entry("192.168.0.25/32")
        history = self.db.conn.execute(
            "SELECT * FROM audit_history WHERE event_type = 'CARVED'"
        ).fetchall()
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0]["incident_id"], "INC002")


# ---------------------------------------------------------------------------
# _backup_name
# ---------------------------------------------------------------------------

class TestBackupName(unittest.TestCase):
    """Backups lead with the timestamp so a file browser sorts them by age."""

    def setUp(self):
        self.db = make_db()

    def _at(self, when, label, suffix=""):
        with patch("BlockListManager.datetime") as mock_dt:
            mock_dt.now.return_value = when
            return self.db._backup_name(label, suffix)

    def test_timestamp_comes_first(self):
        name = self._at(datetime(2026, 8, 4, 11, 35, 59), "block", ".txt")
        self.assertEqual(name, "2026-08-04_11_35_59-block.txt")

    def test_named_location_backup(self):
        name = self._at(datetime(2026, 8, 4, 11, 35, 59), "named_location", ".json")
        self.assertEqual(name, "2026-08-04_11_35_59-named_location.json")

    def test_alphabetical_order_matches_chronological_order(self):
        # Zero-padded fixed-width fields, so a plain string sort is a time sort.
        # Crosses hour, day, month and year boundaries — where naive formats break.
        moments = [
            datetime(2025, 12, 31, 23, 59, 59),
            datetime(2026, 1, 1, 0, 0, 0),
            datetime(2026, 1, 9, 9, 9, 9),
            datetime(2026, 1, 10, 10, 10, 10),
            datetime(2026, 9, 2, 8, 5, 1),
            datetime(2026, 10, 2, 8, 5, 1),
        ]
        names = [self._at(m, "block", ".txt") for m in moments]
        self.assertEqual(sorted(names), names)

    def test_differing_labels_do_not_disturb_time_order(self):
        # "allow" sorts before "block" alphabetically; a later allow backup must
        # still sort after an earlier block backup.
        earlier = self._at(datetime(2026, 8, 4, 10, 0, 0), "block", ".txt")
        later = self._at(datetime(2026, 8, 4, 11, 0, 0), "allow", ".txt")
        self.assertEqual(sorted([later, earlier]), [earlier, later])


# ---------------------------------------------------------------------------
# export_lists — backup + integrity verification
# ---------------------------------------------------------------------------

class TestExportBackup(unittest.TestCase):

    def setUp(self):
        self.db = make_db()
        self.db.config = {"DENY_ONLY": "FALSE", "DEFAULT_EXPIRY": "30"}
        self.tmpdir = tempfile.mkdtemp()
        self.old_cwd = os.getcwd()
        os.chdir(self.tmpdir)
        os.makedirs("rules", exist_ok=True)
        os.makedirs("backups", exist_ok=True)
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.3.4/32", inc_id="INC001")

    def tearDown(self):
        os.chdir(self.old_cwd)
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def test_first_export_creates_file_no_backup(self):
        self.db.export_lists()
        self.assertTrue(os.path.exists("rules/block.txt"))
        self.assertEqual(len(os.listdir("backups")), 0)

    def test_second_export_creates_verified_backup(self):
        self.db.export_lists()
        self.db.export_lists()  # both files now exist -> triggers backup path for each
        backups = os.listdir("backups")
        self.assertEqual(len(backups), 2)  # one for block.txt, one for allow.txt
        # Timestamp leads, so an alphabetical listing is chronological.
        self.assertTrue(any(b.endswith("-block.txt") for b in backups))
        self.assertTrue(any(b.endswith("-allow.txt") for b in backups))
        for b in backups:
            self.assertRegex(b, r"^\d{4}-\d{2}-\d{2}_\d{2}_\d{2}_\d{2}-")

    def test_export_writes_active_cidrs_only(self):
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.3.0/24", inc_id="INC002")  # makes /32 redundant
        self.db.export_lists()
        with open("rules/block.txt") as f:
            lines = [l.strip() for l in f if l.strip()]
        self.assertEqual(lines, ["1.2.3.0/24"])

    def test_export_respects_custom_output_paths(self):
        self.db.config["FILE_OUTPUT_DENY"] = "custom/block-list.txt"
        self.db.export_lists()
        self.assertTrue(os.path.exists("custom/block-list.txt"))

    def test_backup_failure_prompts_and_skips_on_no(self):
        # Force the copy step to fail so the integrity check can't pass
        self.db.export_lists()  # create rules/block.txt
        with patch("BlockListManager.shutil.copy2", side_effect=OSError("disk full")), \
             patch("builtins.input", return_value="n"):
            self.db.export_lists()
        # Original file should be untouched since the operator declined
        with open("rules/block.txt") as f:
            content = f.read()
        self.assertIn("1.2.3.4/32", content)

    def test_backup_failure_overwrites_on_yes(self):
        self.db.export_lists()
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("5.6.7.8/32", inc_id="INC003")
        with patch("BlockListManager.shutil.copy2", side_effect=OSError("disk full")), \
             patch("builtins.input", return_value="y"):
            self.db.export_lists()
        with open("rules/block.txt") as f:
            content = f.read()
        self.assertIn("5.6.7.8/32", content)


# ---------------------------------------------------------------------------
# sync_named_location
# ---------------------------------------------------------------------------

class TestSyncNamedLocation(unittest.TestCase):

    def setUp(self):
        # sync_named_location() writes a Named Location backup into ./backups.
        # Run from a scratch directory so the suite does not depend on the
        # caller's cwd already having one, and does not litter the repo.
        self._prev_cwd = os.getcwd()
        self._tmpdir = tempfile.mkdtemp()
        os.mkdir(os.path.join(self._tmpdir, "backups"))
        os.chdir(self._tmpdir)

        self.db = make_db()
        self.db.config = {
            "DENY_ONLY": "FALSE",
            "DEFAULT_EXPIRY": "30",
            "TENANT_ID": "t",
            "CLIENT_ID": "c",
            "SECRET": "s",
            "BLOCKLIST_NAMED_LOCATION_ID": "loc-123",
        }
        with patch("BlockListManager.getpass.getuser", return_value="testuser"):
            self.db.add_entry("1.2.3.4/32", inc_id="INC001")

    def tearDown(self):
        os.chdir(self._prev_cwd)
        shutil.rmtree(self._tmpdir, ignore_errors=True)

    def test_missing_config_exits(self):
        self.db.config.pop("SECRET")
        with self.assertRaises(SystemExit):
            self.db.sync_named_location()

    @patch("BlockListManager.update_named_location", return_value=True)
    @patch("BlockListManager.get_named_location", return_value={"id": "loc-123", "ipRanges": []})
    @patch("BlockListManager.get_bearer_token", return_value="fake-token")
    def test_sync_calls_graph_with_active_cidrs(self, mock_token, mock_get_loc, mock_update):
        with patch.object(self.db, "export_lists"):
            self.db.sync_named_location()
        mock_update.assert_called_once()
        _, kwargs = mock_update.call_args
        self.assertEqual(kwargs["values"], ["1.2.3.4/32"])
        self.assertEqual(kwargs["uuid"], "loc-123")

    @patch("BlockListManager.update_named_location", return_value=True)
    @patch("BlockListManager.get_named_location", return_value=None)
    @patch("BlockListManager.get_bearer_token", return_value="fake-token")
    def test_sync_continues_when_location_backup_fails(self, mock_token, mock_get_loc, mock_update):
        with patch.object(self.db, "export_lists"), \
             patch("BlockListManager.warn") as mock_warn:
            self.db.sync_named_location()
        mock_warn.assert_called()
        mock_update.assert_called_once()

    @patch("BlockListManager.update_named_location", return_value=False)
    @patch("BlockListManager.get_named_location", return_value={"id": "loc-123"})
    @patch("BlockListManager.get_bearer_token", return_value="fake-token")
    def test_update_failure_exits(self, mock_token, mock_get_loc, mock_update):
        with patch.object(self.db, "export_lists"):
            with self.assertRaises(SystemExit):
                self.db.sync_named_location()

    @patch("BlockListManager.get_bearer_token", side_effect=RuntimeError("token request failed"))
    def test_token_failure_exits(self, mock_token):
        with patch.object(self.db, "export_lists"):
            with self.assertRaises(SystemExit):
                self.db.sync_named_location()

    def test_no_active_block_rules_skips_sync(self):
        self.db.conn.execute("DELETE FROM ip_ranges")
        self.db.conn.commit()
        with patch.object(self.db, "export_lists"), \
             patch("BlockListManager.warn") as mock_warn, \
             patch("BlockListManager.get_bearer_token") as mock_token:
            self.db.sync_named_location()
        mock_warn.assert_called()
        mock_token.assert_not_called()

    @patch("BlockListManager.update_named_location", return_value=True)
    @patch("BlockListManager.get_named_location", return_value={"id": "loc-123", "ipRanges": []})
    @patch("BlockListManager.get_bearer_token", return_value="fake-token")
    def test_sync_logs_audit_event(self, mock_token, mock_get_loc, mock_update):
        with patch.object(self.db, "export_lists"):
            self.db.sync_named_location()
        history = self.db.conn.execute(
            "SELECT * FROM audit_history WHERE event_type = 'SYNC'"
        ).fetchall()
        self.assertEqual(len(history), 1)


if __name__ == "__main__":
    unittest.main()
