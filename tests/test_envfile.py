import os
import sys
import tempfile
import unittest
from pathlib import Path

# Same path setup as the main suite: the code lives in src/, and leaning on the
# caller's cwd would make this pass from the repo root and fail anywhere else.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(_ROOT, "src"))

from modules.envfile import ConfigError, load_config, loads


class TestBasicParsing(unittest.TestCase):
    def test_key_value(self):
        self.assertEqual(loads("DENY_ONLY=true"), {"DENY_ONLY": "true"})

    def test_blank_lines_and_comments_ignored(self):
        text = "\n# a comment\n\n   # indented comment\nA=1\n"
        self.assertEqual(loads(text), {"A": "1"})

    def test_whitespace_around_key_and_value_stripped(self):
        self.assertEqual(loads("  A  =  1  "), {"A": "1"})

    def test_export_prefix_ignored(self):
        self.assertEqual(loads("export SECRET=abc"), {"SECRET": "abc"})

    def test_empty_value(self):
        self.assertEqual(loads("TENANT_ID="), {"TENANT_ID": ""})

    def test_later_key_wins(self):
        self.assertEqual(loads("A=1\nA=2"), {"A": "2"})

    def test_value_may_contain_equals(self):
        # Base64 secrets end in padding; only the first '=' separates.
        self.assertEqual(loads("SECRET=abc=="), {"SECRET": "abc=="})


class TestComments(unittest.TestCase):
    def test_trailing_comment_stripped(self):
        self.assertEqual(loads("DEFAULT_EXPIRY=30  # days"), {"DEFAULT_EXPIRY": "30"})

    def test_hash_without_leading_space_is_literal(self):
        # A '#' inside a password is part of the password, not a comment.
        self.assertEqual(loads("SECRET=abc#def"), {"SECRET": "abc#def"})

    def test_comment_only_value(self):
        self.assertEqual(loads("A= # nothing here"), {"A": ""})

    def test_comment_not_stripped_inside_quotes(self):
        self.assertEqual(loads('A="abc # def"'), {"A": "abc # def"})


class TestQuoting(unittest.TestCase):
    def test_double_quotes_stripped(self):
        self.assertEqual(loads('A="hello world"'), {"A": "hello world"})

    def test_single_quotes_stripped(self):
        self.assertEqual(loads("A='hello world'"), {"A": "hello world"})

    def test_leading_and_trailing_space_preserved_in_quotes(self):
        self.assertEqual(loads('A="  padded  "'), {"A": "  padded  "})

    def test_escapes_processed_in_double_quotes(self):
        self.assertEqual(loads(r'A="one\ntwo\ttab"'), {"A": "one\ntwo\ttab"})

    def test_escaped_quote_in_double_quotes(self):
        self.assertEqual(loads(r'A="say \"hi\""'), {"A": 'say "hi"'})

    def test_escapes_literal_in_single_quotes(self):
        self.assertEqual(loads(r"A='one\ntwo'"), {"A": r"one\ntwo"})

    def test_unknown_escape_keeps_backslash(self):
        # A secret or a Windows path containing a backslash must survive.
        self.assertEqual(loads(r'A="C:\path"'), {"A": r"C:\path"})

    def test_comment_allowed_after_closing_quote(self):
        self.assertEqual(loads('A="x"  # note'), {"A": "x"})

    def test_junk_after_closing_quote_rejected(self):
        with self.assertRaises(ConfigError):
            loads('A="x" y')


class TestMultiline(unittest.TestCase):
    def test_quoted_value_spans_lines(self):
        text = 'IDS="aaa\nbbb\nccc"'
        self.assertEqual(loads(text), {"IDS": "aaa\nbbb\nccc"})

    def test_parsing_resumes_after_multiline_value(self):
        text = 'IDS="aaa\nbbb"\nDENY_ONLY=true'
        self.assertEqual(loads(text), {"IDS": "aaa\nbbb", "DENY_ONLY": "true"})

    def test_comment_inside_multiline_is_literal(self):
        # Everything between the quotes is data, including a '#'.
        text = 'IDS="aaa\n# not a comment\nbbb"'
        self.assertEqual(loads(text), {"IDS": "aaa\n# not a comment\nbbb"})

    def test_unterminated_quote_rejected(self):
        with self.assertRaises(ConfigError):
            loads('IDS="aaa\nbbb')

    def test_single_quoted_value_spans_lines(self):
        self.assertEqual(loads("IDS='aaa\nbbb'"), {"IDS": "aaa\nbbb"})


class TestNoInterpolation(unittest.TestCase):
    def test_dollar_brace_left_alone(self):
        # A secret is opaque; rewriting ${...} would break auth very quietly.
        self.assertEqual(loads("SECRET=${NOT_A_VAR}"), {"SECRET": "${NOT_A_VAR}"})

    def test_dollar_brace_left_alone_in_quotes(self):
        self.assertEqual(loads('SECRET="a${B}c"'), {"SECRET": "a${B}c"})


class TestErrors(unittest.TestCase):
    def test_line_without_equals_rejected(self):
        with self.assertRaises(ConfigError):
            loads("DENY_ONLY true")

    def test_empty_key_rejected(self):
        with self.assertRaises(ConfigError):
            loads("=value")

    def test_key_with_space_rejected(self):
        with self.assertRaises(ConfigError):
            loads("DENY ONLY=true")

    def test_error_names_source_and_line(self):
        with self.assertRaises(ConfigError) as ctx:
            loads("A=1\nbroken line\n", source="config.txt")
        self.assertIn("config.txt:2", str(ctx.exception))


class TestLoadConfig(unittest.TestCase):
    def test_missing_file_yields_empty_dict(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(load_config(Path(tmp) / "nope.txt"), {})

    def test_reads_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "config.txt"
            path.write_text("DENY_ONLY=true\n# comment\nDEFAULT_EXPIRY=30\n")
            self.assertEqual(
                load_config(path), {"DENY_ONLY": "true", "DEFAULT_EXPIRY": "30"}
            )

    def test_real_example_file_parses(self):
        # The shipped example is the file operators copy; it must parse.
        example = Path(_ROOT) / "config.txt.example"
        self.assertTrue(example.exists(), "config.txt.example is missing")
        parsed = load_config(example)
        self.assertEqual(parsed.get("DENY_ONLY"), "true")
        self.assertEqual(parsed.get("DEFAULT_EXPIRY"), "30")
        self.assertEqual(parsed.get("TENANT_ID"), "")
        # Commented-out optional keys must not appear at all.
        self.assertNotIn("MAX_EXPIRY", parsed)
        self.assertNotIn("DATABASE_PATH", parsed)


if __name__ == "__main__":
    unittest.main()
