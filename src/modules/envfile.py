"""
Parser for config.txt.

Standard KEY=VALUE env-file format, which is also what systemd's
EnvironmentFile= and `docker --env-file` read. That means a deployment can
point either one at config.txt and pull SECRET from a vault instead of leaving
it on disk. Keeping that format is why this is a small parser here rather than
a dependency or a switch to TOML.

Supported:

    KEY=value                     # unquoted, trailing comment stripped
    KEY="value"                   # escapes processed: \\n \\t \\r \\\\ \\"
    KEY='value'                   # literal, no escape processing
    KEY="line one
    line two"                     # quoted values may span lines
    export KEY=value              # the export prefix is ignored

${VAR} is not expanded. A client secret can contain a dollar sign or a brace,
and rewriting it would break auth without saying so.
"""

from pathlib import Path

#: Escapes handled inside double quotes. Anything else keeps its backslash, so
#: a Windows path or a secret with one in it comes through unchanged.
_ESCAPES = {"n": "\n", "t": "\t", "r": "\r", "\\": "\\", '"': '"', "'": "'"}


class ConfigError(Exception):
    """Raised when config.txt cannot be parsed. Names the offending line."""


def load_config(path):
    """
    Parse the config file at *path* into a dict of strings.

    A missing file gives back an empty dict, since the tool runs on defaults
    when it is unconfigured and the caller does its own warning. A file that
    exists but does not parse raises ConfigError instead, because this config
    decides firewall rules and a bad line should stop us.
    """
    path = Path(path)
    if not path.exists():
        return {}
    return loads(path.read_text(encoding="utf-8"), source=str(path))


def loads(text, source="<config>"):
    """Parse env-file *text*. See load_config for the accepted syntax."""
    values = {}
    lines = text.splitlines()
    index = 0

    while index < len(lines):
        lineno = index + 1
        line = lines[index].strip()
        index += 1

        if not line or line.startswith("#"):
            continue

        if line.startswith("export ") or line.startswith("export\t"):
            line = line[len("export"):].lstrip()

        key, sep, value = line.partition("=")
        if not sep:
            raise ConfigError(f"{source}:{lineno}: expected KEY=VALUE, got: {line}")

        key = key.strip()
        if not key or any(c.isspace() for c in key):
            raise ConfigError(f"{source}:{lineno}: invalid key: {key!r}")

        value = value.lstrip()
        if value[:1] in ("'", '"'):
            quote = value[0]
            parsed, rest, closed = _scan_quoted(value[1:], quote)
            # A quote left open keeps going on the next lines. That is what
            # lets a list of UUIDs sit one per line instead of all on one.
            while not closed:
                if index >= len(lines):
                    raise ConfigError(
                        f"{source}:{lineno}: unterminated {quote} quote in {key}"
                    )
                more, rest, closed = _scan_quoted(lines[index], quote)
                parsed += "\n" + more
                index += 1
            trailing = rest.strip()
            if trailing and not trailing.startswith("#"):
                raise ConfigError(
                    f"{source}:{lineno}: unexpected text after closing quote in {key}: {trailing}"
                )
            values[key] = parsed
        else:
            values[key] = _strip_comment(value).strip()

    return values


def _scan_quoted(text, quote):
    """
    Read a quoted value from *text*, starting just past the opening quote.

    Returns (parsed, remainder, closed). closed is False when the quote is
    still open at the end of the line, and the caller picks up on the next one.
    """
    escaping = quote == '"'
    out = []
    i = 0
    while i < len(text):
        char = text[i]
        if escaping and char == "\\" and i + 1 < len(text):
            nxt = text[i + 1]
            out.append(_ESCAPES.get(nxt, "\\" + nxt))
            i += 2
            continue
        if char == quote:
            return "".join(out), text[i + 1:], True
        out.append(char)
        i += 1
    return "".join(out), "", False


def _strip_comment(value):
    """
    Drop a trailing comment from an unquoted value.

    A '#' only starts a comment if there is whitespace in front of it, so a
    password or URL fragment with a '#' in the middle is left alone.
    """
    for i, char in enumerate(value):
        if char == "#" and (i == 0 or value[i - 1] in " \t"):
            return value[:i]
    return value
