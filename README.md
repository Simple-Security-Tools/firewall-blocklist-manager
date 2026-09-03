# Firewall Blocklist Manager

One authoritative IP blocklist for hybrid environments — enforced at the network
edge and in cloud identity from a single source of truth.

Rules live in a local SQLite database with full audit history, expiration and
whitelist protection. The same rule set publishes to flat files for firewall
ingestion and to a Microsoft Entra Conditional Access Named Location, so the
perimeter and Conditional Access cannot drift apart. Publishing is deliberately
separate from rule management: additional targets can be added without changing
how rules are written, reviewed or audited.

Full command reference: [DOCUMENTATION.md](DOCUMENTATION.md), or run
`python BlocklistManager.py --help`.

## Quickstart

```bash
python3 -m venv .venv
.venv/bin/pip install -r requirements.txt

cp config.txt.example config.txt
cp whitelist.txt.example whitelist.txt   # then edit — see below
```

No `activate` step: use the `./blocklist` launcher, which runs the script with
the project's own interpreter. Activation only edits `PATH`, and the launcher
names `.venv/bin/python` directly instead.

Edit `whitelist.txt` before adding any rules. It lists the networks that must
never be blocked. Until it exists, nothing is protected and the tool warns on
every run.

Then:

```bash
./blocklist block 45.33.32.156
./blocklist list
./blocklist export
```

To run it from anywhere, symlink the launcher onto your `PATH`:

```bash
ln -s "$PWD/blocklist" ~/bin/blocklist
```

The launcher resolves symlinks to find its own install directory, and the tool
keeps its database, logs, rules, reports, backups, config and whitelist there —
never in the directory you happen to be standing in. So `blocklist list` from
anywhere reads the same database, and the whitelist is always enforced.

`python BlocklistManager.py ...` still works if you prefer, as long as you use
the venv's interpreter (`.venv/bin/python`).

`block`, `allow` and `remove` prompt for an incident/ticket ID, a comment, and
an expiration; every change is written to `logs/audit.log` and the
`audit_history` table.

## How rules interact

Adding a rule that covers existing narrower rules marks those as **redundant**
so exports stay compact. Redundancy is not permanent:

- Remove the covering rule and its children are reactivated under the new
  incident ID.
- Let the covering rule **expire** and its children are reactivated on the next
  run, with a `REACTIVATED` audit entry.

This means a temporary wide sweep never silently cancels a narrower permanent
block. `purge` deletes redundant records for good and warns first if any of
them have no expiration.

## Configuration

`config.txt` is gitignored — it holds your Entra client secret. See
[config.txt.example](config.txt.example) for every key. `sync` additionally
requires `TENANT_ID`, `CLIENT_ID`, `SECRET` and `BLOCKLIST_NAMED_LOCATION_ID`,
and backs up the current Named Location to `backups/` as JSON before
overwriting it.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest tests/ -q
```

## Notes

- Only globally routable addresses are accepted, with no override. Private,
  loopback, link-local and reserved ranges are refused at entry and filtered
  again at export and sync, because Entra accepts them silently rather than
  rejecting them.
- Plain IPv4 is treated as `/32`, plain IPv6 as `/64`.
- Known gaps against Entra Named Location limits are tracked in
  [TODO.txt](TODO.txt).
