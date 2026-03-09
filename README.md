# nft-blacklist

`nft-blacklist` builds and applies nftables sets from public IP blocklists.

This repository uses a Python implementation (`nft-blacklist.py`) with TOML configuration (`nft-blacklist.toml`). It keeps the same operational goal while improving maintainability, parsing robustness, and nftables application safety (including bulk apply with graceful fallback when elements already exist).

For high-volume filtering with lower resource consumption, you can place blacklist drops in a dedicated chain in the nftables `raw` table. Since `raw` is evaluated before connection tracking, matching packets are dropped early in a stateless path, avoiding unnecessary `conntrack` lookups and reducing CPU overhead under noisy or abusive traffic.

Core workflow: fetch blocklists, parse and normalize IP/CIDR entries, collapse ranges, generate an nft ruleset, and optionally apply it.

## Features

- IPv4 and IPv6 blacklist ingestion from multiple sources.
- Supports `http(s)://` and `file://` blacklist URLs.
- Tolerant parser for noisy feeds (extracts leading IP/CIDR tokens even with trailing metadata).
- Filters reserved/local ranges before rule generation:
  - IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, multicast and reserved ranges.
  - IPv6: link-local `fe80::/10`.
- Canonicalization and overlap removal using Python `ipaddress.collapse_addresses`.
- Separate nft sets for host and network entries (`*_host`, `*_net`) for both IPv4 and IPv6.
- Optional whitelist rules (`IP_WHITELIST`, `IP6_WHITELIST`).
- Bulk nft apply with automatic fallback for `File exists` element conflicts.

## Requirements

- Linux with nftables (`nft` command).
- Python 3.11+ (uses `tomllib` from the standard library).
- Python package: `requests`.

## Quick Start

1. Copy script and config:

```sh
sudo mkdir -p /var/cache/nft-blacklist /etc/nft-blacklist
sudo install -m 0755 nft-blacklist.py /usr/local/bin/nft-blacklist.py
sudo install -m 0644 nft-blacklist.toml /etc/nft-blacklist/nft-blacklist.toml
```

2. Edit `/etc/nft-blacklist/nft-blacklist.toml`.

3. Run:

```sh
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml
```

By default, the generated ruleset file is written to `/var/cache/nft-blacklist/blacklist.nft`.

## Usage

```sh
nft-blacklist.py -c <config-file> [-o <ruleset-file>] [--apply|--no-apply] [--nft "nft"]
```

Examples:

```sh
# Generate and apply (default when DRY_RUN=no)
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml

# Generate only, do not apply
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml --no-apply

# Use custom nft command
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml --nft "sudo /sbin/nft"
```

## Configuration

The script reads a TOML file and supports these keys:

- `BLACKLISTS` (`list[str]`, required)
- `TABLE` (`str`, default: `blackhole`, recommended profile: `raw`)
- `CHAIN` (`str`, default: `input`, recommended profile: `prerouting`)
- `HOOK` (`str`, default: `input`, recommended profile: `prerouting`)
- `PRIORITY` (`str`, default: `filter - 1`, recommended profile: `raw`)
- `IP_WHITELIST` (`list[str]`)
- `IP6_WHITELIST` (`list[str]`)
- `DO_OPTIMIZE_CIDR` (`bool`, default: `true`)
- `DRY_RUN` (`bool`, default: `false`)
- `VERBOSE` (`bool`, default: `false`)
- `NFT` (optional command override, for example `sudo /sbin/nft`)

Notes:

- `BLACKLISTS` accepts URLs and local files via `file:///path/to/list`.
- Runtime defaults are kept for backward compatibility.
- For stateless pre-conntrack filtering, use `TABLE="raw"`, `CHAIN="prerouting"`, `HOOK="prerouting"`, and `PRIORITY="raw"`.
- `DRY_RUN=true` means generate only; `DRY_RUN=false` means apply after generation.
- CLI flags `--apply` and `--no-apply` override `DRY_RUN`.

Minimal example (`/etc/nft-blacklist/nft-blacklist.toml`):

```toml
BLACKLISTS = [
  "https://www.spamhaus.org/drop/drop.lasso",
  "https://www.spamhaus.org/drop/dropv6.txt",
]

TABLE = "raw"
CHAIN = "prerouting"
HOOK = "prerouting"
PRIORITY = "raw"

IP_WHITELIST = ["192.0.2.0/24"]
IP6_WHITELIST = ["fd00::/8"]

DO_OPTIMIZE_CIDR = true
DRY_RUN = false
VERBOSE = true
```

## Cron

Run once per day to refresh and apply:

```sh
cat <<EOF | sudo tee /etc/cron.d/nft-blasklist
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
33 */6 * * * root /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml
EOF
```

## Check Dropped Packets

```sh
sudo nft list counter inet raw blacklist_v4
sudo nft list counter inet raw blacklist_v6
```

## Blacklist Sources

Edit `BLACKLISTS` in `nft-blacklist.toml` to add/remove providers:

```toml
BLACKLISTS = [
  "https://example.org/blacklist.txt",
  "file:///etc/nft-blacklist/custom.list",
]
```

For country or ASN aggregated lists, you can use providers such as IPverse and FireHOL feeds.
