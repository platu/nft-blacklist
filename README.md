# nft-blacklist

The aim of this fork is to update and enhance the original project. It replaces shell parsing with a typed Python implementation and uses the TOML configuration format. It also incorporates safer nftables application logic, including the ability to apply in bulk with graceful fallback when elements already exist. The ipAddress Python module is used extensively to verify against address conflicts or duplication. The intention is to maintain the same operational purpose while improving maintainability.

`nft-blacklist` builds and applies nftables sets from public IP blocklists.

The current implementation is Python-based (`nft-blacklist.py`) and keeps the core workflow: fetch blocklists, parse and normalize IP/CIDR entries, collapse ranges, generate an nft ruleset, and optionally apply it.

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

```sh
sudo apt install python3-requests
```

## Quick Start

1. Copy script and config:

```sh
install -m 0755 nft-blacklist.py /usr/local/bin/nft-blacklist.py
install -m 0644 nft-blacklist.toml /etc/nft-blacklist/nft-blacklist.toml
mkdir -p /var/cache/nft-blacklist
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
/usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml --no-apply

# Use custom nft command
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml --nft "sudo /sbin/nft"
```

## Configuration

The script reads a TOML file and supports these keys:

- `BLACKLISTS` (`list[str]`, required)
- `TABLE` (default: `blackhole`)
- `CHAIN` (default: `input`)
- `HOOK` (default: `input`)
- `IP_WHITELIST` (`list[str]`)
- `IP6_WHITELIST` (`list[str]`)
- `DO_OPTIMIZE_CIDR` (`bool`, default: `true`)
- `DRY_RUN` (`bool`, default: `false`)
- `VERBOSE` (`bool`, default: `false`)
- `NFT` (optional command override, for example `sudo /sbin/nft`)

Notes:

- `BLACKLISTS` accepts URLs and local files via `file:///path/to/list`.
- `DRY_RUN=true` means generate only; `DRY_RUN=false` means apply after generation.
- CLI flags `--apply` and `--no-apply` override `DRY_RUN`.

Minimal example (`/etc/nft-blacklist/nft-blacklist.toml`):

```toml
BLACKLISTS = [
  "https://www.spamhaus.org/drop/drop.lasso",
  "https://www.spamhaus.org/drop/dropv6.txt",
]

TABLE = "blackhole"
CHAIN = "input"
HOOK = "input"

IP_WHITELIST = ["192.0.2.0/24"]
IP6_WHITELIST = ["fd00::/8"]

DO_OPTIMIZE_CIDR = true
DRY_RUN = false
VERBOSE = true
```

## Cron

Run once per day to refresh and apply:

```sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
33 */6 * * * root /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.toml
```

## Check Dropped Packets

```sh
sudo nft list counter inet blackhole blacklist_v4
sudo nft list counter inet blackhole blacklist_v6
```

## Blacklist Sources

Edit `BLACKLISTS` in `nft-blacklist.conf` to add/remove providers:

```sh
BLACKLISTS=(
    "https://example.org/blacklist.txt"
    "file:///etc/nft-blacklist/custom.list"
)
```

For country or ASN aggregated lists, you can use providers such as IPverse and FireHOL feeds.
