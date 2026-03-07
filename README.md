# nft-blacklist

`nft-blacklist` builds and applies nftables sets from public IP blocklists.

This project has migrated from a Bash implementation to a Python implementation with the same goal and the same core feature set: fetch blacklists, normalize and collapse CIDRs, keep IPv4/IPv6 whitelists, generate an nft ruleset, and optionally apply it.

## Migration Summary

- Old entrypoint: `nft-blacklist.sh`
- New entrypoint: `nft-blacklist.py`
- Config format: still Bash-style `KEY=value` and arrays (for example `BLACKLISTS=(...)`)
- Ruleset behavior: same table/chain/set/counter model for IPv4 and IPv6

## Features

- IPv4 and IPv6 blacklist ingestion from multiple sources.
- Supports `http(s)://` and `file://` blacklist URLs.
- Tolerant parser for noisy feeds (extracts leading IP/CIDR tokens even with trailing metadata).
- Filters reserved/local ranges:
  - IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, multicast and reserved ranges.
  - IPv6: link-local `fe80::/10`.
- Canonicalization and overlap removal using Python `ipaddress.collapse_addresses`.
- Separate nft sets for host and network entries (`*_host`, `*_net`) for both IPv4 and IPv6.
- Optional whitelist rules (`IP_WHITELIST`, `IP6_WHITELIST`).
- Bulk nft apply with automatic fallback for `File exists` element conflicts.

## Requirements

- Linux with nftables (`nft` command).
- Python 3.
- Python package `requests`.

```sh
sudo apt install python3-requests
```

## Quick Start

1. Copy script and config:

```sh
install -m 0755 nft-blacklist.py /usr/local/bin/nft-blacklist.py
install -m 0644 nft-blacklist.conf /etc/nft-blacklist/nft-blacklist.conf
mkdir -p /var/cache/nft-blacklist
```

2. Edit `/etc/nft-blacklist/nft-blacklist.conf`.

3. Run:

```sh
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.conf
```

By default, the generated ruleset file is written to `/var/cache/nft-blacklist/blacklist.nft`.

## Usage

```sh
nft-blacklist.py -c <config-file> [-o <ruleset-file>] [--apply|--no-apply] [--nft "nft"]
```

Examples:

```sh
# Generate and apply (default when DRY_RUN=no)
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.conf

# Generate only, do not apply
/usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.conf --no-apply

# Use custom nft command
sudo /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.conf --nft "sudo /sbin/nft"
```

## Configuration

The Python script reads a Bash-style config file and supports these keys:

- `BLACKLISTS` (array, required)
- `TABLE` (default: `blackhole`)
- `CHAIN` (default: `input`)
- `HOOK` (default: `input`)
- `IP_WHITELIST` (comma-separated string)
- `IP6_WHITELIST` (comma-separated string)
- `DRY_RUN` (`yes/no`, `true/false`, `1/0`)
- `VERBOSE` (`yes/no`, `true/false`, `1/0`)
- `NFT` (optional command override, for example `sudo /sbin/nft`)

Notes:

- `BLACKLISTS` accepts URLs and local files via `file:///path/to/list`.
- `DRY_RUN=yes` means generate only; `DRY_RUN=no` means apply after generation.
- CLI flags `--apply` and `--no-apply` override `DRY_RUN`.

## Cron

Run once per day to refresh and apply:

```sh
PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
MAILTO=root
33 23 * * * root /usr/local/bin/nft-blacklist.py -c /etc/nft-blacklist/nft-blacklist.conf
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
