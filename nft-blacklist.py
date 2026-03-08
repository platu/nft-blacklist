#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import logging
import re
import shlex
import subprocess  # nosec B404
import sys
import time
import tomllib
from collections.abc import Iterator
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests

PRIVATE_V4: list[ipaddress.IPv4Network] = [
    ipaddress.IPv4Network("0.0.0.0/8"),
    ipaddress.IPv4Network("10.0.0.0/8"),
    ipaddress.IPv4Network("127.0.0.0/8"),
    ipaddress.IPv4Network("172.16.0.0/12"),
    ipaddress.IPv4Network("192.168.0.0/16"),
    ipaddress.IPv4Network("224.0.0.0/4"),
    ipaddress.IPv4Network("240.0.0.0/4"),
]
LINKLOCAL_V6: list[ipaddress.IPv6Network] = [
    ipaddress.IPv6Network("fe80::/10"),
]

# Match a leading IPv4/IPv6 token, optionally with a prefix length.
ELEMENT_LINE = re.compile(
    r"^add element inet "
    r"(?P<table>\S+) "
    r"(?P<set_name>\S+) "
    r"\{ (?P<elements>.*) \}$"
)
ADD_ELEMENT_PREFIX = "add element inet "
USER_AGENT = "nft-blacklist/1.0 (https://github.com/platu/nft-blacklist)"
OUTPUT_DEFAULT = "/var/cache/nft-blacklist/blacklist.nft"


def parse_conf(path: Path) -> dict:
    """Load TOML configuration."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def fetch_urls(urls: list[str], timeout: int = 10) -> Iterator[str]:
    """Fetch all IP lists concurrently and yield stripped lines."""
    user_agent_header = {"User-Agent": USER_AGENT}

    # Reuse one session for connection pooling (faster).
    session = requests.Session()
    session.headers.update(user_agent_header)

    def fetch_single(url: str) -> list[str]:
        """Local helper to fetch one URL."""
        parsed = urlparse(url)
        if parsed.scheme == "file":
            path = Path(unquote(parsed.path))
            try:
                content = path.read_text(encoding="utf-8", errors="replace")
                return content.splitlines()
            except OSError as exc:
                logging.warning(f"File read error: {url} -> {exc}")
                return []

        try:
            r = session.get(url, timeout=timeout)
            # Raise for HTTP errors (404, 500, etc.).
            r.raise_for_status()
            return r.text.splitlines()
        except requests.RequestException as exc:
            logging.warning(f"Download failed: {url} -> {exc}")
            return []

    # Fetch URLs in parallel using 5 worker threads.
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for lines in executor.map(fetch_single, urls):
            for line in lines:
                # Trim and ignore empty lines.
                if line_stripped := line.strip():
                    yield line_stripped


def parse_ips(
    lines: list[str],
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    """Parse raw text lines into IPv4 and IPv6 network objects."""
    v4: list[ipaddress.IPv4Network] = []
    v6: list[ipaddress.IPv6Network] = []

    for line in lines:
        # Remove trailing comments and surrounding whitespace.
        line = line.split("#")[0].split(";")[0].split("$")[0].strip()
        if not line:
            continue

        # Take the first token that looks like an IP/network.
        token = line.split()[0]

        try:
            net = ipaddress.ip_network(token, strict=False)
            if net.version == 4:
                v4.append(net)  # type: ignore
            else:
                v6.append(net)  # type: ignore
        except ValueError:
            # Ignore non-IP tokens.
            continue

    return v4, v6


def drop_reserved(
    v4_list: list[ipaddress.IPv4Network], v6_list: list[ipaddress.IPv6Network]
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    """Filter out private, loopback, and multicast addresses."""
    v4_filtered = [
        n
        for n in v4_list
        if not (n.is_private or n.is_loopback or n.is_multicast)
    ]
    v6_filtered = [
        n
        for n in v6_list
        if not (n.is_link_local or n.is_loopback or n.is_multicast)
    ]
    return v4_filtered, v6_filtered


def collapse_family(
    nets: list, version: int, do_optimize: bool = True
) -> tuple[list[str], list[str]]:
    """Deduplicate and optionally merge overlapping networks."""
    filtered_nets = [n for n in nets if n.version == version]
    unique_nets = set(filtered_nets)
    sorted_nets = sorted(list(unique_nets))

    if do_optimize:
        collapsed = list(ipaddress.collapse_addresses(sorted_nets))
    else:
        collapsed = sorted_nets

    hosts: list[str] = []
    nets_out: list[str] = []

    for net in collapsed:
        if (version == 4 and net.prefixlen == 32) or (
            version == 6 and net.prefixlen == 128
        ):
            hosts.append(str(net.network_address))
        else:
            nets_out.append(str(net.with_prefixlen))

    return hosts, nets_out


def run_subprocess(
    cmd: list[str],
    error_msg: str,
    capture_output: bool = False,
    check: bool = True,
    input_data: str | None = None,
) -> subprocess.CompletedProcess:
    """Run a subprocess command with standardized error handling."""
    try:
        if capture_output:
            result = subprocess.run(  # nosec B603
                cmd,
                capture_output=True,
                input=input_data,
                text=True,
                check=check,
            )
        else:
            result = subprocess.run(  # nosec B603
                cmd,
                stdout=sys.stdout,
                stderr=sys.stderr,
                input=input_data,
                text=True,
                check=check,
            )
        return result
    except subprocess.CalledProcessError as exc:
        details = (exc.stderr or str(exc)).strip()
        logging.error(f"{error_msg}: {details}")
        sys.exit(1)
    except FileNotFoundError:
        logging.error(f"Command not found: {cmd[0]}")
        sys.exit(1)


def _expand_element_line(line: str) -> list[str]:
    """Expand a bulk add element command into one command per element."""
    m = ELEMENT_LINE.match(line)
    if not m:
        return [line]

    table = m.group("table")
    set_name = m.group("set_name")
    elements = [e.strip() for e in m.group("elements").split(",") if e.strip()]
    if not elements:
        return [line]

    expanded = []
    for element in elements:
        expanded.append(f"add element inet {table} {set_name} {{ {element} }}")
    return expanded


def _run_nft_inline(nft_cmd: str, payload: str) -> subprocess.CompletedProcess:
    """Run nft via stdin instead of writing temporary files."""
    cmd = shlex.split(nft_cmd) + ["-f", "-"]
    return run_subprocess(
        cmd,
        error_msg="Failed to execute nft via stdin",
        capture_output=True,
        check=False,
        input_data=payload,
    )


def apply_ruleset(ruleset: str, nft_cmd: str, verbose: bool = False) -> None:
    """Apply the ruleset globally, with a graceful element-by-element fallback."""
    result = _run_nft_inline(nft_cmd, ruleset)
    if result.returncode == 0:
        logging.info("Ruleset applied successfully in bulk.")
        return

    stderr = (result.stderr or "") + (result.stdout or "")
    if "File exists" not in stderr:
        raise RuntimeError(stderr.strip() or "Failed to apply nft ruleset.")

    logging.info(
        "Bulk apply hit existing elements; retrying chunk by chunk..."
    )

    lines = ruleset.splitlines()
    base_lines = [
        line for line in lines if not line.startswith(ADD_ELEMENT_PREFIX)
    ]
    element_lines = [
        line for line in lines if line.startswith(ADD_ELEMENT_PREFIX)
    ]

    base_result = _run_nft_inline(nft_cmd, "\n".join(base_lines) + "\n")
    if base_result.returncode != 0:
        msg = (base_result.stderr or "") + (base_result.stdout or "")
        raise RuntimeError(msg.strip() or "Failed to apply base nft ruleset.")

    for chunk in element_lines:
        chunk_result = _run_nft_inline(nft_cmd, chunk + "\n")

        if chunk_result.returncode != 0:
            logging.info("A chunk failed, expanding to individual elements...")

            for element in _expand_element_line(chunk):
                elem_result = _run_nft_inline(nft_cmd, element + "\n")
                if elem_result.returncode != 0:
                    elem_msg = (elem_result.stderr or "") + (
                        elem_result.stdout or ""
                    )
                    if "File exists" in elem_msg:
                        logging.debug(f"Skipping existing element: {element}")
                    else:
                        logging.error(
                            f"Error on element {element}: {elem_msg.strip()}"
                        )


def generate_ruleset(
    table: str,
    chain: str,
    hook: str,
    priority: str,
    v4_hosts: list[str],
    v4_nets: list[str],
    v6_hosts: list[str],
    v6_nets: list[str],
    v4_whitelist: list[str] | None = None,
    v6_whitelist: list[str] | None = None,
) -> str:
    """Generate the full raw nftables ruleset string."""
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    set_pref = "blacklist"
    counter_v4 = f"{set_pref}_v4"
    counter_v6 = f"{set_pref}_v6"
    s4_host = f"{set_pref}_v4_host"
    s4_net = f"{set_pref}_v4_net"
    s6_host = f"{set_pref}_v6_host"
    s6_net = f"{set_pref}_v6_net"

    base_lines = [
        f"# Generated {created_at}",
        f"add table inet {table}",
        f"add counter inet {table} {counter_v4}",
        f"add counter inet {table} {counter_v6}",
        "",
        f"add set inet {table} {s4_host} {{ type ipv4_addr; }}",
        f"flush set inet {table} {s4_host}",
        (
            f"add set inet {table} {s4_net} "
            "{ type ipv4_addr; flags interval; auto-merge; }"
        ),
        f"flush set inet {table} {s4_net}",
        "",
        f"add set inet {table} {s6_host} {{ type ipv6_addr; }}",
        f"flush set inet {table} {s6_host}",
        (
            f"add set inet {table} {s6_net} "
            "{ type ipv6_addr; flags interval; auto-merge; }"
        ),
        f"flush set inet {table} {s6_net}",
        "",
        (
            f"add chain inet {table} {chain} "
            f"{{ type filter hook {hook} priority {priority}; policy accept; }}"
        ),
        f"flush chain inet {table} {chain}",
        f'add rule inet {table} {chain} iif "lo" accept',
        f"add rule inet {table} {chain} meta pkttype {{ broadcast, multicast }} accept",
    ]

    lines = base_lines

    if v4_whitelist:
        lines.append(
            f"add rule inet {table} {chain} "
            f"ip saddr {{ {', '.join(v4_whitelist)} }} accept"
        )
    if v6_whitelist:
        lines.append(
            f"add rule inet {table} {chain} "
            f"ip6 saddr {{ {', '.join(v6_whitelist)} }} accept"
        )

    lines.extend(
        [
            (
                f"add rule inet {table} {chain} ip saddr @{s4_host} "
                f"counter name {counter_v4} drop"
            ),
            (
                f"add rule inet {table} {chain} ip saddr @{s4_net} "
                f"counter name {counter_v4} drop"
            ),
            (
                f"add rule inet {table} {chain} ip6 saddr @{s6_host} "
                f"counter name {counter_v6} drop"
            ),
            (
                f"add rule inet {table} {chain} ip6 saddr @{s6_net} "
                f"counter name {counter_v6} drop"
            ),
        ]
    )

    def add_elements(
        name: str, elems: list[str], chunk_size: int = 1000
    ) -> None:
        if not elems:
            return

        for i in range(0, len(elems), chunk_size):
            batch = elems[i : i + chunk_size]
            joined_batch = ", ".join(batch)
            lines.append(
                f"add element inet {table} {name} {{ {joined_batch} }}"
            )

    add_elements(s4_host, v4_hosts)
    add_elements(s4_net, v4_nets)
    add_elements(s6_host, v6_hosts)
    add_elements(s6_net, v6_nets)

    return "\n".join(lines) + "\n"


def main() -> None:
    p = argparse.ArgumentParser()
    p.add_argument("-c", "--config", help="simple config file", required=True)
    p.add_argument("-o", "--output", default=OUTPUT_DEFAULT)
    p.add_argument(
        "--nft",
        default=None,
        help="nft command, e.g. 'nft' or 'sudo /sbin/nft'",
    )
    apply_group = p.add_mutually_exclusive_group()
    apply_group.add_argument(
        "--apply",
        dest="apply",
        action="store_true",
        help="apply ruleset via nft",
    )
    apply_group.add_argument(
        "--no-apply",
        dest="apply",
        action="store_false",
        help="only write ruleset file",
    )
    p.set_defaults(apply=None)
    args = p.parse_args()

    cfg_path = Path(args.config)
    cfg = parse_conf(cfg_path)

    dry_run: bool = cfg.get("DRY_RUN", False)
    verbose: bool = cfg.get("VERBOSE", False)

    # Configure logging based on verbosity
    log_level = logging.INFO if verbose else logging.WARNING
    logging.basicConfig(level=log_level, format="%(levelname)s: %(message)s")

    urls: list[str] = cfg.get("BLACKLISTS", [])
    table: str = cfg.get("TABLE", "blackhole")
    chain: str = cfg.get("CHAIN", "input")
    hook: str = cfg.get("HOOK", "input")
    priority: str = cfg.get("PRIORITY", "filter - 1")

    v4_whitelist: list[str] = cfg.get("IP_WHITELIST", [])
    v6_whitelist: list[str] = cfg.get("IP6_WHITELIST", [])

    do_optimize_cidr: bool = cfg.get("DO_OPTIMIZE_CIDR", True)
    nft_cmd: str = args.nft or cfg.get("NFT", "nft")

    raw_lines = list(fetch_urls(urls))
    v4, v6 = parse_ips(raw_lines)
    v4, v6 = drop_reserved(v4, v6)

    v4_hosts, v4_nets = collapse_family(v4, 4, do_optimize=do_optimize_cidr)
    v6_hosts, v6_nets = collapse_family(v6, 6, do_optimize=do_optimize_cidr)

    ruleset = generate_ruleset(
        table,
        chain,
        hook,
        priority,
        v4_hosts,
        v4_nets,
        v6_hosts,
        v6_nets,
        v4_whitelist,
        v6_whitelist,
    )
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(ruleset, encoding="utf-8")

    should_apply = args.apply if args.apply is not None else (not dry_run)
    if should_apply:
        apply_ruleset(ruleset, nft_cmd=nft_cmd, verbose=verbose)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logging.error(f"Fatal Error: {exc}")
        sys.exit(1)
