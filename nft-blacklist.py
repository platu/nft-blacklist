#!/usr/bin/env python3
import argparse
import ipaddress
import re
import shlex
import subprocess  # nosec B404
import sys
import tempfile
import time
import tomllib
from pathlib import Path
from urllib.parse import unquote, urlparse

import requests

PRIVATE_V4 = [
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
]
LINKLOCAL_V6 = [
    ipaddress.ip_network("fe80::/10"),
]

# Match a leading IPv4/IPv6 token, optionally with a prefix length.
LEADING_NET_TOKEN = re.compile(r"^([0-9A-Fa-f:.]+(?:/\d{1,3})?)")


def _strip_comment(line: str) -> str:
    """Strip trailing # comment, but keep # if inside quotes."""
    in_single = False
    in_double = False
    for i, ch in enumerate(line):
        if ch == "'" and not in_double:
            in_single = not in_single
        elif ch == '"' and not in_single:
            in_double = not in_double
        elif ch == "#" and not in_single and not in_double:
            return line[:i]
    return line


def parse_conf(path: Path) -> dict:
    """Charge la configuration TOML."""
    with open(path, "rb") as f:
        return tomllib.load(f)


def parse_bool(value, default=False):
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    s = str(value).strip().lower()
    if s in {"1", "on", "true", "yes"}:
        return True
    if s in {"0", "off", "false", "no"}:
        return False
    return default


def parse_whitelist(value):
    if value is None:
        return []
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    return [part.strip() for part in str(value).split(",") if part.strip()]


def _normalize_v4_token(token: str) -> str:
    if "." not in token:
        return token
    addr, slash, prefix = token.partition("/")
    octets = addr.split(".")
    if len(octets) != 4:
        return token
    try:
        normalized = ".".join(str(int(o, 10)) for o in octets)
    except ValueError:
        return token
    return f"{normalized}/{prefix}" if slash else normalized


def _extract_network_token(line: str) -> str | None:
    m = LEADING_NET_TOKEN.match(line)
    if not m:
        return None
    token = m.group(1)
    if "." in token:
        token = _normalize_v4_token(token)
    return token


def fetch_urls(urls, timeout=10):
    user_agent = {
        "User-Agent": ("nft-blacklist/1.0 " "(https://github.com/platu/nft-blacklist)")
    }
    for url in urls:
        parsed = urlparse(url)
        if parsed.scheme == "file":
            path = Path(unquote(parsed.path))
            try:
                for line in path.read_text(
                    encoding="utf-8", errors="replace"
                ).splitlines():
                    yield line.strip()
            except OSError as exc:
                print(f"# warning: {url} -> {exc}", file=sys.stderr)
            continue

        try:
            r = requests.get(url, timeout=timeout, headers=user_agent)
        except requests.RequestException as exc:
            print(f"# warning: {url} -> {exc}", file=sys.stderr)
            continue
        if r.status_code not in (200, 302):
            print(f"# warning: {url} -> {r.status_code}", file=sys.stderr)
            continue
        for line in r.text.splitlines():
            yield line.strip()


def parse_ips(lines):
    v4, v6 = [], []
    for line in lines:
        if not line or line.startswith(("#", ";", "$")):
            continue
        token = _extract_network_token(line)
        if not token:
            continue
        try:
            net = ipaddress.ip_network(token, strict=False)
        except ValueError:
            continue
        if net.version == 4:
            v4.append(net)
        else:
            v6.append(net)
    return v4, v6


def drop_reserved(v4_list, v6_list):
    def keep_v4(n):
        return not any(n.subnet_of(p) for p in PRIVATE_V4)

    def keep_v6(n):
        return not any(n.subnet_of(p) for p in LINKLOCAL_V6)

    v4_filtered = [n for n in v4_list if keep_v4(n)]
    v6_filtered = [n for n in v6_list if keep_v6(n)]
    return v4_filtered, v6_filtered


def collapse_family(nets, version):
    nets = [n for n in nets if n.version == version]
    collapsed = ipaddress.collapse_addresses(nets)
    hosts, nets_out = [], []
    for net in collapsed:
        if (version == 4 and net.prefixlen == 32) or (
            version == 6 and net.prefixlen == 128
        ):
            hosts.append(str(net.network_address))
        else:
            nets_out.append(str(net.with_prefixlen))
    return hosts, nets_out


def _run_nft_file(nft_cmd: str, ruleset_path: Path):
    cmd = shlex.split(nft_cmd) + ["-f", str(ruleset_path)]
    return subprocess.run(cmd, text=True, capture_output=True)  # nosec B603


def apply_ruleset(ruleset: str, nft_cmd: str, verbose=False):
    with tempfile.NamedTemporaryFile(
        "w", encoding="utf-8", suffix=".nft", delete=False
    ) as tmp:
        tmp.write(ruleset)
        tmp_path = Path(tmp.name)

    try:
        result = _run_nft_file(nft_cmd, tmp_path)
        if result.returncode == 0:
            return

        stderr = (result.stderr or "") + (result.stdout or "")
        if "File exists" not in stderr:
            raise RuntimeError(stderr.strip() or "failed to apply nft ruleset")

        if verbose:
            print(
                "Bulk apply hit existing elements; retrying with fallback mode...",
                file=sys.stderr,
            )

        lines = ruleset.splitlines()
        base_lines = [
            line_text
            for line_text in lines
            if not line_text.startswith("add element inet ")
        ]
        element_lines = [
            line_text
            for line_text in lines
            if line_text.startswith("add element inet ")
        ]

        with tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", suffix=".nft", delete=False
        ) as base_tmp:
            base_tmp.write("\n".join(base_lines) + "\n")
            base_path = Path(base_tmp.name)

        one_path = None
        try:
            base_result = _run_nft_file(nft_cmd, base_path)
            if base_result.returncode != 0:
                msg = (base_result.stderr or "") + (base_result.stdout or "")
                raise RuntimeError(msg.strip() or "failed to apply base nft ruleset")

            for element in element_lines:
                with tempfile.NamedTemporaryFile(
                    "w", encoding="utf-8", suffix=".nft", delete=False
                ) as one_tmp:
                    one_tmp.write(element + "\n")
                    one_path = Path(one_tmp.name)

                elem_result = _run_nft_file(nft_cmd, one_path)
                if elem_result.returncode != 0:
                    elem_msg = (elem_result.stderr or "") + (elem_result.stdout or "")
                    if "File exists" in elem_msg:
                        if verbose:
                            print(
                                f"Skipping existing element: {element}", file=sys.stderr
                            )
                        continue
                    raise RuntimeError(
                        (elem_msg.strip() + "\n" if elem_msg.strip() else "")
                        + f"failed to apply ruleset element: {element}"
                    )
        finally:
            base_path.unlink(missing_ok=True)
            if one_path is not None:
                one_path.unlink(missing_ok=True)
    finally:
        tmp_path.unlink(missing_ok=True)


def generate_ruleset(
    table,
    chain,
    hook,
    v4_hosts,
    v4_nets,
    v6_hosts,
    v6_nets,
    v4_whitelist=None,
    v6_whitelist=None,
):
    created_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    set_pref = "blacklist"
    counter_v4 = f"{set_pref}_v4"
    counter_v6 = f"{set_pref}_v6"
    s4_host = f"{set_pref}_v4_host"
    s4_net = f"{set_pref}_v4_net"
    s6_host = f"{set_pref}_v6_host"
    s6_net = f"{set_pref}_v6_net"

    lines = []
    lines.append(f"# Generated {created_at}")
    lines.append(f"add table inet {table}")
    lines.append(f"add counter inet {table} {counter_v4}")
    lines.append(f"add counter inet {table} {counter_v6}")
    lines.append(f"add set inet {table} {s4_host} {{ type ipv4_addr; }}")
    lines.append(f"flush set inet {table} {s4_host}")
    lines.append(
        f"add set inet {table} {s4_net} {{ type ipv4_addr; flags interval; auto-merge; }}"
    )
    lines.append(f"flush set inet {table} {s4_net}")
    lines.append(f"add set inet {table} {s6_host} {{ type ipv6_addr; }}")
    lines.append(f"flush set inet {table} {s6_host}")
    lines.append(
        f"add set inet {table} {s6_net} {{ type ipv6_addr; flags interval; auto-merge; }}"
    )
    lines.append(f"flush set inet {table} {s6_net}")
    lines.append(
        f"add chain inet {table} {chain} {{ type filter hook {hook} "
        f"priority filter - 1; policy accept; }}"
    )
    lines.append(f"flush chain inet {table} {chain}")
    lines.append(f'add rule inet {table} {chain} iif "lo" accept')
    lines.append(
        f"add rule inet {table} {chain} meta pkttype {{ broadcast, multicast }} accept"
    )

    if v4_whitelist:
        lines.append(
            f"add rule inet {table} {chain} ip saddr {{ {', '.join(v4_whitelist)} }} accept"
        )
    if v6_whitelist:
        lines.append(
            f"add rule inet {table} {chain} ip6 saddr {{ {', '.join(v6_whitelist)} }} accept"
        )

    lines.append(
        f"add rule inet {table} {chain} ip saddr @{s4_host} "
        f"counter name {counter_v4} drop"
    )
    lines.append(
        f"add rule inet {table} {chain} ip saddr @{s4_net} "
        f"counter name {counter_v4} drop"
    )
    lines.append(
        f"add rule inet {table} {chain} ip6 saddr @{s6_host} "
        f"counter name {counter_v6} drop"
    )
    lines.append(
        f"add rule inet {table} {chain} ip6 saddr @{s6_net} "
        f"counter name {counter_v6} drop"
    )

    def add_elements(name, elems):
        if not elems:
            return
        # single big command for speed
        chunks = []
        cur_len = 0
        for e in elems:
            s = e + ", "
            if cur_len + len(s) > 60000:  # avoid giant lines
                if chunks:
                    lines.append(
                        f"add element inet {table} {name} {{ "
                        + "".join(chunks).rstrip(", ")
                        + " }"
                    )
                chunks = []
                cur_len = 0
            chunks.append(s)
            cur_len += len(s)
        if chunks:
            lines.append(
                f"add element inet {table} {name} {{ "
                + "".join(chunks).rstrip(", ")
                + " }"
            )

    add_elements(s4_host, v4_hosts)
    add_elements(s4_net, v4_nets)
    add_elements(s6_host, v6_hosts)
    add_elements(s6_net, v6_nets)

    return "\n".join(lines) + "\n"


def main():
    p = argparse.ArgumentParser()
    p.add_argument("-c", "--config", help="simple config file", required=True)
    p.add_argument("-o", "--output", default="/var/cache/nft-blacklist/blacklist.nft")
    p.add_argument(
        "--nft", default=None, help="nft command, e.g. 'nft' or 'sudo /sbin/nft'"
    )
    apply_group = p.add_mutually_exclusive_group()
    apply_group.add_argument(
        "--apply", dest="apply", action="store_true", help="apply ruleset via nft"
    )
    apply_group.add_argument(
        "--no-apply", dest="apply", action="store_false", help="only write ruleset file"
    )
    p.set_defaults(apply=None)
    args = p.parse_args()

    # very simple config: Python eval of a dict is fine in your context
    cfg_path = Path(args.config)
    cfg = parse_conf(cfg_path)

    urls = cfg["BLACKLISTS"]
    table = cfg.get("TABLE", "blackhole")
    chain = cfg.get("CHAIN", "input")
    hook = cfg.get("HOOK", "input")
    v4_whitelist = parse_whitelist(cfg.get("IP_WHITELIST", []))
    v6_whitelist = parse_whitelist(cfg.get("IP6_WHITELIST", []))
    dry_run = parse_bool(cfg.get("DRY_RUN", "no"), default=False)
    verbose = parse_bool(cfg.get("VERBOSE", "no"), default=False)
    nft_cmd = args.nft or cfg.get("NFT", "nft")

    raw_lines = list(fetch_urls(urls))
    v4, v6 = parse_ips(raw_lines)
    v4, v6 = drop_reserved(v4, v6)

    v4_hosts, v4_nets = collapse_family(v4, 4)
    v6_hosts, v6_nets = collapse_family(v6, 6)

    ruleset = generate_ruleset(
        table,
        chain,
        hook,
        v4_hosts,
        v4_nets,
        v6_hosts,
        v6_nets,
        v4_whitelist,
        v6_whitelist,
    )
    output_path = Path(args.output)
    output_path.write_text(ruleset, encoding="utf-8")

    should_apply = args.apply if args.apply is not None else (not dry_run)
    if should_apply:
        apply_ruleset(ruleset, nft_cmd=nft_cmd, verbose=verbose)


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"Error: {exc}", file=sys.stderr)
        sys.exit(1)
