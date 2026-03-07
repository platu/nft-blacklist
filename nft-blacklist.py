#!/usr/bin/env python3
import argparse
import concurrent.futures
import ipaddress
import re
import shlex
import subprocess  # nosec B404
import sys
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
ELEMENT_LINE = re.compile(
    r"^add element inet (?P<table>\S+) (?P<set_name>\S+) \{ (?P<elements>.*) \}$"
)


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


def fetch_urls(urls, timeout=10):
    user_agent = {
        "User-Agent": "nft-blacklist/1.0 (https://github.com/platu/nft-blacklist)"
    }

    # Utilisation d'une session pour le Connection Pooling (plus rapide)
    session = requests.Session()
    session.headers.update(user_agent)

    def fetch_single(url: str) -> list[str]:
        """Fonction locale pour traiter une seule URL."""
        parsed = urlparse(url)
        if parsed.scheme == "file":
            path = Path(unquote(parsed.path))
            try:
                return path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError as exc:
                print(f"# warning: {url} -> {exc}", file=sys.stderr)
                return []

        try:
            r = session.get(url, timeout=timeout)
            r.raise_for_status()  # Lève une exception pour tout code d'erreur HTTP (404, 500, etc.)
            return r.text.splitlines()
        except requests.RequestException as exc:
            print(f"# warning: {url} -> {exc}", file=sys.stderr)
            return []

    # Parallélisation des téléchargements avec 5 workers (threads)
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as executor:
        for lines in executor.map(fetch_single, urls):
            for line in lines:
                if line_stripped := line.strip():  # Nettoie et ignore les lignes vides
                    yield line_stripped


def parse_ips(
    lines: list[str],
) -> tuple[list[ipaddress.IPv4Network], list[ipaddress.IPv6Network]]:
    v4, v6 = [], []
    for line in lines:
        # Nettoyage des commentaires et espaces
        line = line.split("#")[0].split(";")[0].split("$")[0].strip()
        if not line:
            continue

        # Extraction du premier élément qui ressemble à une IP/Réseau
        # (souvent les listes contiennent "IP commentaire")
        token = line.split()[0]

        try:
            # ipaddress gère nativement les IP seules (converties en /32 ou /128)
            # et les réseaux. strict=False permet d'accepter "192.168.0.1/24"
            # et de le convertir en "192.168.0.0/24" silencieusement.
            net = ipaddress.ip_network(token, strict=False)
            if net.version == 4:
                v4.append(net)
            else:
                v6.append(net)
        except ValueError:
            # Ce n'était pas une IP valide (ex: un nom de domaine ou un format exotique)
            continue

    return v4, v6


def drop_reserved(v4_list, v6_list):
    # .is_private et .is_link_local sont des attributs beaucoup plus rapides
    # que subnet_of() itéré sur une liste.
    v4_filtered = [
        n
        for n in v4_list
        # On exclut les IP privées (10.x, 192.168.x...), loopback (127.x) et multicast
        if not (n.is_private or n.is_loopback or n.is_multicast)
    ]
    v6_filtered = [
        n for n in v6_list if not (n.is_link_local or n.is_loopback or n.is_multicast)
    ]
    return v4_filtered, v6_filtered


def collapse_family(nets, version, do_optimize=True):
    # 1. Ne garder que la bonne version
    filtered_nets = [n for n in nets if n.version == version]

    # 2. Dé-duplication rapide (Set)
    # Convertir en ensemble élimine instantanément les doublons stricts.
    unique_nets = set(filtered_nets)

    # 3. Tri (Crucial pour les performances de collapse_addresses)
    # ipaddress.collapse_addresses s'attend à un itérable. Le fait de lui
    # fournir une liste déjà triée réduit énormément sa complexité temporelle.
    sorted_nets = sorted(list(unique_nets))

    # 4. Collapse (fusion des sous-réseaux)
    if do_optimize:
        collapsed = list(ipaddress.collapse_addresses(sorted_nets))
    else:
        collapsed = sorted_nets

    hosts = []
    nets_out = []

    # 5. Séparation Hôtes (/32 ou /128) vs Réseaux
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
    """Execute une commande subprocess avec gestion d'erreurs standardisee."""
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
        print(f"{error_msg}: {details}", file=sys.stderr)
        sys.exit(1)
    except FileNotFoundError:
        print(f"Commande non trouvee : {cmd[0]}", file=sys.stderr)
        sys.exit(1)


def _expand_element_line(line: str) -> list[str]:
    """Expand a bulk add element command into one command per element.

    If parsing fails, return the original line so fallback still works.
    """
    m = ELEMENT_LINE.match(line)
    if not m:
        return [line]

    table = m.group("table")
    set_name = m.group("set_name")
    elements = [e.strip() for e in m.group("elements").split(",") if e.strip()]
    if not elements:
        return [line]

    return [
        f"add element inet {table} {set_name} {{ {element} }}" for element in elements
    ]


def _run_nft_inline(nft_cmd: str, payload: str):
    """Exécute nft via stdin au lieu d'utiliser des fichiers sur le disque."""
    cmd = shlex.split(nft_cmd) + ["-f", "-"]
    return run_subprocess(
        cmd,
        error_msg="Erreur lors de l'execution de nft via stdin",
        capture_output=True,
        check=False,
        input_data=payload,
    )


def apply_ruleset(ruleset: str, nft_cmd: str, verbose=False):
    # 1. Tentative d'application globale (très rapide)
    result = _run_nft_inline(nft_cmd, ruleset)
    if result.returncode == 0:
        return

    stderr = (result.stderr or "") + (result.stdout or "")
    if "File exists" not in stderr:
        raise RuntimeError(stderr.strip() or "failed to apply nft ruleset")

    if verbose:
        print(
            "Bulk apply hit existing elements; retrying chunk by chunk...",
            file=sys.stderr,
        )

    # 2. Mode Fallback
    lines = ruleset.splitlines()
    base_lines = [line for line in lines if not line.startswith("add element inet ")]
    element_lines = [line for line in lines if line.startswith("add element inet ")]

    # On applique d'abord la structure (tables, chains, sets vides)
    base_result = _run_nft_inline(nft_cmd, "\n".join(base_lines) + "\n")
    if base_result.returncode != 0:
        msg = (base_result.stderr or "") + (base_result.stdout or "")
        raise RuntimeError(msg.strip() or "failed to apply base nft ruleset")

    # On applique ensuite par blocs (les fameux chunks de 60 000 caractères de generate_ruleset)
    for chunk in element_lines:
        chunk_result = _run_nft_inline(nft_cmd, chunk + "\n")

        # Si un bloc échoue, on passe à l'insertion élément par élément uniquement pour ce bloc
        if chunk_result.returncode != 0:
            if verbose:
                print(
                    "A chunk failed, expanding to individual elements...",
                    file=sys.stderr,
                )

            for element in _expand_element_line(chunk):
                elem_result = _run_nft_inline(nft_cmd, element + "\n")
                if elem_result.returncode != 0 and verbose:
                    elem_msg = (elem_result.stderr or "") + (elem_result.stdout or "")
                    if "File exists" in elem_msg:
                        print(f"Skipping existing element: {element}", file=sys.stderr)
                    else:
                        print(
                            f"Error on element {element}: {elem_msg.strip()}",
                            file=sys.stderr,
                        )


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

    # 1. Génération de l'en-tête et de la structure via une f-string multiligne
    # C'est beaucoup plus lisible qu'une dizaine de `lines.append()`
    ruleset = f"""# Generated {created_at}
add table inet {table}
add counter inet {table} {counter_v4}
add counter inet {table} {counter_v6}

add set inet {table} {s4_host} {{ type ipv4_addr; }}
flush set inet {table} {s4_host}
add set inet {table} {s4_net} {{ type ipv4_addr; flags interval; auto-merge; }}
flush set inet {table} {s4_net}

add set inet {table} {s6_host} {{ type ipv6_addr; }}
flush set inet {table} {s6_host}
add set inet {table} {s6_net} {{ type ipv6_addr; flags interval; auto-merge; }}
flush set inet {table} {s6_net}

add chain inet {table} {chain} {{ type filter hook {hook} priority filter - 1; policy accept; }}
flush chain inet {table} {chain}
add rule inet {table} {chain} iif "lo" accept
add rule inet {table} {chain} meta pkttype {{ broadcast, multicast }} accept
"""

    lines = [ruleset]

    # 2. Ajout des listes blanches si elles existent
    if v4_whitelist:
        lines.append(
            f"add rule inet {table} {chain} ip saddr {{ {', '.join(v4_whitelist)} }} accept"
        )
    if v6_whitelist:
        lines.append(
            f"add rule inet {table} {chain} ip6 saddr {{ {', '.join(v6_whitelist)} }} accept"
        )

    # 3. Ajout des règles de drop
    drop_rules = f"""
add rule inet {table} {chain} ip saddr @{s4_host} counter name {counter_v4} drop
add rule inet {table} {chain} ip saddr @{s4_net} counter name {counter_v4} drop
add rule inet {table} {chain} ip6 saddr @{s6_host} counter name {counter_v6} drop
add rule inet {table} {chain} ip6 saddr @{s6_net} counter name {counter_v6} drop
"""
    lines.append(drop_rules)

    # 4. Fonction optimisée pour injecter les éléments par "lots" (batches)
    def add_elements(name, elems, chunk_size=1000):
        if not elems:
            return

        # Parcourir la liste par sauts de `chunk_size`
        for i in range(0, len(elems), chunk_size):
            # Prendre une tranche (slice) de 1000 éléments
            batch = elems[i : i + chunk_size]
            # Concaténer rapidement via la méthode C native de Python (.join)
            joined_batch = ", ".join(batch)
            lines.append(f"add element inet {table} {name} {{ {joined_batch} }}")

    # 5. Injection des adresses
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

    cfg_path = Path(args.config)
    cfg = parse_conf(cfg_path)

    # Récupération directe des valeurs TOML (types natifs)
    urls = cfg.get("BLACKLISTS", [])
    table = cfg.get("TABLE", "blackhole")
    chain = cfg.get("CHAIN", "input")
    hook = cfg.get("HOOK", "input")

    # Plus besoin de parse_whitelist, TOML fournit déjà une liste !
    v4_whitelist = cfg.get("IP_WHITELIST", [])
    v6_whitelist = cfg.get("IP6_WHITELIST", [])

    # Plus besoin de parse_bool, TOML fournit déjà un booléen (True/False) !
    dry_run = cfg.get("DRY_RUN", False)
    verbose = cfg.get("VERBOSE", False)

    # Nouvelle ligne : récupérer l'option de consolidation
    do_optimize_cidr = cfg.get("DO_OPTIMIZE_CIDR", True)

    nft_cmd = args.nft or cfg.get("NFT", "nft")

    raw_lines = list(fetch_urls(urls))
    v4, v6 = parse_ips(raw_lines)
    v4, v6 = drop_reserved(v4, v6)

    # Passer le flag d'optimisation
    v4_hosts, v4_nets = collapse_family(v4, 4, do_optimize=do_optimize_cidr)
    v6_hosts, v6_nets = collapse_family(v6, 6, do_optimize=do_optimize_cidr)

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
    output_path.parent.mkdir(
        parents=True, exist_ok=True
    )  # Sécurité pour créer le dossier
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
