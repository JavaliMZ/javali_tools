import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple

import tqdm
from tabulate import tabulate
from termcolor import colored  # type: ignore


def get_ip_addresses(domain: str) -> Tuple[str, List[str]]:
    try:
        info = socket.getaddrinfo(
            domain,
            None,
            family=socket.AF_UNSPEC,
            proto=socket.IPPROTO_TCP
        )
        ip_addresses = list(set(addr[-1][0] for addr in info))
        return domain, ip_addresses
    except socket.gaierror:
        return domain, []


def resolve_domains(domains: List[str], max_workers: int) -> Dict[str, List[str]]:
    ip_dict: Dict[str, List[str]] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_domain = {
            executor.submit(get_ip_addresses, domain): domain
            for domain in domains
        }

        for future in tqdm.tqdm(
            as_completed(future_to_domain),
            total=len(domains),
            desc="Resolving domains"
        ):
            domain = future_to_domain[future]
            try:
                domain, ip_addresses = future.result()
                ip_dict[domain] = ip_addresses
            except Exception as e:
                ip_dict[domain] = []
                print(f"Error resolving {domain}: {e}", file=sys.stderr)

    return ip_dict


def pretty_print(results: Dict[str, List[str]]) -> None:
    table_data = []

    for domain, ips in results.items():
        if ips:
            ip_list = colored(", ".join(ips), "magenta")
        else:
            ip_list = colored("No IP found", "blue")

        table_data.append([
            colored(domain, "green"),
            ip_list
        ])

    print(tabulate(table_data, tablefmt="presto"))


def get_domains_from_file(file_path: str) -> List[str]:
    try:
        with open(file_path, "r") as f:
            return [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        print(f"File not found: {file_path}", file=sys.stderr)
        sys.exit(1)


def run(args) -> None:
    domains = get_domains_from_file(args.file)
    resolved_ips = resolve_domains(domains, max_workers=args.threads)
    pretty_print(resolved_ips)
