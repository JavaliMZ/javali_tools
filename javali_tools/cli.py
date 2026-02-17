import argparse
import sys
from . import ssl_cert_inspector
from . import tls_table
from . import ntlm_info
from . import nmap_censys
from . import get_ips_from_domains



def main():
    PROGRAM_NAME = "javali_tools"
    DESCRIPTION = "Javali Offensive Toolkit"
    parser = argparse.ArgumentParser(prog=PROGRAM_NAME, description=DESCRIPTION)

    subparsers = parser.add_subparsers(dest="command")

    # SSL Certificate Inspector
    SSL_CERT_COMMAND = "ssl-cert"
    SSL_CERT_HELP = "Inspect SSL certificate"
    ssl_parser = subparsers.add_parser(SSL_CERT_COMMAND, help=SSL_CERT_HELP)
    ssl_parser.add_argument("target", help="Hostname or IP")
    ssl_parser.add_argument("-p", "--port", type=int, default=443, help="Port (default: 443)")
    ssl_parser.set_defaults(func=ssl_cert_inspector.run)

    # TLS Table
    TLS_TABLE_COMMAND = "tls-table"
    TLS_TABLE_HELP = "Parse tlsx JSON output and print TLS table"
    tls_parser = subparsers.add_parser(TLS_TABLE_COMMAND, help=TLS_TABLE_HELP)
    tls_parser.add_argument("file", help="JSON file generated with tlsx -j")
    tls_parser.set_defaults(func=tls_table.run)

    # NTLM Info
    NTLM_INFO_COMMAND = "ntlm_info"
    NTLM_INFO_HELP = "Extract NTLM Type2 challenge information"
    ntlm_parser = subparsers.add_parser(NTLM_INFO_COMMAND, help=NTLM_INFO_HELP)
    ntlm_parser.add_argument("url", help="Target URL (http/https/smb/rdp/smtp)")
    ntlm_parser.set_defaults(func=ntlm_info.run)

    # Nmap/Censys Parser
    NC_COMMAND = "nmap-censys"
    NC_HELP = "Parse Nmap (.gnmap) or Censys (.json) output"
    nc_parser = subparsers.add_parser(NC_COMMAND, help=NC_HELP)
    nc_parser.add_argument("file", help="Input file (.gnmap or .json)")
    nc_parser.add_argument("--zip", action="store_true", help="Shortened output format")
    nc_parser.set_defaults(func=nmap_censys.run)

    # Get IPs from Domains
    IP_COMMAND = "get_ips_from_domains"
    IP_HELP = "Resolve domains to IP addresses"
    ip_parser = subparsers.add_parser(IP_COMMAND, help=IP_HELP)
    ip_parser.add_argument("file", help="File containing domains (one per line)")
    ip_parser.add_argument("--threads", type=int, default=5, help="Number of concurrent threads (default: 5)")
    ip_parser.set_defaults(func=get_ips_from_domains.run)




    # Parse arguments
    args = parser.parse_args()

    if not hasattr(args, "func"):
        parser.print_help()
        return

    # Call the selected tool with the parsed arguments
    args.func(args)