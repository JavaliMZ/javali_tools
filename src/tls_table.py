import json
import subprocess
import os
from tabulate import tabulate  # type: ignore
from datetime import datetime
from termcolor import colored  # type: ignore
from pwn import log

INSECURE_TLS = {"tls10", "tls11"}


def try_except(func):
    def wrapper(*args, **kwargs):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            raise RuntimeError(
                f"Error in function '{func.__name__}': {e}"
            )
    return wrapper


@try_except
def get_system_command(command_list):
    result = subprocess.run(
        command_list,
        capture_output=True,
        text=True
    )

    stdout = result.stdout.strip()
    stderr = result.stderr.strip()

    return stdout, stderr


@try_except
def format_date(date_str):
    date_object = datetime.strptime(date_str, "%Y-%m-%dT%H:%M:%SZ")
    return date_object.strftime("%d%b%Y").upper()


@try_except
def run_check_tls_cert(host):
    binary_path = os.path.expanduser("~/go/bin/check-tls-cert")

    command = [binary_path, "net", "-H", host]
    stdout, stderr = get_system_command(command)

    output = stdout.strip()
    if stderr:
        output = f"{output}\n{stderr}".strip()

    if not output:
        return colored("No output from check-tls-cert", "yellow")

    output = output.replace("\n", " | ")

    upper = output.upper()
    if "CRITICAL" in upper:
        return colored(output, "red")
    if "WARNING" in upper:
        return colored(output, "yellow")
    if "OK" in upper:
        return colored(output, "green")

    return output


@try_except
def parse_line_info(parsed_data, tls_data_host, description, check_result):
    parsed_data.append([
        colored(tls_data_host["host"], "green"),
        colored(tls_data_host["ip"], "magenta"),
        tls_data_host["port"],
        tls_data_host["not_before"],
        colored(tls_data_host["not_after"], "cyan"),
        description,
        check_result
    ])


@try_except
def parse_tls_data(line, log_info):
    json_data = json.loads(line)

    host = json_data["host"]
    ip = json_data["ip"]
    port = json_data["port"]

    not_before = format_date(json_data["not_before"])
    not_after = format_date(json_data["not_after"])

    versions = [v.lower() for v in json_data.get("version_enum", [])]
    insecure = sorted(set(versions) & INSECURE_TLS)

    expired = json_data.get("expired", False)

    log_info.status(f"Processing {host}:{port}")

    tls_data_host = {
        "host": host,
        "ip": ip,
        "port": port,
        "not_before": not_before,
        "not_after": not_after
    }

    check_result = run_check_tls_cert(host)

    if insecure and expired:
        description = colored(
            f"Expired cert + insecure TLS: {', '.join(insecure)}",
            "red"
        )
    elif insecure:
        description = colored(
            f"Insecure TLS versions: {', '.join(insecure)}",
            "red"
        )
    elif expired:
        description = colored("Certificate expired", "yellow")
    else:
        description = colored("TLS versions OK", "green")

    parsed_data = []
    parse_line_info(parsed_data, tls_data_host, description, check_result)
    return parsed_data


@try_except
def print_table(data):
    table = [line for dataset in data for line in dataset]

    print(
        tabulate(
            table,
            headers=[
                "Host",
                "IP",
                "Port",
                "Not Before",
                "Not After",
                "TLS Status",
                "check-tls-cert"
            ],
            tablefmt="presto",
            numalign="left"
        )
    )


def run(args):
    """
    Entry point for javali_tools tls-table
    """
    json_file_path = args.file

    log_info = log.progress("Get all data")
    all_data = []

    with open(json_file_path, "r") as f:
        for line in f:
            if line.strip():
                all_data.append(parse_tls_data(line, log_info))

    print_table(all_data)
