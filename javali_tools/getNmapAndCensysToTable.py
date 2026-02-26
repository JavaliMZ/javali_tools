import os
import re
import json
from tabulate import tabulate  # type: ignore
from termcolor import colored  # type: ignore


class NmapParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = []
        self.cve_pattern = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)

    def parse_file(self):
        with open(self.file_path, "r") as file:
            for line in file:
                if self.is_relevant_info_from_line(line):
                    self.parse_line(line)
        return self.data

    @staticmethod
    def is_relevant_info_from_line(line):
        return not line.startswith("#") or "Host" in line

    def parse_line(self, line):
        ip, ports = self.extract_ip_and_ports(line)
        if not ports:
            return
        self.data.extend(self.port_details(ip, ports))

    @staticmethod
    def extract_ip_and_ports(line):
        parts = line.split()
        if len(parts) < 2:
            return None, []

        ip = parts[1]

        if "Ports:" not in line:
            return ip, []

        ports_info = line.split("Ports: ")[1]
        ports = ports_info.split(",")

        return ip, ports

    def port_details(self, ip, ports):
        data = []
        for port_info in ports:
            port_details = port_info.split("/")

            if len(port_details) >= 7:
                port, state, protocol, _, service, _, info = port_details[:7]

                cves = self.cve_pattern.findall(info)
                cve_string = ", ".join(cves) if cves else "N/A"

                data.append({
                    "IP": ip,
                    "Port": port,
                    "Protocol": protocol.lower(),
                    "State": state.lower(),
                    "Service": service.lower(),
                    "Info": info,
                    "CVEs": cve_string
                })

        return data


class CensysParser:
    def __init__(self, file_path):
        self.file_path = file_path
        self.data = []

    def parse_file(self):
        with open(self.file_path, "r") as file:
            json_data = json.load(file)

        for entry in json_data:
            ip = entry.get("ip", "N/A")

            for service in entry.get("services", []):
                port = service.get("port", "N/A")
                protocol = service.get("transport_protocol", "N/A")
                extended_service_name = service.get("extended_service_name", "N/A")

                self.data.append({
                    "IP": ip,
                    "Port": port,
                    "Protocol": protocol.lower(),
                    "State": "open",
                    "Service": extended_service_name.lower(),
                    "Info": "",
                    "CVEs": "N/A"
                })

        return self.data


class ReportGenerator:
    def __init__(self, all_data, zip_output):
        self.all_data = all_data
        self.zip_output = zip_output

    def print_table(self):
        if self.zip_output:
            self.print_zip_table()
        else:
            self.print_detailed_table()

    def print_detailed_table(self):
        has_cves = any(
            entry.get("CVEs") != "N/A" for entry in self.all_data
        )

        table = [
            [
                colored(line["IP"], "magenta"),
                line["Port"],
                colored(line["Protocol"], "green"),
                line["State"],
                colored(line["Service"], "yellow"),
                line["Info"]
            ] + ([line["CVEs"]] if has_cves else [])
            for line in self.all_data
        ]

        print(tabulate(table, tablefmt="presto", numalign="left"))

    def print_zip_table(self):
        ip_data = {}

        for entry in self.all_data:
            if entry.get("State") != "open":
                continue

            ip = entry["IP"]
            port = entry["Port"]
            protocol = entry["Protocol"].upper()

            if ip not in ip_data:
                ip_data[ip] = {"TCP": [], "UDP": []}

            ip_data[ip][protocol].append(port)

        for ip, protocols in ip_data.items():
            for protocol, ports in protocols.items():
                if ports:
                    ports_str = ", ".join(sorted(set(map(str, ports))), key=int)
                    print(
                        f"{colored(ip, 'magenta')} | "
                        f"{colored(protocol, 'green')} | "
                        f"{colored(ports_str, 'cyan')}"
                    )



class FileManager:
    @staticmethod
    def get_files_paths_to_parse():
        current_directory = os.getcwd()

        files_paths_to_parse = []

        for filename in os.listdir(current_directory):
            filepath = os.path.join(current_directory, filename)

            if (
                os.path.isfile(filepath)
                and filename.lower().endswith((".gnmap", ".json"))
            ):
                files_paths_to_parse.append(filepath)

        if not files_paths_to_parse:
            raise RuntimeError("No .gnmap or .json files found to parse.")

        return sorted(files_paths_to_parse)


class ParserManager:
    """
    Delegates parsing to the correct parser
    based on file extension.
    """

    PARSERS = {
        ".gnmap": NmapParser,
        ".json": CensysParser,
    }

    @classmethod
    def parse(cls, file_path):
        _, ext = os.path.splitext(file_path.lower())

        parser_class = cls.PARSERS.get(ext)

        if not parser_class:
            raise ValueError(f"Unsupported file format: {file_path}")

        parser = parser_class(file_path)
        return parser.parse_file()


def run(args):
    """
    Entry point for:
    javali_tools getNmapAndCensysToTable [--zip]

    --zip functionality:

    Instead of =>
    IP           Port  Protocol  State  Service   Info
    10.10.10.5   22    tcp       open   ssh       OpenSSH 8.2
    10.10.10.5   80    tcp       open   http      Apache 2.4
    10.10.10.5   443   tcp       open   https     nginx

    You print this:
    IP           PROTOCOL   PORTS
    10.10.10.5   TCP        22, 80, 443
    10.10.10.5   UDP        53, 161




    Parses all .gnmap and .json files in the current directory.
    """
    zip_output = args.zip
    files_paths = FileManager.get_files_paths_to_parse()
    all_data = []

    for file_path in files_paths:
        parsed_data = ParserManager.parse(file_path)
        if parsed_data:
            all_data.extend(parsed_data)

    if not all_data:
        raise RuntimeError("No data found to display.")

    report_generator = ReportGenerator(all_data, zip_output)
    report_generator.print_table()