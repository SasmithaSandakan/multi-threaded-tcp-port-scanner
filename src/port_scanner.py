import socket
import threading
import argparse
import csv
import os
from queue import Queue

# Common service mapping
COMMON_SERVICES = {
    20: "FTP Data",
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    67: "DHCP",
    68: "DHCP",
    69: "TFTP",
    80: "HTTP",
    110: "POP3",
    123: "NTP",
    135: "RPC",
    137: "NetBIOS",
    138: "NetBIOS",
    139: "NetBIOS Session",
    143: "IMAP",
    161: "SNMP",
    179: "BGP",
    389: "LDAP",
    443: "HTTPS",
    445: "SMB",
    465: "SMTPS",
    587: "SMTP Submission",
    993: "IMAPS",
    995: "POP3S",
    1433: "MSSQL",
    1521: "Oracle DB",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    6379: "Redis",
    8080: "HTTP Alternate",
    8443: "HTTPS Alternate",
}

# Shared resources
port_queue = Queue()
open_ports = []
lock = threading.Lock()


def get_service_name(port):
    """
    Return a common service name for a known port.
    """
    return COMMON_SERVICES.get(port, "Unknown Service")


def setup_output_folder(output_file):
    """
    Create output folder if it does not exist.
    """
    output_dir = os.path.dirname(output_file)
    if output_dir and not os.path.exists(output_dir):
        os.makedirs(output_dir)


def save_results_to_csv(output_file, target_input, resolved_target, results):
    """
    Save scan results to a CSV file.
    """
    setup_output_folder(output_file)

    with open(output_file, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["target_input", "resolved_ip", "port", "service", "banner"])

        for port, service, banner in results:
            writer.writerow([target_input, resolved_target, port, service, banner])


def scan_port(target, port):
    """
    Scan one TCP port and try to grab a simple banner.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            service = get_service_name(port)
            banner = "No banner"

            try:
                sock.sendall(b"HEAD / HTTP/1.1\r\nHost: test\r\n\r\n")
                response = sock.recv(1024)

                if response:
                    banner = response.decode(errors="ignore").strip().split("\n")[0]
            except Exception:
                banner = "No banner"

            with lock:
                open_ports.append((port, service, banner))
                print(f"Port {port} is OPEN ({service})")
                print(f"   ↳ Banner: {banner}")

        sock.close()

    except socket.error:
        pass


def worker(target):
    """
    Worker thread that scans ports from the queue.
    """
    while not port_queue.empty():
        port = port_queue.get()
        scan_port(target, port)
        port_queue.task_done()


def parse_arguments():
    """
    Parse command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description="Multi-threaded TCP Port Scanner with Service Detection and Banner Grabbing"
    )

    parser.add_argument(
        "--target",
        required=True,
        help="Target IP address or domain name"
    )

    parser.add_argument(
        "--start-port",
        type=int,
        required=True,
        help="Start of port range"
    )

    parser.add_argument(
        "--end-port",
        type=int,
        required=True,
        help="End of port range"
    )

    parser.add_argument(
        "--threads",
        type=int,
        default=50,
        help="Number of worker threads (default: 50)"
    )

    parser.add_argument(
        "--output",
        default="output/scan_results.csv",
        help="CSV output file path (default: output/scan_results.csv)"
    )

    return parser.parse_args()


def main():
    args = parse_arguments()

    target_input = args.target.strip()
    start_port = args.start_port
    end_port = args.end_port
    thread_count = args.threads
    output_file = args.output

    if start_port < 1 or end_port > 65535 or start_port > end_port:
        print("Invalid port range. Use ports between 1 and 65535.")
        return

    if thread_count < 1:
        print("Thread count must be at least 1.")
        return

    try:
        target = socket.gethostbyname(target_input)
        print(f"Resolved {target_input} to {target}")
    except socket.gaierror:
        print("Invalid target.")
        return

    for port in range(start_port, end_port + 1):
        port_queue.put(port)

    print(f"\nScanning {target} from port {start_port} to {end_port}...")
    print(f"Using {thread_count} threads...\n")

    threads = []
    for _ in range(thread_count):
        thread = threading.Thread(target=worker, args=(target,))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    open_ports.sort()

    print("\nScan complete.")

    if open_ports:
        print("\nOpen Ports Summary:")
        for port, service, banner in open_ports:
            print(f"- Port {port}: {service}")
            print(f"   ↳ Banner: {banner}")
    else:
        print("No open ports found in the selected range.")

    save_results_to_csv(output_file, target_input, target, open_ports)
    print(f"\nResults saved to: {output_file}")


if __name__ == "__main__":
    main()