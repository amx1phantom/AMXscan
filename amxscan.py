import socket
import argparse
import subprocess

# Banner for AMX!Phantom
def print_banner():
    print("\033[1;32m   ___    ___    ___  \033[0m   \033[1;36mAMX!Phantom\033[0m")
    print("\033[1;32m  / __|  / __|  | __| \033[0m  \033[1;36mPort Scanner (v1.0)\033[0m")
    print("\033[1;32m | |___  | |___  | __| \033[0m  \033[1;36mSimple, Powerful, and Fast.\033[0m")
    print("\033[1;32m |_____| |_____| |____| \033[0m")
    print("\n[INFO] AMX!Phantom - Port Scanner\n")

# Basic function to check if a port is open
def scan_port(target, port, protocol, timeout):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM if protocol == 'tcp' else socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((target, port))
        if result == 0:
            return True
        else:
            return False
    except Exception as e:
        return False

# Function for TCP port scanning
def tcp_scan(target, ports, timeout):
    open_ports = []
    for port in ports:
        if scan_port(target, port, 'tcp', timeout):
            open_ports.append(port)
    return open_ports

# Function for UDP port scanning
def udp_scan(target, ports, timeout):
    open_ports = []
    for port in ports:
        if scan_port(target, port, 'udp', timeout):
            open_ports.append(port)
    return open_ports

# Argument parsing
def parse_arguments():
    parser = argparse.ArgumentParser(description="AMX!Phantom Advanced Port Scanner")
    parser.add_argument('target', help="Target IP or domain to scan")
    parser.add_argument('-p', '--ports', help="Comma-separated list of ports to scan (e.g., 80,443,8080)", type=str)
    parser.add_argument('--all', action='store_true', help="Scan all ports (1-65535)")
    parser.add_argument('--verbose', action='store_true', help="Enable verbose output")
    parser.add_argument('-v', '--version', action='store_true', help="Detect the version of services")
    parser.add_argument('--os', action='store_true', help="Attempt to detect the target's operating system")
    parser.add_argument('--timeout', type=int, default=1, help="Set timeout for each connection attempt")
    parser.add_argument('--output', type=str, help="Save the scan results to a file")
    parser.add_argument('-r', '--range', type=str, help="Range of ports to scan (e.g., 80-100)")
    return parser.parse_args()

# Main function to start the scan
def main():
    args = parse_arguments()
    target = args.target
    ports = []
    
    print_banner()

    # Parse ports argument
    if args.ports:
        ports = list(map(int, args.ports.split(',')))
    elif args.all:
        # Use all ports (1-65535)
        ports = list(range(1, 65536))
    elif args.range:
        # Range of ports (e.g., 80-100)
        port_range = args.range.split('-')
        ports = list(range(int(port_range[0]), int(port_range[1]) + 1))
    else:
        # Default to common ports
        ports = [22, 80, 443, 8080, 3306]
    
    timeout = args.timeout  # Get timeout value
    open_tcp_ports = []
    open_udp_ports = []

    # Start the scan
    print(f"[INFO] Starting scan on {target}...\n")
    
    # Verbose output
    if args.verbose:
        print(f"[INFO] Scanning target {target} with ports: {ports}")
    
    # Scan TCP and UDP ports
    open_tcp_ports = tcp_scan(target, ports, timeout)
    open_udp_ports = udp_scan(target, ports, timeout)

    # Display Results
    if args.verbose:
        print(f"[INFO] TCP scan results: {open_tcp_ports}")
        print(f"[INFO] UDP scan results: {open_udp_ports}")
    
    print("\n[INFO] Scan results:")
    
    if open_tcp_ports:
        print("\n[INFO] Open TCP ports:")
        for port in open_tcp_ports:
            print(f"Port {port} is OPEN (TCP)")

    if open_udp_ports:
        print("\n[INFO] Open UDP ports:")
        for port in open_udp_ports:
            print(f"Port {port} is OPEN (UDP)")

    # Version detection (simplified for demonstration)
    if args.version:
        print("\n[INFO] Version detection: Not implemented in custom tool.")

    # OS detection (simplified for demonstration)
    if args.os:
        print("\n[INFO] OS detection: Not implemented in custom tool.")

    # Output to file
    if args.output:
        with open(args.output, 'w') as file:
            file.write(f"Scan results for {target}:\n")
            if open_tcp_ports:
                file.write("\nOpen TCP ports:\n")
                for port in open_tcp_ports:
                    file.write(f"Port {port} is OPEN (TCP)\n")
            if open_udp_ports:
                file.write("\nOpen UDP ports:\n")
                for port in open_udp_ports:
                    file.write(f"Port {port} is OPEN (UDP)\n")

    print("\nScan complete!")

if __name__ == "__main__":
    main()
