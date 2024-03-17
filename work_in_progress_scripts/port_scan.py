import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

def check_port(ip, port):
    """
    Attempts to establish a connection to the specified port and returns the port if open.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1)  # Set timeout to 1 second
        result = sock.connect_ex((ip, port))
        if result == 0:
            return port  # Port is open
    return None  # Port is closed or filtered

def scan_ports(ip, start_port, end_port):
    """
    Scans ports on a given IP address from start_port to end_port and returns a list of open ports.
    """
    open_ports = []
    futures = []

    with ThreadPoolExecutor(max_workers=50) as executor:
        for port in range(start_port, end_port + 1):
            futures.append(executor.submit(check_port, ip, port))

    for future in as_completed(futures):
        result = future.result()
        if result:
            open_ports.append(result)

    return open_ports

# Example usage
target_ip = '192.168.1.81'  # Target device's IP address
start_port = 1
end_port = 65535  # Adjust the range as needed

open_ports = scan_ports(target_ip, start_port, end_port)
print(f"Open ports on {target_ip}: {sorted(open_ports)}")
