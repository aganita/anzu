# import socket

# def get_device_name(ip_address):
#     try:
#         # Attempt to get the hostname based on the IP address
#         hostname, _, _ = socket.gethostbyaddr(ip_address)
#         return hostname
#     except socket.herror:
#         # Unable to resolve hostname
#         return None

# # Example usage
# ip_address = '10.80.0.2'  # Replace with the target IP address
# device_name = get_device_name(ip_address)
# if device_name:
#     print(f"The device name of {ip_address} is {device_name}.")
# else:
#     print(f"Could not resolve the device name for {ip_address}.")


def guess_device_type(open_ports):
    # Define patterns for different device types
    device_patterns = {
        "Web Server": [80, 443],
        "SSH Server": [22],
        "SMB/File Server": [445],
        "Network Printer": [631, 9100],
        "IoT Device": [80, 443, 8080],
        # Add more patterns as needed
    }
    
    guessed_devices = []
    for device_type, ports in device_patterns.items():
        if any(port in open_ports for port in ports):
            guessed_devices.append(device_type)
    
    return guessed_devices if guessed_devices else ["Unknown"]

# Example usage
device_type = guess_device_type(open_ports)
print(f"Possible device types based on open ports: {device_type}")



 # TODO
# - guess the devices by open ports
# - guess devices by manufactureres
# - guess devices by traffic  too hard?
# - give a nice explanation for suricata alrts
# - 
