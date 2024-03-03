import scapy.all as scapy
import netifaces
import ipaddress
import requests

def get_network_range(interface=None):
    """Return the network's IPv4 range in CIDR notation."""
    if interface is None:
        interface = scapy.conf.iface
    
    if not isinstance(interface, str):
        interface = str(interface)
    
    try:
        addrs = netifaces.ifaddresses(interface)
        ip_info = addrs[netifaces.AF_INET][0]
        ip = ip_info['addr']
        netmask = ip_info['netmask']
        
        network = ipaddress.ip_network(f"{ip}/{netmask}", strict=False)
        cidr_notation = str(network)
        
        return cidr_notation
    except ValueError as e:
        return f"Error calculating network range: {e}"
    except KeyError as e:
        return f"Interface information not available: {e}"


def get_device_info_by_mac(mac_address):
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        response = requests.get(url)
        print(response.json())
        response_json = response.json()
        if response.status_code == 200 and response_json['found'] == True:
            return response_json['company']
        else:
            print(f"Request failed with status code: {response.status_code}")
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

