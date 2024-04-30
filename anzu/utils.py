# -*- coding: utf-8 -*-
from flask import flash
import json
import scapy.all as scapy
import netifaces
import ipaddress
import requests
from anzu.user.models import Device
from anzu.database import db as _db
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from .suricata_configs import EXPLAINATIONS, REMEDIATIONS


ALERTS = [{
    "timestamp": "April 7 2024 - 4:31pm PST",
    "name":"Multiple SSH connection attempts to your Router (IP = 192.168.50.1)",
    "explanation": "This alert indicates someone is repeatedly trying to access your device using SSH, similar to guessing a door's code multiple times. This behavior, happening in a short period, often signals a brute force attack, where an attacker tries various passwords to break in.",
    "severity": "High",
    "remediation": "Change the default SSH port to a non-standard one, use strong passwords, and consider using a VPN to access your router remotely."
},{"timestamp": "April 7 2024 - 5:20pm PST",
    "name":"Unauthorized open SSH port on your Unknown device (IP = 192.168.50.77)",
    "explanation": "Imagine your device is a house, and the SSH port is a special door that lets authorized people (like you) enter with a key (password). If this door is unexpectedly open on your device, it's like finding a door in your house unlocked that you never use or didn't even know existed. This can be risky because it might allow strangers to sneak in unnoticed, potentially leading to unwanted access or harm.",
    "severity": "High",
    "remediation": "Disconnect this device from network if possible."
}]

def flash_errors(form, category="warning"):
    """Flash all errors for a form."""
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text} - {error}", category)


def get_network_range(interface=None):
    """Return the network's IPv4 range in CIDR notation."""
    # TODO: remove ths line
    # Device.query.delete()
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
    """Return information about a device based on its MAC address."""
    try:
        url = f"https://api.maclookup.app/v2/macs/{mac_address}"
        response = requests.get(url)
        print(response.json())
        response_json = response.json()
        if response.status_code == 200 and response_json['found'] == True:
            return response_json['company']
        else:
            print(f"Request failed with status code: {response.status_code}")
            return "Unknown"
    except Exception as e:
        print(f"An error occurred: {e}")
        return "Unknown"


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


def detect_device_type(manufacturer, open_ports_list):
    """
    Attempts to detect the type of a device based on its IP address.
    """
    if "Arcadyan Corporation" in manufacturer:
        return "LG Smart TV"
    if "Apple" in manufacturer:
        return "Apple Device"
    return "Unknown"


def detect_devices():
    """Detect devices on the network using ARP requests and save in DB."""
    target_ip = get_network_range()
    devices = []
    arp = scapy.ARP(pdst=target_ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = scapy.srp(packet, timeout=3, verbose=False)[0]
    for sent, received in result:
        mac_address = received.hwsrc
        existing_device = Device.query.filter_by(mac_address=mac_address).first()
        if not existing_device:
            print(f"New device detected: {mac_address}")
            manufacturer = get_device_info_by_mac(mac_address)
            open_ports_list = scan_ports(received.psrc, 1, 65535)
            open_ports_str = ",".join(str(port) for port in open_ports_list)
            
            type = detect_device_type(manufacturer, open_ports_list)
            
            risk_score = 'Low'
            if manufacturer == "Unknown":
                risk_score = 'High'
            if manufacturer != "Unknown" and type == "Unknown":
                risk_score = 'Medium'
            
            new_device = Device(mac_address=mac_address, ip_address=received.psrc, type=type, manufacturer=manufacturer, open_ports=open_ports_str, risk_score=risk_score)
            _db.session.add(new_device)
            _db.session.commit()
            devices.append({'mac': f'{mac_address[:8]}:...', 'ip': received.psrc, 'type': type, 'manufacturer': manufacturer, 'open_ports': open_ports_str, 'risk_score': risk_score})
            # devices.append({'mac': f'{mac_address}', 'ip': received.psrc, 'type': type, 'manufacturer': manufacturer, 'open_ports': open_ports_str, 'risk_score': risk_score})
        else:
            devices.append({'mac': f'{mac_address[:8]}:...', 'ip': received.psrc, 'type': existing_device.type, 'manufacturer': existing_device.manufacturer, 'open_ports': existing_device.open_ports, 'risk_score': existing_device.risk_score})
            # devices.append({'mac': f'{mac_address}', 'ip': received.psrc, 'type': existing_device.type, 'manufacturer': existing_device.manufacturer, 'open_ports': existing_device.open_ports, 'risk_score': existing_device.risk_score})    


        # for mac_add in ["b0:f1:d8:4d:0e:f4"]:
        #     update_success = Device.update_device(
        #         mac_address=mac_add, # required
        #         type='Apple Device',  # optional
        #         risk_score='Low'  # optional
        #     )
        #     if update_success:
        #         print("Device updated successfully.")
        #     else:
        #         print("Device update failed.")    

        # update_success = Device.update_device(
        #     mac_address=mac_add, # required
        #     risk_score='Low'  # optional
        # )
        # if update_success:
        #     print("Device updated successfully.")
        # else:
        #     print("Device update failed.")    

    return devices


def read_suricata_alerts():
    harcoded_alerts_for_demo = ALERTS
    return harcoded_alerts_for_demo

def submit_alert(alert):
    if alert['event_type'] is not "alert":
        return
    
    print(f"Received new alert: {json.dumps(alert)}")
    signature_id = alert["alert"]["signature_id"]
    match signature_id:
        case "1000002":
            alert = format_ssh_brute_force(alert)
        case "1000003":
            alert = format_sql_injection_alert(alert)
        case "1000004":
            alert = format_icmp_ping_alert(alert)
        case "1000005":
            alert = format_tor_connection_alert(alert)
        case _:
            return

    ALERTS.append(alert)


def format_ssh_brute_force(alert):
    timestamp = convert_timestamp(alert['timestamp'])
    name = alert['alert']['signature']
    explanation = get_explaination(alert['alert']['signature_id'])
    severity = get_severity(alert['alert']['severity'])
    remediation = get_remediations(alert['alert']['signature_id'])

def format_icmp_ping_alert(alert):
    timestamp = convert_timestamp(alert['timestamp'])
    name = alert['alert']['signature']
    explanation = get_explaination(alert['alert']['signature_id'])
    severity = get_severity(alert['alert']['severity'])
    remediation = get_remediations(alert['alert']['signature_id'])

def format_tor_connection_alert(alert):
    timestamp = convert_timestamp(alert['timestamp'])
    name = alert['alert']['signature']
    explanation = get_explaination(alert['alert']['signature_id'])
    severity = get_severity(alert['alert']['severity'])
    remediation = get_remediations(alert['alert']['signature_id'])


def format_sql_injection_alert(alert):
    timestamp = convert_timestamp(alert['timestamp'])
    name = alert['alert']['signature']
    explanation = get_explaination(alert['alert']['signature_id'])
    severity = get_severity(alert['alert']['severity'])
    remediation = get_remediations(alert['alert']['signature_id'])

def get_explaination(signature_id):
    if signature_id not in EXPLAINATIONS:
        return ""
    return EXPLAINATIONS[signature_id]

def get_remediations(signature_id):
    if signature_id not in REMEDIATIONS:
        return ""
    return REMEDIATIONS[signature_id]

def get_severity(priority):
    if priority < 5:
        return "HIGH"
    elif priority < 20:
        return "MEDIUM"
    else:
        return "LOW"


def convert_timestamp(original_timestamp):
    dt = datetime.strptime(original_timestamp, "%Y-%m-%dT%H:%M:%S.%f%z")
    formatted_timestamp = dt.strftime("%B %d %Y - %-I:%M%p") + " PST"
    return formatted_timestamp
