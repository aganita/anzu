# -*- coding: utf-8 -*-
from flask import flash
import json
import scapy.all as scapy
import netifaces
import ipaddress
import requests


def flash_errors(form, category="warning"):
    """Flash all errors for a form."""
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text} - {error}", category)


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




def detect_devices():
    target_ip = get_network_range() #"192.168.1.0/24"
    devices = []
    arp = scapy.ARP(pdst=target_ip)
    ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = scapy.srp(packet, timeout=3, verbose=False)[0]
    for sent, received in result:
        device_type = get_device_info_by_mac(received.hwsrc)
        devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'device manufacturer': device_type if device_type is not None else "Unknown"})
    return devices

# def detect_devices():
#     target_ip = get_network_range()
#     devices = []
#     arp = ARP(pdst=target_ip)
#     ether = Ether(dst="ff:ff:ff:ff:ff:ff")
#     packet = ether/arp
#     result = srp(packet, timeout=3, verbose=False)[0]
#     for sent, received in result:
#         mac_address = received.hwsrc
#         existing_device = Device.query.filter_by(mac_address=mac_address).first()
#         if not existing_device:
#             device_type = get_device_info_by_mac(mac_address)
#             new_device = Device(mac_address=mac_address, device_type=device_type if device_type else "Unknown")
#             db.session.add(new_device)
#             db.session.commit()
#         devices.append({'ip': received.psrc, 'mac': mac_address, 'device manufacturer': device_type if device_type else "Unknown"})
#     return devices

def read_suricata_alerts():
    return "success"
    # alerts_file_path = '/var/log/suricata/eve.json'
    # alerts = []
    # try:
    #     with open(alerts_file_path, 'r') as file:
    #         for line in file:
    #             alerts.append(json.loads(line))
    # except Exception as e:
    #     alerts.append(str(e))
    # return alerts
