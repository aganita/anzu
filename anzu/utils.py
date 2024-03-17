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

def flash_errors(form, category="warning"):
    """Flash all errors for a form."""
    for field, errors in form.errors.items():
        for error in errors:
            flash(f"{getattr(form, field).label.text} - {error}", category)


def get_network_range(interface=None):
    """Return the network's IPv4 range in CIDR notation."""
    # TODO: remove ths line
    Device.query.delete()
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
            return None
    except Exception as e:
        print(f"An error occurred: {e}")
        return None


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
        print(f"Existing device: {existing_device} for mac: {mac_address}")
        if not existing_device:
            print(f"New device detected: {mac_address}")
            manufacturer = get_device_info_by_mac(mac_address)
            open_ports_list = scan_ports(received.psrc, 1, 65535)
            open_ports_str = ",".join(str(port) for port in open_ports_list)
            print(f"Open ports: {open_ports_str}")
            type = "Unknown"
            new_device = Device(mac_address=mac_address, ip_address=received.psrc, type=type, manufacturer=manufacturer if manufacturer else "Unknown", open_ports=open_ports_str)
            _db.session.add(new_device)
            _db.session.commit()
            devices.append({'mac': mac_address, 'ip': received.psrc, 'type': type, 'manufacturer': manufacturer if manufacturer else "Unknown", 'open_ports': open_ports_str})
        else:
            devices.append({'mac': mac_address, 'ip': received.psrc, 'type': existing_device.type, 'manufacturer': existing_device.manufacturer, 'open_ports': existing_device.open_ports})
    return devices



def read_suricata_alerts():
    harcoded_alerts_for_testing_the_ui = [

{
  "timestamp": "2024-03-03T14:25:30.000000+0000",
  "event_type": "alert",
  "src_ip": "192.168.1.100",
  "src_port": 22,
  "dest_ip": "192.168.1.1",
  "dest_port": 51322,
  "proto": "TCP",
  "alert": {
    "action": "allowed",
    "gid": 1,
    "signature_id": 2010935,
    "rev": 3,
    "signature": "ET SCAN Potential SSH Scan",
    "category": "Attempted Information Leak",
    "severity": 2
  },
  "flow_id": 123456789012345,
  "in_iface": "eth0",
  "tcp": {
    "tcp_flags": "PA",
    "tcp_flags_ts": "PA",
    "tcp_flags_tc": "PA",
    "syn": "false",
    "fin": "false",
    "psh": "true",
    "ack": "true",
    "urg": "false",
    "ece": "false",
    "cwr": "false"
  }
}, 
  {
    "timestamp": "2024-03-03T22:24:37.251547+0100",
    "flow_id": 586497171462735,
    "pcap_cnt": 53381,
    "event_type": "alert",
    "src_ip": "192.168.2.14",
    "src_port": 50096,
    "dest_ip": "209.53.113.5",
    "dest_port": 80,
    "proto": "TCP",
    "metadata": {
      "flowbits": [
        "http.dottedquadhost"
      ]
    },
    "tx_id": 4,
    "alert": {
      "action": "allowed",
      "gid": 1,
      "signature_id": 2018358,
      "rev": 10,
      "signature": "ET HUNTING GENERIC SUSPICIOUS POST to Dotted Quad with Fake Browser 1",
      "category": "Potentially Bad Traffic",
      "severity": 2
    },
    "app_proto": "http"
  }

    ]

    return harcoded_alerts_for_testing_the_ui
    # alerts_file_path = '/var/log/suricata/eve.json'
    # alerts = []
    # try:
    #     with open(alerts_file_path, 'r') as file:
    #         for line in file:
    #             alerts.append(json.loads(line))
    # except Exception as e:
    #     alerts.append(str(e))
    # return alerts
