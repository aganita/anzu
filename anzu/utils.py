# -*- coding: utf-8 -*-
from flask import flash
import json
import scapy.all as scapy
import netifaces
import ipaddress
import requests
from anzu.user.models import Device
from anzu.database import db as _db


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


# def detect_devices():
#     target_ip = get_network_range() #"192.168.1.0/24"
#     devices = []
#     arp = scapy.ARP(pdst=target_ip)
#     ether = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
#     packet = ether/arp
#     result = scapy.srp(packet, timeout=3, verbose=False)[0]
#     for sent, received in result:
#         manufacturer = get_device_info_by_mac(received.hwsrc)
#         devices.append({'ip': received.psrc, 'mac': received.hwsrc, 'manufacturer': manufacturer if manufacturer is not None else "Unknown"})
#     return devices

def detect_devices():
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
            new_device = Device(ip_address=received.psrc, mac_address=mac_address, manufacturer=manufacturer if manufacturer else "Unknown")
            _db.session.add(new_device)
            _db.session.commit()
            devices.append({'ip': received.psrc, 'mac': mac_address, 'manufacturer': manufacturer if manufacturer else "Unknown"})
        else:
            devices.append({'ip': received.psrc, 'mac': mac_address, 'manufacturer': existing_device.manufacturer})
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
