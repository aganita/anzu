from scapy.all import ARP, Ether, srp
import json
from utils.network_utils import get_network_range, get_device_info_by_mac


def detect_devices():
    target_ip = get_network_range() #"192.168.1.0/24"
    devices = []
    arp = ARP(pdst=target_ip)
    ether = Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether/arp
    result = srp(packet, timeout=3, verbose=False)[0]
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
    alerts_file_path = '/var/log/suricata/eve.json'
    alerts = []
    try:
        with open(alerts_file_path, 'r') as file:
            for line in file:
                alerts.append(json.loads(line))
    except Exception as e:
        alerts.append(str(e))
    return alerts
