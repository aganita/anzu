from scapy.all import IP, UDP, send, sr1
from scapy.layers.dns import DNS, DNSQR

def send_mdns_query(query_name="_http._tcp.local"):
    # mDNS uses 224.0.0.251 as the multicast address and 5353 as the port
    multicast_addr = "224.0.0.251"
    port = 5353

    # Craft the DNS query packet
    packet = IP(dst=multicast_addr)/UDP(dport=port)/DNS(rd=1, qd=DNSQR(qname=query_name))
    
    # Send the packet and wait for a response
    # Note: sr1 sends a packet and receives a response; for multicast, you might want to use just 'send'
    response = sr1(packet, timeout=2, verbose=0)

    if response:
        print(response.show())
    else:
        print("No response received.")

from zeroconf import ServiceBrowser, Zeroconf

class MyListener:
    def add_service(self, zeroconf, type, name):
        info = zeroconf.get_service_info(type, name)
        if info:
            print(f"Device Name: {info.server}")
            print(f"Address: {info.parsed_addresses()[0]}")
            print(f"Port: {info.port}")
            print(f"Properties: {info.properties}\n")

zeroconf = Zeroconf()
listener = MyListener()
service_type = "_http._tcp.local."  # Example service type; adjust as needed
browser = ServiceBrowser(zeroconf, service_type, listener)

try:
    input("Press enter to exit...\n\n")
finally:
    zeroconf.close()