import socket
import http.client

# SSDP parameters
SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900
SSDP_MX = 2
SSDP_ST = "ssdp:all"
MS = 1024

# Set up the socket for sending an SSDP M-SEARCH request
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
sock.settimeout(5)

message = (
    "M-SEARCH * HTTP/1.1\r\n" +
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n" +
    "MAN: \"ssdp:discover\"\r\n" +
    f"MX: {SSDP_MX}\r\n" +
    f"ST: {SSDP_ST}\r\n\r\n"
).encode('utf-8')  # Encode the string to bytes

sock.sendto(message, (SSDP_ADDR, SSDP_PORT))

# sock.sendto(
#     f"M-SEARCH * HTTP/1.1\r\n" +
#     f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n" +
#     f"MAN: \"ssdp:discover\"\r\n" +
#     f"MX: {SSDP_MX}\r\n" +
#     f"ST: {SSDP_ST}\r\n\r\n".encode(),
#     (SSDP_ADDR, SSDP_PORT)
# )

try:
    while True:
        # Listen for responses from devices
        data, addr = sock.recvfrom(MS)
        response = data.decode()

        # Find the location of the device description
        lines = response.split("\r\n")
        location_line = next((line for line in lines if line.startswith("LOCATION:")), None)
        if location_line:
            location_url = location_line.split(": ", 1)[1]
            print(f"Device found at {addr[0]}, description URL: {location_url}")

            # Optional: Retrieve and parse the device description from the URL
            # This step requires additional handling based on the description format (usually XML)
except socket.timeout:
    print("Search complete.")
except Exception as e:
    print(f"An error occurred: {e}")
finally:
    sock.close()
