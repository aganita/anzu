import socket
import os

def listen_to_socket(socket_path):
    # Check if the socket already exists and remove it if it does
    if os.path.exists(socket_path):
        os.remove(socket_path)

    # Create a new socket using the AF_UNIX address family
    server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    # Bind the socket to the path
    server_socket.bind(socket_path)

    # Listen for incoming connections
    server_socket.listen()

    print("Server is listening on socket:", socket_path)

    try:
        # Accept connection
        connection, client_address = server_socket.accept()
        print("Connection from", client_address)

        while True:
            # Receive data sent over the connection
            data = connection.recv(1024)  # Adjust buffer size as needed
            if data:
                # Print the received data
                print("Received:", data.decode())
            else:
                # No more data, close the connection
                connection.close()
                print("Connection closed")
                break
    finally:
        # Clean up the connection
        connection.close()
        server_socket.close()
        os.remove(socket_path)

if __name__ == "__main__":
    socket_path = '/tmp/suricata.sock'  # Path to your Unix socket file
    listen_to_socket(socket_path)
