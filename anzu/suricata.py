import os
import psutil
import subprocess
import yaml
import threading
import socket
import time
from datetime import datetime
from .utils import submit_alert

class Suricata:
    def __init__(self):
        self.cwd = os.path.dirname(os.path.abspath(__file__))
        self.readiness_file = f"{self.cwd}/suricata/ready"
        self.sock_file = f"{self.cwd}/suricata/sock"
        self.config_file = f"{self.cwd}/suricata/config.yaml"
        self.rules_file = f"{self.cwd}/suricata/rules/local.rules"
        self.interface = "en0"
        self._sock = None
        self._is_running = False

    def start(self):
        # kill suricata process if it's running
        suricata_proc = self.is_suricata_running()
        if suricata_proc:
            print(f"Suricata is already running with PID {suricata_proc.pid}. Attempting to stop it...")
            self.kill_suricata_process(suricata_proc)
        
        # update config with full sock path
        self.update_config_file()

        # start listening for message on sock file
        thread = threading.Thread(target=self.bind_to_socket)
        thread.daemon = True  # ensures thread exits when main program exits
        thread.start()

        time.sleep(3) # delay for suricata
        self.start_suricata_process()

    def start_suricata_process(self):
        try:
            subprocess.Popen([
                "sudo", "suricata",
                "-c", self.config_file,
                "-i", self.interface,
                "-S", self.rules_file,
                "-vvv"
            ])

            # ensure it's running
            time.sleep(5) # delay for init
            suricata_proc = self.is_suricata_running()
            if suricata_proc:
                print(f"Suricata has started successfully with PID {suricata_proc.pid}")

            # create readiness file to mark ready
            print("Suricata has been started.")
            self.mark_ready()
        except Exception as e:
            print(f"Failed to start Suricata: {e}")
            self.mark_unready()

    def bind_to_socket(self):
        if os.path.exists(self.sock_file):
            os.unlink(self.sock_file)

        # Create a new socket using the AF_UNIX address family
        server_socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        server_socket.bind(self.sock_file)
        server_socket.listen()

        print("Server is listening on socket:", self.sock_file)

        try:
            connection, _ = server_socket.accept()
            print("New connection to sock")

            while True:
                data = connection.recv(4096)
                if data:
                    alert = data.decode().strip()
                    print("New alert:", alert)
                    submit_alert(alert)
                else:
                    connection.close()
                    print("Sock connection closed")
                    break
        finally:
            connection.close()
            server_socket.close()
            os.remove(self.sock_file)

    def update_config_file(self):
        """update the Suricata config.yml to use the new socket file path."""
        with open(self.config_file, 'r') as file:
            config = yaml.safe_load(file)
        config['outputs'][1]['eve-log']['filename'] = self.sock_file
        with open(self.config_file, 'w') as file:
            file.write("%YAML 1.1\n---\n")
            yaml.dump(config, file, default_flow_style=False)
        print("Suricata configuration updated.")

    def is_suricata_running(self):
        """Check if Suricata is running and return the process if it is."""
        for proc in psutil.process_iter(['name']):
            if proc.info['name'] == 'suricata':
                return proc
        return None

    def kill_suricata_process(self, proc):
        """Attempt to terminate a given Suricata process."""
        try:
            proc.terminate()  # sends SIGTERM
            proc.wait(timeout=5)  # wait for suricata process to terminate
            print(f"Suricata process with PID {proc.pid} has been terminated.")
        except psutil.NoSuchProcess:
            print("The process does not exist.")
        except psutil.AccessDenied:
            print("Permission denied to terminate the process.")
        except psutil.TimeoutExpired:
            print("The process did not terminate in time.")
            try:
                proc.kill()  # sends SIGKILL as a last resort
                proc.wait(timeout=5)
                print(f"Suricata forcefully killed.")
            except Exception as e:
                print(f"Failed to forcefully kill Suricata: {e}")

    # def listen_for_alerts(self):
    #     print("Listening for Suricata alerts...")

    #     self.delete_sock_file()

    #     sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    #     sock.bind(self.sock_file)
    #     sock.listen(1)

    #     try:
    #         while True:
    #             connection, _ = sock.accept()
    #             payload = []
    #             while True:
    #                 data = connection.recv(1024)
    #                 if not data:
    #                     break
    #                 payload.append(data)
    #             complete_payload = b''.join(payload)
    #             print(complete_payload.decode('utf-8'))
    #     except KeyboardInterrupt:
    #         print("Socket listener exiting")
    #     finally:
    #         connection.close()
    #         sock.close()

    def delete_sock_file(self):
        try:
            os.unlink(self.sock_file)
        except OSError:
            if os.path.exists(self.sock_file):
                raise

    def mark_ready(self):
        """Create the readiness file."""
        with open(self.readiness_file, 'w') as file:
            file.write('ready')
        print("Marked as ready.")

    def mark_unready(self):
        """Delete the readiness file."""
        try:
            os.remove(self.readiness_file)
            print("Marked as unready.")
        except OSError as e:
            print(f"Failed to remove readiness file: {e}")

# if __name__ == "__main__":
#     suricata = Suricata()
#     threading.Thread(target=suricata.start).start()
