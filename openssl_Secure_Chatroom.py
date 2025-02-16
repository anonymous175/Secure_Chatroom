import socket
import ssl
import threading
import sys
import os
import argparse
import subprocess

CERT_FILE = "cert.pem"
KEY_FILE = "key.pem"

def generate_ssl_keys():
    """Generate OpenSSL keys if they don't exist."""
    if os.path.exists(CERT_FILE) and os.path.exists(KEY_FILE):
        print("[✔] Keys already exist!")
        return

    print("[🔑] Generating new SSL keys...")
    cmd = f'openssl req -x509 -newkey rsa:2048 -keyout {KEY_FILE} -out {CERT_FILE} -days 365 -nodes -subj "/CN=SecureChat"'
    subprocess.run(cmd, shell=True, check=True)
    print("[✔] SSL keys generated successfully!")

def secure_send(conn):
    """Handles sending messages securely."""
    while True:
        try:
            message = input()
            if message.lower() == "exit":
                print("[✔] Exiting chat...")
                conn.sendall(b"exit")
                conn.close()
                sys.exit(0)
            conn.sendall(message.encode())
        except (BrokenPipeError, ConnectionResetError):
            print("\n[❌] Connection lost. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"[❌] Error sending: {e}")
            break

def secure_receive(conn):
    """Handles receiving messages securely."""
    while True:
        try:
            data = conn.recv(4096)
            if not data or data.decode().lower() == "exit":
                print("\n[✔] Connection closed by remote user.")
                conn.close()
                sys.exit(0)
            print(f"\n[📩] Message: {data.decode()}")
        except (BrokenPipeError, ConnectionResetError):
            print("\n[❌] Connection lost. Exiting...")
            sys.exit(0)
        except Exception as e:
            print(f"[❌] Error receiving: {e}")
            break

def start_server(port):
    """Starts the secure chat server."""
    print(f"[✔] Starting server on port {port}...")

    context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
    context.load_cert_chain(certfile=CERT_FILE, keyfile=KEY_FILE)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_sock:
        server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_sock.bind(("0.0.0.0", port))
        server_sock.listen(1)
        print(f"[🔒] Waiting for a connection on port {port}...")

        conn, addr = server_sock.accept()
        print(f"[✔] Connection from {addr}")

        with context.wrap_socket(conn, server_side=True) as secure_conn:
            send_thread = threading.Thread(target=secure_send, args=(secure_conn,))
            recv_thread = threading.Thread(target=secure_receive, args=(secure_conn,))
            send_thread.daemon = True  # Ensure thread closes when program exits
            recv_thread.daemon = True
            send_thread.start()
            recv_thread.start()

            send_thread.join()
            recv_thread.join()

def start_client(ip, port):
    """Starts the secure chat client."""
    print(f"[✔] Connecting to {ip}:{port}...")

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE  # ⚠ Change this if using proper verification!

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client_sock:
        client_sock.connect((ip, port))
        with context.wrap_socket(client_sock, server_hostname=ip) as secure_conn:
            print("[✔] Connected to server!")

            send_thread = threading.Thread(target=secure_send, args=(secure_conn,))
            recv_thread = threading.Thread(target=secure_receive, args=(secure_conn,))
            send_thread.daemon = True
            recv_thread.daemon = True
            send_thread.start()
            recv_thread.start()

            send_thread.join()
            recv_thread.join()

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Secure Chat with OpenSSL")
    parser.add_argument("mode", choices=["server", "client"], help="Mode: server or client")
    parser.add_argument("ip_port", nargs="*", help="For server: port | For client: server_ip port")
    parser.add_argument("--generate-keys", action="store_true", help="Generate SSL keys")

    args = parser.parse_args()

    if args.generate_keys:
        generate_ssl_keys()
        sys.exit(0)

    if args.mode == "server":
        if len(args.ip_port) != 1:
            print("Usage: python secure_chat.py server <port>")
            sys.exit(1)
        port = int(args.ip_port[0])
        start_server(port)

    elif args.mode == "client":
        if len(args.ip_port) != 2:
            print("Usage: python secure_chat.py client <server_ip> <port>")
            sys.exit(1)
        ip, port = args.ip_port
        start_client(ip, int(port))
