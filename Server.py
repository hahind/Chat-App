import socket
import threading
import sys
import time
from datetime import datetime
MAX_CLIENTS = 3
MAX_DATA_RECV = 1024
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080

# List of active clients
clients = []
client_lock = threading.Lock()  # Protect client list

# Client Handler Thread
def handle_client(client_socket, address):
    print(f"[{datetime.now()}] New connection from {address}")
    
    with client_lock:
        clients.append(client_socket)
    
    try:
        while True:
            data = client_socket.recv(MAX_DATA_RECV).decode('utf-8')
            if not data:
                print(f"[{datetime.now()}] Client {address} disconnected.")
                break
            
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] {address} says: {data}")

            # Echo message back to client
            response = f"Server received: {data}"
            client_socket.send(response.encode('utf-8'))

    except Exception as e:
        print(f"Error with {address}: {e}")

    finally:
        with client_lock:
            clients.remove(client_socket)
        client_socket.close()