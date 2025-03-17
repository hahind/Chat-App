import socket
import threading
import sys
from datetime import datetime
MAX_CLIENTS = 3
MAX_DATA_RECV = 1024
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080

clients = []
client_lock = threading.Lock()

def start_server():
    print(f"Starting LU-Connect server on {SERVER_IP}:{SERVER_PORT}")
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(MAX_CLIENTS)
    print(f"Server listening, max {MAX_CLIENTS} clients...")

    while True:
        client_socket, address = server_socket.accept()

        with client_lock:
            if len(clients) >= MAX_CLIENTS:
                print(f"[{datetime.now()}] Max clients reached, no connect {address}")
                client_socket.send("Server is full.".encode('utf-8'))
                client_socket.close()
                continue

        thread = threading.Thread(target=handle_client, args=(client_socket, address))
        thread.start()

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
            response = f"Server received: {data}"
            client_socket.send(response.encode('utf-8'))

    except Exception as e:
        print(f"Error with {address}: {e}")
    finally:
        with client_lock:
            clients.remove(client_socket)
        client_socket.close()

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("\nServer shutting down.")
        sys.exit()