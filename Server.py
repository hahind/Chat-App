#!/usr/bin/env python3
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
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((SERVER_IP, SERVER_PORT))
    server_socket.listen(MAX_CLIENTS)
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT} (max {MAX_CLIENTS} clients)")
    while True:
        client_socket, address = server_socket.accept()
        with client_lock:
            if len(clients) >= MAX_CLIENTS:
                client_socket.send("Server is full. Try again later.".encode('utf-8'))
                client_socket.close()
                continue
        threading.Thread(target=handle_client, args=(client_socket, address)).start()

def handle_client(client_socket, address):
    print(f"[{datetime.now()}] New connection from {address}")
    with client_lock:
        clients.append(client_socket)
    try:
        while True:
            data = client_socket.recv(MAX_DATA_RECV)
            if not data:
                break
            if data.startswith(b"FILE:"):
                if b'\n' in data:
                    header_line, remainder = data.split(b'\n', 1)
                else:
                    header_line = data
                    remainder = b''
                try:
                    header_text = header_line.decode('utf-8').strip()
                    parts = header_text.split(':')
                    if len(parts) < 3:
                        continue
                    _, filename, filesize_str = parts[:3]
                    filesize = int(filesize_str)
                except Exception as e:
                    print(f"Error parsing header from {address}: {e}")
                    continue
                print(f"[{datetime.now()}] Receiving file '{filename}' of size {filesize} bytes from {address}")
                file_data = remainder
                while len(file_data) < filesize:
                    chunk = client_socket.recv(min(MAX_DATA_RECV, filesize - len(file_data)))
                    if not chunk:
                        break
                    file_data += chunk
                try:
                    with open("received_" + filename, "wb") as f:
                        f.write(file_data)
                    print(f"[{datetime.now()}] File received and saved as 'received_{filename}'")
                    client_socket.send(f"File received: {filename}".encode('utf-8'))
                except Exception as e:
                    client_socket.send(f"Error saving file: {e}".encode('utf-8'))
                continue
            else:
                try:
                    message = data.decode('utf-8')
                except:
                    continue
                print(f"[{datetime.now()}] {address} says: {message}")
                response = f"Server received: {message}"
                client_socket.send(response.encode('utf-8'))
    except Exception as e:
        print(f"Error with {address}: {e}")
    finally:
        with client_lock:
            if client_socket in clients:
                clients.remove(client_socket)
        client_socket.close()
        print(f"[{datetime.now()}] Client {address} disconnected.")

if __name__ == "__main__":
    try:
        start_server()
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit()
