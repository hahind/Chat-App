import socket
import sys

SERVER_IP = '127.0.0.1' 
SERVER_PORT =  8080     

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

try:
    client_socket.connect((SERVER_IP, SERVER_PORT))
    print(f"Connected to server at {SERVER_IP}:{SERVER_PORT}")
except Exception as e:
    print(f"Connection failed: {e}")
    sys.exit()
