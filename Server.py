import socket

SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
MAX_CLIENTS = 3 

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind((SERVER_IP, SERVER_PORT))
server_socket.listen()