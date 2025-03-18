#!/usr/bin/env python3
import socket
import threading
import sys
from datetime import datetime
from Authenticate import AuthManager

MAX_CLIENTS = 3
MAX_DATA_RECV = 1024
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080

clients = []
clientLock = threading.Lock()
authMgr = AuthManager()

def startServer():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((SERVER_IP, SERVER_PORT))
    serverSocket.listen(MAX_CLIENTS)
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT} (max {MAX_CLIENTS})")
    while True:
        clientSocket, address = serverSocket.accept()
        with clientLock:
            if len(clients) >= MAX_CLIENTS:
                clientSocket.send("Server is full. Try again later.".encode('utf-8'))
                clientSocket.close()
                continue
        threading.Thread(target=handleClient, args=(clientSocket, address)).start()

def handleClient(clientSocket, addr):
    print(f"[{datetime.now()}] New connection from {addr}")
    with clientLock:
        clients.append(clientSocket)
    try:
        clientSocket.send(b"Welcome to LU-Connect. Type 'register' or 'login': ")
        action = clientSocket.recv(MAX_DATA_RECV).decode('utf-8').strip().lower()
        if action not in ("register", "login"):
            clientSocket.send(b"Invalid option.")
            clientSocket.close()
            return
        clientSocket.send(b"Username: ")
        username = clientSocket.recv(MAX_DATA_RECV).decode('utf-8').strip()
        clientSocket.send(b"Password: ")
        password = clientSocket.recv(MAX_DATA_RECV).decode('utf-8').strip()
        if action == "register":
            success, msg = authMgr.registerUser(username, password)
        else:
            success, msg = authMgr.loginUser(username, password)
        clientSocket.send(msg.encode('utf-8'))
        if not success:
            clientSocket.close()
            return
        interactiveMode(clientSocket)
    except Exception as e:
        print(f"Error with {addr}: {e}")
    finally:
        with clientLock:
            if clientSocket in clients:
                clients.remove(clientSocket)
        clientSocket.close()
        print(f"[{datetime.now()}] Client {addr} disconnected.")

def interactiveMode(clientSocket):
    try:
        while True:
            clientSocket.send(b"Enter message ('exit' to quit): ")
            data = clientSocket.recv(MAX_DATA_RECV)
            if not data:
                break
            text = data.decode('utf-8').strip()
            if text.lower() == "exit":
                break
            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            print(f"[{timestamp}] Message from client: {text}")
            clientSocket.send(f"Server received: {text}".encode('utf-8'))
    except Exception as e:
        print("Interactive mode error:", e)

if __name__ == "__main__":
    try:
        startServer()
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit()
