#!/usr/bin/env python3
import socket
import threading
import sys
import time
from datetime import datetime
from Authenticate import AuthManager

MAX_CLIENTS = 3
MAX_DATA_RECV = 1024
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
ESTIMATED_SESSION = 30

clients = []
clientLock = threading.Lock()
waiting_q = []
waiting_lock = threading.Lock()
connection_sem = threading.Semaphore(MAX_CLIENTS)
auth_m = AuthManager()

def processWaiting():
    while True:
        with waiting_lock:
            if waiting_q and connection_sem.acquire(blocking=False):
                clientSocket, address, _ = waiting_q.pop(0)
                try:
                    clientSocket.send("You are now connected to the server.\n".encode('utf-8'))
                except:
                    clientSocket.close()
                    continue
                threading.Thread(target=handleClient, args=(clientSocket, address)).start()
        time.sleep(1)

def startServer():
    serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serverSocket.bind((SERVER_IP, SERVER_PORT))
    serverSocket.listen(100)
    print(f"Server listening on {SERVER_IP}:{SERVER_PORT} (max {MAX_CLIENTS} active)")
    threading.Thread(target=processWaiting, daemon=True).start()
    while True:
        clientSocket, address = serverSocket.accept()
        if connection_sem.acquire(blocking=False):
            threading.Thread(target=handleClient, args=(clientSocket, address)).start()
        else:
            with waiting_lock:
                pos = len(waiting_q) + 1
                estWait = pos * ESTIMATED_SESSION
                try:
                    clientSocket.send(f"Server busy\n".encode('utf-8'))
                except:
                    clientSocket.close()
                    continue
                waiting_q.append((clientSocket, address, time.time()))

def handleClient(clientSocket, addr):
    with clientLock:
        clients.append(clientSocket)
    print(f"[{datetime.now()}] New connection from {addr}")
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
            success, msg = auth_m.registerUser(username, password)
        else:
            success, msg = auth_m.loginUser(username, password)
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
        connection_sem.release()
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
            print(f"[{timestamp}] Message: {text}")
            clientSocket.send(f"Server received: {text}".encode('utf-8'))
    except Exception as e:
        print("Interactive mode error:", e)

if __name__ == "__main__":
    try:
        startServer()
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit()
