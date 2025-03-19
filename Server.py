import socket
import threading
import sys
import time
from datetime import datetime
from Authenticate import AuthManager
from encryption_util import encrypt_message 

MAX_CLIENTS = 3
MAX_DATA_RECV = 1024
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
ESTIMATED_SESSION = 30

clients = []                  
client_usernames = {}            

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
                except Exception as e:
                    print(f"Error notifying waiting client: {e}")
                    clientSocket.close()
                    continue
                threading.Thread(target=handleClient, args=(clientSocket, address)).start()
        time.sleep(1)

def broadcastMessage(message, sender_socket):
    with clientLock:
        for client in clients:
            if client != sender_socket:
                try:
                    client.send(message.encode('utf-8'))
                except Exception as e:
                    print("Error sending to client:", e)

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
                    clientSocket.send(f"Server busy, estimated wait time: {estWait} seconds\n".encode('utf-8'))
                except Exception as e:
                    print(f"Error notifying busy client: {e}")
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

        with clientLock:
            client_usernames[clientSocket] = username

        interactiveMode(clientSocket)
    except Exception as e:
        print(f"Error with {addr}: {e}")
    finally:
        with clientLock:
            if clientSocket in clients:
                clients.remove(clientSocket)
            if clientSocket in client_usernames:
                del client_usernames[clientSocket]
        clientSocket.close()
        connection_sem.release()
        print(f"[{datetime.now()}] Client {addr} disconnected.")

def handleFileTransfer(clientSocket, header):
    """Process file transfers from clients with allowed file types."""
    try:
        header_parts = header.strip().split(":")
        if len(header_parts) != 3:
            clientSocket.send(b"Invalid file header.")
            return
        _, filename, filesize_str = header_parts
        filesize = int(filesize_str)
        allowed = (".pdf", ".docx", ".jpeg")
        if not filename.lower().endswith(allowed):
            clientSocket.send(b"File type not allowed.")
            return

        file_data = b""
        while len(file_data) < filesize:
            chunk = clientSocket.recv(min(1024, filesize - len(file_data)))
            if not chunk:
                break
            file_data += chunk
        with open("received_" + filename, "wb") as f:
            f.write(file_data)
        clientSocket.send(f"File received: {filename}".encode('utf-8'))
    except Exception as e:
        clientSocket.send(f"Error receiving file: {e}".encode('utf-8'))


def interactiveMode(clientSocket):
    username = client_usernames.get(clientSocket, "Unknown")
    try:
        while True:
            clientSocket.send(b"Enter message ('exit' to quit): ")
            data = clientSocket.recv(MAX_DATA_RECV)
            if not data:
                break
            text = data.decode('utf-8').strip()

            if text.lower() == "exit":
                break

            if text.lower().startswith("file:"):
                handleFileTransfer(clientSocket, text)
                continue

            timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
            formatted_message = f"[{timestamp}] {username}: {text}"
            encrypted_message = "ENC:" + encrypt_message(formatted_message)

            broadcastMessage(encrypted_message, clientSocket)
            clientSocket.send(encrypted_message.encode('utf-8'))
    except Exception as e:
        print("Interactive mode error:", e)

if __name__ == "__main__":
    try:
        startServer()
    except KeyboardInterrupt:
        print("Server shutting down.")
        sys.exit()
