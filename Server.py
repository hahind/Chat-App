import socket
import threading
import sys
import time
from datetime import datetime
from Authenticate import AuthManager
from encryption_util import EncryptionUtil  # Import the class, not the methods

MAX_CLIENTS = 3
MAX_DATA_RECV = 1024
SERVER_IP = '127.0.0.1'
SERVER_PORT = 8080
ESTIMATED_SESSION = 30
# Server class to manage all backend and client handling, their login or register, also their msg and file transfers
class LUConnectServer:
    def __init__(self, host=SERVER_IP, port=SERVER_PORT, max_clients=MAX_CLIENTS):
        self.host = host
        self.port = port
        self.max_clients = max_clients


        self.clients = []
        self.client_usernames = {}
        self.clientLock = threading.Lock()


        self.waiting_q = []
        self.waiting_lock = threading.Lock()


        self.connection_sem = threading.Semaphore(self.max_clients)

    
        self.auth_m = AuthManager()


        self.enc_util = EncryptionUtil()

# Handles the que and watches if the client can be put into the server
    def processWaiting(self):
        while True:
            with self.waiting_lock:
                if self.waiting_q and self.connection_sem.acquire(blocking=False):
                    clientSocket, address, _ = self.waiting_q.pop(0)
                    try:
                        clientSocket.send("You are now connected to the server.\n".encode('utf-8'))
                    except Exception as e:
                        print(f"Error notifying waiting client: {e}")
                        clientSocket.close()
                        continue
                    threading.Thread(target=self.handleClient, args=(clientSocket, address)).start()

                for idx, (wclientSocket, waddress, wtime) in enumerate(self.waiting_q):
                    pos = idx + 1
                    estWait = pos * ESTIMATED_SESSION
                    try:
                        wclientSocket.send(
                            f"Updated: You are #{pos} in queue. Estimated wait time: {estWait} seconds.\n".encode('utf-8')
                        )
                    except Exception as e:
                        print(f"Error updating waiting client {waddress}: {e}")
                        wclientSocket.close()
                        self.waiting_q.remove((wclientSocket, waddress, wtime))
            time.sleep(5)
# Braodcasts message to everyone
    def broadcastMessage(self, message, sender_socket):
        with self.clientLock:
            for client in self.clients:
                if client != sender_socket:
                    try:
                        client.send(message.encode('utf-8'))
                    except Exception as e:
                        print("Error sending to client:", e)
# Starts the server 
    def startServer(self):
        serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        serverSocket.bind((self.host, self.port))
        serverSocket.listen(100)
        print(f"Server listening on {self.host}:{self.port} (max {self.max_clients} active)")

        threading.Thread(target=self.processWaiting, daemon=True).start()

        while True:
            clientSocket, address = serverSocket.accept()
            if self.connection_sem.acquire(blocking=False):
                threading.Thread(target=self.handleClient, args=(clientSocket, address)).start()
            else:
                with self.waiting_lock:
                    pos = len(self.waiting_q) + 1
                    estWait = pos * ESTIMATED_SESSION
                    try:
                        clientSocket.send(f"Server busy, estimated wait time: {estWait} seconds\n".encode('utf-8'))
                    except Exception as e:
                        print(f"Error notifying busy client: {e}")
                        clientSocket.close()
                        continue
                    self.waiting_q.append((clientSocket, address, time.time()))

# Handles client registration and login and their input
    def handleClient(self, clientSocket, addr):
        with self.clientLock:
            self.clients.append(clientSocket)
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
                success, msg = self.auth_m.registerUser(username, password)
            else:
                success, msg = self.auth_m.loginUser(username, password)
            clientSocket.send(msg.encode('utf-8'))

            if not success:
                clientSocket.close()
                return

            with self.clientLock:
                self.client_usernames[clientSocket] = username

            self.interactiveMode(clientSocket)
        except Exception as e:
            print(f"Error with {addr}: {e}")
        finally:
            with self.clientLock:
                if clientSocket in self.clients:
                    self.clients.remove(clientSocket)
                if clientSocket in self.client_usernames:
                    del self.client_usernames[clientSocket]
            clientSocket.close()
            self.connection_sem.release()
            print(f"[{datetime.now()}] Client {addr} disconnected.")

# Handles file transfers and sets what type of files are able to be transfered
    def handleFileTransfer(self, clientSocket, header):
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

# Starts taking in user inputs and timestamps them
    def interactiveMode(self, clientSocket):
        username = self.client_usernames.get(clientSocket, "Unknown")
        try:
            while True:
                data = clientSocket.recv(MAX_DATA_RECV)
                if not data:
                    break
                text = data.decode('utf-8').strip()

                if text.lower() == "exit":
                    break

                if text.lower().startswith("file:"):
                    self.handleFileTransfer(clientSocket, text)
                    continue

                timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                formatted_message = f"[{timestamp}] {username}: {text}"

                # Encrypt using the instance's method
                encrypted_message = "ENC:" + self.enc_util.encrypt_message(formatted_message)

                self.broadcastMessage(encrypted_message, clientSocket)
                clientSocket.send(encrypted_message.encode('utf-8'))
        except Exception as e:
            print("Interactive mode error:", e)

    def run(self):
        try:
            self.startServer()
        except KeyboardInterrupt:
            print("Server shutting down.")
            sys.exit()

if __name__ == "__main__":
    server = LUConnectServer()
    server.run()
