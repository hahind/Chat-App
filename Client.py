import socket
import sys
import argparse
import os

# Class for handling clients
class Client_c:

    def __init__(self):
        self.clientSocket = None
        self.args = None
# Parses comand line to understand what to do
    def parseArgs(self):

        parser = argparse.ArgumentParser(description="LU-Connect Client")
        parser.add_argument("--host", type=str, default="127.0.0.1")
        parser.add_argument("--port", type=int, default=8080)
        parser.add_argument("--file", type=str, help="Path to a .pdf, .docx, or .jpeg file to send")
        parser.add_argument("--message", type=str, help="A single text message to send")
        return parser.parse_args()
    
# Sendinf file funtion
    def sendFile(self, filePath):

        allowed_extensions = ['.pdf', '.docx', '.jpeg']
        if not any(filePath.endswith(ext) for ext in allowed_extensions):
            print("File type not allowed.")
            return
        if not os.path.exists(filePath):
            print(f"File '{filePath}' not found.")
            self.clientSocket.close()
            sys.exit(1)
        fname = os.path.basename(filePath)
        fsize = os.path.getsize(filePath)
        header = f"FILE:{fname}:{fsize}\n".encode('utf-8')
        self.clientSocket.send(header)
        with open(filePath, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                self.clientSocket.send(chunk)
        print("File sent. Waiting for acknowledgment...")
        ack = self.clientSocket.recv(1024).decode('utf-8')
        print("Server:", ack)

# Mode to take inputs from server and print them back
    def interactiveMode(self):
        try:
            while True:
                data = self.clientSocket.recv(1024)
                if not data:
                    break
                print(data.decode('utf-8'), end="")
                userInput = input()
                self.clientSocket.send(userInput.encode('utf-8'))
                if userInput.lower() == "exit":
                    break
        except Exception as e:
            print("Interactive mode error:", e)

# Main run function for the client server
    def run(self):

        self.args = self.parseArgs()

        # Create and connect the client socket
        self.clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.clientSocket.connect((self.args.host, self.args.port))
            print(f"Connected to server at {self.args.host}:{self.args.port}")
        except Exception as e:
            print("Connection failed:", e)
            sys.exit(1)

        # Decide what to do based on arguments
        if self.args.file:
            self.sendFile(self.args.file)
        elif self.args.message:
            self.clientSocket.send(self.args.message.encode('utf-8'))
            resp = self.clientSocket.recv(1024).decode('utf-8')
            print(resp)
        else:
            self.interactiveMode()

        # Close the connection
        self.clientSocket.close()
#If run directly, instantiate and run the CLI client.
def main():

    cli = Client_c()
    cli.run()

if __name__ == "__main__":
    main()
