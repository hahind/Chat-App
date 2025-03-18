import socket
import sys
import argparse
import os

def parseArgs():
    parser = argparse.ArgumentParser(description="LU-Connect Client")
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--file", type=str)
    parser.add_argument("--message", type=str)
    return parser.parse_args()

def sendFile(clientSocket, filePath):
    allowed_extensions = ['.pdf', '.docx', '.jpeg']
    if not any(filePath.endswith(ext) for ext in allowed_extensions):
        print("File type not allowed.")
        return
    if not os.path.exists(filePath):
        print(f"File '{filePath}' not found.")
        clientSocket.close()
        sys.exit(1)
    fname = os.path.basename(filePath)
    fsize = os.path.getsize(filePath)
    header = f"FILE:{fname}:{fsize}\n".encode('utf-8')
    clientSocket.send(header)
    with open(filePath, "rb") as f:
        while True:
            chunk = f.read(1024)
            if not chunk:
                break
            clientSocket.send(chunk)
    print("File sent. Waiting for acknowledgment...")
    ack = clientSocket.recv(1024).decode('utf-8')
    print("Server:", ack)

def interactiveMode(clientSocket):
    try:
        while True:
            data = clientSocket.recv(1024)
            if not data:
                break
            print(data.decode('utf-8'), end="")
            userInput = input()
            clientSocket.send(userInput.encode('utf-8'))
            if userInput.lower() == "exit":
                break
    except Exception as e:
        print("Interactive mode error:", e)

def main():
    args = parseArgs()
    clientSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        clientSocket.connect((args.host, args.port))
        print(f"Connected to server at {args.host}:{args.port}")
    except Exception as e:
        print("Connection failed:", e)
        sys.exit(1)
    if args.file:
        sendFile(clientSocket, args.file)
    elif args.message:
        clientSocket.send(args.message.encode('utf-8'))
        resp = clientSocket.recv(1024).decode('utf-8')
        print(resp)
    else:
        interactiveMode(clientSocket)
    clientSocket.close()

if __name__ == "__main__":
    main()
