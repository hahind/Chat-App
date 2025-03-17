#!/usr/bin/env python3
import socket
import sys
import argparse
import os

def parse_args():
    parser = argparse.ArgumentParser(description='LU-Connect Client')
    parser.add_argument('--host', type=str, default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--file', type=str)
    parser.add_argument('--message', type=str)
    return parser.parse_args()

def send_file(client_socket, file_path):
    if not os.path.exists(file_path):
        print(f"File '{file_path}' not found.")
        client_socket.close()
        sys.exit(1)
    filename = os.path.basename(file_path)
    filesize = os.path.getsize(file_path)
    print(f"Sending {filename}, size {filesize} bytes...")
    header = f"FILE:{filename}:{filesize}\n".encode('utf-8')
    client_socket.send(header)
    with open(file_path, "rb") as f:
        while True:
            data = f.read(1024)
            if not data:
                break
            client_socket.send(data)
    print("File sent. Waiting for acknowledgment...")
    try:
        ack = client_socket.recv(1024).decode('utf-8')
        print("Server response:", ack)
    except Exception as e:
        print("Error receiving acknowledgment:", e)

def interactive_mode(client_socket):
    try:
        while True:
            inp = input("Enter message (or 'exit' to quit): ")
            if inp.lower() == 'exit':
                break
            client_socket.send(inp.encode('utf-8'))
            resp = client_socket.recv(1024).decode('utf-8')
            print(resp)
    except KeyboardInterrupt:
        pass

def main():
    args = parse_args()
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        client_socket.connect((args.host, args.port))
        print(f"Connected to server at {args.host}:{args.port}")
    except Exception as e:
        print("Connection failed:", e)
        sys.exit(1)
    if args.file:
        send_file(client_socket, args.file)
    elif args.message:
        client_socket.send(args.message.encode('utf-8'))
        resp = client_socket.recv(1024).decode('utf-8')
        print(resp)
    else:
        interactive_mode(client_socket)
    client_socket.close()

if __name__ == "__main__":
    main()
