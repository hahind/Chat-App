import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import socket, threading, time, os

HOST = '127.0.0.1'
PORT = 8080
BUFFER_SIZE = 1024

client_socket = None

def buildChatUI():
    for widget in tkinter.winfo_children():
        widget.destroy()
    print("DEBUG: client_socket after login:", client_socket)
    global chat_area, message_entry
    chat_frame = tk.Frame(tkinter)
    chat_frame.pack(fill="both", expand=True)
    
    chat_area = scrolledtext.ScrolledText(chat_frame, state="disabled", wrap="word")
    chat_area.pack(fill="both", expand=True, padx=20, pady=10)
    
    bottom_frame = tk.Frame(chat_frame)
    bottom_frame.pack(fill="x", padx=20, pady=10)
    
    message_entry = tk.Entry(bottom_frame)
    message_entry.pack(side="left", fill="x", expand=True)
    message_entry.bind("<Return>", sendMessage)
    message_entry.focus_set()
    
    send_button = tk.Button(bottom_frame, text="Send", command=sendMessage)
    send_button.pack(side="left", padx=5)
    
    file_button = tk.Button(bottom_frame, text="Send File", command=sendFileUI)
    file_button.pack(side="left", padx=5)
    
    threading.Thread(target=receiveMessages, daemon=True).start()

def sendMessage(event=None):
    msg = message_entry.get().strip()
    print("DEBUG: Attempting to send:", msg)
    if msg and client_socket:
        try:
            client_socket.sendall(msg.encode("utf-8"))
            message_entry.delete(0, tk.END)
        except Exception as e:
            messagebox.showerror("Send Error", str(e))

def sendFileUI():
    file_path = filedialog.askopenfilename(
        title="Select a file to send",
        filetypes=[("Allowed files", "*.pdf *.docx *.jpeg"), ("All files", "*.*")]
    )
    if file_path:
        sendFile(client_socket, file_path)

def sendFile(sock, filePath):
    allowed_extensions = ['.pdf', '.docx', '.jpeg']
    if not any(filePath.lower().endswith(ext) for ext in allowed_extensions):
        messagebox.showerror("File Error", "File type not allowed.")
        return
    if not os.path.exists(filePath):
        messagebox.showerror("File Error", f"File '{filePath}' not found.")
        return
    fname = os.path.basename(filePath)
    fsize = os.path.getsize(filePath)
    header = f"FILE:{fname}:{fsize}\n".encode('utf-8')
    try:
        sock.sendall(header)
        with open(filePath, "rb") as f:
            while True:
                chunk = f.read(1024)
                if not chunk:
                    break
                sock.sendall(chunk)
        ack = sock.recv(BUFFER_SIZE).decode("utf-8")
        chat_area.config(state="normal")
        chat_area.insert(tk.END, f"Server: {ack}\n")
        chat_area.config(state="disabled")
        chat_area.see(tk.END)
    except Exception as e:
        messagebox.showerror("File Transfer Error", str(e))

def receiveMessages():
    global client_socket
    print("DEBUG: Started receiveMessages thread")
    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break
            message = data.decode("utf-8")
            chat_area.config(state="normal")
            chat_area.insert(tk.END, message + "\n")
            chat_area.config(state="disabled")
            chat_area.see(tk.END)
    except Exception as e:
        print("Receive error:", e)

def handleLoginAttempt():
    global client_socket
    usr = username_entry.get().strip()
    pwd = password_entry.get().strip()
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        
        welcome = client_socket.recv(BUFFER_SIZE).decode("utf-8")
        print("Server says:", welcome)
        
        client_socket.sendall("login".encode("utf-8"))
        time.sleep(0.1)
        
        usr_prompt = client_socket.recv(BUFFER_SIZE).decode("utf-8")
        print("Server says:", usr_prompt)
        client_socket.sendall(usr.encode("utf-8"))
        time.sleep(0.1)
        
        pwd_prompt = client_socket.recv(BUFFER_SIZE).decode("utf-8")
        print("Server says:", pwd_prompt)
        client_socket.sendall(pwd.encode("utf-8"))
        time.sleep(0.1)
        
        reply = client_socket.recv(BUFFER_SIZE).decode("utf-8")
        print("Server reply:", reply)
        if "successful" in reply.lower():
            buildChatUI()
        else:
            messagebox.showerror("Login Failed", reply)
    except Exception as e:
        messagebox.showerror("Login Error", str(e))

tkinter = tk.Tk()
tkinter.title("LU-Connect UI")
tkinter.geometry("600x400")

username_label = tk.Label(tkinter, text="Username:")
username_label.pack(padx=20, pady=(40,5))
username_entry = tk.Entry(tkinter, width=30)
username_entry.pack(padx=20, pady=5)
password_label = tk.Label(tkinter, text="Password:")
password_label.pack(padx=20, pady=5)
password_entry = tk.Entry(tkinter, show="*", width=30)
password_entry.pack(padx=20, pady=5)
submit_button = tk.Button(tkinter, text="Submit", command=handleLoginAttempt)
submit_button.pack(padx=20, pady=20)

tkinter.mainloop()
