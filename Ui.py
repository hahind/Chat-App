import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import socket, threading
import winsound
from encryption_util import decrypt_message 

HOST = '127.0.0.1'
PORT = 8080
BUFFER_SIZE = 1024

client_socket = None
notifications_enabled = True

def toggle_notifications():
    global notifications_enabled
    notifications_enabled = not notifications_enabled
    if notifications_enabled:
        mute_button.config(text="Mute")
    else:
        mute_button.config(text="Unmute")

def receiveMessages():

    try:
        while True:
            data = client_socket.recv(BUFFER_SIZE)
            if not data:
                break
            text = data.decode('utf-8', errors='replace').strip()

            if text.startswith("ENC:"):
                enc_part = text[4:]
                try:
                    decrypted_text = decrypt_message(enc_part)
                    text = decrypted_text
                except Exception as e:
                    print("Decryption error:", e)

            chat_area.config(state="normal")
            chat_area.insert(tk.END, text + "\n")
            chat_area.config(state="disabled")
            chat_area.see(tk.END)

            if notifications_enabled:
                try:
                    winsound.PlaySound("notification.wav", winsound.SND_FILENAME | winsound.SND_ASYNC)
                except Exception as e:
                    print("Sound error:", e)
    except Exception as e:
        print("Receive error:", e)

def sendMessage(event=None):

    msg = message_entry.get().strip()
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
        pass

def buildChatUI():

    login_frame.destroy()

    chat_frame = tk.Frame(root)
    chat_frame.pack(fill="both", expand=True)

    global chat_area, message_entry, mute_button

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

    mute_button = tk.Button(bottom_frame, text="Mute", command=toggle_notifications)
    mute_button.pack(side="left", padx=5)

    threading.Thread(target=receiveMessages, daemon=True).start()

def handleLoginOrRegister():
    global client_socket
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((HOST, PORT))
        print(f"Connected to server at {HOST}:{PORT}")

        welcome_prompt = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='replace')
        print("Server says:", welcome_prompt)

        mode = login_mode.get()
        client_socket.sendall(mode.encode('utf-8'))

        server_prompt = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='replace')
        print("Server says:", server_prompt)
        client_socket.sendall(username_entry.get().encode('utf-8'))

        server_prompt = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='replace')
        print("Server says:", server_prompt)
        client_socket.sendall(password_entry.get().encode('utf-8'))

        auth_response = client_socket.recv(BUFFER_SIZE).decode('utf-8', errors='replace')
        print("Auth response:", auth_response)
        if "successful" in auth_response.lower():
            buildChatUI()
        else:
            messagebox.showerror("Error", auth_response)
            client_socket.close()
            client_socket = None

    except Exception as e:
        messagebox.showerror("Connection Error", str(e))
        if client_socket:
            client_socket.close()
            client_socket = None

root = tk.Tk()
root.title("LU-Connect")
root.geometry("600x400")

login_frame = tk.Frame(root)
login_frame.pack(fill="both", expand=True, padx=20, pady=20)

login_mode = tk.StringVar(value="login")
login_radio = tk.Radiobutton(login_frame, text="Login", variable=login_mode, value="login")
login_radio.pack(anchor="w")
register_radio = tk.Radiobutton(login_frame, text="Register", variable=login_mode, value="register")
register_radio.pack(anchor="w")

tk.Label(login_frame, text="Username:").pack(anchor="w", pady=(10,0))
username_entry = tk.Entry(login_frame)
username_entry.pack(anchor="w", fill="x")

tk.Label(login_frame, text="Password:").pack(anchor="w", pady=(10,0))
password_entry = tk.Entry(login_frame, show="*")
password_entry.pack(anchor="w", fill="x", pady=(0,10))

submit_button = tk.Button(login_frame, text="Submit", command=handleLoginOrRegister)
submit_button.pack(pady=10)

root.mainloop()
