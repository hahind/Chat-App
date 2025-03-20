import tkinter as tk
from tkinter import scrolledtext, messagebox, filedialog
import socket, threading
import winsound
from encryption_util import EncryptionUtil  # Import the class

# The class for all the front end for all the visuals the user will see and their handling
class Ui:
    HOST = '127.0.0.1'
    PORT = 8080
    BUFFER_SIZE = 1024

    def __init__(self, master):
        self.root = master
        self.client_socket = None
        self.notifications_enabled = True
        self.local_username = None

        # Instantiate EncryptionUtil for decryption
        self.enc_util = EncryptionUtil()

        # UI components
        self.login_frame = None
        self.chat_area = None
        self.message_entry = None
        self.mute_button = None
        self.login_mode = tk.StringVar(value="login")
        self.username_entry = None
        self.password_entry = None

        self.initUI()

# Initialises Ui for the user and displays fields to register and log in
    def initUI(self):
        self.root.title("LU-Connect")
        self.root.geometry("600x400")

        self.login_frame = tk.Frame(self.root)
        self.login_frame.pack(fill="both", expand=True, padx=20, pady=20)

        login_radio = tk.Radiobutton(self.login_frame, text="Login", variable=self.login_mode, value="login")
        login_radio.pack(anchor="w")
        register_radio = tk.Radiobutton(self.login_frame, text="Register", variable=self.login_mode, value="register")
        register_radio.pack(anchor="w")

        tk.Label(self.login_frame, text="Username:").pack(anchor="w", pady=(10,0))
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.pack(anchor="w", fill="x")

        tk.Label(self.login_frame, text="Password:").pack(anchor="w", pady=(10,0))
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.pack(anchor="w", fill="x", pady=(0,10))

        submit_button = tk.Button(self.login_frame, text="Submit", command=self.handleLoginOrRegister)
        submit_button.pack(pady=10)

# Handles turnong off and on notifications
    def toggle_notifications(self):
        self.notifications_enabled = not self.notifications_enabled
        if self.notifications_enabled:
            self.mute_button.config(text="Mute")
        else:
            self.mute_button.config(text="Unmute")

# Handles message receiving also, if they are encrypted we call decrypt functions
    def receiveMessages(self):
        while True:
            data = self.client_socket.recv(self.BUFFER_SIZE)
            if not data:
                break
            text = data.decode('utf-8', errors='replace').strip()

            # If message starts with "ENC:", we decrypt
            if text.startswith("ENC:"):
                enc_part = text[4:]
                try:
                    text = self.enc_util.decrypt_message(enc_part)
                except Exception as e:
                    print("Decryption error:", e)

            self.chat_area.config(state="normal")
            self.chat_area.insert(tk.END, text + "\n")
            self.chat_area.config(state="disabled")
            self.chat_area.see(tk.END)

            sender = self.parse_sender_username(text)
            if self.notifications_enabled and sender and sender != self.local_username:
                try:
                    winsound.PlaySound("notification.wav", winsound.SND_FILENAME | winsound.SND_ASYNC)
                except Exception as e:
                    print("Sound error:", e)

# Parses who sent the message in order not to double up on sound effects and manage who it is
    def parse_sender_username(self, full_text):
        close_bracket_index = full_text.find(']')
        if close_bracket_index == -1:
            return None
        after_bracket = full_text[close_bracket_index+1:].strip()
        colon_index = after_bracket.find(':')
        if colon_index == -1:
            return None
        return after_bracket[:colon_index].strip()

# Sends a message to the server not much else
    def sendMessage(self, event=None):
        msg = self.message_entry.get().strip()
        if msg and self.client_socket:
            try:
                self.client_socket.sendall(msg.encode("utf-8"))
                self.message_entry.delete(0, tk.END)
            except Exception as e:
                messagebox.showerror("Send Error", str(e))

# File Ui to be able to send files
    def sendFileUI(self):
        file_path = filedialog.askopenfilename(
            title="Select a file to send",
            filetypes=[("Allowed files", "*.pdf *.docx *.jpeg"), ("All files", "*.*")]
        )
        if file_path:
            pass

# Creates the main chat Ui where users can see all the messages
    def buildChatUI(self):
        self.login_frame.destroy()

        chat_frame = tk.Frame(self.root)
        chat_frame.pack(fill="both", expand=True)

        self.chat_area = scrolledtext.ScrolledText(chat_frame, state="disabled", wrap="word")
        self.chat_area.pack(fill="both", expand=True, padx=20, pady=10)

        bottom_frame = tk.Frame(chat_frame)
        bottom_frame.pack(fill="x", padx=20, pady=10)

        self.message_entry = tk.Entry(bottom_frame)
        self.message_entry.pack(side="left", fill="x", expand=True)
        self.message_entry.bind("<Return>", self.sendMessage)
        self.message_entry.focus_set()

        send_button = tk.Button(bottom_frame, text="Send", command=self.sendMessage)
        send_button.pack(side="left", padx=5)

        file_button = tk.Button(bottom_frame, text="Send File", command=self.sendFileUI)
        file_button.pack(side="left", padx=5)

        self.mute_button = tk.Button(bottom_frame, text="Mute", command=self.toggle_notifications)
        self.mute_button.pack(side="left", padx=5)

        threading.Thread(target=self.receiveMessages, daemon=True).start()

# Manages login and register ui
    def handleLoginOrRegister(self):
        try:
            self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.client_socket.connect((self.HOST, self.PORT))
            print(f"Connected to server at {self.HOST}:{self.PORT}")

            welcome_prompt = self.client_socket.recv(self.BUFFER_SIZE).decode('utf-8', errors='replace')
            print("Server says:", welcome_prompt)

            mode = self.login_mode.get()
            self.client_socket.sendall(mode.encode('utf-8'))

            server_prompt = self.client_socket.recv(self.BUFFER_SIZE).decode('utf-8', errors='replace')
            print("Server says:", server_prompt)
            self.client_socket.sendall(self.username_entry.get().encode('utf-8'))

            server_prompt = self.client_socket.recv(self.BUFFER_SIZE).decode('utf-8', errors='replace')
            print("Server says:", server_prompt)
            self.client_socket.sendall(self.password_entry.get().encode('utf-8'))

            auth_response = self.client_socket.recv(self.BUFFER_SIZE).decode('utf-8', errors='replace')
            print("Auth response:", auth_response)
            if "successful" in auth_response.lower():
                self.local_username = self.username_entry.get().strip()
                self.buildChatUI()
            else:
                messagebox.showerror("Error", auth_response)
                self.client_socket.close()
                self.client_socket = None
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))
            if self.client_socket:
                self.client_socket.close()
                self.client_socket = None

# The main run function
def main():
    root = tk.Tk()
    app = Ui(root)
    root.mainloop()

if __name__ == "__main__":
    main()
