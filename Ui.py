import tkinter as tk
import socket
import time

HOST = '127.0.0.1'
PORT = 8080
BUFFER_SIZE = 1024

def handleLoginAttempt():
    usr = username_entry.get().strip()
    pwd = password_entry.get().strip()
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        # Send login protocol items in sequence
        for item in ["login", usr, pwd]:
            sock.sendall(item.encode("utf-8"))
            time.sleep(0.1)
        reply = sock.recv(BUFFER_SIZE).decode("utf-8")
        print("Server reply:", reply)
    except Exception as e:
        print("Login attempt error:", e)
    finally:
        sock.close()

tkinter = tk.Tk()
tkinter.title("UI for User")
tkinter.geometry("600x400")

username_label = tk.Label(tkinter, text="Username:")
username_label.pack(padx=20, pady=(40,5))

username_entry = tk.Entry(tkinter, width=30)
username_entry.pack(padx=20, pady=5)

password_label = tk.Label(tkinter, text="Password:")
password_label.pack(padx=20, pady=5)

password_entry = tk.Entry(tkinter, show="*", width=30)
password_entry.pack(padx=20, pady=5)
def submitAction():
    username = username_entry.get()
    password = password_entry.get()
    print(f"Username: {username}, Password: {password}")

submit_button = tk.Button(tkinter, text="Submit", command=submitAction)
submit_button.pack(padx=20, pady=20)

tkinter.mainloop()
