import tkinter as tk

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
