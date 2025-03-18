import tkinter as tk

tkinter = tk.Tk()
tkinter.title("Ui for user")
tkinter.geometry("600x400")

tkinter_label = tk.Label(tkinter, text="Test")
tkinter_label.pack(padx=20, pady=20)

tkinter.mainloop()            
