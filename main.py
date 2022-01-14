import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from cryptography.fernet import Fernet

ROOT = tk.Tk()
ROOT.withdraw()

in1 = simpledialog.askstring(title="Test", prompt="Enter the message you want to be encrypted with AES:")

key = Fernet.generate_key()
fernet = Fernet(key)
enc = fernet.encrypt(in1.encode())
dec = fernet.decrypt(enc).decode()

messagebox.askquestion("Do you want to encrypt?", in1)

messagebox.showinfo("encrypted message",  enc)
messagebox.showinfo("decrypted message",  dec)

