import tkinter as tk
from tkinter import messagebox
from tkinter import simpledialog
from hashlib import sha512
import Crypto
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import binascii


# This file has the RSA encryption method, Signed signatures and a verification of the signature. As well as a hashed in SHA256

keyPair = RSA.generate(3072)
# generating a public key
pubKey = keyPair.publickey()
print(f"Public key:  (n={hex(pubKey.n)}, e={hex(pubKey.e)})")
pubKeyPEM = pubKey.exportKey()
print(pubKeyPEM.decode('ascii'))
# generating a private key
print(f"Private key: (n={hex(pubKey.n)}, d={hex(keyPair.d)})")
privKeyPEM = keyPair.exportKey()
print(privKeyPEM.decode('ascii'))
# initializing the window prompt to get input
ROOT = tk.Tk()
ROOT.withdraw()

in1 = simpledialog.askstring(title="Test", prompt="Enter the message you want to be encrypted in RSA:")
# converting the message from string to byte
msg = bytes(in1, 'utf-8')
encryptor = PKCS1_OAEP.new(pubKey)
enc = encryptor.encrypt(msg)

decryptor = PKCS1_OAEP.new(keyPair)
dec = decryptor.decrypt(enc)
# display the encrypted and decrypted message
messagebox.askquestion("Do you want to encrypt?", msg)
messagebox.showinfo("encrypted message", binascii.hexlify(enc))
messagebox.showinfo("decrypted message", dec)

# generating a signed signature
hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
signature = pow(hash, keyPair.d, keyPair.n)
hashFromSignature = pow(signature, keyPair.e, keyPair.n)

# check to see if the hash function is verifiyable
if hash == hashFromSignature:
    verify = "True"
else:
    verify = "False"
# displaying the signed signatures via textbox
messagebox.showinfo("Signed", hex(signature))
messagebox.showinfo("Signed verification", verify)
# displaying the SHA256 Hashed message to a textbox
hash_object = SHA256.new(data=msg)
messagebox.showinfo("Hashed SHA256", hash_object.hexdigest())