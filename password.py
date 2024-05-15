import os
import base64
from functools import partial
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import sqlite3
import tkinter as tk
from tkinter import messagebox

mainWindow = tk.Tk()
mainWindow.withdraw()
# placeholder, will be replaced with sql database or json file
passwords = {}

"""
Adds password to database. Takes encryption key as parameter. Gets account name, username and password from
respective text fields, encrypts username and password and stores them.
"""
def addPassword(key):
    account = mainWindow.accountEntry.get()
    uname = mainWindow.unameEntry.get()
    pword = mainWindow.pwordEntry.get()

    if account and uname and pword:
        encPword = encryptPassword(key, pword)
        passwords[account] = {"username": uname, "password": encPword}
        messagebox.showinfo("Success","Password added successfully")
    else:
        messagebox.showwarning("Error", "An error occurred")
    return

"""
Gets password from database. Takes encryption key as parameter. Gets account name from text field,
gets respective username and password from db and decrypts them. Displays credentials in message box.
"""
def getPassword(key):
    account = mainWindow.accountEntry.get()
    if account in passwords:
        uname = passwords[account]["username"]
        encPword = passwords[account]["password"]
        decPword = decryptPassword(key, encPword)
        displayText = "Username: "+uname+"\nPassword: "+decPword
        messagebox.showinfo("Password", displayText)
    else:
        messagebox.showwarning("Error", "Password not found")
    return

"""
Generates new master password. Takes new master password as plain text input. Uses PBKDF2HMAC to derive
a key from master password. Generates new plain text key, which is encrypted with the password key.
This encrypted key is stored in a file and used for cryptography in this program (after decryption).
Another key is further derived from the password key, this is stored in a file and used to verify if the password is correct.
"""
def generateMasterPassword(input):
    input = input.encode()
    file = open("salt", "rb")
    salt = file.read()
    file.close()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    passwordKey = base64.urlsafe_b64encode(kdf.derive(input))
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    passwordHash = base64.urlsafe_b64encode(kdf.derive(passwordKey))

    secretKey = Fernet.generate_key()
    f = Fernet(passwordKey)
    encryptedKey = f.encrypt(secretKey)

    file = open("master", "wb")
    file.write(passwordHash)
    file.close()
    file = open("key", "wb")
    file.write(encryptedKey)
    file.close()
    return

"""
Verifies master password entered by user. Takes plain text password as parameter. Derives a key from the password with PBKDF2HMAC,
and derives yet another key from the previous one. The second key is compared to the stored master password. If the password is correct,
use the first key to decrypt the secret key, and return the secret key.
"""
def verifyMasterPassword(input):
    input = input.encode()
    file = open("salt", "rb")
    salt = file.read()
    file.close()

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    passwordKey = base64.urlsafe_b64encode(kdf.derive(input))

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA512(),
        length=32,
        salt=salt,
        iterations=480000,
    )
    passwordHash = base64.urlsafe_b64encode(kdf.derive(passwordKey))
    file = open("master", "rb")
    master = file.read()
    file.close()
    if(passwordHash != master):
        return

    f = Fernet(passwordKey)
    encryptedKey = loadKey()
    decryptedKey = f.decrypt(encryptedKey)
    return decryptedKey

"""
Generate random salt and store it in a file.
"""
def generateSalt():
    salt = os.urandom(16)
    file = open("salt", "wb")
    file.write(salt)
    file.close()
    return

"""
Load the encrypted secret key from a file.
"""
def loadKey():
    file = open("key", "rb")
    key = file.read()
    file.close()
    return key

"""
Encrypt a password to be stored in database. Takes encryption key and plain text password,
returns encrypted password.
"""
def encryptPassword(key, pword):
    f = Fernet(key)
    encPword = f.encrypt(pword.encode()).decode()
    return encPword

"""
Decrypt a password. Takes encryption key and encrypted password, returns decrypted password.
"""
def decryptPassword(key, pword):
    f = Fernet(key)
    decPword = f.decrypt(pword.encode()).decode()
    return decPword

"""
User interface for entering a new master password. Creates UI and calls
generateMasterPassword and verifyMasterPassword accordingly. Returns decrypted secret key.
"""
def newMasterPasswordUI():
    masterPwWindow = tk.Toplevel()
    masterPwWindow.title("Login")

    masterPwWindow.masterLabel = tk.Label(masterPwWindow, text="Enter new master password:")
    masterPwWindow.masterLabel.grid(row=0, column=0)

    masterPwWindow.masterEntry = tk.Entry(masterPwWindow)
    masterPwWindow.masterEntry.grid(row=1, column=0)

    # wait until user presses the Save button
    ready = tk.IntVar()
    masterPwWindow.saveButton = tk.Button(masterPwWindow, text="Save", command=lambda:ready.set(1))
    masterPwWindow.saveButton.grid(row=2, column=0)
    masterPwWindow.saveButton.wait_variable(ready)

    # generate new master password and retrieve decrypted secret key
    input = masterPwWindow.masterEntry.get()
    generateMasterPassword(input)
    key = verifyMasterPassword(input)

    masterPwWindow.focus()
    masterPwWindow.grab_set()

    masterPwWindow.destroy()
    return key

"""
User interface for entering existing master password. Creates UI and calls verifyMasterPassword.
Returns decrypted secret key.
"""
def enterMasterPasswordUI():
    masterPwWindow = tk.Toplevel()
    masterPwWindow.title("Login")

    masterPwWindow.masterLabel = tk.Label(masterPwWindow, text="Enter master password:")
    masterPwWindow.masterLabel.grid(row=0, column=0)

    masterPwWindow.masterEntry = tk.Entry(masterPwWindow)
    masterPwWindow.masterEntry.grid(row=1, column=0)

    # wait until user presses the Save button
    ready = tk.IntVar()
    masterPwWindow.saveButton = tk.Button(masterPwWindow, text="Save", command=lambda:ready.set(1))
    masterPwWindow.saveButton.grid(row=2, column=0)
    masterPwWindow.saveButton.wait_variable(ready)

    # retrieve decrypted secret key
    key = verifyMasterPassword(masterPwWindow.masterEntry.get())

    masterPwWindow.focus()
    masterPwWindow.grab_set()

    masterPwWindow.destroy()
    return key

"""
Calls master password UI. Creates main UI.
"""
def main():
    # check if master password exists, call respective UI function and retrieve key
    if(not os.path.exists("master")):
        key = newMasterPasswordUI()
    else:
        key = enterMasterPasswordUI()
    if(key == None):
        messagebox.showwarning("Error","Master password incorrect")
        return

    # create main UI
    mainWindow.deiconify()
    mainWindow.title("Password Manager")
    mainWindow.mainFrame = tk.Frame(mainWindow)
    mainWindow.mainFrame.grid(row=0, column=0)

    mainWindow.accountLabel = tk.Label(mainWindow.mainFrame, text="Account:")
    mainWindow.accountLabel.grid(row=1, column=0)
    mainWindow.accountEntry = tk.Entry(mainWindow.mainFrame)
    mainWindow.accountEntry.grid(row=1, column=1)

    mainWindow.unameLabel = tk.Label(mainWindow.mainFrame, text="Username:")
    mainWindow.unameLabel.grid(row=2, column=0)
    mainWindow.unameEntry = tk.Entry(mainWindow.mainFrame)
    mainWindow.unameEntry.grid(row=2, column=1)

    mainWindow.pwordLabel = tk.Label(mainWindow.mainFrame, text="Password:")
    mainWindow.pwordLabel.grid(row=3, column=0)
    mainWindow.pwordEntry = tk.Entry(mainWindow.mainFrame)
    mainWindow.pwordEntry.grid(row=3, column=1)

    mainWindow.addButton = tk.Button(mainWindow.mainFrame, text="Add password", command=partial(addPassword, key))
    mainWindow.addButton.grid(row=5, column=0)
    mainWindow.getButton = tk.Button(mainWindow.mainFrame, text="Get password", command=partial(getPassword, key))
    mainWindow.getButton.grid(row=5, column=1)

    mainWindow.mainloop()
    return 1

if __name__ == "__main__":
    main()
