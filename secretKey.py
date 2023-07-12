import sqlite3
import tkinter as tk
import hashlib
from tkinter import *
from tkinter.ttk import *  # for pop-ups
from tkinter import simpledialog
from functools import partial
import random
import string
from tkinter import messagebox
import os
import uuid
import pyperclip
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import base64

with sqlite3.connect("SecretKey.db") as db:
    cursor = db.cursor()

cursor.execute("""
CREATE TABLE IF NOT EXISTS user(
user_id INTEGER PRIMARY KEY,
master_password TEXT NOT NULL,
recoveryKey TEXT NOT NULL);
""")

cursor.execute("""
CREATE TABLE IF NOT EXISTS passwords(
password_id TEXT PRIMARY KEY,
website_name TEXT NOT NULL,
username TEXT NOT NULL,
password TEXT NOT NULL);
""")

# backend
backend = default_backend()
salt = b'2444'


kdf = PBKDF2HMAC(
    algorithm=hashes.SHA256(),
    length=32,
    salt=salt,
    iterations=100000,
    backend=backend,
)


encryptionKey = 0


def encrypt(message: bytes, key: bytes) -> bytes:
    return Fernet(key).encrypt(message)


def decrypt(message: bytes, token: bytes) -> bytes:
    return Fernet(token).decrypt(message)

# def decrypt(message: bytes, key: bytes) -> bytes:
#     return Fernet(key).decrypt(message)


# Creating the window
window = Tk()


style = Style()

style.configure('W.TButton', font=('calibri', 10, 'bold'),)

window.title("SECRET KEY")


def hashingPassword(password):
    hash = hashlib.sha256(password)
    hash = hash.hexdigest()

    return hash


def generatePassword():
    randomPassword = ''
    punc = ['@', '_']
    passlist = random.choices(string.ascii_uppercase, k=3) + random.choices(
        string.ascii_lowercase, k=4) + random.choices(string.digits, k=3) + random.choices(punc, k=1)

    random.shuffle(passlist)
    # if '@' not in passlist:
    #     passlist[2] = '@'
    random.shuffle(passlist)
    randomPassword = ''.join(passlist)
    return randomPassword


# def recoveryScreen():
#     for widget in window.winfo_children():
#         widget.destroy()

#     window.geometry('250x125')

#     lbl = Label(window, text='Save This Key to recover your account')
#     lbl.config(anchor=CENTER)
#     lbl.pack()

#     lbl1 = Label(window, text=key)
#     lbl1.config(anchor=CENTER)
#     lbl1.pack()

#     def copyKey():
#         pyperclip.copy(lbl1.cget('text'))

#     btn = Button(window, text="Copy Key", command=copyKey)
#     btn.pack(pady=5)

#     def done():
#         loginScreen()

#     btn = Button(window, text="Done", command=done)
#     btn.pack(pady=5)

# setting up the credentials


def register():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("350x200")

    # Master Password
    label = Label(window, text="Create Master Password")
    label.config(anchor=CENTER)
    label.pack()

    password = Entry(window, width=20, show='*')
    password.pack(pady=5)
    password.focus()

    # Confirm Master Password
    label = Label(window, text="Confirm Master Password")
    label.config(anchor=CENTER)
    label.pack()

    confirmPassword = Entry(window, width=20, show='*')
    confirmPassword.pack(pady=5)
    confirmPassword.focus()

    label = Label(window, text="Enter Security Answer")
    label.config(anchor=CENTER)
    label.pack()

    secAns = Entry(window, width=20, show='*')
    secAns.pack(pady=5)
    secAns.focus()

    unmatched = Label(window)
    unmatched.pack()

    def savePassword():
        if (password.get() == confirmPassword.get()):

            hashedPassword = hashingPassword(password.get().encode('utf-8'))

            global encryptionKey
            encryptionKey = base64.urlsafe_b64encode(
                kdf.derive(secAns.get().encode()))

            securityAns = secAns.get()

            insert = """INSERT INTO user(master_password,recoveryKey) VALUES(?,?) """
            cursor.execute(insert, ((hashedPassword), (securityAns)))
            db.commit()

            loginScreen()
        else:
            password.delete(0, 'end')
            confirmPassword.delete(0, 'end')
            unmatched.config(text='Passwords DO NOT match')

    button = Button(window, text="Register", style='W.TButton',
                    cursor="hand2", command=savePassword)
    button.pack(pady=10)


def resetScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x125')

    label = Label(window, text="Create New Master Password")
    label.config(anchor=CENTER)
    label.pack()

    password = Entry(window, width=20, show='*')
    password.pack(pady=5)
    password.focus()

    # Confirm Master Password
    label = Label(window, text="Confirm New Master Password")
    label.config(anchor=CENTER)
    label.pack()

    confirmPassword = Entry(window, width=20, show='*')
    confirmPassword.pack(pady=5)
    confirmPassword.focus()

    def updatePassword():
        if password.get() and confirmPassword.get():
            if password.get() == confirmPassword.get():
                hashed = hashingPassword(password.get().encode('utf-8'))
                cursor.execute(
                    'UPDATE user SET master_password = ? WHERE user_id = 1', (hashed,))
                db.commit()
                loginScreen()
            else:
                messagebox.showerror("Error", "Passwords did not match")
        else:
            messagebox.showerror("Error", "Fill out the given Fields")

    button = Button(window, text="Update", style='W.TButton',
                    cursor="hand2", command=updatePassword)
    button.pack(pady=10)

# reset Screen


def verifyScreen():
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry('250x125')

    label = Label(window, text="Enter Security answer")
    label.config(anchor=CENTER)
    label.pack()

    secAns = Entry(window, width=20, show='*')
    secAns.pack(pady=5)
    secAns.focus()

    def checkSecAns():
        if secAns.get():
            cursor.execute('SELECT * FROM user')
            array = cursor.fetchall()
            print(array[0][2])
            if secAns.get() == array[0][2]:
                resetScreen()
            else:
                messagebox.showerror("Error", "Security Answer did not match")
        else:
            messagebox.showerror("Error", "Fill the given field")

    button = Button(window, text="Verify", style='W.TButton',
                    cursor="hand2", command=checkSecAns)
    button.pack(pady=10)


# login screen


def loginScreen():

    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("200x150")

    label = Label(window, text="Enter Master Password")
    label.config(anchor=CENTER)
    label.pack()

    text = Entry(window, width=20, show='*')
    text.pack(pady=5)
    text.focus()

    wrongPasswordLabel = Label(window)
    wrongPasswordLabel.pack()

    def getMasterPassword():
        hashed = hashingPassword(text.get().encode('utf-8'))
        cursor.execute(
            "SELECT * from user where user_id = 1 AND master_password = ?", [(hashed)])
        return cursor.fetchall()

    def checkPassword():
        match = getMasterPassword()

        if (match):
            global encryptionKey
            if encryptionKey == 0:
                cursor.execute('SELECT * FROM user')
                array = cursor.fetchall()

                encryptionKey = base64.urlsafe_b64encode(
                    kdf.derive(array[0][2].encode()))

            passwordVault()
        else:
            text.delete(0, 'end')
            wrongPasswordLabel.config(text='Wrong Password')

    button = Button(window, text="Login", style='W.TButton',
                    cursor="hand2", command=checkPassword)
    button.pack(pady=10)

    def resetPassword():
        verifyScreen()

    button1 = Button(window, text="Reset", style='W.TButton',
                     cursor="hand2", command=resetPassword)
    button1.pack(pady=10)


# The actual vault/application after logging in
def passwordVault():
    # Removing all the text after successful login
    for widget in window.winfo_children():
        widget.destroy()

    window.geometry("850x300")
    label = Label(window, text="Your Passwords")
    label.grid(column=1)

    # taking new details for a new site
    def addNewPassword():
        addPasswordWindow = Tk()

        addPasswordWindow.title('Add New Password')

        addPasswordWindow.geometry("300x300")

        websiteNameLabel = Label(addPasswordWindow, text="Enter Website Name")
        websiteNameLabel.config(anchor=CENTER)
        websiteNameLabel.pack()

        websiteNameText = Entry(addPasswordWindow, width=20)
        websiteNameText.pack(pady=5)
        websiteNameText.focus()

        usernameLabel = Label(
            addPasswordWindow, text="Enter Username of the website")
        usernameLabel.config(anchor=CENTER)
        usernameLabel.pack()

        userNameText = Entry(addPasswordWindow, width=20)
        userNameText.pack(pady=5)
        userNameText.focus()

        passwordLabel = Label(addPasswordWindow, text="Enter Password")
        passwordLabel.config(anchor=CENTER)
        passwordLabel.pack()

        passwordText = Entry(addPasswordWindow, width=20)
        passwordText.pack(pady=5)
        passwordText.focus()

        orLabel = Label(
            addPasswordWindow, text='OR')
        orLabel.config(anchor=CENTER)
        orLabel.pack(pady=5)

        def generateRandomPassword():
            store = generatePassword()
            cmd = 'echo | set /p nul=' + store + '| clip'
            messagebox.showinfo(
                "Info", "Password copied to clipboard. Press CTRL+V in PASSWORD box")
            os.system(cmd)

        generate = Button(addPasswordWindow, text="Generate",
                          style='W.TButton', cursor="hand2", command=generateRandomPassword)
        generate.pack(pady=5)

        # adding details to database

        def addToDB():

            if (websiteNameText.get() and userNameText.get() and passwordText.get()):
                rnd = random.choices(string.ascii_letters,
                                     k=5) + random.choices(string.digits, k=5)
                random.shuffle(rnd)
                id = ''.join(rnd)
                text1 = websiteNameText.get().encode()
                text2 = userNameText.get().encode()
                text3 = passwordText.get().encode()
                print(f'{text1}, {text2}, {text3}')
                global encryptionKey
                websiteName = encrypt(text1, encryptionKey)
                username = encrypt(text2, encryptionKey)
                password = encrypt(text3, encryptionKey)
                insertStatement = """INSERT INTO passwords(password_id, website_name, username, password) VALUES(?, ?, ?, ?)"""
                cursor.execute(insertStatement,
                               (id, websiteName, username, password))
                db.commit()
                addPasswordWindow.destroy()
                passwordVault()
            else:
                messagebox.showerror("Error", "Please fill out all the fields")

        addNewButton = Button(addPasswordWindow, text="Add", style='W.TButton',
                              cursor="hand2", command=addToDB)
        addNewButton.pack(pady=10)

        addPasswordWindow.mainloop()

    addPassword = Button(window, text="Add", style='W.TButton',
                         cursor="hand2", command=addNewPassword)
    addPassword.grid(column=1, pady=10)

    def updatePassword(id):
        updatePass = Tk()

        updatePass.title(f'Manage Your Password {id}')
        updatePass.geometry("300x300")

        cursor.execute('SELECT * FROM passwords WHERE password_id=?', (id,))
        info = cursor.fetchall()

        websiteNameLabel = Label(updatePass, text="Website Name")
        websiteNameLabel.config(anchor=CENTER)
        websiteNameLabel.pack()

        websiteNameText = Entry(updatePass, width=20)
        websiteNameText.insert(0, decrypt(info[0][1], encryptionKey))
        websiteNameText.configure(state=tk.DISABLED)
        websiteNameText.pack(pady=5)
        websiteNameText.focus()

        usernameLabel = Label(
            updatePass, text="Enter New Username")
        usernameLabel.config(anchor=CENTER)
        usernameLabel.pack()

        userNameText = Entry(updatePass, width=20)
        userNameText.pack(pady=5)
        userNameText.focus()

        passwordLabel = Label(updatePass, text="Enter New Password")
        passwordLabel.config(anchor=CENTER)
        passwordLabel.pack()

        passwordText = Entry(updatePass, width=20)
        passwordText.pack(pady=5)
        passwordText.focus()

        orLabel = Label(
            updatePass, text='OR')
        orLabel.config(anchor=CENTER)
        orLabel.pack(pady=5)

        def generateRandomPassword():
            store = generatePassword()
            cmd = 'echo | set /p nul=' + store + '| clip'
            messagebox.showinfo(
                "Info", "Password copied to clipboard. Press CTRL+V in PASSWORD box")
            os.system(cmd)

        generate = Button(updatePass, text="Generate",
                          style='W.TButton', cursor="hand2", command=generateRandomPassword)
        generate.pack(pady=5)

        def updateDB(id):
            if (websiteNameText.get() and userNameText.get() and passwordText.get()):
                text1 = userNameText.get().encode()
                text2 = passwordText.get().encode()
                global encryptionKey
                username = encrypt(text1, encryptionKey)
                password = encrypt(text2, encryptionKey)
                updateStatement = """UPDATE passwords SET username=?, password = ? WHERE password_id=?"""
                cursor.execute(updateStatement, (username, password, id))
                db.commit()
                updatePass.destroy()
                passwordVault()
            else:
                messagebox.showerror("Error", "Please fill out all the fields")

        updateButton = Button(updatePass, text="Update", style='W.TButton',
                              cursor="hand2", command=partial(updateDB, info[0][0]))
        updateButton.pack(pady=10)

        updatePass.mainloop()

    # delete password

    def deletePassword(id):
        deleteCommand = "DELETE FROM passwords where password_id=?"
        cursor.execute(deleteCommand, (id,))
        db.commit()

        passwordVault()

    lbl = Label(window, text="Website")
    lbl.grid(row=2, column=0, padx=80)
    lbl = Label(window, text="Username")
    lbl.grid(row=2, column=1, padx=80)
    lbl = Label(window, text="Password")
    lbl.grid(row=2, column=2, padx=80)

    cursor.execute("SELECT * from passwords")
    if (cursor.fetchall() != None):
        i = 0
        while True:
            cursor.execute("SELECT * from passwords")
            array = cursor.fetchall()

            if (len(array) == 0):
                break

            website = Label(window, text=(decrypt(array[i][1], encryptionKey)))
            website.grid(column=0, row=i+3)

            username = Label(window, text=(
                decrypt(array[i][2], encryptionKey)))
            username.grid(column=1, row=i+3)

            password = Label(window, text=(
                decrypt(array[i][3], encryptionKey)))
            password.grid(column=2, row=i+3)

            update = Button(window, text="Update", style='W.TButton',
                            cursor="hand2", command=partial(updatePassword, array[i][0]))
            update.grid(column=3, row=i+3, pady=10)

            delete = Button(window, text="Delete", style='W.TButton',
                            cursor="hand2", command=partial(deletePassword, array[i][0]))
            delete.grid(column=4, row=i+3, pady=20)

            i = i+1

            cursor.execute("SELECT * from passwords")
            if (len(cursor.fetchall()) <= i):
                break


cursor.execute("SELECT * from user")
if (cursor.fetchall()):
    loginScreen()
else:
    register()

window.mainloop()
