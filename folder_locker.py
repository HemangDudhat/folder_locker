import os
import tkinter as tk
from tkinter import messagebox, simpledialog
import hashlib
import json
import pyAesCrypt
import shutil


# === CONFIGURATION ===
ROOT_DIR = "RootLocker"
PHOTOS = "Photos"
VIDEOS = "Videos"
LOCKER_FOLDER = "SecureLocker"
PRIVATE_FOLDER = "Private"
LOCKER_HIDDEN = ".secure_locker"
PRIVATE_HIDDEN = ".private_hidden"
PASS_FILE = "passwords.json"


# === PASSWORD MANAGEMENT ===
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def load_passwords():
    if not os.path.exists(PASS_FILE):
        # Default passwords: main=1234, sub=4321
        passwords = {
            "main": hash_password("1234"),
            "sub": hash_password("4321")
        }
        with open(PASS_FILE, 'w') as f:
            json.dump(passwords, f)
    else:
        with open(PASS_FILE, 'r') as f:
            passwords = json.load(f)
    return passwords

def save_passwords(passwords):
    with open(PASS_FILE, 'w') as f:
        json.dump(passwords, f)
        
        
# === FUNCTIONS ===
def create_structure():
    os.makedirs(ROOT_DIR, exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, PHOTOS), exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, VIDEOS), exist_ok=True)
    os.makedirs(os.path.join(ROOT_DIR, LOCKER_FOLDER, PRIVATE_FOLDER), exist_ok=True)
    messagebox.showinfo("Created", f"Structure created inside '{ROOT_DIR}'")

def lock_main():
    if os.path.exists(ROOT_DIR):
        os.rename(ROOT_DIR, LOCKER_HIDDEN)
        os.system(f'attrib +h +s "{LOCKER_HIDDEN}"')
        messagebox.showinfo("Locked", "RootLocker is now locked and hidden.")
    else:
        messagebox.showwarning("Not Found", "RootLocker not found!")

def unlock_main():
    pw = simpledialog.askstring("Main Locker", "Enter main password:", show="*")
    if not pw:
        return
    passwords = load_passwords()
    if hash_password(pw) != passwords["main"]:
        messagebox.showerror("Access Denied", "Wrong main password.")
        return
    if os.path.exists(LOCKER_HIDDEN):
        os.system(f'attrib -h -s "{LOCKER_HIDDEN}"')
        os.rename(LOCKER_HIDDEN, ROOT_DIR)
    messagebox.showinfo("Unlocked", f"Access granted to: {PHOTOS}, {VIDEOS}, and SecureLocker.")

def lock_private():
    secure_path = os.path.join(ROOT_DIR, LOCKER_FOLDER)
    private_path = os.path.join(secure_path, PRIVATE_FOLDER)
    hidden_path = os.path.join(secure_path, PRIVATE_HIDDEN)

    if os.path.exists(private_path):
        os.rename(private_path, hidden_path)
        os.system(f'attrib +h +s "{hidden_path}"')
        messagebox.showinfo("Locked", "Private folder is now hidden.")
    else:
        messagebox.showwarning("Not Found", "Private folder already locked or missing.")

def unlock_private():
    pw = simpledialog.askstring("Secure Locker", "Enter secondary password:", show="*")
    if not pw:
        return
    passwords = load_passwords()
    if hash_password(pw) != passwords["sub"]:
        messagebox.showerror("Access Denied", "Wrong secondary password.")
        return

    secure_path = os.path.join(ROOT_DIR, LOCKER_FOLDER)
    hidden_path = os.path.join(secure_path, PRIVATE_HIDDEN)
    private_path = os.path.join(secure_path, PRIVATE_FOLDER)

    if os.path.exists(hidden_path):
        os.system(f'attrib -h -s "{hidden_path}"')
        os.rename(hidden_path, private_path)
        messagebox.showinfo("Unlocked", "Private folder is now accessible.")
    else:
        messagebox.showinfo("Already Unlocked", "Private folder is already unlocked.")

def change_password(key):
    passwords = load_passwords()
    current = simpledialog.askstring("Change Password", f"Enter current {key} password:", show="*")
    if not current or hash_password(current) != passwords[key]:
        messagebox.showerror("Error", "Current password incorrect.")
        return

    new_pass = simpledialog.askstring("New Password", "Enter new password:", show="*")
    confirm_pass = simpledialog.askstring("Confirm Password", "Re-enter new password:", show="*")

    if new_pass != confirm_pass:
        messagebox.showerror("Mismatch", "Passwords do not match.")
        return

    passwords[key] = hash_password(new_pass)
    save_passwords(passwords)
    messagebox.showinfo("Success", f"{key.capitalize()} password changed successfully.")
    
    
# === Encreption of private file ===

def encrypt_private_files():
    pw = simpledialog.askstring("Encrypt Files", "Enter secondary password for encryption:", show="*")
    if not pw or hash_password(pw) != load_passwords()["sub"]:
        messagebox.showerror("Error", "Wrong secondary password.")
        return

    private_path = os.path.join(ROOT_DIR, LOCKER_FOLDER, PRIVATE_FOLDER)
    buffer_size = 64 * 1024

    if not os.path.exists(private_path):
        messagebox.showerror("Error", "Private folder does not exist.")
        return

    files = [f for f in os.listdir(private_path) if not f.endswith(".aes")]
    if not files:
        messagebox.showinfo("No Files", "No files to encrypt.")
        return

    for filename in files:
        file_path = os.path.join(private_path, filename)
        enc_path = file_path + ".aes"
        try:
            pyAesCrypt.encryptFile(file_path, enc_path, pw, buffer_size)
            os.remove(file_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to encrypt {filename}.\n{e}")
            return

    messagebox.showinfo("Encrypted", "All private files encrypted successfully.")

# === Decreption of private file ===


def decrypt_private_files():
    pw = simpledialog.askstring("Decrypt Files", "Enter secondary password for decryption:", show="*")
    if not pw or hash_password(pw) != load_passwords()["sub"]:
        messagebox.showerror("Error", "Wrong secondary password.")
        return

    private_path = os.path.join(ROOT_DIR, LOCKER_FOLDER, PRIVATE_FOLDER)
    buffer_size = 64 * 1024

    if not os.path.exists(private_path):
        messagebox.showerror("Error", "Private folder does not exist.")
        return

    files = [f for f in os.listdir(private_path) if f.endswith(".aes")]
    if not files:
        messagebox.showinfo("No Files", "No encrypted files found.")
        return

    for filename in files:
        enc_path = os.path.join(private_path, filename)
        dec_path = os.path.join(private_path, filename[:-4])  # remove ".aes"
        try:
            pyAesCrypt.decryptFile(enc_path, dec_path, pw, buffer_size)
            os.remove(enc_path)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt {filename}.\n{e}")
            return

    messagebox.showinfo("Decrypted", "All private files decrypted successfully.")


# === GUI ===
def build_gui():
    root = tk.Tk()
    root.title("Secure Dual-Level Locker")
    root.geometry("400x600")
    root.resizable(True,True)

    tk.Button(root, text="📁 Create Folder Structure", command=create_structure, width=40).pack(pady=10)
    tk.Button(root, text="🔒 Lock Root Locker", command=lock_main, width=40).pack(pady=5)
    tk.Button(root, text="🔓 Unlock Root Locker", command=unlock_main, width=40).pack(pady=5)

    tk.Label(root, text="— After Root Unlock —").pack(pady=10)

    tk.Button(root, text="🔐 Lock Private Folder", command=lock_private, width=40).pack(pady=5)
    tk.Button(root, text="🔓 Unlock Private Folder", command=unlock_private, width=40).pack(pady=5)
    tk.Button(root, text="🔒 Encrypt Private Files", command=encrypt_private_files, width=40).pack(pady=5)
    tk.Button(root, text="🔓 Decrypt Private Files", command=decrypt_private_files, width=40).pack(pady=5)

    tk.Label(root, text="— Password Options —").pack(pady=10)

    tk.Button(root, text="🛠 Change Main Password", command=lambda: change_password("main"), width=40).pack(pady=5)
    tk.Button(root, text="🛠 Change Secondary Password", command=lambda: change_password("sub"), width=40).pack(pady=5)

    tk.Button(root, text="🚪 Exit", command=root.quit, width=40).pack(pady=15)

    root.mainloop()


# === MAIN ===
if __name__ == "__main__":
    build_gui()
