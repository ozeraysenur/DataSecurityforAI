import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
import tkinter.messagebox as messagebox
import random
import string

encryption_key = Fernet.generate_key()


cipher = Fernet(encryption_key)

username = "admin"
password = "password123"

# Function to calculate the hash of the data
def calculate_hash():
    user_input = entry.get()
    hash_object = hashlib.sha256(user_input.encode())
    result_label["text"] = "Hash: " + hash_object.hexdigest()

def encrypt_data():
    user_input = entry.get()
    encrypted_data = cipher.encrypt(user_input.encode())
    encrypted_entry.delete(0, tk.END)  # Clear the encrypted entry field
    encrypted_entry.insert(tk.END, encrypted_data.decode())  # Insert encrypted data
    result_label["text"] = "Encrypted data: " + encrypted_data.decode()

def decrypt_data():
    user_input = encrypted_entry.get()
    decrypted_data = cipher.decrypt(user_input.encode())
    result_label["text"] = "Decrypted data: " + decrypted_data.decode()

    # data integrity
    original_data = entry.get()
    hash_object = hashlib.sha256(original_data.encode())
    original_hash = hash_object.hexdigest()

    if calculate_hash_from_decrypted(decrypted_data.decode()) == original_hash:
        messagebox.showinfo("Data Integrity", "Data integrity verified!")
    else:
        messagebox.showerror("Data Integrity", "Data integrity check failed!")

#calculate the hash of the decrypted data
def calculate_hash_from_decrypted(decrypted_data):
    hash_object = hashlib.sha256(decrypted_data.encode())
    return hash_object.hexdigest()

# Function for character substitution masking of the name field
def mask_name():
    user_input = entry.get()
    masked_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(len(user_input)))
    result_label["text"] = "Masked Name: " + masked_name

# Function for format-preserving encryption masking of the SSN field
def mask_ssn():
    user_input = entry.get()
    masked_ssn = ''
    for char in user_input:
        if char.isdigit():
            masked_ssn += random.choice(string.digits)
        else:
            masked_ssn += char
    result_label["text"] = "Masked SSN: " + masked_ssn

# authenticate the user
def authenticate():
    entered_username = username_entry.get()
    entered_password = password_entry.get()

    if entered_username == username and entered_password == password:
        messagebox.showinfo("Authentication", "Authentication successful!")
        enable_privacy_features()
    else:
        messagebox.showerror("Authentication", "Invalid username or password")

# if authentication successful, this function will call
def enable_privacy_features():
    encrypt_button.config(state=tk.NORMAL)
    decrypt_button.config(state=tk.NORMAL)
    mask_name_button.config(state=tk.NORMAL)
    mask_ssn_button.config(state=tk.NORMAL)

# creating gui
window = tk.Tk()
window.title("Artificial Intelligence Security Demo")

entry = tk.Entry(window)
entry.pack()


hash_button = tk.Button(window, text="Calculate Hash", command=calculate_hash)
hash_button.pack()

encrypted_entry = tk.Entry(window)
encrypted_entry.pack()

encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_data, state=tk.DISABLED)
encrypt_button.pack()

decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_data, state=tk.DISABLED)
decrypt_button.pack()

mask_name_button = tk.Button(window, text="Mask Name", command=mask_name, state=tk.DISABLED)
mask_name_button.pack()

mask_ssn_button = tk.Button(window, text="Mask SSN", command=mask_ssn, state=tk.DISABLED)
mask_ssn_button.pack()

username_label = tk.Label(window, text="Username:")
username_label.pack()
username_entry = tk.Entry(window)
username_entry.pack()

password_label = tk.Label(window, text="Password:")
password_label.pack()
password_entry = tk.Entry(window, show="*")
password_entry.pack()


authenticate_button = tk.Button(window, text="Authenticate", command=authenticate)
authenticate_button.pack()

# Result label
result_label = tk.Label(window, text="Result: ")
result_label.pack()

# Run the GUI
window.mainloop()
