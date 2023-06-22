import hashlib
from cryptography.fernet import Fernet
import tkinter as tk
import tkinter.messagebox as messagebox
import random
import string

encryption_key = Fernet.generate_key()

cipher = Fernet(encryption_key)

admin_username = "admin"
admin_password = "password123"

user_username = "user"
user_password = "userpassword"

def read_input_from_file(file_path):
    with open(file_path, "r") as file:
        return file.read()

# Read input from the "personal-info.txt" file
user_input = read_input_from_file("C:\\Users\\ozera\\OneDrive\\Masaüstü\\personal-info.txt")

# Function to calculate the hash of the data
def calculate_hash():
    hash_object = hashlib.sha256(user_input.encode())
    result_label["text"] = "Hash: " + hash_object.hexdigest()

def encrypt_data():
    encrypted_data = cipher.encrypt(user_input.encode())
    encrypted_entry.delete(0, tk.END)  # Clear the encrypted entry field
    encrypted_entry.insert(tk.END, encrypted_data.decode())  # Insert encrypted data
    result_label["text"] = "Encrypted data: " + encrypted_data.decode()

def decrypt_data():
    decrypted_data = cipher.decrypt(encrypted_entry.get().encode())
    result_label["text"] = "Decrypted data: " + decrypted_data.decode()

    # Data integrity
    original_data = user_input
    hash_object = hashlib.sha256(original_data.encode())
    original_hash = hash_object.hexdigest()

    if calculate_hash_from_decrypted(decrypted_data.decode()) == original_hash:
        messagebox.showinfo("Data Integrity", "Data integrity verified!")
    else:
        messagebox.showerror("Data Integrity", "Data integrity check failed!")

# Calculate the hash of the decrypted data
def calculate_hash_from_decrypted(decrypted_data):
    hash_object = hashlib.sha256(decrypted_data.encode())
    return hash_object.hexdigest()

# Function for character substitution masking of the name field
def mask_name():
    masked_name = ''.join(random.choice(string.ascii_uppercase) for _ in range(len(user_input)))
    result_label["text"] = "Masked Name: " + masked_name

# Function for format-preserving encryption masking of the SSN field
def mask_ssn():
    masked_ssn = ''
    for char in user_input:
        if char.isdigit():
            masked_ssn += random.choice(string.digits)
        else:
            masked_ssn += char
    result_label["text"] = "Masked SSN: " + masked_ssn

# Authenticate the user
def authenticate():
    entered_username = username_entry.get()
    entered_password = password_entry.get()

    if entered_username == admin_username and entered_password == admin_password:
        messagebox.showinfo("Authentication", "Admin authentication successful!")
        enable_privacy_features()
    elif entered_username == user_username and entered_password == user_password:
        messagebox.showinfo("Authentication", "User authentication successful! ")
    else:
        messagebox.showerror("Authentication", "Invalid username or password")

# If authentication successful, this function will be called
def enable_privacy_features():
    encrypt_button.config(state=tk.NORMAL)
    decrypt_button.config(state=tk.NORMAL)
    mask_name_button.config(state=tk.NORMAL)
    mask_ssn_button.config(state=tk.NORMAL)
    fetch_data_button.config(state=tk.NORMAL)

# Creating GUI
window = tk.Tk()
window.title("Artificial Intelligence Security Demo")

hash_button = tk.Button(window, text="Calculate Hash", command=calculate_hash)
encrypt_button = tk.Button(window, text="Encrypt", command=encrypt_data, state=tk.DISABLED)
decrypt_button = tk.Button(window, text="Decrypt", command=decrypt_data, state=tk.DISABLED)
mask_name_button = tk.Button(window, text="Mask Name", command=mask_name, state=tk.DISABLED)
mask_ssn_button = tk.Button(window, text="Mask SSN", command=mask_ssn, state=tk.DISABLED)
fetch_data_button = tk.Button(window, text="Fetch Data", command=lambda: result_label.config(text=user_input), state =tk.DISABLED)

username_label = tk.Label(window, text="Username:")
username_label.pack(pady=8)
username_entry = tk.Entry(window)
username_entry.pack()

password_label = tk.Label(window, text="Password:")
password_label.pack(pady=8)
password_entry = tk.Entry(window, show="*")
password_entry.pack()

authenticate_button = tk.Button(window, text="Authenticate", command=authenticate)
authenticate_button.pack(pady=8)

# Result label
result_label = tk.Label(window, text="Result: ")
result_label.pack(pady=8)

# Encrypted entry field
encrypted_entry = tk.Entry(window)
encrypted_entry.pack(pady=8)

# Layout management
hash_button.pack(pady=8)
encrypt_button.pack(pady=8)
decrypt_button.pack(pady=8)
mask_name_button.pack(pady=8)
mask_ssn_button.pack(pady=8)
fetch_data_button.pack(pady=8)

# Run the GUI
window.mainloop()
