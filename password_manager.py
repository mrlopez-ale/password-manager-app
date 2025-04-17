import os
import getpass
import hashlib
import base64
import random
import string
import tkinter as tk
from tkinter import messagebox, simpledialog
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend

# Define the name of the file where passwords will be stored
PASSWORD_FILE = "passwords.dat"

def generate_password(length=12, include_uppercase=True, include_lowercase=True, include_numbers=True, include_symbols=True):
    """Generates a random and secure password based on the specified criteria."""
    characters = ''
    if include_uppercase:
        characters += string.ascii_uppercase  # Add uppercase letters
    if include_lowercase:
        characters += string.ascii_lowercase  # Add lowercase letters
    if include_numbers:
        characters += string.digits             # Add numbers
    if include_symbols:
        characters += string.punctuation        # Add symbols

    if not characters:
        return "Error: You must select at least one character type."

    password = ''.join(random.choice(characters) for _ in range(length))
    return password

def _derive_key(password: str, salt: bytes) -> bytes:
    """Derives an encryption key from the master password and salt using PBKDF2HMAC."""
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,  # 256 bits for AES-256 encryption key
        salt=salt,
        iterations=100000,  # A high number of iterations for security
        backend=default_backend()
    )
    return kdf.derive(password.encode())

def _load_key():
    """Loads the encryption key from the password file or creates a new one if it doesn't exist."""
    if not os.path.exists(PASSWORD_FILE):
        # First time running, ask for a new master password
        master_password = simpledialog.askstring("New Master Password", "Enter a new master password:", show='*')
        if master_password is None:
            return None
        salt = os.urandom(16)  # Generate a random salt
        key = _derive_key(master_password, salt)
        fernet_key = base64.urlsafe_b64encode(key)  # Encode the key for storage
        with open(PASSWORD_FILE, "wb") as f:
            f.write(b"salt:" + base64.b64encode(salt) + b"\n")  # Store the salt (encoded)
            f.write(b"key:" + fernet_key + b"\n")              # Store the derived key (encoded)
        return Fernet(fernet_key)  # Return a Fernet object for encryption/decryption
    else:
        # File exists, try to load the key using the entered master password
        with open(PASSWORD_FILE, "rb") as f:
            lines = f.readlines()
            if len(lines) < 2:
                messagebox.showerror("Error", "Password file is corrupted.")
                return None
            salt_line = lines[0].strip()
            key_line = lines[1].strip()
            if salt_line.startswith(b"salt:") and key_line.startswith(b"key:"):
                salt = base64.b64decode(salt_line[5:])  # Decode the stored salt
                stored_key = key_line[4:]              # Extract the stored key
                master_password = simpledialog.askstring("Master Password", "Enter your master password:", show='*')
                if master_password is None:
                    return None
                key = _derive_key(master_password, salt)  # Derive the key from the entered password and stored salt
                derived_fernet_key = base64.urlsafe_b64encode(key)  # Encode the derived key
                if derived_fernet_key == stored_key:
                    return Fernet(stored_key)  # Return Fernet object if passwords match
                else:
                    messagebox.showerror("Error", "Incorrect master password.")
                    return None
            else:
                messagebox.showerror("Error", "Password file is corrupted.")
                return None

def add_password(fernet_key: Fernet, website: str, password: str):
    """Adds a new website and its password to the encrypted file."""
    encrypted_data = fernet_key.encrypt(f"{website}:{password}".encode())  # Encrypt the website:password string
    with open(PASSWORD_FILE, "ab") as f:  # Open the file in append binary mode
        f.write(b"entry:" + encrypted_data + b"\n")  # Write the encrypted entry
    messagebox.showinfo("Success", f"Password for '{website}' added successfully.")

def get_password(fernet_key: Fernet, website: str):
    """Retrieves the password for a given website from the encrypted file."""
    found = False
    with open(PASSWORD_FILE, "rb") as f:  # Open the file in read binary mode
        for line in f:
            if line.startswith(b"entry:"):
                encrypted_entry = line[len(b"entry:"):].strip()  # Extract the encrypted data
                try:
                    decrypted_entry = fernet_key.decrypt(encrypted_entry).decode()  # Decrypt the entry
                    stored_website, stored_password = decrypted_entry.split(":", 1)  # Split into website and password
                    if stored_website == website:
                        messagebox.showinfo(f"Password for '{website}'", stored_password)
                        found = True
                        break
                except Exception as e:
                    print(f"Error decrypting entry: {e}")  # Print decryption errors to console for debugging
        if not found:
            messagebox.showinfo("Not Found", f"No password found for '{website}'.")

def show_generate_dialog(fernet_key):
    """Shows a dialog for generating a new password with various options."""
    def generate_and_save():
        # Get values from the input fields and checkboxes
        length = int(length_entry.get()) if length_entry.get().isdigit() else 12
        include_upper = upper_var.get()
        include_lower = lower_var.get()
        include_nums = numbers_var.get()
        include_symb = symbols_var.get()
        website = website_entry.get()

        # Generate the password
        new_password = generate_password(length, include_upper, include_lower, include_nums, include_symb)
        password_result.config(text=f"Generated Password: {new_password}")

        # Ask if the user wants to save the generated password
        if website:
            save_choice = messagebox.askyesno("Save Password?", f"Do you want to save this password for '{website}'?")
            if save_choice:
                add_password(fernet_key, website, new_password)
        else:
            messagebox.showinfo("Info", "Enter a website name to save the generated password.")

    # Create a new top-level window for the generator
    generate_dialog = tk.Toplevel(root)
    generate_dialog.title("Generate Password")

    # Labels and entry for password length
    length_label = tk.Label(generate_dialog, text="Length:")
    length_label.grid(row=0, column=0, padx=5, pady=5)
    length_entry = tk.Entry(generate_dialog)
    length_entry.insert(0, "12")
    length_entry.grid(row=0, column=1, padx=5, pady=5)

    # Checkboxes for character types
    upper_var = tk.BooleanVar(value=True)
    upper_check = tk.Checkbutton(generate_dialog, text="Uppercase", variable=upper_var)
    upper_check.grid(row=1, column=0, columnspan=2, padx=5, pady=2, sticky="w")

    lower_var = tk.BooleanVar(value=True)
    lower_check = tk.Checkbutton(generate_dialog, text="Lowercase", variable=lower_var)
    lower_check.grid(row=2, column=0, columnspan=2, padx=5, pady=2, sticky="w")

    numbers_var = tk.BooleanVar(value=True)
    numbers_check = tk.Checkbutton(generate_dialog, text="Numbers", variable=numbers_var)
    numbers_check.grid(row=3, column=0, columnspan=2, padx=5, pady=2, sticky="w")

    symbols_var = tk.BooleanVar(value=True)
    symbols_check = tk.Checkbutton(generate_dialog, text="Symbols", variable=symbols_var)
    symbols_check.grid(row=4, column=0, columnspan=2, padx=5, pady=2, sticky="w")

    # Label and entry for website name (optional for saving)
    website_label = tk.Label(generate_dialog, text="Website (optional):")
    website_label.grid(row=5, column=0, padx=5, pady=5)
    website_entry = tk.Entry(generate_dialog)
    website_entry.grid(row=5, column=1, padx=5, pady=5)

    # Button to trigger password generation and potential saving
    generate_button = tk.Button(generate_dialog, text="Generate", command=generate_and_save)
    generate_button.grid(row=6, column=0, columnspan=2, padx=5, pady=10)

    # Label to display the generated password
    password_result = tk.Label(generate_dialog, text="Generated Password:")
    password_result.grid(row=7, column=0, columnspan=2, padx=5, pady=5)

def show_add_dialog(fernet_key):
    """Shows a dialog for adding a new website and password."""
    def add_new():
        # Get website and password from the input fields
        website = website_entry.get()
        password = password_entry.get()
        if website and password:
            add_password(fernet_key, website, password)  # Call the add_password function
            add_dialog.destroy()  # Close the add dialog
        else:
            messagebox.showerror("Error", "Website and password cannot be empty.")

    # Create a new top-level window for adding passwords
    add_dialog = tk.Toplevel(root)
    add_dialog.title("Add New Password")

    # Label and entry for website name
    website_label = tk.Label(add_dialog, text="Website:")
    website_label.grid(row=0, column=0, padx=5, pady=5)
    website_entry = tk.Entry(add_dialog)
    website_entry.grid(row=0, column=1, padx=5, pady=5)

    # Label and entry for the password (obscured)
    password_label = tk.Label(add_dialog, text="Password:")
    password_label.grid(row=1, column=0, padx=5, pady=5)
    password_entry = tk.Entry(add_dialog, show="*")
    password_entry.grid(row=1, column=1, padx=5, pady=5)

    # Button to trigger the password adding action
    add_button = tk.Button(add_dialog, text="Add", command=add_new)
    add_button.grid(row=2, column=0, columnspan=2, padx=5, pady=10)

def show_get_dialog(fernet_key):
    """Shows a dialog for retrieving the password for a given website."""
    def get_existing():
        # Get the website name to retrieve
        website = website_entry.get()
        if website:
            get_password(fernet_key, website)  # Call the get_password function
            get_dialog.destroy()  # Close the get dialog
        else:
            messagebox.showerror("Error", "Website cannot be empty.")

    # Create a new top-level window for getting passwords
    get_dialog = tk.Toplevel(root)
    get_dialog.title("Get Password")

    # Label and entry for the website to retrieve
    website_label = tk.Label(get_dialog, text="Website:")
    website_label.grid(row=0, column=0, padx=5, pady=5)
    website_entry = tk.Entry(get_dialog)
    website_entry.grid(row=0, column=1, padx=5, pady=5)

    # Button to trigger the password retrieval action
    get_button = tk.Button(get_dialog, text="Get Password", command=get_existing)
    get_button.grid(row=1, column=0, columnspan=2, padx=5, pady=10)

if __name__ == "__main__":
    # Create the main Tkinter window
    root = tk.Tk()
    root.title("Local Password Manager")

    # Load the encryption key
    encryption_key = _load_key()
    if encryption_key:
        # Create buttons for the main functionalities
        generate_button = tk.Button(root, text="Generate Password", command=lambda: show_generate_dialog(encryption_key))
        generate_button.pack(pady=10)

        add_button = tk.Button(root, text="Add New Password", command=lambda: show_add_dialog(encryption_key))
        add_button.pack(pady=5)

        get_button = tk.Button(root, text="Get Password", command=lambda: show_get_dialog(encryption_key))
        get_button.pack(pady=5)

        # Start the Tkinter event loop to display the GUI
        root.mainloop()
    else:
        # If key loading fails, we can't proceed with the GUI
        pass