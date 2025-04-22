# Documentation for Local Password Manager

This document provides a description of the Python code for a local password manager application. The application allows users to generate strong passwords and securely store them on their local machine using AES-256 encryption. It features a basic Graphical User Interface (GUI) built with Tkinter.

## 1. Overview

The password manager encrypts and stores website-password pairs in a local file (`passwords.dat`). The encryption key is derived from a master password provided by the user, using the PBKDF2HMAC key derivation function with a salt. The application provides functionalities to:

- Generate strong, customizable passwords.
- Add new website-password entries to the encrypted storage.
- Retrieve passwords for specific websites.

The GUI provides a user-friendly way to interact with these functionalities.

## 2. Modules Used

The script utilizes the following Python modules:

- `os`: For interacting with the operating system, such as checking if a file exists.
- `getpass`: (Though replaced by `tkinter.simpledialog` in the GUI version) Used for securely prompting the user for passwords without displaying them on the console.
- `hashlib`: Provides various hashing algorithms, used here as part of PBKDF2HMAC.
- `base64`: For encoding and decoding data, used to store the salt and derived key in the file.
- `random`: For generating random data, used in the password generation function.
- `string`: Contains string constants, used to define character sets for password generation.
- `tkinter`: The standard Python GUI library, used to create the application's interface.
- `tkinter.messagebox`: For displaying standard message boxes (info, error, yes/no).
- `tkinter.simpledialog`: For displaying simple input dialogs, used for getting the master password.
- `cryptography.fernet`: Provides symmetric encryption using AES-CBC with HMAC authentication, used for encrypting the stored passwords.
- `cryptography.hazmat.primitives`: Contains cryptographic primitives.
- `cryptography.hazmat.primitives.hashes`: Provides hash algorithms like SHA256.
- `cryptography.hazmat.primitives.kdf.pbkdf2`: Implements the PBKDF2HMAC key derivation function.
- `cryptography.hazmat.backends`: Provides a consistent backend for cryptographic operations.

## 3. Constants

- `PASSWORD_FILE`: A string constant defining the name of the file (`passwords.dat`) where the encrypted password data is stored.

## 4. Functions

### 4.1. `generate_password(length=12, include_uppercase=True, include_lowercase=True, include_numbers=True, include_symbols=True)`

- **Purpose:** Generates a random and secure password based on the specified criteria.
- **Parameters:**
    - `length` (int, optional): The desired length of the password (default is 12).
    - `include_uppercase` (bool, optional): Whether to include uppercase letters (default is True).
    - `include_lowercase` (bool, optional): Whether to include lowercase letters (default is True).
    - `include_numbers` (bool, optional): Whether to include numbers (default is True).
    - `include_symbols` (bool, optional): Whether to include symbols (default is True).
- **Returns:**
    - `str`: The generated password.
    - `str`: An error message if no character types are selected.

### 4.2. `_derive_key(password: str, salt: bytes) -> bytes`

- **Purpose:** Derives an encryption key from the master password and salt using the PBKDF2HMAC algorithm. This function is intended for internal use (hence the leading underscore).
- **Parameters:**
    - `password` (str): The user's master password.
    - `salt` (bytes): A random salt value.
- **Returns:**
    - `bytes`: A 256-bit encryption key.

### 4.3. `_load_key() -> Fernet | None`

- **Purpose:** Loads the encryption key from the `PASSWORD_FILE`. If the file doesn't exist, it prompts the user for a new master password, generates a salt and key, stores them in the file, and returns a `Fernet` object. This function is intended for internal use.
- **Returns:**
    - `Fernet`: A `Fernet` object initialized with the encryption key if successful.
    - `None`: If the master password is incorrect or if there's an error reading the file.

### 4.4. `add_password(fernet_key: Fernet, website: str, password: str)`

- **Purpose:** Encrypts a website and its password using the provided `Fernet` key and appends the encrypted data to the `PASSWORD_FILE`.
- **Parameters:**
    - `fernet_key` (`Fernet`): The encryption key wrapped in a `Fernet` object.
    - `website` (str): The name of the website or service.
    - `password` (str): The password to be stored.
- **Returns:**
    - `None`: Displays a success message in a `tkinter.messagebox`.

### 4.5. `get_password(fernet_key: Fernet, website: str)`

- **Purpose:** Retrieves the password for a given website from the encrypted file. It decrypts each entry and compares the website name.
- **Parameters:**
    - `fernet_key` (`Fernet`): The encryption key wrapped in a `Fernet` object.
    - `website` (str): The name of the website to retrieve the password for.
- **Returns:**
    - `None`: Displays the retrieved password in a `tkinter.messagebox` if found, or a "Not Found" message if not.

### 4.6. `show_generate_dialog(fernet_key: Fernet)`

- **Purpose:** Creates and displays a top-level dialog window for generating a new password with options for length and character types. It allows the user to generate a password and optionally save it for a specific website.
- **Parameters:**
    - `fernet_key` (`Fernet`): The encryption key wrapped in a `Fernet` object.
- **Returns:**
    - `None`: Interacts with the user through a GUI dialog.

### 4.7. `show_add_dialog(fernet_key: Fernet)`

- **Purpose:** Creates and displays a top-level dialog window for adding a new website and password to the storage.
- **Parameters:**
    - `fernet_key` (`Fernet`): The encryption key wrapped in a `Fernet` object.
- **Returns:**
    - `None`: Interacts with the user through a GUI dialog.

### 4.8. `show_get_dialog(fernet_key: Fernet)`

- **Purpose:** Creates and displays a top-level dialog window for retrieving the password for a specified website.
- **Parameters:**
    - `fernet_key` (`Fernet`): The encryption key wrapped in a `Fernet` object.
- **Returns:**
    - `None`: Interacts with the user through a GUI dialog.

## 5. Main Execution (`if __name__ == "__main__":`)

- Initializes the main Tkinter window (`root`).
- Sets the title of the main window.
- Calls `_load_key()` to retrieve the encryption key.
- If the key is loaded successfully, it creates three buttons in the main window:
    - "Generate Password": Opens the `show_generate_dialog`.
    - "Add New Password": Opens the `show_add_dialog`.
    - "Get Password": Opens the `show_get_dialog`.
- Starts the Tkinter event loop (`root.mainloop()`) to display and handle interactions with the GUI.
- If `_load_key()` fails, the GUI might not fully initialize (further error handling could be added here).

## 6. Security Considerations

- **Master Password:** The security of the stored passwords relies heavily on the strength and secrecy of the user's master password.
- **Encryption:** AES-256 encryption (via `Fernet`) is used, which is a strong symmetric encryption algorithm.
- **Key Derivation:** PBKDF2HMAC with a high number of iterations (100,000) and a salt is used to derive the encryption key from the master password, making it more resistant to brute-force attacks.
- **Local Storage:** Passwords are stored locally in an encrypted file, which means their security depends on the security of the user's local machine.

## 7. Potential Improvements

- **Listing Stored Websites:** Implement a feature to display a list of stored website names.
- **Deleting Passwords:** Add functionality to remove specific website-password entries.
- **Changing Master Password:** Allow users to change their master password (requiring re-encryption of stored data).
- **More Robust Error Handling:** Improve error handling for file operations and user input.
- **Clipboard Integration:** Add an option to copy retrieved passwords to the clipboard (with a timeout for security).
- **Enhanced GUI:** Improve the layout and add more features to the GUI.
- **Data Integrity Checks:** While `Fernet` provides some integrity protection, more explicit checks could be added.
