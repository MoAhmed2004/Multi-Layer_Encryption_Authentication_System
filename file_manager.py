"""

This module handles all file operations including:
 Creating necessary files (users_data.txt, rsa_keys.pem)
 Generating and saving RSA key pairs
 Loading RSA keys from storage
 Saving and retrieving user data
"""

import os
from Crypto.PublicKey import RSA


def ensure_files_exist():
    if not os.path.exists("users_data.txt"):
        open("users_data.txt", "w").close()
    
    if not os.path.exists("rsa_keys.pem"):
        generate_and_save_rsa_keys()


def generate_and_save_rsa_keys():
    """
    Generate a new RSA key pair (2048-bit) and save to file.
    
    """
    key_pair = RSA.generate(2048)
    
    with open("rsa_keys.pem", "wb") as f:
        f.write(key_pair.export_key())
    
    return key_pair


def load_rsa_keys():
    """
    Load RSA keys from the rsa_keys.pem file.
    If file doesn't exist, generates new keys.
    
    """
    try:
        with open("rsa_keys.pem", "rb") as f:
            key_pair = RSA.import_key(f.read())
        return key_pair
    except FileNotFoundError:
        return generate_and_save_rsa_keys()


def save_user_to_file(username, encrypted_password_hex):
    """
    Save username and encrypted password to users_data.txt file.
    Format: username : encrypted_password_hex
    
    """
    try:
        with open("users_data.txt", "a") as file:
            file.write(f"{username} : {encrypted_password_hex}\n")
        return True
    except Exception as e:
        print(f"Error saving to file: {e}")
        return False


def get_stored_password(username):
    """
    Retrieve the stored encrypted password for a given username.
    
    """
    try:
        with open("users_data.txt", "r") as file:
            for line in file:
                parts = line.strip().split(" : ")
                if len(parts) == 2:
                    stored_user, stored_enc_pass = parts
                    if stored_user == username:
                        return stored_enc_pass
    except FileNotFoundError:
        return None
    return None


def check_username_exists(username):
    """
    Check if a username already exists in the database.
    
    """
    try:
        with open("users_data.txt", "r") as file:
            for line in file:
                parts = line.strip().split(" : ")
                if len(parts) >= 1:
                    stored_user = parts[0]
                    if stored_user == username:
                        return True
    except FileNotFoundError:
        return False
    return False