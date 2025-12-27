"""

This module handles authentication processes:
 User registration with multi-layer encryption
 User login with multi-layer decryption
 Hash comparison for authentication
"""

from file_manager import check_username_exists, save_user_to_file, get_stored_password
from validation import check_password_strength
from crypto_operations import (
    hash_password_sha256,
    encrypt_des, encrypt_aes, encrypt_rsa,
    decrypt_des, decrypt_aes, decrypt_rsa
)


def register_user(username, password, des_key, aes_key, rsa_public_key, log_callback=None):
    """
    Register a new user with multi-layer encryption.
    
    Process:
        1. Check if username exists
        2. Validate password strength
        3. Hash password with SHA-256
        4. Encrypt hash with DES
        5. Encrypt DES result with AES
        6. Encrypt AES result with RSA
        7. Save final encrypted result to file
    
    """
    # Step 1: Check if username already exists
    if check_username_exists(username):
        return False, f"Username '{username}' already exists!"
    
    # Step 2: Validate password strength
    valid, msg = check_password_strength(password)
    if not valid:
        return False, msg
    
    steps = []
    
    # Step 3: SHA-256 Hashing
    hashed_pass_bytes, hashed_pass_hex = hash_password_sha256(password)
    steps.append(f"Step 1: SHA-256 Hash\n  Original: {password}\n  Hash (Hex): {hashed_pass_hex}\n")
    
    # Step 4: DES Encryption
    des_encrypted = encrypt_des(hashed_pass_bytes, des_key)
    steps.append(f"Step 2: DES Encryption (ECB)\n  Key: {des_key}\n  Encrypted (Hex): {des_encrypted.hex()}\n")
    
    # Step 5: AES Encryption
    aes_encrypted = encrypt_aes(des_encrypted, aes_key)
    steps.append(f"Step 3: AES Encryption (ECB)\n  Key: {aes_key}\n  Encrypted (Hex): {aes_encrypted.hex()}\n")
    
    # Step 6: RSA Encryption
    final_encrypted = encrypt_rsa(aes_encrypted, rsa_public_key)
    steps.append(f"Step 4: RSA Encryption (2048-bit)\n  Final Encrypted (Hex): {final_encrypted.hex()}\n")
    
    # Step 7: Save to file
    final_encrypted_hex = final_encrypted.hex()
    if save_user_to_file(username, final_encrypted_hex):
        steps.append(f"\n SUCCESS! User '{username}' registered successfully!")
        
        # Log steps if callback provided
        if log_callback:
            for step in steps:
                log_callback(step)
        
        return True, "Registration successful!"
    else:
        return False, "Failed to save user data."


def login_user(username, password_input, des_key, aes_key, private_key, log_callback=None):
    """
    Authenticate user by decrypting stored password and comparing hashes.
    
    Process:
        1. Retrieve stored encrypted password
        2. Decrypt RSA layer
        3. Decrypt AES layer
        4. Decrypt DES layer (get original hash)
        5. Hash input password
        6. Compare hashes
        7. Return authentication result

    """
    # Step 1: Retrieve stored encrypted password
    stored_hex = get_stored_password(username)
    
    if stored_hex is None:
        return False, "User not found!"

    try:
        steps = []
        steps.append("=== DECRYPTION PROCESS ===\n")
        
        # Convert hex string to bytes
        stored_bytes = bytes.fromhex(stored_hex)
        
        # Step 2: Decrypt RSA layer
        decrypted_rsa = decrypt_rsa(stored_bytes, private_key)
        steps.append("Step 1: RSA Decryption \n")
        
        # Step 3: Decrypt AES layer
        decrypted_aes = decrypt_aes(decrypted_rsa, aes_key)
        steps.append("Step 2: AES Decryption \n")
        
        # Step 4: Decrypt DES layer (get original SHA-256 hash)
        original_hash_bytes = decrypt_des(decrypted_aes, des_key)
        steps.append("Step 3: DES Decryption \n")
        
        # Step 5: Hash the input password
        input_hash_bytes, input_hash_hex = hash_password_sha256(password_input)
        steps.append(f"\nInput Password Hash: {input_hash_hex}\n")
        steps.append(f"Stored Password Hash: {original_hash_bytes.hex()}\n")
        
        # Step 6: Compare hashes
        if original_hash_bytes == input_hash_bytes:
            steps.append("\n LOGIN SUCCESSFUL! Hashes match.\n")
            
            # Log steps if callback provided
            if log_callback:
                for step in steps:
                    log_callback(step)
            
            return True, "Login successful!"
        else:
            steps.append("\n ACCESS DENIED! Password incorrect.\n")
            
            # Log steps if callback provided
            if log_callback:
                for step in steps:
                    log_callback(step)
            
            return False, "Incorrect password!"
            
    except Exception as e:
        return False, f"Decryption failed: {str(e)}"