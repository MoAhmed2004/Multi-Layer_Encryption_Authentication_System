"""

This module contains all cryptographic operations:
 SHA-256 hashing
 DES encryption/decryption
 AES encryption/decryption
 RSA encryption/decryption
"""

import hashlib
from Crypto.Cipher import DES, AES, PKCS1_OAEP
from Crypto.Util.Padding import pad, unpad


#  HASHING 

def hash_password_sha256(password):
    """
    Hash password using SHA-256 algorithm.
    Hashing creates a one-way hash that cannot be reversed.
    
    """
    password_bytes = password.encode('utf-8')
    hashed_password = hashlib.sha256(password_bytes)
    return hashed_password.digest(), hashed_password.hexdigest()


#  DES ENCRYPTION/DECRYPTION 

def encrypt_des(data, key):
    """
    Encrypt data using DES algorithm.
    Uses ECB (Electronic Codebook) mode with 8-byte blocks.
    
    """
    # Ensure key is exactly 8 bytes 
    if len(key) > 8:
        key = key[:8]
    elif len(key) < 8:
        key = key.ljust(8, b'0')

    # Create DES cipher in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Add padding to make data multiple of 8 bytes
    padded_data = pad(data, 8)
    
    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data


def decrypt_des(encrypted_data, key):
    """
    Decrypt DES-encrypted data.
    Reverses the DES encryption process.
    
    """
    # Ensure key is exactly 8 bytes
    if len(key) > 8:
        key = key[:8]
    elif len(key) < 8:
        key = key.ljust(8, b'0')
    
    # Create DES cipher in ECB mode
    cipher = DES.new(key, DES.MODE_ECB)
    
    # Decrypt the data
    decrypted_padded = cipher.decrypt(encrypted_data)
    
    # Remove padding and return original data
    return unpad(decrypted_padded, 8)


#  AES ENCRYPTION/DECRYPTION 

def encrypt_aes(data, key):
    """
    Encrypt data using AES algorithm.
    Uses ECB mode with 16-byte blocks and 128-bit key.
    
    """
    # Ensure key is exactly 16 bytes 
    if len(key) > 16:
        key = key[:16]
    elif len(key) < 16:
        key = key.ljust(16, b'0')
    
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Add padding to make data multiple of 16 bytes
    padded_data = pad(data, 16)
    
    # Encrypt the padded data
    encrypted_data = cipher.encrypt(padded_data)
    
    return encrypted_data


def decrypt_aes(encrypted_data, key):
    """
    Decrypt AES-encrypted data.
    Reverses the AES encryption process.
    
    """
    # Ensure key is exactly 16 bytes
    if len(key) > 16:
        key = key[:16]
    elif len(key) < 16:
        key = key.ljust(16, b'0')
    
    # Create AES cipher in ECB mode
    cipher = AES.new(key, AES.MODE_ECB)
    
    # Decrypt the data
    decrypted_padded = cipher.decrypt(encrypted_data)
    
    # Remove padding and return original data
    return unpad(decrypted_padded, 16)


#  RSA ENCRYPTION/DECRYPTION 

def encrypt_rsa(data, public_key):
    """
    Encrypt data using RSA (Rivest-Shamir-Adleman) algorithm.
    Uses PKCS1_OAEP padding for security.
    RSA is asymmetric: uses public key for encryption.
 
    """
    # Create RSA cipher with PKCS1_OAEP padding
    rsa_cipher = PKCS1_OAEP.new(public_key)
    
    # Encrypt the data
    encrypted_data = rsa_cipher.encrypt(data)
    
    return encrypted_data


def decrypt_rsa(encrypted_data, private_key):
    """
    Decrypt RSA-encrypted data.
    Uses private key to reverse RSA encryption.
    
    """
    # Create RSA cipher with PKCS1_OAEP padding
    rsa_cipher = PKCS1_OAEP.new(private_key)
    
    # Decrypt the data
    decrypted_data = rsa_cipher.decrypt(encrypted_data)
    
    return decrypted_data