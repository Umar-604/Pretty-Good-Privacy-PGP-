import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import base64

# Functions for RSA and Symmetric encryption
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

def symmetric_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext, iv

def rsa_encrypt_key(aes_key, public_key):
    return public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

if __name__ == "__main__":
    print("========== CASE 1: Encrypting a Message for Confidentiality ==========\n")
    
    # Step 1: Generate RSA Keys
    print("Generating RSA key pair for secure communication...")
    private_key, public_key = generate_rsa_keys()
    print("RSA Key Pair Generated!\n")
    
    # Step 2: Encrypt the Message with AES
    message = "Confidential Message"
    aes_key = os.urandom(32)
    print(f"Encrypting the message: '{message}' using AES...\n")
    ciphertext, iv = symmetric_encrypt(message, aes_key)
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}\n")
    
    # Step 3: Encrypt AES Key with RSA
    print("Encrypting the AES key using RSA public key for secure key exchange...\n")
    encrypted_key = rsa_encrypt_key(aes_key, public_key)
    print(f"Encrypted AES Key (Base64): {base64.b64encode(encrypted_key).decode()}\n")
    
    print("Message successfully encrypted for confidentiality!")
    print("============================================================\n")
