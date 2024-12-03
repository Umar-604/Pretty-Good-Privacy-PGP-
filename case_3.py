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

def sign_message(message, private_key):
    signature = private_key.sign(
        message.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return signature

def verify_signature(message, signature, public_key):
    try:
        public_key.verify(
            signature,
            message.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

if __name__ == "__main__":
    print("========== CASE 3: Encrypting and Signing a Message ==========\n")
    
    # Generate RSA Key Pairs for Sender and Receiver
    print("Generating RSA key pairs for both sender and receiver...")
    sender_private_key, sender_public_key = generate_rsa_keys()
    receiver_private_key, receiver_public_key = generate_rsa_keys()
    print("RSA Key Pairs Generated for Sender and Receiver!\n")
    
    # Encrypt the Message (Confidentiality)
    message = "Confidential and Authentic Message"
    aes_key = os.urandom(32)
    print(f"Encrypting the message: '{message}' using AES...")
    ciphertext, iv = symmetric_encrypt(message, aes_key)
    encrypted_key = rsa_encrypt_key(aes_key, receiver_public_key)
    print(f"Ciphertext (Base64): {base64.b64encode(ciphertext).decode()}")
    print(f"Encrypted AES Key (Base64): {base64.b64encode(encrypted_key).decode()}\n")
    
    # Sign the Encrypted Message (Authenticity)
    print("✍️ Signing the encrypted message using the sender's private RSA key...\n")
    signature = sign_message(base64.b64encode(ciphertext).decode(), sender_private_key)
    print(f"Digital Signature (Base64): {base64.b64encode(signature).decode()}\n")
    
    # Verify the Signature
    print("Verifying the digital signature using the sender's public RSA key...\n")
    is_valid = verify_signature(base64.b64encode(ciphertext).decode(), signature, sender_public_key)
    print(f"Signature Verification Result: {'Valid' if is_valid else 'Invalid'}\n")
    
    print("Message successfully encrypted and signed!")
    print("============================================================\n")
