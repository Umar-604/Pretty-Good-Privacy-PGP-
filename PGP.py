# Import necessary libraries
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64

# Step 1: Generate RSA Key Pair for Asymmetric Encryption
def generate_rsa_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    return private_key, public_key

# Step 2: Serialize RSA Keys for Storage/Sharing
def serialize_keys(private_key, public_key):
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return private_pem, public_pem

# Step 3: Symmetric Encryption of Message
def symmetric_encrypt(message, key):
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(message.encode()) + encryptor.finalize()
    return ciphertext, iv

# Step 4: RSA Encryption of AES Key
def rsa_encrypt_key(aes_key, public_key):
    encrypted_key = public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_key

# Step 5: RSA Decryption of AES Key
def rsa_decrypt_key(encrypted_key, private_key):
    aes_key = private_key.decrypt(
        encrypted_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return aes_key

# Step 6: Symmetric Decryption of Message
def symmetric_decrypt(ciphertext, key, iv):
    cipher = Cipher(algorithms.AES(key), modes.CFB(iv))
    decryptor = cipher.decryptor()
    plaintext = decryptor.update(ciphertext) + decryptor.finalize()
    return plaintext.decode()

# Utility Function: Print in a Professional Format
def print_section(title, content):
    print(f"{'-' * 10} {title} {'-' * 10}")
    print(content)
    print("-" * (22 + len(title)))

# Main PGP Workflow
if __name__ == "__main__":
    print("========== PGP Implementation Workflow ==========\n")

    # Step 1: Key Generation
    print("Step 1: Generating RSA key pair...")
    private_key, public_key = generate_rsa_keys()
    print_section("Generated RSA Private Key", private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode())
    print_section("Generated RSA Public Key", public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode())

    # Step 2: Serialize Keys
    print("\nStep 2: Serializing RSA keys...")
    private_pem, public_pem = serialize_keys(private_key, public_key)
    print_section("Serialized Private Key (PEM Format)", private_pem.decode())
    print_section("Serialized Public Key (PEM Format)", public_pem.decode())

    # Step 3: Symmetric Encryption
    message = "This is a secure message."
    print(f"\nOriginal Message: {message}")
    aes_key = os.urandom(32)  # Generate a 256-bit AES key
    ciphertext, iv = symmetric_encrypt(message, aes_key)
    print_section("Generated AES Key (Base64)", base64.b64encode(aes_key).decode())
    print_section("Ciphertext (Base64)", base64.b64encode(ciphertext).decode())
    print_section("Initialization Vector (Base64)", base64.b64encode(iv).decode())

    # Step 4: Encrypt AES Key with RSA
    print("\nStep 4: Encrypting AES key with RSA public key...")
    encrypted_aes_key = rsa_encrypt_key(aes_key, public_key)
    print_section("Encrypted AES Key (Base64)", base64.b64encode(encrypted_aes_key).decode())

    # Step 5: Decrypt AES Key with RSA
    print("\nStep 5: Decrypting AES key with RSA private key...")
    decrypted_aes_key = rsa_decrypt_key(encrypted_aes_key, private_key)
    print_section("Decrypted AES Key (Base64)", base64.b64encode(decrypted_aes_key).decode())

    # Step 6: Decrypt Message with Symmetric Key
    print("\nStep 6: Decrypting the message with the decrypted AES key...")
    plaintext = symmetric_decrypt(ciphertext, decrypted_aes_key, iv)
    print_section("Decrypted Message", plaintext)

    print("\n========== PGP Workflow Completed Successfully ==========")
