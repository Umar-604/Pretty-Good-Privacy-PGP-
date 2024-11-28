from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes
import base64

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
    
def generate_rsa_keys():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    return private_key, public_key

if __name__ == "__main__":
    print("========== CASE 2: Signing a Message for Authenticity ==========\n")
    
    # Generate RSA Key Pair
    print("Generating RSA key pair for signing the message...")
    private_key, public_key = generate_rsa_keys()
    print("RSA Key Pair Generated!\n")
    
    # Sign the Message
    message = "Authentic Message"
    print(f"✍️ Signing the message: '{message}' using the private RSA key...\n")
    signature = sign_message(message, private_key)
    print(f"Digital Signature (Base64): {base64.b64encode(signature).decode()}\n")
    
    # Verify the Signature
    print("Verifying the digital signature using the public RSA key...\n")
    is_valid = verify_signature(message, signature, public_key)
    print(f"Signature Verification Result: {'Valid' if is_valid else 'Invalid'}\n")
    
    print("Message successfully signed for authenticity!")
    print("============================================================\n")
