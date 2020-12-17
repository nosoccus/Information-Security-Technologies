from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import time


# Encryption function
def encrypt(text, public_key):
    # Import the public key using PKCS1_OAEP
    rsa_key = RSA.importKey(public_key)
    rsa_key = PKCS1_OAEP.new(rsa_key)

    # Chunk size determines as the private key length used in bytes
    # and subtract 42 bytes(when using PKCS1_OAEP)
    chunk_size = 470
    offset = 0
    end_loop = True
    encrypted = bytes("", encoding='utf-8')

    while end_loop:
        chunk = text[offset:offset + chunk_size]

        # If chunk is less then the chunk size, then add padding(" ").
        # This indicates end of loop.
        if len(chunk) % chunk_size != 0:
            end_loop = False
            chunk += bytes(" ", encoding='utf-8') * (chunk_size - len(chunk))

        # Append the encrypted chunk
        encrypted += rsa_key.encrypt(chunk)

        # Change offset(add chunk size)
        offset += chunk_size

    # Base 64 encode the encrypted file
    return base64.b64encode(encrypted)


start = time.process_time()
# Use the public key for encryption
with open("public_key.pem", "rb") as f:
    public_key = f.read()

# File to be encrypted
with open("text.txt", "rb") as f:
    text_to_encrypt = f.read()

encrypted_text = encrypt(text_to_encrypt, public_key)

# Write the encrypted content to a file
with open("encrypted_rsa.txt", "wb") as f:
    f.write(encrypted_text)

enc_time = (time.process_time() - start)
print(f"Time for encryption: {enc_time}")
