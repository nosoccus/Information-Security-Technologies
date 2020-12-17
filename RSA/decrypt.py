from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import base64
import time


# Decryption function
def decrypt(byte_text, private_key):
    # Import the private key using PKCS1_OAEP
    rsakey = RSA.importKey(private_key)
    rsakey = PKCS1_OAEP.new(rsakey)

    # Base 64 decode the data
    byte_text = base64.b64decode(byte_text)

    # Chunk size determines as the private key length used in bytes
    chunk_size = 512
    offset = 0
    decrypted = bytes("", encoding='utf-8')

    # Do until the last chunk
    while offset < len(byte_text):
        chunk = byte_text[offset: offset + chunk_size]

        # Append the decrypted chunk
        decrypted += rsakey.decrypt(chunk)

        # Change offset(add chunk size)
        offset += chunk_size

    return decrypted


start = time.process_time()
# Use the private key for decryption
with open("private_key.pem", "rb") as f:
    private_key = f.read()

# File to be decrypt
with open("encrypted_rsa.txt", "rb") as f:
    encrypted_text = f.read()

# Write the decrypted content to a file
with open("decrypted_rsa.txt", "wb") as f:
    f.write(decrypt(encrypted_text, private_key))

dec_time = (time.process_time() - start)
print(f"Time for decryption: {dec_time}")
