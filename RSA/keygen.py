from Crypto.PublicKey import RSA
import time

start = time.process_time()
# Generate public/private keys(512 bytes)
new_key = RSA.generate(4096, e=65537)

private_key = new_key.exportKey("PEM")
public_key = new_key.publickey().exportKey("PEM")

gen_time = (time.process_time() - start)
print(f"Time for key generation: {gen_time}")

# Write private key into file
with open("private_key.pem", "wb+") as f:
    f.write(private_key)

# Write public key into file
with open("public_key.pem", "wb+") as f:
    f.write(public_key)

write_time = (time.process_time() - gen_time)
print(f"Time for writing keys: {write_time}")
