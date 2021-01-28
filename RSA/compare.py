import time

import modules.rc5 as rc5


w = 16  # довжина слова в бітах
r = 20  # кількість раундів
b = 16  # довжина ключа в байтах

_password = "comparing"
_src = "text.txt"
_res = "encrypted_rc5.txt"
_dec = "decrypted_rc5.txt"

start = time.process_time()

key = rc5.key_hash(_password)
cypher = rc5.RC5(key, w, r)
cypher.encryption(_src, _res)
enc_time = (time.process_time() - start)
print("Encrypted")
print(f"Time for encryption: {enc_time}")


cypher.decryption(_res, _dec)
dec_time = (time.process_time() - enc_time)
print("Decrypted")
print(f"Time for decryption: {dec_time}")
