from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA1
import time


def view_function_timer(function):
    def wrapped(*args):
        start_time = time.process_time()
        res = function(*args)
        took = time.process_time() - start_time
        print(f"Time for function execution {took}s")
        return res
    return wrapped


@view_function_timer
def key_gen(size):
    key = DSA.generate(size)
    with open('public_key.pem', 'wb') as public_key:
        public_key.write(key.publickey().export_key())
    with open('private_key.pem', 'wb') as private_key:
        private_key.write(key.export_key())


@view_function_timer
def sign_message(message,  signature_file):
    hash_object = SHA1.new(message)
    with open('private_key.pem', 'rb') as f:
        key = DSA.importKey(f.read())
    signer = DSS.new(key, 'fips-186-3')
    sign = signer.sign(hash_object)
    print("Signature: ", sign)
    with open(signature_file, 'wb') as signature:
        signature.write(sign)


@view_function_timer
def verify_message(message, signature_file):
    with open(signature_file, 'rb') as signature:
        sign = signature.read()
    with open('public_key.pem', 'rb') as f:
        public_key = DSA.importKey(f.read())
    hash_object = SHA1.new(message)
    verifier = DSS.new(public_key, 'fips-186-3')

    try:
        verifier.verify(hash_object, sign)
        return "Verified"
    except ValueError:
        return "Not verified"


@view_function_timer
def sign_file(input_file, size, signature_file):
    hash_object = SHA1.new()
    with open(input_file, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(size)
            hash_object.update(chunk)
    with open('private_key.pem', 'rb') as f:
        key = DSA.importKey(f.read())
    signer = DSS.new(key, 'fips-186-3')
    sign = signer.sign(hash_object)
    print("Signature: ", sign)
    with open(signature_file, 'wb') as signature:
        signature.write(sign)


@view_function_timer
def verify_file(input_file, size, signature_file):
    signature = open(signature_file, 'rb').read()
    hash_object = SHA1.new()
    with open(input_file, 'rb') as file:
        chunk = 0
        while chunk != b'':
            chunk = file.read(size)
            hash_object.update(chunk)
    with open('public_key.pem', 'rb') as f:
        public_key = DSA.importKey(f.read())
    verifier = DSS.new(public_key, 'fips-186-3')

    try:
        verifier.verify(hash_object, signature)
        return "Verified"
    except ValueError:
        return "Not verified"


while True:
    option = int(input("1 - generate keys\n2 - sign string\n3 - check string\n"
                        "4 - sign file\n5 - check file\n6 - exit\n"))

    if option == 1:
        size = int(input("Key length in bits: "))
        key_gen(size)

    elif option == 2:
        text = bytes(input("Text to create signature: "), 'utf-8')
        signature_file = input("Filename to write signature: ")
        sign_message(text, signature_file)

    elif option == 3:
        text = bytes(input("Text to check signature: "), 'utf-8')
        signature_file = input("Filename to check signature: ")
        print(verify_message(text, signature_file))

    elif option == 4:
        file = input("Filename to create signature: ")
        signature_file = input("Filename to write signature: ")
        sign_file(file, 1024,  signature_file)

    elif option == 5:
        file = input("Filename to check signature: ")
        signature_file = input("Filename to check signature: ")
        print(verify_file(file, 1024, signature_file))

    else:
        exit()
