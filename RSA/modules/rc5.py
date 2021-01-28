import sys
from modules.lab1 import generator
from modules.md5 import md5sum


# Хешування паролю
def key_hash(password):
    key = md5sum(password)
    key += md5sum(key)
    return bytes.fromhex(key)


# Масив підключів S
def S_array(rounds):
    T = 2 * (rounds + 1)
    S = generator(T)
    # print(S)
    return S


# Масив ключів L
def L_array(key, value):
    L = []
    for i in range(0, len(key), value):
        L.append(int.from_bytes(key[i: i + value], byteorder="little"))
    return L


class BlockPreparation:
    # Циклічний зсув вліво
    def left_shift(self, value, amount, mod):
        mask = 2 ** mod - 1
        v1 = (value << amount % mod) & mask
        v2 = (value & mask) >> (mod - (amount % mod))
        return v1 | v2

    # Циклічний зсув вправо
    def right_shift(self, value, amount, mod):
        mask = 2 ** mod - 1
        v1 = (value & mask) >> amount % mod
        v2 = value << (mod - (amount % mod)) & mask
        return v1 | v2

    def ready(self, key, wordsize, rounds, IV=None):
        # Функція змішування ініціалізованого масиву підключів S з масивом ключів L
        def shuffling(L, S, rounds, w, c):
            T = 2 * (rounds + 1)
            m = max(c, T)
            i = j = A = B = 0
            for k in range(3 * m):
                A = S[i] = self.left_shift(S[i] + A + B, 3, w)
                B = L[j] = self.left_shift(L[j] + A + B, A + B, w)
                i = (i + 1) % T
                j = (j + 1) % c
            return S

        L = L_array(key, wordsize // 8)

        if IV == None:
            S = S_array(rounds)
            IV = S[:]
            return IV, shuffling(L, S, rounds, wordsize, len(L))
        else:
            return shuffling(L, IV, rounds, wordsize, len(L))

    # Функція шифрування блоку повідомлення
    def _encrypt(self, block, S, block_size, rounds):
        w = block_size // 2
        b = block_size // 8
        mod = 2 ** w

        A = int.from_bytes(block[:b // 2], byteorder='little')
        B = int.from_bytes(block[b // 2:], byteorder='little')
        A = (A + S[0]) % mod
        B = (B + S[1]) % mod

        for i in range(1, rounds + 1):
            A = (self.left_shift((A ^ B), B, w) + S[2 * i]) % mod
            B = (self.left_shift((A ^ B), A, w) + S[2 * i + 1]) % mod

        return A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')

    # Функція розшифрування блоку повідомлення
    def _decrypt(self, block, S, block_size, rounds):
        w = block_size // 2
        b = block_size // 8
        mod = 2 ** w

        A = int.from_bytes(block[:b // 2], byteorder='little')
        B = int.from_bytes(block[b // 2:], byteorder='little')
        for i in range(rounds, 0, -1):
            B = self.right_shift(B - S[2 * i + 1], A, w) ^ A
            A = self.right_shift(A - S[2 * i], B, w) ^ B
        B = (B - S[1]) % mod
        A = (A - S[0]) % mod

        return A.to_bytes(b // 2, byteorder='little') + B.to_bytes(b // 2, byteorder='little')


class RC5(BlockPreparation):
    def __init__(self, key, block_size, rounds):
        self.key = key
        self.block_size = block_size
        self.rounds = rounds

    " Функція зчитування файлу для шифрування "
    def encryption(self, input_file, output_file):
        block_size = self.block_size
        rounds = self.rounds
        key = self.key
        w = block_size // 2
        b = block_size // 8
        IV, S = super().ready(key, w, rounds)
        cbc = 0

        read_bytes = open(input_file, 'rb')
        write_bytes = open(output_file, 'wb')
        for i in IV:
            temp = i.to_bytes(b, byteorder="little")
            write_bytes.write(super()._encrypt(temp, [0] * (2 * (rounds + 1)), block_size, rounds))
        isNext = True

        while isNext:
            block = read_bytes.read(b)

            if not block:
                break

            if len(block) != b:
                block = block.ljust(b, b'\x00')
                isNext = False

            block = int.from_bytes(block, byteorder='little')
            block = block ^ cbc
            block = block.to_bytes(b, byteorder='little')
            block = super()._encrypt(block, S, block_size, rounds)
            write_bytes.write(block)
            cbc = int.from_bytes(block, byteorder='little')

    " Функція зчитування файлу для розшифрування "
    def decryption(self, inputFile, outputFile):
        block_size = self.block_size
        rounds = self.rounds
        key = self.key
        w = block_size // 2
        b = block_size // 8
        cbc = 0

        read_bytes = open(inputFile, 'rb')
        write_bytes = open(outputFile, 'wb')
        IV = []  # init vector
        for i in range(2 * (rounds + 1)):
            temp = read_bytes.read(b)
            temp = super()._decrypt(temp, [0] * (2 * (rounds + 1)), block_size, rounds)
            IV.append(int.from_bytes(temp, byteorder="little"))

        S = super().ready(key, w, rounds, IV=IV)

        while True:
            block = read_bytes.read(b)
            temp = int.from_bytes(block, byteorder="little")

            if not block:
                break

            decrypted = super()._decrypt(block, S, block_size, rounds)
            decrypted = int.from_bytes(decrypted, byteorder="little") ^ cbc
            decrypted = decrypted.to_bytes(b, byteorder="little")
            decrypted = decrypted.split(b'\x00',1)[0]
            write_bytes.write(decrypted)
            cbc = temp


if __name__ == "__main__":
    w = 16  # довжина слова в бітах
    r = 20  # кількість раундів
    b = 16  # довжина ключа в байтах

    while True:
        option = int(input("1 - encrypt\n2 - decrypt\n"))

        if option == 1:
            read_file = input("Enter a filename to read for encryption: ")
            write_file = input("Enter a filename to write encrypted: ")
            password = input("Enter a password: ")

            key = key_hash(password)
            cypher = RC5(key, w, r)
            cypher.encryption(read_file, write_file)
            print("Encrypted\n")

        elif option == 2:
            read_file = input("Enter a filename to read for decryption: ")
            write_file = input("Enter a filename to write decrypted: ")
            password = input("Enter a password: ")

            key = key_hash(password)
            cypher = RC5(key, w, r)
            cypher.decryption(read_file, write_file)
            print("Decrypted\n")

        else:
            sys.exit(0)
