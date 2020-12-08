# RC5-CBC-Pad Implementation
## Task:
 Create a software implementation of the RC5 algorithm. Testing of the created program is carried out using test hash values (according to RFC 1321).


## Requirements:
 - The program must receive a passphrase from the user and, based on it, encrypt files of any size, and save the result as a file with the possibility of further decryption (by entering the same passphrase).
 - To convert a passphrase into an encryption key, use the MD5 algorithm implemented in the lab №2 - the encryption key must be a hash of the passphrase. If according to the variant the key length is 64 bits, the lower 64 bits of the hash are taken; if the key length is to be 256 bits, then the hash of the password phrase becomes the higher 128 bits, and the younger is the hash of the higher 128 bits.
- To enable the creation of the created software product with plaintext of any length, the software implementation should be carried out in the RC5-CBC-Pad mode. As the initialization vector (IV) use a pseudo-random number generator implemented in the lab №1.
 - For each new encrypted message should generate a new initialization vector. The initialization vector is encrypted in ECB mode and stored in the first block of the encrypted file.
 - In the report to give the protocol of work of the program and to draw conclusions about a combination of various cryptographic primitives for information protection tasks.
 
 
## How to use:
 - [```main.py```](https://github.com/nosoccus/information-security-technologies/blob/main/RC5/main.py) - contains the implemetation of RC5-CBC-Pad algorithm.
 - [```md5.py```](https://github.com/nosoccus/information-security-technologies/blob/main/RC5/md5.py) - contains the implemetation of MD5 from the previous task.
 - [```lab1.py```](https://github.com/nosoccus/information-security-technologies/blob/main/RC5/lab1.py) - contains pseudo-random generator.
 
