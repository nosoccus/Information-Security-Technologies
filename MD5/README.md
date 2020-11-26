# MD5 Implemetation in Python
## Task:
 Create a software implementation of the MD5 hashing algorithm. Testing of the created program is carried out using test hash values (according to RFC 1321).
 ```
 H() = D41D8CD98F00B204E9800998ECF8427E
 H(a) = 0CC175B9C0F1B6A831C399E269772661
 H(abc) = 900150983CD24FB0D6963F7D28E17F72
 H(message digest) = F96B697D7CB7938D525A2F31AAF161D0
 H(abcdefghijklmnopqrstuvwxyz) = C3FCD3D76192E4007DFB496CCA67E13B
 H(ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789) = D174AB98D277D9F5A5611C2C9F419D9F
 H(12345678901234567890123456789012345678901234567890123456789012345678901234567890) = 57EDF4A22BE3C955AC49DA2E2107B67A
 ```

## Requirements:
 - The software implementation must output a hash value for both the string specified in the input field and the file.
 - The result of the program should be displayed on the screen with the possibility of subsequent writing to a file.
 - In addition, the program must be able to verify the integrity of any file with a cash file with an MD5 hash written in hexadecimal format.
 - In the report to give the protocol of testing and work of the program and to draw conclusions.
 
## How to use:
 - [```ownmd5.py```](https://github.com/nosoccus/information-security-technologies/blob/main/MD5/own_md5.py) - contains the classic implemetation of md5 algorithm.
   - Run script without argument to hash your own string:
     ```python
     python ownmd5.py
     ```
   - To run test hash values run script like this:
     ```python
     python ownmd5.py test
     ```
   - To run script for hashing files type filename as an argument:
     ```python
     python ownmd5.py filename
     ```
 - [```string_check.py```](https://github.com/nosoccus/information-security-technologies/blob/main/MD5/string_check.py) - contains built-in function to get hash of a string.
 - [```file_check.py```](https://github.com/nosoccus/information-security-technologies/blob/main/MD5/file_check.py) - contains built-in function to get hash of a file.
 
## Addition
> The implementaion of MD5 i Python is VERY SUPER MEGA slow for files, so i decided to use Cython to speed up the hash for large files.
To run implemetation in Python:
- Check the implementation in [```cmd5.pyx```](https://github.com/nosoccus/information-security-technologies/blob/main/MD5/cmd5.pyx)
- Build solution using:
```python
python setup.py build_ext --inplace
```
- Run script using:
```python
python run.py
```
