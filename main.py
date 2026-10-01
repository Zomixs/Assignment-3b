import base64
import os
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad
 
 
def AES_Encryption(plaintext: bytes, key: bytes) -> bytes:
    """AES-CBC encryption. Output = IV (16 bytes) || ciphertext."""
    iv = get_random_bytes(AES.block_size)          # fresh random IV every time
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return iv + cipher.encrypt(pad(plaintext, AES.block_size))  # PKCS#7 padding
 
 
def AES_Decryption(enc_message: bytes, key: bytes) -> bytes:
    iv, ct = enc_message[:AES.block_size], enc_message[AES.block_size:]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(ct), AES.block_size)
 
 
def AES_Encryption_File(filename: str, key: bytes) -> bytes:
    """Read a file, Base64-encode it, then encrypt it."""
    with open(filename, 'rb') as f:
        data = base64.b64encode(f.read())
    return AES_Encryption(data, key)
 
 
def AES_Decryption_File(enc_file: bytes, key: bytes) -> bytes:
    """Returns the Base64-encoded file content (caller decodes it)."""
    return AES_Decryption(enc_file, key)
 
 
if __name__ == "__main__":
    key = b'1234sfsfdsafasdf'
    plaintext = b'Hello World'
    plaintext = base64.b64encode(plaintext)
    print(plaintext)
 
    enc_message = AES_Encryption(plaintext, key)
    print(enc_message)
    original_message = AES_Decryption(enc_message, key)
    print(plaintext == original_message)
 
    if not os.path.exists('hello.txt'):           # demo file if none exists
        with open('hello.txt', 'w') as f:
            f.write('Hello from hello.txt')
 
    enc_file = AES_Encryption_File('hello.txt', key)
    print(enc_file)
 
    dec_file = AES_Decryption_File(enc_file, key)
    dec_file = base64.b64decode(dec_file)         # original code had a typo: b64decode(dec)
    print(dec_file)
