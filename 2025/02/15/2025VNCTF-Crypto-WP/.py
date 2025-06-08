from gmssl import sm4, func
from os import urandom
from flag import FLAG, secret_message

def xor(a, b):
    return bytes(x ^ y for x, y in zip(a, b))

def encrypt(key, plaintext, iv):
    cipher = sm4.CryptSM4(sm4.SM4_ENCRYPT, 0)
    cipher.set_key(key, sm4.SM4_ENCRYPT)
    ciphertext = cipher.crypt_cbc(iv,plaintext)
    return ciphertext


def main():
    key = secret_message
    while len(key) < 16:
        key += secret_message
    key = key[:16]
    iv = urandom(16)

    plaintext = b"My FLAG? If you want it, I'll let you have it... search for it! I left all of it at that place: " + FLAG
    assert len(plaintext) % 16 == 0, "The message must be a multiple of 16 bytes."
    ciphertext = encrypt(key, plaintext, iv)
    print(f"Ciphertext: {ciphertext.hex()}")
    print(f"What is this: {xor(key, iv).hex()}")
    
if __name__ == "__main__":
    main()