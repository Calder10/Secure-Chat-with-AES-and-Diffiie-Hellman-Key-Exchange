from Crypto.Cipher import AES
from hashlib import sha256

def apply_sha256(key):
    k=str(key)
    k = sha256(k.encode()).digest()
    return k

def encrypt(key,msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
    return nonce, ciphertext, tag

def decrypt(nonce, ciphertext, tag,key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        return plaintext.decode('utf-8')
    except:
        return False
"""
print("Shared Key",hex(K))
"""


