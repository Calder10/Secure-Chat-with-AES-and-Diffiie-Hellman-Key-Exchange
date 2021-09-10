"""
Università degli Studi Di Palermo
Corso di Laurea Magistrale in Informatica
Anno Accademico 2020/2021
Cybersecurity
@author Salvatore Calderaro
DH-AES256 - Chatter
"""
from Crypto.Hash import SHA256
from Crypto.Cipher import AES

"""
Funzione che applica SHA-256 sulla chiave data in input.
"""
def apply_sha256(key):
    key=str(key)
    h = SHA256.new()
    h.update(key.encode())
    k = h.digest()
    return k

"""
Funzione per l'encrypt mediante AES-256
"""
def encrypt(key,msg):
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    print("Nonce",nonce)
    ciphertext, tag = cipher.encrypt_and_digest(msg.encode('utf-8'))
    return nonce, ciphertext, tag

"""
Funzione per il decrypt mediante AES-256
"""
def decrypt(nonce, ciphertext, tag,key):
    print("Nonce",nonce)
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("The message is authentic")
        return plaintext.decode('utf-8')
    except:
        print("Key incorrect or message corrupted")
        return False


