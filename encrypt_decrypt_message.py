def create_ciphertext_from_list(message):
    ct=""
    for c in message:
        ct+=str(c)
    return ct

def create_string_from_list(message):
    text = ''.join(message)
    return text

def encrypt_message(message,key):
    encrypted_message = []     
    for i in range(0, len(message)):
        encrypted_message.append(message[i])

    for i in range(0, len(encrypted_message)):
        encrypted_message[i] = key * ord(encrypted_message[i])
    return encrypted_message

def decrypt_message(message,key):
    decrypted_message=[]
    for i in range(0, len(message)):
        decrypted_message.append(chr(int(message[i]/key)))
    return decrypted_message