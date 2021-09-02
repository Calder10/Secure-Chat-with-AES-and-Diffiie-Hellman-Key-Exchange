import socket
from random import choice,shuffle
from time import sleep
import pickle
from tkinter.font import names
import diffie_hellman as dh
import encrypt_decrypt_message as edm
import AES

p=None 
g=None
b=None
A=None
B=None
K=None

def set_p_g_parmeters():
    global p,g
    p,g=dh.upload_p_g()

def print_parameters():
    print("Server:")
    print("p:",p)
    print("g:",g)

def create_random_text_list():
    texts=[]
    prefix="Random text "
    for i in range(10):
        texts.append(prefix + str(i+1))
    texts.append("Bye")
    shuffle(texts)
    return texts

def server():
    global b,A,B,K
    names=["Alice","Bob","Claudia","Giuseppe"]
    print("===================================================")
    print("********* SERVER *********")
    print("===================================================")
    set_p_g_parmeters()
    print_parameters()
    b=dh.create_private_key(p,g)
    print("Private Key", b)
    B=dh.create_public_key(g,p,b)
    print("Public Key",B)
    host = socket.gethostname()
    port = 5000 
    server_socket = socket.socket()
    server_socket.bind((host,port))
    server_socket.listen(1)
    conn, address = server_socket.accept() 
    print("Connection from: " + str(address))
    while True:
        print("Waiting the client publick key:")
        A = conn.recv(512).decode()
        A = int (A)
        print("I recivied :",A)
        print("Sending Public Key")
        conn.send(str(B).encode())
        name=choice(names)
        print("Send my name to client...")
        conn.send(name.encode())
        break
    K=dh.create_shared_key(A,b,p)
    print("Shared Key (Hex)",hex(K))
    K=AES.apply_sha256(K)
    print("Shared Key (Byte)",K)
    texts=create_random_text_list()
    print(texts)
    while True:
        print("Waiting for a message...")
        data = conn.recv(1000000)
        aes_data = pickle.loads(data)
        print("I recivied",aes_data[1])
        plaintext = AES.decrypt(aes_data[0],aes_data[1],aes_data[2],K)
        print("Plaintext:",plaintext)
        if plaintext == "Bye":
            print("End of comunication !")
            break
        else:
            plaintext=choice(texts)
            if plaintext == "Bye":
                nonce, ciphertext, tag=AES.encrypt(K,plaintext)
                print("Ciphertext",ciphertext)
                conn.send(pickle.dumps([nonce,ciphertext,tag]))
                print("End of comunication !")
                break
            else:
                nonce, ciphertext, tag=AES.encrypt(K,plaintext)
                print("Ciphertext",ciphertext)
                conn.send(pickle.dumps([nonce,ciphertext,tag]))

    

if __name__=="__main__":
    server()