"""
Università degli Studi Di Palermo
Corso di Laurea Magistrale in Informatica
Anno Accademico 2020/2021
Cybersecurity
@author: Salvatore Calderaro
DH-AES256 - Chatter
"""
import socket
from random import randint,choice
import pickle
from lorem_text import lorem
import diffie_hellman as dh
import AES

p=None 
g=None
b=None
A=None
B=None
K=None
name=None
host=None
port=None
server_socket=None
conn=None
address=None

"""
Funzione per la creazione della socket
"""
def create_server_socket():
    global host,port,server_socket,conn,address
    host = socket.gethostname()
    port = 5000 
    server_socket = socket.socket()
    server_socket.bind((host,port))
    server_socket.listen(1)
    conn, address = server_socket.accept() 

"""
Funzione per il settaggio dei parametri p e g,
"""
def set_p_g_parmeters(parameters):
    global p,g
    p=parameters[0]
    g=parameters[1]

"""
Funzione per la stampa dei parametri p e g
"""
def print_parameters():
    print("Server:")
    print("p:",p)
    print("g:",g)
    print("p bit size:",p.bit_length())
    print("g bit size:",g.bit_length())

"""
Funzione per la creazione di un testo random.
"""
def create_random_text():
    s=randint(0,5)
    if(s==0):
        text="Bye"
    else:
        text=lorem.sentence()
    return text

"""
Funzione per l'inizializzazione della comunicazione
"""
def init_comm():
    global b,A,B,K,name
    names=["Alice","Bob","Claudia","Giuseppe"]
    print("===================================================")
    print("********* SERVER *********")
    print("===================================================")
    create_server_socket()
    while True:
        print("Waiting p,g from Client...")
        data = conn.recv(2048)
        parameters = pickle.loads(data)
        print("I recivied:")
        set_p_g_parmeters(parameters)
        print_parameters()
        break
    b=dh.create_private_key(p,g)
    print("Private Key", b)
    B=dh.create_public_key(g,p,b)
    print("Public Key",B)
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
    print("Shared Key",K)
    K=AES.apply_sha256(K)
    print("Shared Key (Byte)",K)

"""
Funzione per la gestione dell'invio/ricezione dei messaggi.
"""
def comm():
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
            plaintext=create_random_text()
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

    
def server():
    init_comm()
    comm()

if __name__=="__main__":
    server()