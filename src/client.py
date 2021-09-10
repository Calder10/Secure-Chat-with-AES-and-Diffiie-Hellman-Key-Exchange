"""
Università degli Studi Di Palermo
Corso di Laurea Magistrale in Informatica
Anno Accademico 2020/2021
Cybersecurity
@author:Salvatore Calderaro
DH-AES256 - Chatter
"""

from tkinter import *
from time import sleep 
import threading
import os
import socket
import pickle
import diffie_hellman as dh
import configobj
import AES


p=None 
g=None
a=None
A=None
B=None
K=None
name = "Salvatore"
user = None
edit_text=None
listbox=None
root=None
scrollbar=None
host=None
port=None
client_socket=None

"""
Funzionw per il settaggio dei parametri p e g.
"""
def set_p_g_parmeters(parameters):
    global p,g
    p=parameters[0]
    g=parameters[1]

"""
Funzione per il print dei parametri.
"""
def print_parameters():
    print("Client:")
    print("p:",p)
    print("g:",g)
    print("p bit size:",p.bit_length())
    print("g bit size:",g.bit_length())

"""
Funzione per la creazione della socket
"""
def create_client_socket():
    global host,port,client_socket
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))

"""
Funzione per l'inizializzazione della comunicazione
"""
def init_comm():
    global a,A,B,K,user
    print("===================================================")
    print("********* CLIENT *********")
    print("===================================================")
    create_client_socket()
    parameters=dh.create_p_g()
    set_p_g_parmeters(parameters)
    print("Send to Server p,g;")
    print_parameters()
    client_socket.send(pickle.dumps(parameters))
    a=dh.create_private_key(p,g)
    print("Private Key", a)
    A=dh.create_public_key(g,p,a)
    print("Public Key",A)
    print("Sending Public Key")
    client_socket.send(str(A).encode())
    while True:
        print("Waiting the server public key:")
        B = client_socket.recv(512).decode()
        B = int (B)
        print("I recivied:",B)
        user=client_socket.recv(512).decode()
        print("I recivied:",user)
        break
    K=dh.create_shared_key(B,a,p)
    print("Shared Key",K)
    K=AES.apply_sha256(K)
    print("Shared Key (Byte)",K)

"""
Funzione per l'invio dei messaggi
"""
def send():
    global client_socket,scrollbar,root
    nonce, ciphertext, tag=AES.encrypt(K,edit_text.get())
    print("Ciphertext",ciphertext)
    client_socket.send(pickle.dumps([nonce,ciphertext,tag]))
    listbox.insert(END, name+":")
    listbox.insert(END, "Plaintext: "+ edit_text.get())
    listbox.insert(END, "Ciphertext: "+ str(ciphertext))
    listbox.see('end')
    if edit_text.get() == "Bye":
        edit_text.delete(0, END)
        print("End of comunication !")
        listbox.insert(END, "Fine comunicazione, chiudi la finestra !")
        listbox.insert(END, "*****************************************************")
        listbox.see('end')
        sleep(5)
        root.destroy()
    else:
        edit_text.delete(0, END)
        listbox.insert(END, "*****************************************************")
        listbox.see('end')

"""
Funzione per la ricezione dei messaggi
"""
def recv():
    global root,scrollbar,client_socket
    while True:
        data = client_socket.recv(1000000)
        try:
            aes_data = pickle.loads(data)
        except:
            break
        print("I recivied:",aes_data[1])
        plaintext = AES.decrypt(aes_data[0],aes_data[1],aes_data[2],K)
        print("Plaintext:",plaintext)
        listbox.insert(END, user+":")
        listbox.insert(END, "Ciphertext: "+ str(aes_data[1]))
        listbox.insert(END, "Plaintext: "+ plaintext)
        listbox.insert(END, "*****************************************************")
        edit_text.delete(0, END)
        listbox.see('end')
        if plaintext == "Bye":
            print("End of comunication !")
            listbox.insert(END, "Fine comunicazione, chiudi la finestra !")
            listbox.see('end')
            break

"""
Funzione per la gestione della gui
"""      
def client_gui():
    global edit_text,listbox,root
    root = Tk()
    init_comm()
    shared_key_label = Label(root, text="Shared key"+ "\n"+str(K))
    shared_key_label.pack(fill=X, side=TOP)
    scrollbar = Scrollbar(root)
    scrollbar.pack(side=RIGHT, fill=Y)
    listbox = Listbox(root, yscrollcommand=scrollbar.set)
    listbox.pack(fill=BOTH, side=TOP)
    scrollbar.config(command=listbox.yview)
    button = Button(root, text="Send Message", command=send, bg='#4040bf')
    button.pack(fill=X, side=BOTTOM)
    edit_text = Entry(root)
    edit_text.pack(fill=X, side=BOTTOM)
    root.title("DH - AES 256 Chatter")
    root.geometry()
    root.resizable(width=False, height=False)
    threading.Thread(target=recv).start()
    root.mainloop()

if __name__=="__main__":
    client_gui()