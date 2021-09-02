from tkinter import *
import socket
import pickle
import diffie_hellman as dh
import encrypt_decrypt_message as edm
import AES

p=None 
g=None
a=None
A=None
B=None
K=None

def set_p_g_parmeters():
    global p,g
    p,g=dh.upload_p_g()

def print_parameters():
    print("Client:")
    print("p:",p)
    print("g:",g)
    print("p bit size:",p.bit_length())
    print("g bit size:",g.bit_length())

def client():
    global a,A,B,K
    print("===================================================")
    print("********* CLIENT *********")
    print("===================================================")
    print("Upload p and parameters...")
    set_p_g_parmeters()
    print_parameters()
    a=dh.create_private_key(p,g)
    print("Private Key", a)
    A=dh.create_public_key(g,p,a)
    print("Public Key",A)
    host = socket.gethostname()
    port = 5000
    client_socket = socket.socket()
    client_socket.connect((host, port))
    print("Send to server Public Key")
    client_socket.send(str(A).encode())
    while True:
        B = client_socket.recv(512).decode()
        B = int (B)
        print("I received:",B)
        break
    K=dh.create_shared_key(B,a,p)
    print("Shared Key",hex(K))
    K=AES.apply_sha256(K)
    print("Shared Key",K)
    win = create_window(str(K),True)
    #win.mainloop()

    while(True):
        plaintext=input("Insert the message to send--->")
        nonce, ciphertext, tag=AES.encrypt(K,plaintext)
        print("Ciphertext",ciphertext)
        client_socket.send(pickle.dumps([nonce,ciphertext,tag]))
        if plaintext == "Bye":
            print("Comunication finished.")
            win = create_window(str(K),False)
            win.mainloop()
            break
            
        print("Waiting for a message...")
        data = client_socket.recv(1000000)
        aes_data = pickle.loads(data)
        print("I recivied:",aes_data[1])
        plaintext = AES.decrypt(aes_data[0],aes_data[1],aes_data[2],K)
        print("Plaintext:",plaintext)
        if (plaintext=="Bye"):
            print("Comunication finished")
            win = create_window(str(K),False)
            win.mainloop()
            break
    print("End !")


def create_window(k,flag):

# Create an instance of tkinter frame
    win= Tk()
    win.title("DH - AES 256")
    win.resizable(False, False)
    #win.configure(background="white")
    win.geometry("1000x350")
    frame= Frame(win, relief= 'sunken')
    frame.grid(sticky= "we")

    # Make the frame sticky for every case
    frame.grid_rowconfigure(0, weight=1)
    frame.grid_columnconfigure(0, weight=1)

    # Make the window sticky for every case
    win.grid_rowconfigure(0, weight=1)
    win.grid_columnconfigure(0, weight=1)
    if flag:
        label= Label(frame, text= "Shared Key: " + "\n"+ str(k),
        font=('Helvetica 20 bold'), bg= "grey")
    else:
        label= Label(frame, text= "End of comunication !",
        font=('Helvetica 20 bold'), bg= "grey")
    label.grid(row=3,column=0)
    label.grid_rowconfigure(1, weight=1)
    label.grid_columnconfigure(1, weight=1)
    return win 

if __name__=="__main__":
    client()