import os
import pickle
import configobj
from Crypto.Util.number import getPrime,getRandomInteger
from Crypto.Random import get_random_bytes

config = configobj.ConfigObj('path.b')
path=config['PG_FILE']
SIZE_P_G=1024
SIZE_PUBLIC_KEY=512
"""
Funzione che ritorna un numero primo p che ha una dimensione in bit 
uguale a quella del parametro dato in input e un intero g compreso 
tra 1 e p
"""
def create_p_g():
    while True:
        p=getPrime(SIZE_P_G, randfunc=get_random_bytes)
        if p !=0:
            break

    while True:
        g=getRandomInteger(SIZE_P_G,randfunc=get_random_bytes)
        if g>=1 and g<=p and g.bit_length()==1024:
            break

    parameters={"p":p,"g":g}
    with open(path, 'wb') as handle:
        pickle.dump(parameters, handle, protocol=pickle.HIGHEST_PROTOCOL)

def upload_p_g():
    with open(path, 'rb') as handle:
        data = pickle.load(handle)
    p=data['p']
    g=data['g']
    return p,g

# Exponential Squaring (Fast Modulo Multiplication) (quadra e moltiplica)
def exponentiation(bas, exp,N):
	if (exp == 0):
		return 1
	if (exp == 1):
		return bas % N
	
	t = exponentiation(bas, int(exp / 2),N)
	t = (t * t) % N
	
	# if exponent is
	# even value
	if (exp % 2 == 0):
		return t
		
	# if exponent is
	# odd value
	else:
		return ((bas % N) * t) % N

"""
Funzione che calcola la chiave privata
scegliendo un intero a compreso tra 1 e p-1 
e a partire da quest'ultima la chiave pubblica.
"""
def create_private_key(p,g):
    while True:
        private_key=getRandomInteger(SIZE_PUBLIC_KEY)
        if(private_key >=1 and private_key <= p-1):
            break
    return private_key
 

def create_public_key(g,p,a):
    public_key=exponentiation(g,a,p)
    #public_key=(g**a) % p
    return public_key

def create_shared_key(x,y,p):
    shared_key=exponentiation(x,y,p)
    #shared_key=(x ** y) % p
    return shared_key


