"""
Università degli Studi Di Palermo
Corso di Laurea Magistrale in Informatica
Anno Accademico 2020/2021
Cybersecurity
@author: Salvatore Calderaro
DH-AES256 - Chatter
"""

from Crypto.Util.number import getPrime,getRandomInteger
from Crypto.Random import get_random_bytes

SIZE_PG=1024
SIZE_PK=512

"""
Funzione che ritorna un numero primo p che ha una dimensione in bit 
uguale a quella del parametro dato in input e un intero g compreso 
tra 1 e p
"""
def create_p_g():
    while True:
        p=getPrime(SIZE_PG, randfunc=get_random_bytes)
        if p !=0:
            break

    while True:
        g=getRandomInteger(SIZE_PG,randfunc=get_random_bytes)
        if g>=1 and g<=p and g.bit_length()==SIZE_PG:
            break

    parameters=[p,g]
    return parameters


"""
Algorimto quadra e moltiplica
"""
def exponentiation(bas, exp,N):
	if (exp == 0):
		return 1
	if (exp == 1):
		return bas % N
	
	t = exponentiation(bas, int(exp / 2),N)
	t = (t * t) % N
	
	if (exp % 2 == 0):
		return t
	else:
		return ((bas % N) * t) % N

"""
Funzione che calcola la chiave privata
scegliendo un intero a compreso tra 1 e p-1 
e a partire da quest'ultima la chiave pubblica.
"""
def create_private_key(p):
    while True:
        private_key=getRandomInteger(SIZE_PK)
        if(private_key >=1 and private_key <= p-1):
            break
    return private_key
 
"""
Funzione per la creazione della chiave pubblica
"""
def create_public_key(g,p,a):
    public_key=exponentiation(g,a,p)
    return public_key
"""
Funzione per la creazione della chiave condivisa
"""
def create_shared_key(x,y,p):
    shared_key=exponentiation(x,y,p)
    return shared_key


