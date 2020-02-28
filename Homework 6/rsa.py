#!/usr/bin/env python3
from BitVector import *
from PrimeGenerator import PrimeGenerator

BLOCK_SIZE = 128 #Message Block Size
e = 65537

def generate(p_file, q_file):
    #Determine integers p,q
    p = 0
    q = 0 #set equal so condition is false.
    p_g = PrimeGenerator(bits=128)
    while(not check_conditions(int(p),int(q))):
        p = p_g.findPrime()
        q = p_g.findPrime()

    #Save P into file
    p_file_pointer = open(file=p_file, mode='w')
    p_file_pointer.write(str(p))
    p_file_pointer.close()
    #Save Q into file
    q_file_pointer = open(file=q_file, mode='w')
    q_file_pointer.write(str(q))
    q_file_pointer.close()
    return

def bgcd(a,b): #Taken from lecture notes By: Avinash Kak
    if a == b: return a                                         #(A)
    if a == 0: return b                                         #(B)
    if b == 0: return a                                         #(C)
    if (~a & 1):                                                #(D)
        if (b &1):                                              #(E)
            return bgcd(a >> 1, b)                              #(F)
        else:                                                   #(G)
            return bgcd(a >> 1, b >> 1) << 1                    #(H)
    if (~b & 1):                                                #(I)
        return bgcd(a, b >> 1)                                  #(J)
    if (a > b):                                                 #(K)
        return bgcd( (a-b) >> 1, b)                             #(L)
    return bgcd( (b-a) >> 1, a )

def check_conditions(p,q):
    # Check if P==Q
    if (p == q):
        return False
    # Check leftmost bits
    bv_p = BitVector(intVal=p, size=128)
    if (bv_p[0] != 1 and bv_p[1] != 1):
        return False
    bv_q = BitVector(intVal=q, size=128)
    if (bv_q[0] != 1 and bv_q[1] != 1):
        return False
    #Check if (p − 1) and (q − 1) should be co-prime to e
    if(bgcd(p-1, e) != 1):
        return False
    if (bgcd(q - 1, e) != 1):
        return False
    return True

def encrypt(message_file, p_file, q_file, encrypted_file):



    return

def decrypt(encrypted_file, p_file, q_file, decrypted_file):

    return


if __name__ == "__main__":
    if sys.argv[1] == '-g':
        if len(sys.argv) != 4:
            print("Incorrect number of Arguments")
            exit(1)
        p_file = sys.argv[2]
        q_file = sys.argv[3]
        generate(p_file, q_file)
    elif sys.argv[1] == '-e':
        if len(sys.argv) != 5:
            print("Incorrect number of Arguments")
            exit(1)
        message_file = sys.argv[2]
        p_file = sys.argv[3]
        q_file = sys.argv[4]
        encrypted_file = sys.argv[5]
        encrypt(message_file, p_file, q_file, encrypted_file)
    elif sys.argv[1] == '-d':
        if len(sys.argv) != 5:
            print("Incorrect number of Arguments")
            exit(1)

    else:
        print("Incorrect Generate/Encryption/Decryption Option.")
        exit(1)
