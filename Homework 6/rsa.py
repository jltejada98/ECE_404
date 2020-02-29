#!/usr/bin/env python3
import sys
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
    #Open P file
    p_file_pointer = open(file=p_file, mode='r')
    p = int(p_file_pointer.read())
    p_file_pointer.close()

    #Open Q file
    q_file_pointer = open(file=q_file, mode='r')
    q = int(q_file_pointer.read())
    q_file_pointer.close()

    #Determine Modulus
    modulus = p*q

    #Read message and split into 128 bit blocks
    message_bv = BitVector(filename=message_file)

    #Encrypted Bitvector
    encrypted_bv = BitVector(size=0)

    while(message_bv.more_to_read):
        #Obtain segment
        message_bv_segment = message_bv.read_bits_from_file(BLOCK_SIZE)

        # Pad read bits with 0's when block size
        if message_bv_segment.size < BLOCK_SIZE:
            message_bv_segment.pad_from_right(BLOCK_SIZE - len(message_bv_segment))

        #Append 128 zero bits
        message_bv_segment.pad_from_left(BLOCK_SIZE)
        message_int = message_bv_segment.int_val()

        #Perform fast exponentiation
        result = exponentiate(message_int,e,modulus) #Remember its A^B modulo n
        result_bv = BitVector(intVal=result, size=BLOCK_SIZE*2)
        encrypted_bv += result_bv

    #Write to file
    encrypted_file_pointer = open(file=encrypted_file, mode='w')
    encrypted_hex_string = encrypted_bv.get_bitvector_in_hex()
    encrypted_file_pointer.write(encrypted_hex_string)
    encrypted_file_pointer.close()

    return


def exponentiate(A,B,n):
    result = 1
    while B > 0:
        if B & 1:
            result = (result * A) % n
        B = B >> 1
        A = (A * A) % n

    return result

def decrypt(encrypted_file, p_file, q_file, decrypted_file):
    # Open P file
    p_file_pointer = open(file=p_file, mode='r')
    p = int(p_file_pointer.read())
    p_file_pointer.close()

    # Open Q file
    q_file_pointer = open(file=q_file, mode='r')
    q = int(q_file_pointer.read())
    q_file_pointer.close()

    # Compute d
    modulus = p * q
    totient = (p - 1) * (q - 1)
    totient_bv = BitVector(intVal=totient, size=256)
    e_bv = BitVector(intVal=e, size=256)
    d_bv = e_bv.multiplicative_inverse(totient_bv)
    d = d_bv.int_val()

    #Open encrypted file
    encrypted_file_pointer = open(file=encrypted_file, mode='r')
    encrypted_bv = BitVector(hexstring=encrypted_file_pointer.read())  # Assume conversion from hexstring to bitvector

    #Split encrypted message into 256 bit blocks
    encrypted_bv_split = [encrypted_bv[i * BLOCK_SIZE * 2:(i + 1) * BLOCK_SIZE * 2] for i in range((len(encrypted_bv) // (BLOCK_SIZE* 2)))]  # Check if correct

    #Notes:
    #Encyrpted text is being read correctly.

    decrypted_file_pointer = open(file=decrypted_file, mode='w')
    #Decrypted bitvector
    decrypted_bv = BitVector(size=0)
    for encrypted_bv_segment in encrypted_bv_split:
        # Perform fast exponentiation
        encrypted_message_int = encrypted_bv_segment.int_val()
        result = exponentiate(encrypted_message_int, d, modulus)  # Remember its A^B modulo n
        result_bv = BitVector(intVal=result, size=BLOCK_SIZE*2)
        result_bv = result_bv[128:256]
        decrypted_bv += result_bv
    # Write to file
    decrypted_hex = decrypted_bv.get_hex_string_from_bitvector()
    #Removing Null characters
    while(decrypted_hex[-2:] == "00"):
        decrypted_hex = decrypted_hex[:-2]
    decrypted_string = BitVector(hexstring=decrypted_hex).get_text_from_bitvector()
    decrypted_file_pointer.write(decrypted_string)
    decrypted_file_pointer.close()

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
        if len(sys.argv) != 6:
            print("Incorrect number of Arguments")
            exit(1)
        message_file = sys.argv[2]
        p_file = sys.argv[3]
        q_file = sys.argv[4]
        encrypted_file = sys.argv[5]
        encrypt(message_file, p_file, q_file, encrypted_file)
    elif sys.argv[1] == '-d':
        if len(sys.argv) != 6:
            print("Incorrect number of Arguments")
            exit(1)
        encrypted_file = sys.argv[2]
        p_file = sys.argv[3]
        q_file = sys.argv[4]
        decrypted_file = sys.argv[5]
        decrypt(encrypted_file, p_file, q_file, decrypted_file)

    else:
        print("Incorrect Generate/Encryption/Decryption Option.")
        exit(1)
