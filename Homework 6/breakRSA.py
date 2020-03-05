#!/usr/bin/env python3
import sys
import numpy as np
from BitVector import *
from solve_pRoot_BST import solve_pRoot
from PrimeGenerator import PrimeGenerator

BLOCK_SIZE = 128 #Message Block Size
e = 3

def encrypt(message_file, enc_file_1, enc_file_2, enc_file_3, n_file):
    #Initialize prime number generator
    p_g = PrimeGenerator(bits=128)

    # Determine integers p,q for file 1
    p_1 = 0
    q_1 = 0  # set equal so condition is false.
    while (not check_conditions(int(p_1), int(q_1))):
        p_1 = p_g.findPrime()
        q_1 = p_g.findPrime()
    # Determine Modulus
    modulus_1 = p_1 * q_1

    # Determine integers p,q for file 2
    p_2 = 0
    q_2 = 0  # set equal so condition is false.
    while (not check_conditions(int(p_2), int(q_2))):
        p_2 = p_g.findPrime()
        q_2 = p_g.findPrime()
    # Determine Modulus
    modulus_2 = p_2 * q_2

    # Determine integers p,q for file 3
    p_3 = 0
    q_3 = 0  # set equal so condition is false.
    while (not check_conditions(int(p_3), int(q_3))):
        p_3 = p_g.findPrime()
        q_3 = p_g.findPrime()
    # Determine Modulus
    modulus_3 = p_3 * q_3

    # Read message and split into 128 bit blocks
    message_bv = BitVector(filename=message_file)
    # message_fp = open(file=message_file, mode='r')
    # test = BitVector(textstring=message_fp.read())
    # print(test.int_val())

    # Encrypted Bitvector
    encrypted_bv_1 = BitVector(size=0)
    encrypted_bv_2 = BitVector(size=0)
    encrypted_bv_3 = BitVector(size=0)

    while (message_bv.more_to_read):
        # Obtain segment
        message_bv_segment = message_bv.read_bits_from_file(BLOCK_SIZE)

        # Pad read bits with 0's when block size
        if message_bv_segment.size < BLOCK_SIZE:
            message_bv_segment.pad_from_right(BLOCK_SIZE - len(message_bv_segment))

        # Append 128 zero bits
        message_bv_segment.pad_from_left(BLOCK_SIZE)
        message_int = message_bv_segment.int_val()

        # Perform fast exponentiation for file 1
        result = exponentiate(message_int, e, modulus_1)  # Remember its A^B modulo n
        result_bv = BitVector(intVal=result, size=BLOCK_SIZE * 2)
        encrypted_bv_1 += result_bv

        # Perform fast exponentiation for file 2
        result = exponentiate(message_int, e, modulus_2)  # Remember its A^B modulo n
        result_bv = BitVector(intVal=result, size=BLOCK_SIZE * 2)
        encrypted_bv_2 += result_bv

        # Perform fast exponentiation for file 2
        result = exponentiate(message_int, e, modulus_3)  # Remember its A^B modulo n
        result_bv = BitVector(intVal=result, size=BLOCK_SIZE * 2)
        encrypted_bv_3 += result_bv

    #Write to file 1
    encrypted_file_pointer_1 = open(file=enc_file_1, mode='w')
    encrypted_hex_string = encrypted_bv_1.get_bitvector_in_hex()
    encrypted_file_pointer_1.write(encrypted_hex_string)
    encrypted_file_pointer_1.close()

    # Write to file 2
    encrypted_file_pointer_2 = open(file=enc_file_2, mode='w')
    encrypted_hex_string = encrypted_bv_2.get_bitvector_in_hex()
    encrypted_file_pointer_2.write(encrypted_hex_string)
    encrypted_file_pointer_2.close()

    # Write to file 3
    encrypted_file_pointer_3 = open(file=enc_file_3, mode='w')
    encrypted_hex_string = encrypted_bv_3.get_bitvector_in_hex()
    encrypted_file_pointer_3.write(encrypted_hex_string)
    encrypted_file_pointer_3.close()

    #Write moduli to file n
    n_file_pointer = open(file=n_file, mode='w')
    n_file_pointer.writelines([str(modulus_1), "\n", str(modulus_2), "\n", str(modulus_3), "\n"])
    n_file_pointer.close()

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

def exponentiate(A,B,n):
    result = 1
    while B > 0:
        if B & 1:
            result = (result * A) % n
        B = B >> 1
        A = (A * A) % n

    return result


def crack_rsa(enc_file_1, enc_file_2, enc_file_3, n_file, cracked_file):
    #Read public keys 1,2,3
    n_file_pointer = open(file=n_file, mode='r')
    n_1 = int(n_file_pointer.readline())
    n_2 = int(n_file_pointer.readline())
    n_3 = int(n_file_pointer.readline())
    n_file_pointer.close()

    #Read encrypted files
    enc_file_1_pointer = open(file=enc_file_1, mode='r')
    enc_file_1_bv = BitVector(hexstring=enc_file_1_pointer.read())  # Assume conversion from hexstring to bitvector
    enc_file_1_pointer.close()
    enc_file_2_pointer = open(file=enc_file_2, mode='r')
    enc_file_2_bv = BitVector(hexstring=enc_file_2_pointer.read())  # Assume conversion from hexstring to bitvector
    enc_file_2_pointer.close()
    enc_file_3_pointer = open(file=enc_file_3, mode='r')
    enc_file_3_bv = BitVector(hexstring=enc_file_3_pointer.read())  # Assume conversion from hexstring to bitvector
    enc_file_3_pointer.close()


    #Split files into 256 bit blocks
    enc_file_1_bv_split = [enc_file_1_bv[i * BLOCK_SIZE * 2:(i + 1) * BLOCK_SIZE * 2] for i in range((len(enc_file_1_bv) // (BLOCK_SIZE * 2)))]  # Check if correct
    enc_file_2_bv_split = [enc_file_2_bv[i * BLOCK_SIZE * 2:(i + 1) * BLOCK_SIZE * 2] for i in range((len(enc_file_2_bv) // (BLOCK_SIZE * 2)))]  # Check if correct
    enc_file_3_bv_split = [enc_file_3_bv[i * BLOCK_SIZE * 2:(i + 1) * BLOCK_SIZE * 2] for i in range((len(enc_file_3_bv) // (BLOCK_SIZE * 2)))]  # Check if correct

    # Assuming n's are pairwise coprime we can use CRT as follows
    n_1_bv = BitVector(intVal=n_1, size=256)
    n_2_bv = BitVector(intVal=n_2, size=256)
    n_3_bv = BitVector(intVal=n_3, size=256)
    m_1 = n_2 * n_3
    m_2 = n_1 * n_3
    m_3 = n_1 * n_2
    n_2_3 = BitVector(intVal=m_1, size=512)
    t_1_inv = n_2_3.multiplicative_inverse(n_1_bv)
    n_1_3 = BitVector(intVal=m_2, size=512)
    t_2_inv = n_1_3.multiplicative_inverse(n_2_bv)
    n_1_2 = BitVector(intVal=m_3, size=512)
    t_3_inv = n_1_2.multiplicative_inverse(n_3_bv)

    message_bv = BitVector(size=0)

    index = 0
    while(index < len(enc_file_1_bv_split)):
        enc_file_1_bv_segment = enc_file_1_bv_split[index]
        enc_file_2_bv_segment = enc_file_2_bv_split[index]
        enc_file_3_bv_segment = enc_file_3_bv_split[index]
        #Calculate first term
        t_1 = enc_file_1_bv_segment.int_val()*(m_1)*t_1_inv.int_val()
        #Calculate second term
        t_2 = enc_file_2_bv_segment.int_val() * (m_2) * t_2_inv.int_val()
        # Calculate third term
        t_3 = enc_file_3_bv_segment.int_val() * (m_3) * t_3_inv.int_val()
        #Use Chinese Remainer Theorem to calculate sum of terms modulo n1*n2*n3
        segment_message_moduli = (t_1+t_2+t_3) % (n_1*n_2*n_3)
        #Take cube root of result
        segment_message = solve_pRoot(p=3, x=segment_message_moduli)
        segment_message_bv = BitVector(intVal=segment_message, size=256)
        segment_message_bv = segment_message_bv[128:256] #Remove padding.
        message_bv += segment_message_bv
        index += 1

    #Write Bitvector to file
    messsage_hex = message_bv.get_hex_string_from_bitvector()
    # Removing Null characters
    while (messsage_hex[-2:] == "00"): #Obtain last two characters
        messsage_hex = messsage_hex[:-2] #Remove them
    message_string = BitVector(hexstring=messsage_hex).get_text_from_bitvector()
    cracked_file_pointer = open(file=cracked_file, mode='w')
    cracked_file_pointer.write(message_string)
    cracked_file_pointer.close()

    return

if __name__ == "__main__":
    if sys.argv[1] == '-e':
        if len(sys.argv) != 7:
            print("Incorrect number of Arguments")
            exit(1)
        message_file = sys.argv[2]
        enc_file_1 = sys.argv[3]
        enc_file_2 = sys.argv[4]
        enc_file_3 = sys.argv[5]
        n_file = sys.argv[6]
        encrypt(message_file, enc_file_1, enc_file_2, enc_file_3, n_file)
    elif sys.argv[1] == '-c':
        if len(sys.argv) != 7:
            print("Incorrect number of Arguments")
            exit(1)
        enc_file_1 = sys.argv[2]
        enc_file_2 = sys.argv[3]
        enc_file_3 = sys.argv[4]
        n_file = sys.argv[5]
        cracked_file = sys.argv[6]
        crack_rsa(enc_file_1, enc_file_2, enc_file_3, n_file, cracked_file)
    else:
        print("Incorrect Generate/Encryption/Decryption Option.")
        exit(1)
