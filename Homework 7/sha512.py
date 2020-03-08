#!/usr/bin/env python3
import sys
from BitVector import *

#Round constants
K = ["428a2f98d728ae22", "7137449123ef65cd", "b5c0fbcfec4d3b2f", "e9b5dba58189dbbc",
"3956c25bf348b538", "59f111f1b605d019", "923f82a4af194f9b", "ab1c5ed5da6d8118",
"d807aa98a3030242", "12835b0145706fbe", "243185be4ee4b28c", "550c7dc3d5ffb4e2",
"72be5d74f27b896f", "80deb1fe3b1696b1", "9bdc06a725c71235", "c19bf174cf692694",
"e49b69c19ef14ad2", "efbe4786384f25e3", "0fc19dc68b8cd5b5", "240ca1cc77ac9c65",
"2de92c6f592b0275", "4a7484aa6ea6e483", "5cb0a9dcbd41fbd4", "76f988da831153b5",
"983e5152ee66dfab", "a831c66d2db43210", "b00327c898fb213f", "bf597fc7beef0ee4",
"c6e00bf33da88fc2", "d5a79147930aa725", "06ca6351e003826f", "142929670a0e6e70",
"27b70a8546d22ffc", "2e1b21385c26c926", "4d2c6dfc5ac42aed", "53380d139d95b3df",
"650a73548baf63de", "766a0abb3c77b2a8", "81c2c92e47edaee6", "92722c851482353b",
"a2bfe8a14cf10364", "a81a664bbc423001", "c24b8b70d0f89791", "c76c51a30654be30",
"d192e819d6ef5218", "d69906245565a910", "f40e35855771202a", "106aa07032bbd1b8",
"19a4c116b8d2d0c8", "1e376c085141ab53", "2748774cdf8eeb99", "34b0bcb5e19b48a8",
"391c0cb3c5c95a63", "4ed8aa4ae3418acb", "5b9cca4f7763e373", "682e6ff3d6b2b8a3",
"748f82ee5defb2fc", "78a5636f43172f60", "84c87814a1f0ab72", "8cc702081a6439ec",
"90befffa23631e28", "a4506cebde82bde9", "bef9a3f7b2c67915", "c67178f2e372532b",
"ca273eceea26619c", "d186b8c721c0c207", "eada7dd6cde0eb1e", "f57d4f7fee6ed178",
"06f067aa72176fba", "0a637dc5a2c898a6", "113f9804bef90dae", "1b710b35131c471b",
"28db77f523047d84", "32caab7b40c72493", "3c9ebe0a15c9bebc", "431d67c49c100d4c",
"4cc5d4becb3e42b6", "597f299cfc657e2a", "5fcb6fab3ad6faec", "6c44198c4a475817"]

BLOCK_SIZE = 1024
LENGTH_SIZE = 128
WORD_SIZE = 64
LEN_SCHEDULE = 80
MOD_64 = 0xFFFFFFFFFFFFFFFF

def sha512(input_file, output_file):
    # Initialize hash buffer registers
    h0 = BitVector(hexstring="6a09e667f3bcc908")
    h1 = BitVector(hexstring="bb67ae8584caa73b")
    h2 = BitVector(hexstring="3c6ef372fe94f82b")
    h3 = BitVector(hexstring="a54ff53a5f1d36f1")
    h4 = BitVector(hexstring="510e527fade682d1")
    h5 = BitVector(hexstring="9b05688c2b3e6c1f")
    h6 = BitVector(hexstring="1f83d9abfb41bd6b")
    h7 = BitVector(hexstring="5be0cd19137e2179")

    #Generate bitvectors from round constants
    K_bv = [BitVector(hexstring=k_constant) for k_constant in K]

    #Open file and add requitite padding
    with open(input_file, mode='r') as input_file_pointer:
        message = input_file_pointer.read()
    input_file_pointer.close()

    #Pad input message so length is integer multiple of block size, padding accounts that
    #last 128 bits of message contain length.
    message_bv = BitVector(textstring=message)
    message_length = message_bv.length()
    m_1_bv = message_bv + BitVector(bitstring="1") #Add 1
    m_1_bv_len = m_1_bv.length()
    num_zeroes = ((BLOCK_SIZE - LENGTH_SIZE) - m_1_bv_len) % BLOCK_SIZE #Determine number of zeroes to add.
    zero_bv = BitVector(intVal=0, size=num_zeroes)
    m_1_bv += zero_bv
    length_bv = BitVector(intVal=message_length, size=LENGTH_SIZE)
    final_message = m_1_bv + length_bv


    message_schedule = [None] *  LEN_SCHEDULE #Create 80 word 64-bit schedule
    for n in range(0, final_message.length(), BLOCK_SIZE): #For each 1024 bit block
        #Generate Message Schedule
        segment = final_message[n:n+BLOCK_SIZE] #Get 1024 bit segment
        message_schedule[0:16] = [segment[j:j+WORD_SIZE] for j in range(0,BLOCK_SIZE,WORD_SIZE)] #First 16 words are directly from message

        #Perform word expansion
        for i in range(16,LEN_SCHEDULE):
            word_i_15 = message_schedule[i - 15]
            word_i_2 = message_schedule[i-2]
            sigma_0 = (word_i_15.deep_copy() >> 1) ^ (word_i_15.deep_copy() >> 8) ^ (word_i_15.deep_copy().shift_right(7))
            sigma_1 = (word_i_2.deep_copy() >> 19) ^ (word_i_2.deep_copy() >> 61) ^ (word_i_2.deep_copy().shift_right(6))
            message_schedule[i] = BitVector(intVal=(int(message_schedule[i-16]) + int(sigma_0) + int(message_schedule[i-7]) + int(sigma_1)) & MOD_64, size=WORD_SIZE)

        #Get hash buffer form perious message block
        a, b, c, d, e, f, g, h = h0, h1, h2, h3, h4, h5, h6, h7

        #Perform round based processing for 80 rounds.
        for i in range(LEN_SCHEDULE):
            ch = (e & f) ^ ((~e) & g)
            maj = (a & b) ^ (a & c) ^ (b & c)
            sum_a = (a.deep_copy() >> 28) ^ (a.deep_copy() >> 34) ^ (a.deep_copy() >> 39)
            sum_e = (e.deep_copy() >> 14) ^ (e.deep_copy() >> 18) ^ (e.deep_copy() >> 41)
            t1 = BitVector(intVal=((int(h) + int(ch) + int(sum_e) + int(message_schedule[i]) + int(K_bv[i])) & MOD_64), size=WORD_SIZE)
            t2 = BitVector(intVal=((int(sum_a) + int(maj)) & MOD_64), size=WORD_SIZE)
            h = g
            g = f
            f = e
            e = BitVector(intVal=(int(d) + int(t1)) & MOD_64, size=WORD_SIZE)
            d = c
            c = b
            b = a
            a = BitVector(intVal=(int(t1) + int(t2)) & MOD_64, size=WORD_SIZE)

        #After 80th round output is added to the content of the hash buffer at beginning of message
        h0 = BitVector(intVal=(int(h0) + int(a)) & MOD_64, size=WORD_SIZE)
        h1 = BitVector(intVal=(int(h1) + int(b)) & MOD_64, size=WORD_SIZE)
        h2 = BitVector(intVal=(int(h2) + int(c)) & MOD_64, size=WORD_SIZE)
        h3 = BitVector(intVal=(int(h3) + int(d)) & MOD_64, size=WORD_SIZE)
        h4 = BitVector(intVal=(int(h4) + int(e)) & MOD_64, size=WORD_SIZE)
        h5 = BitVector(intVal=(int(h5) + int(f)) & MOD_64, size=WORD_SIZE)
        h6 = BitVector(intVal=(int(h6) + int(g)) & MOD_64, size=WORD_SIZE)
        h7 = BitVector(intVal=(int(h7) + int(h)) & MOD_64, size=WORD_SIZE)

    #Add elements of hash buffer to obtain 1024bit message digest for segment
    message_hash = h0 + h1 + h2 + h3 + h4 + h5 + h6 + h7

    #Write contents to output file
    output_file_pointer = open(output_file, mode='w')
    message_hash_hex = message_hash.getHexStringFromBitVector()
    output_file_pointer.write(message_hash_hex)
    output_file_pointer.close()

    return

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Incorrect number of Arguments")
        exit(1)
    input_file = sys.argv[1]
    output_file = sys.argv[2]
    sha512(input_file, output_file)