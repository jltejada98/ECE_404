#!/usr/bin/env python3

from BitVector import *
import sys

#AES irreducible polynomial equation
AES_modulus = BitVector(bitstring='100011011')
NUM_ROUNDS = 14 #Number of rounds corresponding to 256 bit key.


def encrypt(message_file, key_file, encrypted_file):
    #Read key file.
    key_file_pointer = open(file=key_file, mode='r')
    key_string = key_file_pointer.read()
    key_bv = BitVector(textstring=key_string)
    key_file_pointer.close()

    #Encryption Key Word Generation
    key_words = []
    byte_sub_table = generate_sub_bytes_table()
    key_words = gen_key_schedule_256(key_bv, byte_sub_table)

    #Obtain key schedule
    key_schedule = []
    for word_index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i * 8:i * 8 + 8].intValue())
        key_schedule.append(keyword_in_ints)

    #Produce round keys
    round_keys = [None for i in range(NUM_ROUNDS + 1)]
    for i in range(NUM_ROUNDS + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3]).get_bitvector_in_hex()

    # #Read input text file.
    message_bv = BitVector(filename=message_file)  # Assume conversion with textstring.

    encrypted_bv = BitVector(size=0)
    while(message_bv.more_to_read):
        # Obtain 128 bit Segment
        message_bv_segment = message_bv.read_bits_from_file(128)

        # Pad read bits with 0's when block size is not 128
        if message_bv_segment.size < 128:
            message_bv_segment.pad_from_right(128 - len(message_bv_segment))

        #Add first round key to message segment
        current_round_key = BitVector(hexstring=round_keys[0])
        message_bv_segment ^= current_round_key

        #Perform remaning rounds of encryption
        for i in range(1,NUM_ROUNDS):
            #Substitute bytes step.
            message_bv_segment = sub_bytes(message_bv_segment,byte_sub_table)
            #Shift Rows
            message_bv_segment = shift_rows(message_bv_segment)
            #Mix Collumns
            message_bv_segment = mix_collumns(message_bv_segment)
            #Add Round Key
            current_round_key = BitVector(hexstring=round_keys[i])
            message_bv_segment ^= current_round_key

        ##Last round of encryption
        # Substitute bytes step.
        message_bv_segment = sub_bytes(message_bv_segment,byte_sub_table)
        # Shift Rows
        message_bv_segment = shift_rows(message_bv_segment)
        # Add Round Key
        current_round_key = BitVector(hexstring=round_keys[14])
        message_bv_segment ^= current_round_key

        #Append encrypted message to bitvector
        encrypted_bv += message_bv_segment

    # Once finished reading, write bitvector to encrypted_ppm
    encrypted_file_pointer = open(file=encrypted_file, mode='w')
    encrypted_bv_hex_string = encrypted_bv.get_hex_string_from_bitvector()
    encrypted_file_pointer.write(encrypted_bv_hex_string)
    encrypted_file_pointer.close()# Close file

    return


def generate_sub_bytes_table():
    sub_bytes_table = list()
    c_char = BitVector(bitstring='01100011') #Corresponds to 'c' constant
    for i in range(0,256): #For each poossible bitpatern
        #Generate Substitution table for encryption
        a = BitVector(intVal=i, size=8).gf_MI(AES_modulus, 8) if i != 0 else BitVector(intVal=0)
        a1, a2, a3, a4 = [a.deep_copy() for x in range(4)]
        a ^= (a1 >> 4) ^ (a2 >> 5) ^ (a3 >> 6) ^ (a4 >> 7) ^ c_char
        sub_bytes_table.append(int(a))
    return  sub_bytes_table

def gen_key_schedule_256(key_bv, byte_sub_table):
    key_words = [None for i in range(60)]
    round_constant = BitVector(intVal=0x01, size=8)
    for i in range(8):
        key_words[i] = key_bv[i * 32: i * 32 + 32]
    for i in range(8, 60):
        if i % 8 == 0:
            kwd, round_constant = g_function(key_words[i - 1], round_constant, byte_sub_table)
            key_words[i] = key_words[i - 8] ^ kwd
        elif (i - (i // 8) * 8) < 4:
            key_words[i] = key_words[i - 8] ^ key_words[i - 1]
        elif (i - (i // 8) * 8) == 4:
            key_words[i] = BitVector(size=0)
            for j in range(4):
                key_words[i] += BitVector(intVal=byte_sub_table[key_words[i - 1][8 * j:8 * j + 8].intValue()], size=8)
            key_words[i] ^= key_words[i - 8]
        elif ((i - (i // 8) * 8) > 4) and ((i - (i // 8) * 8) < 8):
            key_words[i] = key_words[i - 8] ^ key_words[i - 1]
        else:
            sys.exit("error in key scheduling algo for i = %d" % i)
    return key_words

def g_function(keyword, round_constant, byte_sub_table):
    rotated_word = keyword.deep_copy()
    rotated_word << 8
    newword = BitVector(size = 0)
    for i in range(4):
        newword += BitVector(intVal = byte_sub_table[rotated_word[8*i:8*i+8].intValue()], size = 8)
    newword[:8] ^= round_constant
    round_constant = round_constant.gf_multiply_modular(BitVector(intVal = 0x02), AES_modulus, 8)
    return newword, round_constant

def sub_bytes(segment_bv,byte_sub_table):
    subs_byte = BitVector(size=0)
    for i in range(16):
        byte_to_substitute = segment_bv[i*8:(i+1)*8]
        byte_substitution = BitVector(intVal=byte_sub_table[int(byte_to_substitute)], size=8)
        subs_byte += byte_substitution
    return subs_byte

def shift_rows(segment_bv):
    row_shifting = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11] #Mapping from byte index to desired index
    shifted_segment = BitVector(size=0)
    for shift in row_shifting:
        shifted_byte = segment_bv[shift*8:(shift+1)*8]  #Obtain bytes to shift around
        shifted_segment += shifted_byte #Append shifted byte
    return shifted_segment

def mix_collumns(segment_bv):
    mixed_segment = BitVector(size=0)
    b_02 = BitVector(hexstring="2")
    b_03 = BitVector(hexstring="3")
    for i in range(16):
        min_ind_col = (i // 4 ) * 4 #Minimum index to loop back to
        max_ind_col = (i // 4 + 1) * 4 #Maximum index to loop back to
        byte_1_index = (i+1) % max_ind_col #Determine index of first byte operation
        byte_2_index = (i+2) % max_ind_col #Determine index of second byte operation
        byte_3_index = (i+3) % max_ind_col #Determine index of third byte operation
        if byte_1_index < min_ind_col: byte_1_index += min_ind_col #Add minimum offset to get correct element in column
        if byte_2_index < min_ind_col: byte_2_index += min_ind_col
        if byte_3_index < min_ind_col: byte_3_index += min_ind_col
        byte_0 = b_02.gf_multiply_modular(b=segment_bv[i*8:(i+1)*8], mod=AES_modulus, n=8)
        byte_1 = b_03.gf_multiply_modular(b=segment_bv[byte_1_index*8:(byte_1_index+1)*8] ,mod=AES_modulus, n=8)
        byte_2 = segment_bv[byte_2_index*8:(byte_2_index+1)*8]
        byte_3 = segment_bv[byte_3_index*8:(byte_3_index+1)*8]
        mixed_segment += byte_0 ^ byte_1 ^ byte_2 ^ byte_3

    return mixed_segment

def decrypt(encrypted_file, key_file, decrypted_file):
    # Read key file.
    key_file_pointer = open(file=key_file, mode='r')
    key_string = key_file_pointer.read()
    key_bv = BitVector(textstring=key_string)
    key_file_pointer.close()

    # Encryption Key Word Generation
    key_words = []
    byte_sub_table = generate_inv_sub_bytes_table()
    key_words = gen_key_schedule_256(key_bv, byte_sub_table)

    #Obtain key schedule
    key_schedule = []
    for word_index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i * 8:i * 8 + 8].intValue())
        key_schedule.append(keyword_in_ints)

    #Produce round keys
    round_keys = [None for i in range(NUM_ROUNDS + 1)]
    for i in range(NUM_ROUNDS + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[i * 4 + 3]).get_bitvector_in_hex()

    #Reverse round keys for usage in decryption
    round_keys.reverse()



    return



def generate_inv_sub_bytes_table():
    inv_sub_bytes_table = list()
    d_char = BitVector(bitstring='00000101')  # Corresponds to 'd' constant
    for i in range(0,256):
        # Generate Substitution table for decryption
        b = BitVector(intVal=i, size=8)
        b1, b2, b3 = [b.deep_copy() for x in range(3)]
        b = (b1 >> 2) ^ (b2 >> 5) ^ (b3 >> 7) ^ d_char
        check = b.gf_MI(AES_modulus, 8)
        b = check if isinstance(check, BitVector) else 0
        inv_sub_bytes_table.append(int(b))
    return  inv_sub_bytes_table

if __name__ == "__main__":
    # Assume correct number of arguments and format
    if len(sys.argv) != 5:
        print("Incorrect number of Arguments")
        exit(1)
    if sys.argv[1] == '-e':
        message = sys.argv[2]
        key = sys.argv[3]
        encrypted = sys.argv[4]
        encrypt(message, key, encrypted)
    elif sys.argv[1] == '-d':
        encrypted = sys.argv[2]
        key = sys.argv[3]
        decrypted = sys.argv[4]
        decrypt(encrypted, key, decrypted)
    else:
        print("Incorrect Encryption/Decryption Option.")
        exit(1)