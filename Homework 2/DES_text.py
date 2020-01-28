#!/usr/bin/env python3
import sys
from BitVector import *

#Permutation / Substitution  arrays

key_permutation_1 = [56,48,40,32,24,16,8,0,57,49,41,33,25,17,
                      9,1,58,50,42,34,26,18,10,2,59,51,43,35,
                     62,54,46,38,30,22,14,6,61,53,45,37,29,21,
                     13,5,60,52,44,36,28,20,12,4,27,19,11,3]

key_permutation_2 = [13,16,10,23,0,4,2,27,14,5,20,9,22,18,11,
                      3,25,7,15,6,26,19,12,1,40,51,30,36,46,
                     54,29,39,50,44,32,47,43,48,38,55,33,52,
                     45,41,49,35,28,31]

shifts_for_round_key_gen = [1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1]


expansion_permutation = [31,  0,  1,  2,  3,  4,
                          3,  4,  5,  6,  7,  8,
                          7,  8,  9, 10, 11, 12,
                         11, 12, 13, 14, 15, 16,
                         15, 16, 17, 18, 19, 20,
                         19, 20, 21, 22, 23, 24,
                         23, 24, 25, 26, 27, 28,
                         27, 28, 29, 30, 31, 0]

s_boxes = {i:None for i in range(8)}

s_boxes[0] = [ [14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7],
               [0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8],
               [4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0],
               [15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13] ]

s_boxes[1] = [ [15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10],
               [3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5],
               [0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15],
               [13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9] ]

s_boxes[2] = [ [10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8],
               [13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1],
               [13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7],
               [1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12] ]

s_boxes[3] = [ [7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15],
               [13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9],
               [10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4],
               [3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14] ]

s_boxes[4] = [ [2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9],
               [14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6],
               [4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14],
               [11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3] ]

s_boxes[5] = [ [12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11],
               [10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8],
               [9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6],
               [4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13] ]

s_boxes[6] = [ [4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1],
               [13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6],
               [1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2],
               [6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12] ]

s_boxes[7] = [ [13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7],
               [1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2],
               [7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8],
               [2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11] ]

pbox_permutation = [15,6,19,20,28,11,27,16,0,14,22,25,4,
                    17,30,9,1,7,23,13,31,26,2,8,18,12,29,
                    5,21,10,3,24]


def encrypt(message, key, encrypted):
    #Obtain key and round keys
    encryption_key, round_keys = generate_keys(key)

    #Convert Message to bitvector
    message_bv = BitVector(filename=message) #Assume conversion with textstring.

    #Continue for entirety of message
    encrypted_bv = BitVector(size=0)
    while(message_bv.more_to_read):
        #Obtain Segment
        message_bv_segment = message_bv.read_bits_from_file(64)

        # Pad read bits with 0's when block size is not 64
        if message_bv_segment.size < 64:
            message_bv_segment.pad_from_right(64-len(message_bv_segment))

        #Feistel function
        [Left, Right] = message_bv_segment.divide_into_two()  # Perform left/right division
        for r_key in round_keys: #For each segement of 64-bits perform 16 rounds of encryption
            new_Right = Right.deep_copy()
            new_Right = new_Right.permute(permute_list=expansion_permutation) #Perform expansion permutation on right half to 48 bits
            new_Right ^= r_key # Perform xor with key, must be 48bits

            # Perform substitution with s-boxes, remember input -> 48bits, output -> 32bits
            s_box_output = substitution(new_Right)

            p_box_Right = s_box_output.permute(permute_list=pbox_permutation) # Perform permutation with P Box
            p_box_Right ^= Left  # Perform final Xoring with requisite half

            #Set left and right for next round.
            Left = Right.deep_copy()
            Right = p_box_Right
            #End of 16 Encryption Rounds for current segment
        #Append each segment's left and right halves together.
        encrypted_bv += (Right + Left) #Check Method of usage

    #Once finished reading, write bitvector to encrypted_ppm
    encrypted_fp = open(file=encrypted, mode='w')
    encrypted_bv_hex_string = encrypted_bv.get_hex_string_from_bitvector()
    encrypted_fp.write(encrypted_bv_hex_string)

    #Close files
    encrypted_fp.close()

    return

def decrypt(encrypted,key, decrypted):
    # Obtain key and round keys
    encryption_key, round_keys = generate_keys(key)
    #Attempt to flip round keys so that key 16 is run 1st
    round_keys.reverse()

    # Convert Message to bitvector
    fp = open(file=encrypted, mode='r')
    encrypted_bv = BitVector(hexstring=fp.read())  # Assume conversion from hexstring to bitvector

    # Continue for entirety of message
    decrypted_bv = BitVector(size=0)

    #Split hexfile into 64 bit chunks
    encrypted_bv_split = [encrypted_bv[i*64:(i+1)*64] for i in range((len(encrypted_bv) // 64))]  #Check if correct

    for encrypted_bv_segment in encrypted_bv_split:
        # Obtain Segments
        [Left, Right] = encrypted_bv_segment.divide_into_two()  # Perform left/right division
        for r_key in round_keys:  # For each segement of 64-bits perform 16 rounds of encryption
            new_Right = Right.deep_copy()
            new_Right = new_Right.permute(permute_list=expansion_permutation)  # Perform expansion permutation on right half to 48 bits
            new_Right ^= r_key  # Perform xor with key, must be 48bits

            # Perform substitution with s-boxes, remember input -> 48bits, output -> 32bits
            s_box_output = substitution(new_Right)

            p_box_Right = s_box_output.permute(permute_list=pbox_permutation)  # Perform permutation with P Box
            p_box_Right ^= Left  # Perform final Xoring with requisite half
            Left = Right.deep_copy()
            Right = p_box_Right
        # End of 16 Encryption Rounds for current segment
        # Append each segment's left and right halves together.
        decrypted_bv += (Right + Left)  # Check Method of usage

    # Once finished reading, write bitvector to decrypted
    decrypted_fp = open(file=decrypted, mode='w')
    decrypted_bv_text = decrypted_bv.get_text_from_bitvector()
    decrypted_fp.write(decrypted_bv_text)

    #Close files
    fp.close()
    decrypted_fp.close()

    return

def generate_keys(key):
    #Obtain Encryption key
    key_file_pointer = open(file=key, mode='r')
    key_string = key_file_pointer.read()
    key_bv = BitVector(textstring=key_string)
    key_bv_p = key_bv.permute(permute_list=key_permutation_1)

    #Generate Round Keys
    round_keys = []
    encryption_key_bv = key_bv_p.deep_copy()
    for round_num in range(16):
        [left_key, right_key] = encryption_key_bv.divide_into_two()
        round_shift = shifts_for_round_key_gen[round_num]
        left_key << round_shift
        right_key << round_shift
        complete_key = left_key + right_key
        round_key = complete_key.permute(key_permutation_2)
        round_keys.append(round_key)

    return key_bv_p, round_keys

def substitution(half_block_48):

    s_box_output = BitVector(size=32)
    s_segments = [half_block_48[(i * 6):(i * 6 + 6)] for i in range(8)]  # Determine segments for substitution
    for s_index in range(len(s_segments)): #For each segment
        row = 2 * s_segments[s_index][0] + s_segments[s_index][-1]  # Determine row of substitution
        col = int(s_segments[s_index][1:-1])  # Determine column in row of s_box to be substituted with
        s_box_output[s_index * 4:(s_index * 4 + 4)] = BitVector(intVal=s_boxes[s_index][row][col],size=4)  # Perform substitution

    return s_box_output

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
        decrypt(encrypted,key, decrypted)
    else:
        print("Incorrect Encryption/Decryption Option.")
        exit(1)
