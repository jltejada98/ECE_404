#!/usr/bin/env python3
from BitVector import *


#AES irreducible polynomial equation
AES_modulus = BitVector(bitstring='100011011')
NUM_ROUNDS = 14 #Number of rounds corresponding to 256 bit key.
ROW_SHIFTING_ENCRYPTION = [0,5,10,15,4,9,14,3,8,13,2,7,12,1,6,11] #Row shifts for encryption
#Precomputed byte susbstitution table (For speed)
byte_sub_table = [99, 124, 119, 123, 242, 107, 111, 197, 48, 1, 103, 43, 254, 215, 171, 118, 202, 130, 201, 125, 250, 89, 71, 240, 173, 212, 162, 175, 156, 164, 114, 192, 183, 253, 147, 38, 54, 63, 247, 204, 52, 165, 229, 241, 113, 216, 49, 21, 4, 199, 35, 195, 24, 150, 5, 154, 7, 18, 128, 226, 235, 39, 178, 117, 9, 131, 44, 26, 27, 110, 90, 160, 82, 59, 214, 179, 41, 227, 47, 132, 83, 209, 0, 237, 32, 252, 177, 91, 106, 203, 190, 57, 74, 76, 88, 207, 208, 239, 170, 251, 67, 77, 51, 133, 69, 249, 2, 127, 80, 60, 159, 168, 81, 163, 64, 143, 146, 157, 56, 245, 188, 182, 218, 33, 16, 255, 243, 210, 205, 12, 19, 236, 95, 151, 68, 23, 196, 167, 126, 61, 100, 93, 25, 115, 96, 129, 79, 220, 34, 42, 144, 136, 70, 238, 184, 20, 222, 94, 11, 219, 224, 50, 58, 10, 73, 6, 36, 92, 194, 211, 172, 98, 145, 149, 228, 121, 231, 200, 55, 109, 141, 213, 78, 169, 108, 86, 244, 234, 101, 122, 174, 8, 186, 120, 37, 46, 28, 166, 180, 198, 232, 221, 116, 31, 75, 189, 139, 138, 112, 62, 181, 102, 72, 3, 246, 14, 97, 53, 87, 185, 134, 193, 29, 158, 225, 248, 152, 17, 105, 217, 142, 148, 155, 30, 135, 233, 206, 85, 40, 223, 140, 161, 137, 13, 191, 230, 66, 104, 65, 153, 45, 15, 176, 84, 187, 22]

#Arguments:
# iv: 128-bit initialization vector
# image_file: input .ppm image file name
# out_file: encrypted .ppm image file name
# key_file: String of file name containing encryption key (in ASCII)
#Function Descrption:
# Encrypts image_file using CTR mode AES and writes said file to out_file. No
#required return value.
def ctr_aes_image(iv,image_file='image.ppm',out_file='enc_image.ppm',key_file='key.txt'):
    # Open input_image, Read three lines as header
    image_fp = open(file=image_file, mode='rb')
    image_header = []
    image_header.append(image_fp.readline())
    image_header.append(image_fp.readline())
    image_header.append(image_fp.readline())

    # Read remaining lines as data to encrypt.
    image_data = image_fp.read()
    image_bv = BitVector(rawbytes=image_data)  # Convert input_image data to bitvector

    # Close files
    image_fp.close()

    # Split contents of input_image, must pad last byte if not divisible by 128
    num_segments = len(image_bv) // 128
    image_bv_split = [image_bv[i * 128:(i + 1) * 128] for i in range(num_segments)]
    if (len(image_bv) % 128 != 0):
        last_segment = image_bv[num_segments * 128:len(image_bv)]
        last_segment.pad_from_right(128 - (len(image_bv) - num_segments * 128))
        image_bv_split.append(last_segment)

    # Write encrypted_ppm bitvector to ppm
    # Use 'wb' as write binary option
    encrypted_fp = open(file=out_file, mode='wb')
    for h in image_header:
        encrypted_fp.write(h)

    # Read key file.
    key_file_pointer = open(file=key_file, mode='r')
    key_string = key_file_pointer.read()
    key_bv = BitVector(textstring=key_string)
    key_file_pointer.close()

    # Encryption Key Word Generation
    key_words = gen_key_schedule_256(key_bv, byte_sub_table)

    # Obtain key schedule
    key_schedule = []
    for word_index, word in enumerate(key_words):
        keyword_in_ints = []
        for i in range(4):
            keyword_in_ints.append(word[i * 8:i * 8 + 8].intValue())
        key_schedule.append(keyword_in_ints)

    # Produce round keys
    round_keys = [None for i in range(NUM_ROUNDS + 1)]
    for i in range(NUM_ROUNDS + 1):
        round_keys[i] = (key_words[i * 4] + key_words[i * 4 + 1] + key_words[i * 4 + 2] + key_words[
            i * 4 + 3]).get_bitvector_in_hex()

    # Continue for entirety of message
    bv_1 = BitVector(intVal=1)
    i =0
    for image_bv_segment in image_bv_split:
        print(i)
        i+=1
        encrypted_bv = encrypt(iv, round_keys)
        encrypted_bv ^= image_bv_segment
        encrypted_bv.write_to_file(file_out=encrypted_fp)
        iv += bv_1

    # Close File
    encrypted_fp.close()

    return


#####Code from Homework 4#####
def encrypt(message_bv_segment, round_keys):  #Modified from Homework 4
    # Add first round key to message segment
    current_round_key = BitVector(hexstring=round_keys[0])
    message_bv_segment ^= current_round_key

    # Perform remaning rounds of encryption
    for i in range(1, NUM_ROUNDS):
        # Substitute bytes step.
        message_bv_segment = sub_bytes(message_bv_segment, byte_sub_table)
        # Shift Rows
        message_bv_segment = shift_rows(message_bv_segment, ROW_SHIFTING_ENCRYPTION)
        # Mix Collumns
        message_bv_segment = mix_collumns(message_bv_segment)
        # Add Round Key
        current_round_key = BitVector(hexstring=round_keys[i])
        message_bv_segment ^= current_round_key

    ##Last round of encryption
    # Substitute bytes step.
    message_bv_segment = sub_bytes(message_bv_segment, byte_sub_table)
    # Shift Rows
    message_bv_segment = shift_rows(message_bv_segment, ROW_SHIFTING_ENCRYPTION)
    # Add Round Key
    current_round_key = BitVector(hexstring=round_keys[14])
    message_bv_segment ^= current_round_key

    return  message_bv_segment


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

def shift_rows(segment_bv, row_shifting):
    #Mapping from byte index to desired index
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
