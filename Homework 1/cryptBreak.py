from BitVector import *

# Homework Number: 1
# Name: Jose Luis Tejada
# ECN Login: tejada
# Due Date: Thursday 1/23/2020 at 4:29PM


#Arguments:
# ciphertextFile: String containing file name of the ciphertext (e.g. encrypted.txt )
# key_bv: 16-bit BitVector of the key used to try to decrypt the ciphertext.
#Function Description:
# Attempts to decrypt ciphertext contained in ciphertextFile using key_bv and returns
#   the original plaintext as a string

def cryptBreak(ciphertextFile,key_bv):
    BLOCKSIZE = 16
    NUM_BYTES_BLOCK = BLOCKSIZE // 8

    #Read original file, Convert file to bitvector block by block
    fp = open(ciphertextFile)
    cipher_bv = BitVector(hexstring=fp.read())

    #Passphrase
    pass_phrase = "Hopes and dreams of a million years"
    pass_phrase_bv = BitVector(bitlist=[0]*BLOCKSIZE) #Generate Bitvector of size blocksize
    for byte in range(0,len(pass_phrase) // NUM_BYTES_BLOCK):
        partial_string = pass_phrase[byte*NUM_BYTES_BLOCK:(byte+1)*NUM_BYTES_BLOCK]
        pass_phrase_bv ^= BitVector(textstring=partial_string)


    #For each block in bitvector perform incremental xoring
    plaintext_bv = BitVector(size=0) #Holds original message
    previous_cipher_block = pass_phrase_bv  #Previous bitblock is passphrase for 1st iteration
    for i in range(0, (len(cipher_bv) // BLOCKSIZE)):
        current_cipher_block = cipher_bv[i*BLOCKSIZE:(i+1)*BLOCKSIZE] #Obtain one block of ciphertext
        temp = current_cipher_block.deep_copy()
        current_cipher_block ^=  previous_cipher_block
        previous_cipher_block = temp
        current_cipher_block ^= key_bv
        plaintext_bv += current_cipher_block

    plaintext = plaintext_bv.get_text_from_bitvector()

    return plaintext

if __name__ == "__main__":
    #Brute Force all combinations
    for i in range(0,65536): #Attempt to use all blocksize 16 keys
        key_bv = BitVector(intVal=i, size=16)
        decryptedMessage = cryptBreak('encrypted.txt', key_bv)
        if i % 1000 == 0:
            print(i)
        if 'Mark Twain' in decryptedMessage:
            print(i,':',key_bv)
            print('Encryption Broken!')
            print(decryptedMessage)
            break;

    #Usage Example##
    # someRandomInteger = 9999  # Arbitrary integer for creating a BitVector
    # key_bv = BitVector(intVal=someRandomInteger, size=16)
    # decryptedMessage = cryptBreak('encrypted.txt', key_bv)
    # if 'Mark Twain' in decryptedMessage:
    #     print('Encryption Broken!')
    # else:
    #     print('Not decrypted yet')

