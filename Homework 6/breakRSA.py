#!/usr/bin/env python3
import sys
import numpy as np

def encrypt(message_file, enc_file_1, enc_file_2, enc_file_3, n_file):



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


    else:
        print("Incorrect Generate/Encryption/Decryption Option.")
        exit(1)
