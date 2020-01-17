#Arguments:
# ciphertextFile: String containing file name of the ciphertext (e.g. encrypted.txt )
# key_bv: 16-bit BitVector of the key used to try to decrypt the ciphertext.
#Function Description:
# Attempts to decrypt ciphertext contained in ciphertextFile using key_bv and returns
#   the original plaintext as a string
def cryptBreak(ciphertextFile,key_bv):
