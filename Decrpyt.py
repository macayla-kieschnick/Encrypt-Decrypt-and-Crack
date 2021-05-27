#!/usr/bin/env python3

#imports all of the necessary information
import base64
from hashlib import new
import os, sys, random, struct, os.path, shutil
import pyAesCrypt
from bitstring import ConstBitStream

def aes_encryption(question): 
    # Defines important variables 
    global aes_en
    global password
    global aes_filename 
    global password_file
    characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*') # Available characters for password
    aes_filename = 'AES-' + question + '.aes' # Creates the file name for AES
    password = '' # Creates the password 
    for i in range(35):
        password += random.choice(characters)
    password_file = aes_filename[:-8] + '-password' + aes_filename[-8:-4]
    file = open(password_file, 'w') # Writes the password to a file for the user to use 
    file.write(password) 
    file.close()
    aes_en = pyAesCrypt.encryptFile(question, aes_filename, password) # Encrypts the file 
    encrypt = {'aes_en' : aes_en, 'password' : password, 'aes_filename' : aes_filename, ' password_file' : password_file} # Creates the dictionary for multiple returns
    return(encrypt)

def aes_decryption(aes_en, password):
    global aes_de_filename
    aes_de_filename = 'decrypted.txt' # Creates a file for decrypted data
    aes_de = pyAesCrypt.decryptFile(aes_filename, aes_de_filename, password) # Decrypts the file
    decrypt = {'aes_de' : aes_de, 'aes_de_filename' : aes_de_filename}
    return(decrypt)

question = str(sys.argv[1]) # Takes text document from command line and creates a variable
if 'txt' in question: # Ensures that the variable is a txt document
    newpath = (question[:-4] + '-AES-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
    if not os.path.exists(newpath): # Checks to see if folder has been created already
        os.mkdir(newpath) # Makes the actual path
        aes_en = aes_encryption(question) # Runs the document through encryption
        aes_de = aes_decryption(aes_en, password) # Runs the encrypted file through decryption
        print('Finished encryption and decryption')
        files = [password_file, aes_filename, aes_de_filename] # Creates a list of all the files to move to a new folder
        for f in files:
            shutil.move(f, newpath) # Moves list of files to new folder
        redirection = os.path.join(newpath, aes_filename)
        b = ConstBitStream(filename = redirection)
        output = b.read(24) # Reads the first 24 bits (first 3 bytes of the data)
        if output == '0x414553': # HEX values for AES
            print('This is an AES encrypted document')
        else:
            print('Some other encryption or not encrypted')
    elif os.path.exists(newpath): # Checks to see if the folder has been created already
        print('Files are already created, check the folder or move folder and try again')
else:
    print('That is not a valid text file, please try again') 
