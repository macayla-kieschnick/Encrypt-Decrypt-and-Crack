#!/usr/bin/env python3

#imports all of the necessary information
import os, sys, random, os.path, shutil
import pgpy
import gnupg
import pyAesCrypt
import pandas
import dill
import pandas as pd 
from bitstring import ConstBitStream
from Crypto.PublicKey import RSA
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

def size(question):
    byte_size = os.path.getsize(question) # Determines the number of bytes in given file
    bit_size = byte_size * 8 # Converts the bytes into bits
    with open(question, 'r') as f: # Reads the file
        contents = f.read()
    result=[] # Empty list for data
    s = '' # Empty variable for data
    for i in range(0, len(contents), bit_size):
        o = contents[i:i+bit_size] 
        hexa = ' '.join(['%02X'%ord(x) for x in o]) # Reads the file in hex
        result.append(hexa)
        for item in result:
            s += item
            low = s.lower()
            msg = (''.join(low.split())) # Prints the hex value for the file
            return(msg) # Prints the hex value for the file

def xor_encryption(input, key):
    global xor_en
    global xor_filename

    xor_en = [] # Encodes it here
    for i in range(len(input)):
        xor_num = ord(input[i]) ^ ord(key[i % len(key)])
        xor_en.append(chr(xor_num))
    xor_filename = 'xor-' + question + '.xor'
    file = open(xor_filename, 'w') # Writes to the file
    file.write(''.join(xor_en))
    file.close()
    files.append(xor_filename)
    return ''.join(xor_en)

def xor_decryption(input, key):
    global xor_de
    global xor_filename
    xor_de = [] # Encodes it here
    for i in range(len(input)):
        xor_num = ord(input[i]) ^ ord(key[i % len(key)])
        xor_de.append(chr(xor_num))
    xor_de_string = ''
    for i in xor_de:
        xor_de_string = xor_de_string + i
    print(xor_de_string)
    change = bytes.fromhex(xor_de_string).decode('utf-8')
    xor_filename = 'dexor-' + question + '.xor'
    file = open(xor_filename, 'w')
    file.write(''.join(change))
    files.append(xor_filename)
    return ''.join(change)

question = str(sys.argv[1]) # Takes text document from command line and creates a variable
global files
files = []

if 'txt' in question: # Ensures that the variable is a txt document
    format = size(question)
    ask = input('Would you like to use AES or PGP or XOR encrytion? ')
    if ask in 'XORxor':
        newpath = (question[:-4] + '-XOR-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            
            characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*[]()`~-=_+\|?><') # Available characters for password
            password = '' # Creates the password 
            for i in range(25):
                password += random.choice(characters)
            password_file = 'password.txt'
            file = open(password_file, 'w')
            file.write(password)
            file.close()
            xor_en = xor_encryption(format, password)
            xor_de = xor_decryption(xor_en, password)
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, xor_filename, password_file)
    else:
        print('Invalid option')