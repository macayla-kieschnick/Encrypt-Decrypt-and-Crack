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

question = str(sys.argv[1]) # Takes text document from command line and creates a variable

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

format = size(question)

def encrypt(filename, key):
    with open(filename, 'rb') as f:
        data = f.read()
    data = bytearray(data)
    for index, value in enumerate(data):
        data[index] = value ^ key
    with open('CC-' + filename, 'wb') as g:
        g.write(data)
def decrypt(filename, key):
    with open(filename, 'rb') as f:
        data = f.read()
    data = bytearray(data)
    for index, value in enumerate(data):
        data[index] = value ^ key
    with open('DECC-' + filename, 'wb') as g:
        g.write(data)
key = 85
filename = question

def enc(format):
    characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*') # Available characters for password
    password = '' # Creates the password 
    for i in range(1):
        password += random.choice(characters)
    no_of_itr = len(format)
    output_str = ''
    print(password)

    for i in range(no_of_itr):
        current = format[i]
        current_key = password[i%len(password)]
        output_str += chr(ord(current) ^ ord(current_key))

    print("Here's the output: ", output_str)
    with open('CC-' + filename, 'w') as g:
            g.write(output_str)
enc(format)

'''
def xor_encryption(question):
    global xor_en
    global xor_filename
    xor_en = '' # Encode it here
    xor_filename = 'xor-' + question + '.whatever'
    files.append(xor_filename)
    return(xor_en)
def xor_decryption(xor_en):
    global xor_de_filename
    xor_de = '' # Decode here
    xor_de_filename = 'decrypted-xor.txt'
    files.append(xor_de_filename)
    return(xor_de)
question = str(sys.argv[1]) # Takes text document from command line and creates a variable
global file
files = []

if 'txt' in question: # Ensures that the variable is a txt document
    format = size(question)
    ask = input('Would you like to use AES or PGP or XOR encrytion? ')
    if ask in 'XORxor':
        newpath = (question[:-4] + '-XOR-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            xor_en = xor_encryption(question)
            xor_de = xor_decryption(xor_en)
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, xor_filename)
    else:
        print('Invalid option')
'''