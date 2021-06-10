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

def convertToDF(data):
    if type(data) == str:
        s = data
    else:
        try:
            s = str(data,'utf-8')
        except:
            s = str(data,'latin1')
            data = StringIO(s)
            df = pd.read_csv(data)
            return df
key_1 = RSA.generate(2048)
public_key = key_1.publickey()
print('key: ',key_1, 'public-key: ', public_key)

#pubKey, _ = pgpy.PGPKey.from_file('./publicKey.key')
#priKey, _ = pgpy.PGPKey.from_file('./privateKey.key')
fileName = question
file_message = pgpy.PGPMessage.new(fileName, file=True)
print(file_message)
print (type('\n\n\n\n',file_message))
originalData = convertToDF(file_message.message)
print(originalData)
encryptedData = public_key.encrypt(file_message)
print(encryptedData)
saveFile = 'EncryptedData'
with open('saveFile+.pkl', 'wb') as file:
    dill.dump(encryptedData, file)
loadFile = 'EncryptedData'
with open('loadFile+.pkl', 'rb') as file:
    encLData = dill.load(file)
recoveredData = convertToDF(decryptedData.message)
print(decryptedData)
print(recoveredData)

'''            
def pgp_encryption(question, format):
    global pgp_en
    global pgp_filename
    global key
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new('Abraham Lincoln', comment = 'Honest Abe', email = 'abraham.lincoln@whitehouse.gov')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    message =  pgpy.PGPMessage.new(format, file=True)
    pgp_en = message.encrypt(key) # Encode it here
    second_pgp_en = pubkey.encrypt(format)
    print(pgp_en, '\n\n', second_pgp_en)
    pgp_filename = 'pgp-' + question + '.whatever'
    files.append(pgp_filename)
    return(pgp_en)
def pgp_decryption(pgp_en,):
    global pgp_de_filename
    pgp_de = key.decrypt(pgp_en) # Decode here
    pgp_de_filename = 'decrypted-pgp.txt'
    files.append(pgp_de_filename)
    return(pgp_de)    
def three_encryption(question):
    global three_en
    global three_filename
    three_en = '' # Encode it here
    three_filename = 'three-' + question + '.whatever'
    files.append(three_filename)
    return(three_en)
def three_decryption(three_en):
    global three_de_filename
    three_de = '' # Decode here
    three_de_filename = 'decrypted-three.txt'
    files.append(three_de_filename)
    return(three_de)
def aes_encryption(question): 
    # Defines important variables 
    global aes_en
    global password_aes
    global aes_filename 
    global password_file
    characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*') # Available characters for password
    password_aes = '' # Creates the password 
    for i in range(35):
        password_aes += random.choice(characters)
    aes_filename = 'AES-' + question + '.aes' # Creates the file name for AES
    password_file = aes_filename[:-8] + '-password' + aes_filename[-8:-4]
    file = open(password_file, 'w') # Writes the password to a file for the user to use 
    file.write(password_aes) 
    file.close()
    files.append(aes_filename)
    files.append(password_file)
    aes_en = pyAesCrypt.encryptFile(question, aes_filename, password_aes) # Encrypts the file 
    encrypt = {'aes_en' : aes_en, 'password_aes' : password_aes, 'aes_filename' : aes_filename, ' password_file' : password_file} # Creates the dictionary for multiple returns
    return(encrypt)
def aes_decryption(aes_en, password_aes):
    global aes_de_filename
    aes_de_filename = 'decrypted-aes.txt' # Creates a file for decrypted data
    files.append(aes_de_filename)
    aes_de = pyAesCrypt.decryptFile(aes_filename, aes_de_filename, password_aes) # Decrypts the file
    decrypt = {'aes_de' : aes_de, 'aes_de_filename' : aes_de_filename}
    return(decrypt)
 
question = str(sys.argv[1]) # Takes text document from command line and creates a variable
global file
files = []

if 'txt' in question: # Ensures that the variable is a txt document
    format = size(question)
    ask = input('Would you like to use AES or PGP encrytion? ')
    if ask in 'AESaes':
        newpath = (question[:-4] + '-AES-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            aes_en = aes_encryption(question) # Runs the document through encryption
            aes_de = aes_decryption(aes_en, password_aes) # Runs the encrypted file through decryption
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, aes_filename)
        elif os.path.exists(newpath): # Checks to see if the folder has been created already
            print('Files are already created, check the folder or move folder and try again')
    elif ask in 'PGPpgp':
        newpath = (question[:-4] + '-PGP-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            pgp_en = pgp_encryption(question, format)
            pgp_de = pgp_decryption(pgp_en, key)
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, pgp_filename)
        elif os.path.exists(newpath): # Checks to see if the folder has been created already
            print('Files are already created, check the folder or move folder and try again')
    elif ask in 'three':
        newpath = (question[:-4] + '-three-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            three_en = three_encryption(question)
            three_de = three_decryption(three_en)
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, three_filename)
    else:
        print('Invalid option')
else:
    print('That is not a valid text file, please try again') 
''
    b = ConstBitStream(filename = redirection)
    output = b.read(24) # Reads the first 24 bits (first 3 bytes of the data)
    if output == '0x414553': # HEX values for AES
        print('This is an AES encrypted document')
    elif output == '0x7f': # HEX values for PGP
        print('This is an PGP encrypted document')
    else:
        print('Some other encryption or not encrypted')''
'''











'''
#!/usr/bin/env python3

#imports all of the necessary information
import os, sys, random, os.path, shutil
import pgpy
import gnupg
import pyAesCrypt
from bitstring import ConstBitStream
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
#from twofish import Twofish
#from ctypes import (cdll, Structure, POINTER, pointer, c_char_p, c_int, c_uint32, create_string_buffer)

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
def pgp_encryption(question, format):
    global pgp_en
    global pgp_filename
    global key
    key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
    uid = pgpy.PGPUID.new('Abraham Lincoln', comment = 'Honest Abe', email = 'abraham.lincoln@whitehouse.gov')
    key.add_uid(uid, usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
            hashes=[HashAlgorithm.SHA256, HashAlgorithm.SHA384, HashAlgorithm.SHA512, HashAlgorithm.SHA224],
            ciphers=[SymmetricKeyAlgorithm.AES256, SymmetricKeyAlgorithm.AES192, SymmetricKeyAlgorithm.AES128],
            compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
    message =  pgpy.PGPMessage.new(format, file=True)
    pgp_en = message.encrypt(key) # Encode it here
    second_pgp_en = pubkey.encrypt(format)
    print(pgp_en, '\n\n', second_pgp_en)
    pgp_filename = 'pgp-' + question + '.whatever'
    files.append(pgp_filename)
    return(pgp_en)
def pgp_decryption(pgp_en,):
    global pgp_de_filename
    pgp_de = key.decrypt(pgp_en) # Decode here
    pgp_de_filename = 'decrypted-pgp.txt'
    files.append(pgp_de_filename)
    return(pgp_de)    
def three_encryption(question):
    global three_en
    global three_filename
    three_en = '' # Encode it here
    three_filename = 'three-' + question + '.whatever'
    files.append(three_filename)
    return(three_en)
def three_decryption(three_en):
    global three_de_filename
    three_de = '' # Decode here
    three_de_filename = 'decrypted-three.txt'
    files.append(three_de_filename)
    return(three_de)
def aes_encryption(question): 
    # Defines important variables 
    global aes_en
    global password_aes
    global aes_filename 
    global password_file
    characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*') # Available characters for password
    password_aes = '' # Creates the password 
    for i in range(35):
        password_aes += random.choice(characters)
    aes_filename = 'AES-' + question + '.aes' # Creates the file name for AES
    password_file = aes_filename[:-8] + '-password' + aes_filename[-8:-4]
    file = open(password_file, 'w') # Writes the password to a file for the user to use 
    file.write(password_aes) 
    file.close()
    files.append(aes_filename)
    files.append(password_file)
    aes_en = pyAesCrypt.encryptFile(question, aes_filename, password_aes) # Encrypts the file 
    encrypt = {'aes_en' : aes_en, 'password_aes' : password_aes, 'aes_filename' : aes_filename, ' password_file' : password_file} # Creates the dictionary for multiple returns
    return(encrypt)
def aes_decryption(aes_en, password_aes):
    global aes_de_filename
    aes_de_filename = 'decrypted-aes.txt' # Creates a file for decrypted data
    files.append(aes_de_filename)
    aes_de = pyAesCrypt.decryptFile(aes_filename, aes_de_filename, password_aes) # Decrypts the file
    decrypt = {'aes_de' : aes_de, 'aes_de_filename' : aes_de_filename}
    return(decrypt)
 
question = str(sys.argv[1]) # Takes text document from command line and creates a variable
global file
files = []

if 'txt' in question: # Ensures that the variable is a txt document
    format = size(question)
    ask = input('Would you like to use AES or PGP encrytion? ')
    if ask in 'AESaes':
        newpath = (question[:-4] + '-AES-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            aes_en = aes_encryption(question) # Runs the document through encryption
            aes_de = aes_decryption(aes_en, password_aes) # Runs the encrypted file through decryption
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, aes_filename)
        elif os.path.exists(newpath): # Checks to see if the folder has been created already
            print('Files are already created, check the folder or move folder and try again')
    elif ask in 'PGPpgp':
        newpath = (question[:-4] + '-PGP-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            pgp_en = pgp_encryption(question, format)
            pgp_de = pgp_decryption(pgp_en, key)
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, pgp_filename)
        elif os.path.exists(newpath): # Checks to see if the folder has been created already
            print('Files are already created, check the folder or move folder and try again')
    elif ask in 'three':
        newpath = (question[:-4] + '-three-INFORMATION').upper() # Defines a new folder where AES information can be stored depending on file
        if not os.path.exists(newpath): # Checks to see if folder has been created already
            os.mkdir(newpath) # Makes the actual path
            three_en = three_encryption(question)
            three_de = three_decryption(three_en)
            print('Finished encryption and decryption')
            for f in files:
                shutil.move(f, newpath) # Moves list of files to new folder
            redirection = os.path.join(newpath, three_filename)
    else:
        print('Invalid option')
else:
    print('That is not a valid text file, please try again') 
    
    b = ConstBitStream(filename = redirection)
    output = b.read(24) # Reads the first 24 bits (first 3 bytes of the data)
    if output == '0x414553': # HEX values for AES
        print('This is an AES encrypted document')
    elif output == '0x7f': # HEX values for PGP
        print('This is an PGP encrypted document')
    else:
        print('Some other encryption or not encrypted')
'''