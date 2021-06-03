import os, sys, random, struct, os.path, shutil, binascii
import pgpy
import pyAesCrypt
from typing import ValuesView
from hashlib import new
from struct import pack
from Crypto.Cipher import DES
from bitstring import ConstBitStream
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm

'''
IV = CryptoRandom.new().read(DES.block_size)
des = self.get_des(IV)
padding = DES.block_size - len(format) % DES.block_size
format += bytes([padding]) * padding
data = IV + des.encrypt(format)
self.set_salt()
encoded = base64.b64encode(data)

'''

format = 'whateverthehexk2232408358q45798345709437509475294835rghfjsiuytpghf'
characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*') # Available characters for password
password_des = '' # Creates the password 
for i in range(16):
    password_des += random.choice(characters)
des = DES.new(password_des, DES.MODE_ECB)
text = format
text = text + (8 - (len(text) % 8)) * '='

encrypto_text = des.encyrypt(text.encode())
encrypto_text = binascii.b2a_hex(encrypto_text)
print(encrypto_text)
'''
def pad_message(message):
    while len(message) % 7 != 0:
        message = message + ' '
    return message
characters = ('abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890!@#$%^&*') # Available characters for password
password_des = '' # Creates the password 
for i in range(16):
    password_des += random.choice(characters)
message = format   
message = pad_message(message)
cipher = DES.new(password_des, DES.MODE_ECB)
cipher_text = cipher.encrypt(message.encode('utf-8'))
print('Encrpyted message is ', cipher_text)
print('Hex of text is ', cipher_text.hex())

decrypted_message = cipher.decrypt(cipher_text)
print('Decrypted message is ', decrypted_message)'''