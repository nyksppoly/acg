#------------------------------------------------------------------------------------------
# Client.py
#------------------------------------------------------------------------------------------
#!/usr/bin/env python3
# Please starts the tcp server first before running this client
 
import base64
import hashlib
import os
os.chdir("client/")
from Crypto.Util.Padding import pad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random       # For AES Encryption/Decryption
from Crypto.PublicKey import RSA    # For RSA 
from Crypto.Random import get_random_bytes

import datetime
import sys              # handle system error
import socket
import time

global host, port

def aes_encrypt(message, password):     # Password should be the same for encryption and decryption
    print('here: ', password)
    password = str(password)
    private_aes_key = hashlib.sha256(password.encode("utf-8")).digest()     # Turns password into a hash to be used as encryption key
    message = pad(data_to_pad = message, block_size = 16)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_aes_key, AES.MODE_CBC, iv)     # Cipher is generated
    print("Message Encrypted")
    return base64.b64encode(iv + cipher.encrypt(message))       # Encrypted message is returned

host = socket.gethostname()
port = 8888         # The port used by the server
cmd_GET_MENU = b"GET_MENU"
cmd_END_DAY = b"CLOSING"
cmd_KEY_EXCH = b"KEY_EXCH"
menu_file = "menu.csv"
return_file = "day_end.csv"

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:        # Sending public rsa key
    my_socket.connect((host, port))
    my_socket.sendall(cmd_KEY_EXCH)
    aes_key_seed_recieved = my_socket.recv(4096)
    aes_key_seed = aes_key_seed_recieved       # ADD DIGITAL SIGNATURE AND RSA PRIV KEY DECRYPTION HERE
    print("AES key seed recieved")
    print(aes_key_seed)
    my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    my_socket.connect((host, port))
    my_socket.sendall(cmd_GET_MENU )
    print("Getting menu")
    data = my_socket.recv(4096)
    #hints : need to apply a scheme to verify the integrity of data.  
    menu_file = open(menu_file,"wb")
    menu_file.write(data)
    menu_file.close()
    my_socket.close()
print('Menu today received from server')
#print('Received', repr(data))  # for debugging use
my_socket.close()

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as my_socket:
    #password = input("Enter encryption password: ")     # Password should be the same for encryption and decryption
    my_socket.connect((host, port))
    my_socket.sendall(cmd_END_DAY)
    try:
        out_file = open(return_file,"rb")
    except:
        print("file not found : " + return_file)
        sys.exit(0)
    file_bytes = out_file.read(1024)
    sent_bytes=b''
    while file_bytes != b'':
        # hints: need to protect the file_bytes in a way before sending out.
        file_bytes = aes_encrypt(file_bytes, aes_key_seed)
        my_socket.send(file_bytes)
        sent_bytes+=file_bytes
        file_bytes = out_file.read(1024) # read next block from file
    out_file.close()
    my_socket.close()
print('Sale of the day sent to server')
#print('Sent', repr(sent_bytes))  # for debugging use
my_socket.close()
