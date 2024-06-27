#------------------------------------------------------------------------------------------
# Server.py
#------------------------------------------------------------------------------------------

import base64
import hashlib
import os
os.chdir("server/")
from Crypto.Util.Padding import unpad
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto import Random       # For AES Encryption/Decryption
from Crypto.PublicKey import RSA    # For RSA
from Crypto.Random import get_random_bytes


from threading import Thread    # for handling task in separate jobs we need threading
import socket           # tcp protocol
import datetime         # for composing date/time stamp
import sys              # handle system error
import traceback        # for print_exc function
import time             # for delay purpose

global host, port

cmd_GET_MENU = "GET_MENU"
cmd_END_DAY = "CLOSING"
cmd_KEY_EXCH = "KEY_EXCH"
default_menu = "menu_today.txt"
default_save_base = "result-"

host = socket.gethostname() # get the hostname or ip address
port = 8888                 # The port used by the server


def aes_decrypt(message, password):     # encrypted message format = iv (16 bit length) + ciphertext (to be decoded)
    print('here:, ', password)
    password = str(password)
    print("Encrypted message: " + str(message))     # Password should be the same for encryption and decryption - comment to hide encrypted message
    private_key = hashlib.sha256(password.encode("utf-8")).digest()     # Turns password into a hash to be used as decryption key
    message = base64.b64decode(message)
    iv = message[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)     # Message key is generated from password hash
    print("Message Decrypted")
    message = unpad(padded_data = cipher.decrypt(message), block_size = 16) # message decrypted
    return message[16:]          # Decrypted message is returned

def process_connection( conn , ip_addr, MAX_BUFFER_SIZE):
    password = send_bytes       # encrypt with RSA pub key here
    print('Processing connection')  
    blk_count = 0
    net_bytes = conn.recv(MAX_BUFFER_SIZE)
    dest_file = open("temp","w")  # temp file is to satisfy the syntax rule. Can ignore the file.
    while net_bytes != b'':
        if blk_count == 0: #  1st block
            usr_cmd = net_bytes[0:15].decode("utf8").rstrip()
            if cmd_GET_MENU in usr_cmd: # ask for menu
                try:
                    src_file = open(default_menu,"rb")
                except:
                    print("file not found : " + default_menu)
                    sys.exit(0)
                while True:
                    read_bytes = src_file.read(MAX_BUFFER_SIZE)
                    if read_bytes == b'':
                        break
                    #hints: you may apply a scheme (hashing/encryption) to read_bytes before sending to client.
                    conn.send(read_bytes)
                src_file.close()
                print("Processed SENDING menu") 
                return
            elif cmd_KEY_EXCH in usr_cmd:        # custom to send over public key for encryption
                #hints: you may apply a scheme (hashing/encryption) to read_bytes before sending to client.
                aes_key_seed = password # ENCRYPT WITH RSA PUB KEY HERE BEFORE SENDING
                conn.send(aes_key_seed)
                print("AES session key seed sent")
                print('password: ', password)
            elif cmd_END_DAY in usr_cmd: # ask for to save end day order
                #password = input("Enter encryption password: ")     # Password should be the same for encryption and decryption
                #Hints: the net_bytes after the cmd_END_DAY may be encrypted. 
                now = datetime.datetime.now()
                filename = default_save_base +  ip_addr + "-" + now.strftime("%Y-%m-%d_%H%M")                
                dest_file = open(filename,"wb")

                # Hints: net_bytes may be an encrypted block of message.
                # e.g. plain_bytes = my_decrypt(net_bytes)
                plain_bytes = aes_decrypt(net_bytes[ len(cmd_END_DAY): ], password) # remove the CLOSING header and decrypt
                dest_file.write(plain_bytes)    
        else:  # write subsequent blocks of END_DAY message block
            # Hints: net_bytes may be an encrypted block of message.
            net_bytes = conn.recv(MAX_BUFFER_SIZE)
            dest_file.write(net_bytes)
    # last block / empty block
    dest_file.close()
    print("saving file as " + filename)
    time.sleep(3)
    print("Processed CLOSING done") 
    return

def client_thread(conn, ip, port, MAX_BUFFER_SIZE = 4096):
    process_connection( conn, ip, MAX_BUFFER_SIZE)
    conn.close()  # close connection
    print('Connection ' + ip + ':' + port + "ended")
    return

def start_server():
    global send_bytes
    send_bytes = get_random_bytes(16)
    global host, port
    # Here we made a socket instance and passed it two parameters. AF_INET and SOCK_STREAM. 
    soc = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    # this is for easy starting/killing the app
    soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    print('Socket created')
    
    try:
        soc.bind((host, port))
        print('Socket bind complete')
    except socket.error as msg:
        
        print('Bind failed. Error : ' + str(sys.exc_info()))
        print( msg.with_traceback() )
        sys.exit()

    #Start listening on socket and can accept 10 connection
    soc.listen(10)
    print('Socket now listening')

    # this will make an infinite loop needed for 
    # not reseting server for every client
    try:
        while True:
            conn, addr = soc.accept()
            # assign ip and port
            ip, port = str(addr[0]), str(addr[1])
            print('Accepting connection from ' + ip + ':' + port)
            try:
                Thread(target=client_thread, args=(conn, ip, port,)).start()
            except:
                print("Terrible error!")
                traceback.print_exc()
    except:
        pass
    soc.close()
    return

start_server()  
