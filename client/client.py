import socket
import os
import sys
from stegano import exifHeader as stg
from Crypto.Cipher import AES
from Crypto import Random 
from base64 import b64encode
from base64 import b64decode
import json
import cv2
#Secret Data Transfer using Steganography and Hybrid Encryption
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from RSA import *

def encryptAES(info,key):
    msg = info
    BLOCK_SIZE = 16
    PAD = "("
    padding = lambda s: s +(BLOCK_SIZE - len(s)% BLOCK_SIZE)*PAD
    cipher = AES.new(key, AES.MODE_ECB)
    result = cipher.encrypt(padding(msg).encode('utf-8'))
    return result

def decryptAES(info,key):
    msg = info
    PAD = "("
    decipher = AES.new(key, AES.MODE_ECB)
    pt = decipher.decrypt(msg).decode('utf-8')
    pad_index = pt.find(PAD)
    result = pt[:pad_index]
    return result

def generate_aes_key():
    return Random.get_random_bytes(AES.key_size[0])

def writefile(msg):
    file1 = open(r"C:\Users\USER\Desktop\CLI FYP\LSB\Plain Message.txt","w+")
    file1.write(msg)

def writefileEn(enc_msg):
    file2 = open(r"C:\Users\USER\Desktop\CLI FYP\LSB\Encrypted Message.txt","w+")
    file2.write(enc_msg)

def writekeyfile(aeskey):
    keyfile = open(r"C:\Users\USER\Desktop\CLI FYP\LSB\Public key.txt","wb")
    keyfile.write(aeskey)

def Encoder(img,enmsg):
    global stegimage
    stegimage = stg.hide(img,r"C:\Users\USER\Desktop\CLI FYP\LSB\stego.jpg",enmsg)

def Decoder(steg):
    Message=stg.reveal(steg)
    return Message

s = socket.socket()

host = '127.0.0.1'
port = 8888

s.connect((host, port))
print("\n\n ------------CONNECTION----------------\n")

print(f"\nConnected to {host} on port {str(port)}")

#---------------------------PRIVATE AND PUBLIC KEY RSA PROCESS ----------------------------------
print("\nGenerating Public key and Private key")
public_key, private_key = generating_keys()
print("\n\n ------------RSA PUBLIC KEY EXCHANGE----------------\n")
print(f"\nThis is server public key : {public_key}")
valid_secret_message = private_key_digital_signature(private_key)


s.send(str(public_key).encode()) #SEND 1
server_public_key_received = s.recv(65000) #RECV 1
server_public_key = eval(server_public_key_received.decode("utf-8"))
print(f"Server Public Key : {server_public_key}\n")
s.send(bytes(str(valid_secret_message),"utf-8")) #SEND 2
server_valid_secret_message = s.recv(65000) #RECV 2
print("\n\n ------------RSA VALIDATION MESSAGE----------------\n")
valid_secret_message_received = str(server_valid_secret_message,"utf-8")
is_valid = validating_digital_signature(valid_secret_message_received,server_public_key)
print(is_valid)
#---------------------------PRIVATE AND PUBLIC KEY RSA PROCESS ----------------------------------

print("\n\n ------------STEGO-HYCRYPTO SYSTEM----------------\n")
print("\nThis is Stego-HyCrypto Tool \n")
# keyrecv = s.recv(65000) #bytes
hkey = s.recv(65000)
# encryptedhkey = str(keyrecv,"utf-8") 
print("\n\n ------------PUBLIC KEY FROM SERVER----------------\n")
# print("\nReceived the Encrypted AES key from server : \n>",encryptedhkey)
print("\nReceived the  AES key from server : \n>",hkey)
# hkey = decrypt(encryptedhkey,private_key)
# aeskey = hkey.encode("utf-8")
# print("\nAES key : ",hkey)
print("\n Type of this AES key : ",type(hkey))


filepath = r"C:\Users\USER\Desktop\CLI FYP\client\stego.jpg"
file= open(r"C:\Users\USER\Desktop\CLI FYP\client\stego.jpg","wb")
condition = True
print("\n\n ------------RECEIVE STEGO IMAGE FROM SERVER ----------------\n")
print("\nReceiving Stego Media from . . .")
while condition:
    image_chunk = s.recv(32768)
    if str(image_chunk=="b''"):
        condition = False
    file.write(image_chunk)
    print("\nStego Media Received from server")

    print("\n\n ------------EXTRACT MESSAGE FROM STEG IMAGE ----------------\n")
    stegpath = input("\nEnter Stego Image path > ")

# while True:
#     m = s.recv(2048)
#     file.write(m)
#     file.close()
    print("\nExtracting message from stego media . . .")
    de_msg = Decoder(stegpath)
    print("\nEncrypted message Retrieved from image : \n>", de_msg)
    dec_msg = decryptAES(de_msg,hkey)
    print("\nPlaintext message Retrieved from image : \n>", dec_msg)




