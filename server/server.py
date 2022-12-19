import socket
from stegano import exifHeader as stg
from Crypto.Cipher import AES
from Crypto import Random 
from base64 import b64encode
from base64 import b64decode
import cv2
from tkinter.filedialog import *
from tkinter import *
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
#Secret Data Transfer using Steganography and Hybrid Encryption

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
    decipher = AES.new(hkey, AES.MODE_ECB)
    pt = decipher.decrypt(msg).decode('utf-8')
    pad_index = pt.find(PAD)
    result = pt[:pad_index]
    return result

def generate_aes_key():
    return Random.get_random_bytes(AES.key_size[0])

def writefile(msg):
    file1 = open(r"C:\Users\USER\Desktop\CLI FYP\server\Plain Message.txt","w+")
    file1.write(msg)

def writefileEn(enc_msg):
    file2 = open(r"C:\Users\USER\Desktop\CLI FYP\server\Encrypted Message.txt","w+")
    file2.write(enc_msg)

def writekeyfile(aeskey):
    keyfile = open(r"C:\Users\USER\Desktop\CLI FYP\server\Public key.txt","wb")
    keyfile.write(aeskey)

def Encoder(img,enmsg):
    global stegimage
    stegimage = stg.hide(img,r"C:\Users\USER\Desktop\CLI FYP\server\stego.jpg",enmsg)

def Decoder(steg):
    Message=stg.reveal(steg)
    return Message


server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('',8888))
server_socket.listen(5)
print("\nListen for connection")

while(1):
    client, addr = server_socket.accept()
    print("\n\n ------------CONNECTION----------------\n")
    print("\nConnection to ", str(addr), "Established")
    #---------------------------PRIVATE AND PUBLIC KEY RSA PROCESS ----------------------------------
    print("\nGenerating Public key and Private key")
    key = RSA.generate(2048)

    private_key = key.export_key()
    public_key = key.public_key().export_key()
    print(f'\nPrivate key : {private_key} \nPublic key : {public_key}')

    
    # public_key, private_key = generating_keys()
    print("\n\n ------------RSA PUBLIC KEY EXCHANGE----------------\n")
    print(f"\nThis is server public key : {public_key}")
    # valid_secret_message = private_key_digital_signature(private_key)
    # client_public_key = client.recv(65000) #RECV 1
    # client_public_key_received = eval(client_public_key.decode("utf-8"))
    # print(f"Client Public Key : {client_public_key_received}")
    # client.send(str(public_key).encode()) #SEND 1

    print("\nThis is Stego-HyCrypto System \n\nPlease Enter your message")
    msg = input("Message > ")
    writefile(msg)
    print("\nSelect AES key generate option : \n1.Enter your own key \n2.Generate random key")
    option = str(input("\nOption > "))
    if(option=="1"):
        password = input("\nEnter password: \n> ")
        hash_obj=SHA256.new(password.encode("utf-8"))
        hkey = hash_obj.digest()
        print("\n\n ------------SERVER PUBLIC KEY----------------\n")
        print("\nPublic key for the session : \n>",hkey)
        print("\nType of this key : ",type(hkey))
    
        # encryptedhkey = encrypt(hkey, client_public_key_received) #str
        # print("\n This is AES encrypted key : ", encryptedhkey)
        # print("\n Type of this encrypted key : ", type(encryptedhkey))
        # writekeyfile(encryptedhkey)
        # client.send(bytes(str(encryptedhkey),"utf-8"))
        client.send(hkey)
    else:
        print("\nGenerate new key . . .")
        hkey = generate_aes_key()
        print("The public key for the session : \n>",hkey,"\n\nThe key written in the file")
        writekeyfile(hkey)
        client.send(hkey)
        
    print("\n\n ------------ENCRYPTING THE MESSAGE ----------------\n")
    print("\n\nEncrypting your message . . . ")
    enc_msg = encryptAES(msg,hkey)
    print("\nYour message :\n>",msg)
    print("\nEncrypted message :\n>",enc_msg)
    writefileEn(str(enc_msg))
    print("\n\n ------------SELECT IMAGE ----------------\n")
    print("\nStep 3 - Enter the image path : ")
    img_input = input("Enter path > ")
    img = cv2.imread(img_input)
    print("\n\nYou want to see the image first : \n1. Yes \n2. No")
    yn = int(input("\n> "))
    if(yn==1):
        cv2.imshow('duck-original', img)
        cv2.waitKey(0)    
        cv2.destroyAllWindows()
    else:
        pass

    print("\n\n ------------EMBED DATA INTO IMAGE AND SEND ----------------\n")
    Encoder(img_input,enc_msg)
    # print("\n\nStep 4 - Select stego image to decode : ")
    # stego_input =input("Enter Path > ")
    # steg = cv2.imread(r"C:\Users\USER\Desktop\CLI FYP\server\stego.jpg")
    file= open(r"C:\Users\USER\Desktop\CLI FYP\server\stego.jpg",'rb')
    image_data= file.read(32768) 
    # cv2.imshow('duck-stega', steg)
    # cv2.waitKey(0)    
    # cv2.destroyAllWindows()

    while (image_data):
        client.send(image_data)
        image_data = file.read(32768)
        
    print("\nStego Media Sent Successfully!")
    file.close()

    # file = open(r"C:\Users\USER\Desktop\CLI FYP\socket\duck.jpg","rb")
    # m = file.read(2048)
    # client.sendall(m)
    # file.close()

    # de_msg = Decoder(stego_input)
    # print("\nExtracted Message : \n>",de_msg)

    # dec_msg = decryptAES(de_msg,hkey)
    # print("\nDecrypting using AES key . . . ")
    # print("\nDecrypted Text : \n>",dec_msg)

client.close()



    