import time
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Util.Padding import pad


# Generate a key for AES and RSA
aes_key = b'1234567812345678'
rsa_key = RSA.generate(2048)

# Create an AES cipher
aes_cipher = AES.new(aes_key, AES.MODE_ECB)

# Create an RSA cipher
rsa_cipher = PKCS1_OAEP.new(rsa_key)

# Define the message to be encrypted
message = b'HADIFASIDFHSFSIDFAFF ADFASDLFSLFJ JLSA ADJFL DJF SLFKJDSF'
#pad the data
padded_data = pad(message,16)

# Encrypt the message with AES
aes_ciphertext = aes_cipher.encrypt(padded_data)

# Encrypt the AES key with RSA
rsa_ciphertext = rsa_cipher.encrypt(aes_key)

# Measure the time it takes to encrypt the message with the hybrid scheme
start_time = time.perf_counter()
hybrid_ciphertext = rsa_ciphertext + aes_ciphertext
hybrid_encrypt_time = time.perf_counter() - start_time

# Measure the time it takes to decrypt the message with the hybrid scheme
start_time = time.perf_counter()
rsa_plaintext = rsa_cipher.decrypt(rsa_ciphertext)

# Decrypt the AES key with RSA
aes_plaintext = rsa_cipher.decrypt(rsa_ciphertext)

# Create an AES cipher using the decrypted key
aes_decipher = AES.new(aes_plaintext, AES.MODE_ECB)

# Decrypt the ciphertext with AES
hybrid_plaintext = aes_decipher.decrypt(aes_ciphertext)
hybrid_decrypt_time = time.perf_counter() - start_time

# Print the results
print(f'Hybrid encryption time: {hybrid_encrypt_time:.6f} seconds')
print(f'Hybrid decryption time: {hybrid_decrypt_time:.6f} seconds')


