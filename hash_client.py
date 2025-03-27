import socket
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad

# Function for modular exponentiation (Diffie-Hellman)
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

# Compute SHA-512 Hash
def compute_hash(message):
    return SHA512.new(message.encode()).digest()

# Encrypt message + hash using AES
def encrypt_message(session_key, message):
    hash_code = compute_hash(message).hex()
    combined_data = message + "@@" + hash_code

    cipher = AES.new(session_key, AES.MODE_CBC)
    return cipher.iv + cipher.encrypt(pad(combined_data.encode(), AES.block_size))

# Client Setup
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect(("localhost", 12345))

p = int(input("Enter a prime number (p): "))
g = int(input("Enter a primitive root (g): "))
private_key = int(input("Alice, enter your private key: "))  # Client (Alice) Private Key
public_key = mod_exp(g, private_key, p)

client_socket.send(f"{p},{g},{public_key}".encode())

server_public_key = int(client_socket.recv(1024).decode())
shared_secret = mod_exp(server_public_key, private_key, p)
session_key = SHA512.new(str(shared_secret).encode()).digest()[:16]

print("Shared Key:", session_key.hex())

# Send encrypted message
message = input("Enter text: ")
encrypted_message = encrypt_message(session_key, message)
print("\nEncrypted Data:", encrypted_message.hex())

client_socket.send(encrypted_message)
client_socket.close()
