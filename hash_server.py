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

# Decrypt and verify integrity
def decrypt_message(session_key, encrypted_data):
    iv, ciphertext = encrypted_data[:16], encrypted_data[16:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    message, received_hash = decrypted_data.rsplit("@@", 1)
    expected_hash = compute_hash(message).hex()

    print("\nAfter Decryption:", decrypted_data)
    if received_hash == expected_hash:
        print("Integrity Check Passed")
        return message
    else:
        print("Integrity Check Failed")
        return None

# Server Setup
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 12345))
server_socket.listen(1)
print("Waiting for connection...")

conn, _ = server_socket.accept()
p, g, client_public_key = map(int, conn.recv(1024).decode().split(","))
private_key = int(input("Bob, enter your private key: "))  # Server (Bob) Private Key
public_key = mod_exp(g, private_key, p)
conn.send(str(public_key).encode())

shared_secret = mod_exp(client_public_key, private_key, p)
session_key = SHA512.new(str(shared_secret).encode()).digest()[:16]

print("Shared Key:", session_key.hex())

# Receive encrypted message
encrypted_data = conn.recv(1024)
message = decrypt_message(session_key, encrypted_data)
if message:
    print("Final Decrypted Message:", message)

conn.close()
server_socket.close()
