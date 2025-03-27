import os
from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.Util.Padding import pad, unpad

# Function for modular exponentiation (used in Diffie-Hellman)
def mod_exp(base, exp, mod):
    return pow(base, exp, mod)

# Step 1: Classic Diffie-Hellman Key Exchange
p = int(input("Enter a prime number (p): "))  # Prime number
g = int(input("Enter a primitive root (g): "))  # Primitive root

private_key_A = int(input("Alice, enter your private key: "))  # Alice's private key
private_key_B = int(input("Bob, enter your private key: "))  # Bob's private key

public_key_A = mod_exp(g, private_key_A, p)  # A = g^a % p
public_key_B = mod_exp(g, private_key_B, p)  # B = g^b % p

shared_secret_A = mod_exp(public_key_B, private_key_A, p)  # B^a % p
shared_secret_B = mod_exp(public_key_A, private_key_B, p)  # A^b % p
print("shared key: ",shared_secret_A)

assert shared_secret_A == shared_secret_B, "Key mismatch!"  # Verify same key

# Convert shared secret to 128-bit AES key
session_key = SHA512.new(str(shared_secret_A).encode()).digest()[:16]

# Step 2: Compute Hash of the Message
def compute_hash(message):
    hash_obj = SHA512.new()
    hash_obj.update(message.encode())
    return hash_obj.digest()  # 32-byte hash

# Step 3: Encrypt (Message + Hash) using AES
def encrypt_message(session_key, message):
    hash_code = compute_hash(message)
    combined_data = message + "@@" + hash_code.hex()  # Append hash to message
    print("\nBefore Encryption:", combined_data)  # Print in readable format

    cipher = AES.new(session_key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(pad(combined_data.encode(), AES.block_size))
    return cipher.iv + ciphertext  # Prepend IV for decryption

# Step 4: Decrypt and Verify Integrity
def decrypt_message(session_key, encrypted_data):
    iv = encrypted_data[:16]  # Extract IV
    ciphertext = encrypted_data[16:]
    cipher = AES.new(session_key, AES.MODE_CBC, iv)
    decrypted_data = unpad(cipher.decrypt(ciphertext), AES.block_size).decode()

    # Step 5: Extract Message and Hash
    message, received_hash = decrypted_data.rsplit("@@", 1)  # Split message and hash

    print("\nAfter Decryption:", message + "@@" + received_hash)  # Print in readable format

    # Step 6: Integrity Check
    expected_hash = compute_hash(message).hex()
    if received_hash == expected_hash:
        print("Integrity Check Passed ")
        return message
    else:
        print("Integrity Check Failed ")
        return None

# Encrypt Message
message = input("Enter text: ")
encrypted_data = encrypt_message(session_key, message)
print("Encrypted Data:", encrypted_data.hex())

# Decrypt and Verify
decrypted_message = decrypt_message(session_key, encrypted_data)
if decrypted_message:
    print("Final Decrypted Message:", decrypted_message)
