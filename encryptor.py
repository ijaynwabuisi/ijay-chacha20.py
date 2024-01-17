import logging
import os
import sys
import random
import zlib
from Crypto.Cipher import ChaCha20
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256

# Configure logging
logging.basicConfig(filename='crypto_activity.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

def get_file_hash(data):
    hash_obj = SHA256.new(data)
    return hash_obj.hexdigest()

def derive_key(password: str, salt: bytes):
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

def secure_delete(file_path):
    try:
        with open(file_path, "r+b") as file:
            length = os.path.getsize(file_path)
            for _ in range(10):
                file.seek(0)
                file.write(bytes(random.getrandbits(8) for _ in range(length)))
        os.remove(file_path)
        logging.info(f"Securely deleted original file: {file_path}")
    except Exception as e:
        logging.error(f"Error during secure deletion of file '{file_path}': {e}")

def is_valid_file(file_path):
    return os.path.isfile(file_path)

def validate_password(password):
    return len(password) >= 5

def encrypt_file(file_path: str, password: str):
    try:
        salt = get_random_bytes(16)
        key = derive_key(password, salt)
        cipher = ChaCha20.new(key=key)

        with open(file_path, 'rb') as file:
            file_data = file.read()

        compressed_data = zlib.compress(file_data)
        original_hash = get_file_hash(file_data)
        logging.info(f"Original file hash before encryption: {original_hash}")

        hmac = HMAC.new(key, digestmod=SHA256)
        hmac.update(compressed_data)
        hmac_digest = hmac.digest()

        ciphertext = cipher.encrypt(compressed_data)
        encrypted_hash = get_file_hash(ciphertext)
        logging.info(f"Encrypted file hash: {encrypted_hash}")

        encrypted_file_path = file_path + ".enc"
        with open(encrypted_file_path, 'wb') as encrypted_file:
            encrypted_file.write(salt)
            encrypted_file.write(hmac_digest)
            encrypted_file.write(cipher.nonce)
            encrypted_file.write(ciphertext)

        print(f"File encrypted successfully as {encrypted_file_path}")
        logging.info(f"File '{file_path}' encrypted successfully as '{encrypted_file_path}'")
    except Exception as e:
        print(f"An error occurred: {e}")
        logging.error(f"Encryption failed for file '{file_path}': {e}")
    finally:
        secure_delete(file_path)

if len(sys.argv) != 3:
    print("Usage: python encryptor.py [file_path] [password]")
    sys.exit(1)

file_path = sys.argv[1]
password = sys.argv[2]

if not is_valid_file(file_path):
    print(f"Error: The file '{file_path}' does not exist or is not a file.")
    sys.exit(1)

if not validate_password(password):
    print("Error: The password must be at least 5 characters long.")
    sys.exit(1)

encrypt_file(file_path, password)
