import logging
import os
import sys
import zlib
from Crypto.Cipher import ChaCha20
from Crypto.Protocol.KDF import scrypt
from Crypto.Hash import HMAC, SHA256

# Configure logging to record events and errors
logging.basicConfig(filename='crypto_activity.log', level=logging.INFO,
                    format='%(asctime)s - %(levelname)s - %(message)s')

# Function to compute SHA256 hash of data
def get_file_hash(data):
    hash_obj = SHA256.new(data)
    return hash_obj.hexdigest()

# Function to derive cryptographic key from a password using scrypt
def derive_key(password: str, salt: bytes):
    return scrypt(password, salt, key_len=32, N=2**14, r=8, p=1)

# Function to check if a file is a valid encrypted file
def is_valid_encrypted_file(file_path):
    return os.path.isfile(file_path) and file_path.endswith('.enc')

# Function to validate the length of the password
def validate_password(password):
    return len(password) >= 5

# Function to handle the decryption of a file
def decrypt_file(file_path: str, password: str):
    try:
        # Open and read the encrypted file
        with open(file_path, 'rb') as encrypted_file:
            salt = encrypted_file.read(16)  # Read salt
            stored_hmac = encrypted_file.read(32)  # Read stored HMAC
            nonce = encrypted_file.read(8)  # Read nonce
            ciphertext = encrypted_file.read()  # Read the ciphertext

            # Derive the key and decrypt the data
            key = derive_key(password, salt)
            cipher = ChaCha20.new(key=key, nonce=nonce)
            plaintext = cipher.decrypt(ciphertext)

            # Decompress the decrypted data
            decompressed_data = zlib.decompress(plaintext)
            decrypted_hash = get_file_hash(decompressed_data)

            # Verify HMAC for data integrity
            hmac = HMAC.new(key, digestmod=SHA256)
            hmac.update(plaintext)
            hmac.verify(stored_hmac)

            # Retrieve the original hash from the log file
            original_hash = ""
            with open('crypto_activity.log', 'r') as log_file:
                for line in log_file:
                    if "Original file hash before encryption" in line:
                        original_hash = line.split()[-1]
                        break

            # Check if the file has been tampered with
            if original_hash == decrypted_hash:
                print("The file has not been tampered with and the hash matches.")
                logging.info("Integrity check passed: The hash of the decrypted file matches the original file's hash.")
            else:
                print("WARNING: The file may have been tampered with after encryption.")
                logging.warning("Integrity check failed: The hash of the decrypted file does not match the original file's hash.")

            # Write the decrypted data to a file
            decrypted_file_path = file_path.replace(".enc", "")
            with open(decrypted_file_path, 'wb') as decrypted_file:
                decrypted_file.write(decompressed_data)

            print(f"File decrypted successfully as {decrypted_file_path}")
            logging.info(f"File '{file_path}' decrypted successfully as '{decrypted_file_path}'")
            return True
    except ValueError:
        # Handle incorrect password or corrupted file error
        print("Decryption failed: Incorrect password or corrupted file. Please try again.")
        logging.warning(f"Decryption failed for file '{file_path}': Incorrect password or corrupted file.")
        return False
    except zlib.error as e:
        # Handle decompression error
        print("Decompression error:", e)
        logging.error(f"Decompression failed for file '{file_path}': {e}")
        return False
    except Exception as e:
        # Handle other exceptions
        print(f"An error occurred: {e}")
        logging.error(f"Decryption failed for file '{file_path}': {e}")
        return False

# Check command-line arguments
if len(sys.argv) != 3:
    print("Usage: python decryptor.py [encrypted_file_path] [password]")
    sys.exit(1)

file_path = sys.argv[1]
password = sys.argv[2]

# Validate file and password
if not is_valid_encrypted_file(file_path):
    print(f"Error: The file '{file_path}' does not exist, is not a file, or has not been encrypted yet.")
    sys.exit(1)

if not validate_password(password):
    print("Error: The password must be at least 5 characters long.")
    sys.exit(1)

# Decrypt the file and handle the result
if decrypt_file(file_path, password):
    os.remove(file_path)  # Delete the .enc file after successful decryption
else:
    sys.exit(1)
