from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import os

def load_key(filename, private=False):
    with open(filename, "rb") as key_file:
        key_data = key_file.read()
        if private:
            return serialization.load_pem_private_key(
                key_data,
                password=None,
            )
        else:
            return serialization.load_pem_public_key(
                key_data,
            )

def decrypt_file(private_key, file_path):
    with open(file_path, "rb") as file:
        encrypted_data = file.read()
    decryptor = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decryptor

def encrypt_file(public_key, data, file_path):
    encrypted_data = public_key.encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    with open(file_path, "wb") as file:
        file.write(encrypted_data)

def main():
    old_private_key = load_key("old_private_key.pem", private=True)
    new_public_key = load_key("new_public_key.pem")

    os.makedirs("new_user_profiles", exist_ok=True)

    # Loopi
    for filename in os.listdir("user_profiles"):
        if filename.endswith(".bin"):
            # Extracts nam
            username = filename.split('.')[0]
            # Decrypt file
            decrypted_data = decrypt_file(old_private_key, f"user_profiles/{filename}")
            # Encrypt
            encrypt_file(new_public_key, decrypted_data, f"new_user_profiles/{username}.bin")

    print("Decryption and encryption of all files completed.")

if __name__ == "__main__":
    main()