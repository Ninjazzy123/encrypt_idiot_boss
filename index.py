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

    # Decrypt sample file
    decrypted_data = decrypt_file(old_private_key, "user_profiles/aaron_diaz.bin")

    # Encrypt
    encrypted_data = encrypt_file(new_public_key, decrypted_data, "new_user_profiles/aaron_diaz_new.bin")

    print("Decryption and encryption completed.")

if __name__ == "__main__":
    main()
