from cryptography.fernet import Fernet
import os
import docx2txt
import base64
import getpass
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

def generate_key_from_password(password):
    """Generate a Fernet key from a password"""
    # Generate a random salt
    salt = os.urandom(16)

    # Use PBKDF2 to derive a key from the password
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))

    # Save salt for later use
    with open('salt.key', 'wb') as salt_file:
        salt_file.write(salt)

    return key

def load_key_from_password(password):
    """Load or generate key from password"""
    try:
        # Load existing salt
        with open('salt.key', 'rb') as salt_file:
            salt = salt_file.read()

        # Regenerate key from password and salt
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key
    except FileNotFoundError:
        return generate_key_from_password(password)

def read_file_content(file_path):
    """Read content from either .txt or .docx file with Persian support"""
    file_extension = os.path.splitext(file_path)[1].lower()

    if file_extension == '.docx':
        text = docx2txt.process(file_path)
    else:
        with open(file_path, 'r', encoding='utf-8') as file:
            text = file.read()

    return text.encode('utf-8')

def encrypt_file(input_file, password, output_file=None):
    """Encrypt the input file using a password-derived key"""
    key = load_key_from_password(password)
    f = Fernet(key)

    if output_file is None:
        output_file = os.path.splitext(input_file)[0] + '.encrypted'

    try:
        file_data = read_file_content(input_file)
        encrypted_data = f.encrypt(file_data)

        with open(output_file, 'wb') as file:
            file.write(encrypted_data)

        print(f"File encrypted successfully! Saved as: {output_file}")
        return True

    except Exception as e:
        print(f"An error occurred during encryption: {str(e)}")
        return False

def decrypt_file(input_file, password, output_file=None):
    """Decrypt the input file using a password-derived key"""
    key = load_key_from_password(password)
    f = Fernet(key)

    if output_file is None:
        output_file = os.path.splitext(input_file)[0] + '_decrypted.txt'

    try:
        with open(input_file, 'rb') as file:
            encrypted_data = file.read()

        decrypted_data = f.decrypt(encrypted_data)

        with open(output_file, 'w', encoding='utf-8') as file:
            file.write(decrypted_data.decode('utf-8'))

        print(f"File decrypted successfully! Saved as: {output_file}")
        return True

    except Exception as e:
        print(f"An error occurred during decryption: {str(e)}")
        return False

def main():
    while True:
        print("\nSecure File Encryption/Decryption Tool (Persian Support)")
        print("1. Encrypt a file (.txt or .docx)")
        print("2. Decrypt a file (outputs as .txt)")
        print("3. Exit")

        choice = input("Enter your choice (1-3): ")

        if choice == '1':
            input_file = input("Enter the path to the file you want to encrypt (.txt or .docx): ")
            if os.path.exists(input_file):
                if input_file.lower().endswith(('.txt', '.docx')):
                    password = getpass.getpass("Enter encryption password: ")
                    confirm_password = getpass.getpass("Confirm password: ")
                    if password == confirm_password:
                        encrypt_file(input_file, password)
                    else:
                        print("Passwords don't match!")
                else:
                    print("Only .txt and .docx files are supported!")
            else:
                print("File not found!")

        elif choice == '2':
            input_file = input("Enter the path to the file you want to decrypt: ")
            if os.path.exists(input_file):
                password = getpass.getpass("Enter decryption password: ")
                decrypt_file(input_file, password)
            else:
                print("File not found!")

        elif choice == '3':
            print("Goodbye!")
            break

        else:
            print("Invalid choice! Please try again.")

if __name__ == "__main__":
    main()