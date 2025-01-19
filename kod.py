from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.backends import default_backend
import os
import base64

# Funkcja do wyprowadzania klucza z hasła i soli
def derive_key(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Funkcja szyfrowania wiadomości
def encrypt_message(message: str, password: str) -> (str, str, str):
    salt = os.urandom(16)
    key = derive_key(password, salt)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message.encode()) + padder.finalize()
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    return base64.b64encode(salt).decode(), base64.b64encode(iv).decode(), base64.b64encode(ciphertext).decode()

# Funkcja brute force
def brute_force_attack(ciphertext: str, salt: str, iv: str):
    ciphertext = base64.b64decode(ciphertext)
    salt = base64.b64decode(salt)
    iv = base64.b64decode(iv)

    # Lista haseł do sprawdzenia: cyfry od 0 do 999
    wordlist = [str(i).zfill(3) for i in range(1000)]

    for password in wordlist:
        try:
            key = derive_key(password, salt)
            cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
            decryptor = cipher.decryptor()
            padded_message = decryptor.update(ciphertext) + decryptor.finalize()

            # Usunięcie paddingu
            unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
            message = unpadder.update(padded_message) + unpadder.finalize()

            # Sprawdzanie, czy wiadomość jest czytelnym tekstem
            decoded_message = message.decode()
            print(f"Znaleziono haslo: {password}")
            print(f"Odszyfrowana wiadomosc: {decoded_message}")
            return
        except (Exception, UnicodeDecodeError):
            pass

    print("Atak brute force nie powiodl sie. Haslo nie jest w przedziale 0 - 999.")

# Main program
def main():
    print("Demonstracja enkrypcji AES i ataku brute force.")
    
    # Przykładowa wiadomość i hasło
    original_message = "This is a secret message."
    correct_password = "957"
    
    # Szyfrowanie wiadomości
    salt, iv, ciphertext = encrypt_message(original_message, correct_password)
    
    print("\nZaszyfrowane dane:")
    print(f"Salt: {salt}")
    print(f"IV: {iv}")
    print(f"Ciphertext: {ciphertext}")

    print("\nRozpoczynam atak brute force...")
    brute_force_attack(ciphertext, salt, iv)

if __name__ == "__main__":
    main()