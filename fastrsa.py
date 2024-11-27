import random
from gmpy2 import powmod
from Crypto.PublicKey import RSA
import time

def rsa_encrypt_fast(plaintext, public_key):
    e, n = public_key
    plaintext_int = int.from_bytes(plaintext.encode('utf-8'), byteorder='big')
    return powmod(plaintext_int, e, n)

def rsa_decrypt_fast(ciphertext, private_key):
    d, n = private_key
    plaintext_int = powmod(ciphertext, d, n)
    return plaintext_int.to_bytes((plaintext_int.bit_length() + 7) // 8, byteorder='big').decode('utf-8')

def main():
    # Генерация ключей с PyCryptodome
    print("Генерация ключей RSA...")
    key = RSA.generate(16384)
    public_key = (key.e, key.n)
    private_key = (key.d, key.n)

    # Шифрование
    message = "RSA-16384"
    print(f"Исходное сообщение: {message}")

    start_time = time.time()
    ciphertext = rsa_encrypt_fast(message, public_key)
    end_time = time.time()

    print(f"Зашифрованное сообщение: {ciphertext}")
    print(f"Время шифрования: {end_time - start_time:.6f} секунд")

    # Дешифрование
    start_time = time.time()
    decrypted_message = rsa_decrypt_fast(ciphertext, private_key)
    end_time = time.time()
    print(f"Расшифрованное сообщение: {decrypted_message}")
    print(f"Время дешифрования: {end_time - start_time:.6f} секунд")


if __name__ == "__main__":
    main()
