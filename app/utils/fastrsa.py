from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
import time

#TODO: Изменить добавление ключей в файл, ускорить работу

# Генерация ключей RSA с длиной 8192 бит
def generate_rsa_keys(bits=1024):
    print("Generating RSA keys...")
    start_time = time.time()
    key = RSA.generate(bits)
    private_key = key.export_key()
    public_key = key.publickey().export_key()
    end_time = time.time()
    print(f"Keys generated in {end_time - start_time:.2f} seconds.")
    return private_key, public_key

# Шифрование данных
def encrypt_message(public_key, message):
    rsa_key = RSA.import_key(public_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_message = cipher.encrypt(message)
    return encrypted_message

# Расшифрование данных
def decrypt_message(private_key, encrypted_message):
    rsa_key = RSA.import_key(private_key)
    cipher = PKCS1_OAEP.new(rsa_key)
    decrypted_message = cipher.decrypt(encrypted_message)
    return decrypted_message

# Пример использования
if __name__ == "__main__":
    private_key, public_key = generate_rsa_keys()

    # Сохранение ключей в файлы
    with open("private_key.pem", "wb") as priv_file:
        priv_file.write(private_key)
    with open("public_key.pem", "wb") as pub_file:
        pub_file.write(public_key)

    print("Keys saved to 'private_key.pem' and 'public_key.pem'.")

    # Шифрование сообщения
    message = b"Hello, this is a test message!"
    print(f"Original message: {message}")
    encrypted_message = encrypt_message(public_key, message)
    print(f"Encrypted message: {encrypted_message.hex()}")

    # Расшифрование сообщения
    decrypted_message = decrypt_message(private_key, encrypted_message)
    print(f"Decrypted message: {decrypted_message}")
