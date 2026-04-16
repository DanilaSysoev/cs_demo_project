from cryptography.fernet import Fernet

key = Fernet.generate_key()

print(f"Key: {key.decode()}")

data = input("Enter text for encryption:\n")

if data:
    secret = Fernet(key).encrypt(data.encode())
    print(f"Encrypted data: {secret.decode()}")
    print(f"Decrypted data: {Fernet(key).decrypt(secret).decode()}")
else:
    print("Text can't be empty")
