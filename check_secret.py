import os
from dotenv import load_dotenv


load_dotenv()

if not os.getenv("SECRET_KEY"):
    print("ERROR: Secret key not found")
    exit(1)

print("Secret key found, OK!")
