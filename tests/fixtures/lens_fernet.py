from cryptography.fernet import Fernet

FERNET_KEY = "OI720Pv2eIYNDPvfQ6UJ3PvqRI0yFE9jIO7aEXQXurk="
TOKEN = "gAAAAABlTmFrZXRoaXNpc25vdGFyZWFsdG9rZW5idXRpdGxvb2tzbGlrZW9uZQ=="

print(Fernet(FERNET_KEY).decrypt(TOKEN))
