import os

salt = os.urandom(16)
file = open("salt", "wb")
file.write(salt)
file.close()
