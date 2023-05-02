import binascii
import secrets
import hashlib
import os
import bcrypt

class Random_generator:

    # generates a random token
    # let's keep the simple default alphabet since 
    # are working with 'not complex' passwords (as per level description)
    def generate_token(self, length=8, alphabet=(
    '0123456789'
    'abcdefghijklmnopqrstuvwxyz'
    'ABCDEFGHIJKLMNOPQRSTUVWXYZ' 
    )):
        # The secrets module in Python is designed to generate cryptographically secure random numbers and strings, 
        # suitable for use in security-sensitive applications. Unlike the random module, it uses a secure source of entropy, 
        # ensuring that generated values are unpredictable and statistically random.
        return ''.join(secrets.choice(alphabet) for i in range(length))

    # In this case is a mistake to run away from pre-built security libraries,
    # like bcrypt, hashlib, cryptography, etc..
    # Bcrypt is already being used in another method and it provides built-in salt generation and additional security features such 
    # as a variable cost factor and adaptive hash function, which make it more secure and reliable than implementing salt on your own.
    # ROUNDS -- >>  The salt used in the code should be unique and unpredictable. It's recommended to use a randomly generated salt for each password and store it alongside the hashed password.
    def generate_salt(self):
        salt = bcrypt.gensalt()
        return salt

class SHA256_hasher:
    # While SHA-256 is a secure hashing algorithm, it's generally 
    # recommended to use a dedicated password hashing algorithm such as Argon2, scrypt, or bcrypt. 

    # produces the password hash by combining password + salt because hashing
    def password_hash(self, password, salt):
        # Validate input
        if not password:
            raise ValueError("Password cannot be empty")

        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = bcrypt.hashpw(password, salt)
        return password_hash.decode('ascii')

    # verifies that the hashed password reverses to the plain text version on verification
    def password_verification(self, password, password_hash):
        # Validate input
        if not password or not password_hash:
            return False

        password = binascii.hexlify(hashlib.sha256(password.encode()).digest())
        password_hash = password_hash.encode('ascii')
        return bcrypt.checkpw(password, password_hash)

class MD5_hasher:
    
    # same as above but using a different algorithm to hash which is MD5
    def password_hash(self, password):
        # Validate input
        if not password:
            return False

        return hashlib.md5(password.encode()).hexdigest()

    def password_verification(self, password, password_hash):
        # Validate input
        if not password or not password_hash:
            return False

        password = self.password_hash(password)
        return secrets.compare_digest(password.encode(), password_hash.encode())    

# a collection of sensitive secrets necessary for the software to operate
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
PUBLIC_KEY = os.environ.get('PUBLIC_KEY')
SECRET_KEY = 'TjWnZr4u7x!A%D*G-KaPdSgVkXp2s5v8'
PASSWORD_HASHER = 'MD5_hasher'
