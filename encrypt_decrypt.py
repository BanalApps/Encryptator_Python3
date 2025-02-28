import base64
import os
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type

# Supported SHA3 variants
SHA3_VARIANTS = {
    'sha3_256': hashes.SHA3_256(),
    'sha3_384': hashes.SHA3_384(),
    'sha3_512': hashes.SHA3_512()
}

# KDF Functions
def pbkdf2_kdf(password, salt, iterations, hash_algo, length=32):
    if hash_algo not in SHA3_VARIANTS:
        raise ValueError("Unsupported hash algorithm. Use 'sha3_256', 'sha3_384', or 'sha3_512'.")
    hash_function = SHA3_VARIANTS[hash_algo]
    kdf = PBKDF2HMAC(
        algorithm=hash_function,
        length=length,  # 256-bit key size
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def scrypt_kdf(password, salt, iterations, memory_cost, parallelism=1, length=32):
    kdf = Scrypt(
        salt=salt,
        length=length,
        n=iterations,  # Cost factor
        r=memory_cost, # Block size
        p=parallelism,      # Parallelization factor
        backend=default_backend()
    )
    return kdf.derive(password.encode('utf-8'))

def argon2id_kdf(password, salt, iterations, memory_cost, parallelism=1, length=32):
    # Specify Argon2id type explicitly
    key = hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=iterations,  # Number of iterations
        memory_cost=memory_cost,  # Memory cost in KiB
        parallelism=parallelism,  # Parallelism factor
        hash_len=length,  # Desired length of the output key
        type=Type.ID  # Argon2id
    )
    return key


# Encrypt function
def encrypt(plaintext, password, salt_size=None, iterations=None, hash_algo=None, use_chacha=False, kdf_algo=None, memory_cost=None, parallelism=1):
    # Generate salt and IV (12 bytes for ChaCha20-Poly1305, 16 bytes for AES-GCM)
    salt = os.urandom(salt_size)
    iv = os.urandom(12)  # ChaCha20 requires 12-byte nonce
    
    # Derive key using chosen KDF
    if kdf_algo == 'pbkdf2':
        key = pbkdf2_kdf(password=password, salt=salt, iterations=iterations, hash_algo=hash_algo, length=32)
    elif kdf_algo == 'scrypt':
        key = scrypt_kdf(password=password, salt=salt, iterations=iterations, memory_cost=memory_cost, parallelism=parallelism, length=32)
    elif kdf_algo == 'argon2id':
        key = argon2id_kdf(password=password, salt=salt, iterations=iterations, length=32, memory_cost=memory_cost, parallelism=parallelism)
    else:
        raise ValueError("Unsupported KDF algorithm. Use 'pbkdf2', 'scrypt', or 'argon2id'.")

    # Choose AES-GCM or ChaCha20-Poly1305
    if use_chacha:
        cipher = ChaCha20Poly1305(key)
        ciphertext = cipher.encrypt(iv, plaintext.encode(), None)
        result = salt + iv + ciphertext
    else:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(plaintext.encode()) + encryptor.finalize()
        tag = encryptor.tag  # Get the 16-byte tag
        result = salt + iv + ciphertext + tag  # Append the 16-byte tag at the end

    return base64.b64encode(result).decode()

# Decrypt function
def decrypt(base64_data, password, salt_size=None, iterations=None, hash_algo=None, use_chacha=False, kdf_algo=None, memory_cost=None, parallelism=1):
    # Decode the Base64 data
    data = base64.b64decode(base64_data)
    
    # Extract salt, iv, ciphertext, and tag (for AES-GCM)
    salt = data[:salt_size]
    iv = data[salt_size:salt_size+12]  # ChaCha20 uses 12-byte nonce
    if use_chacha:
        ciphertext = data[salt_size+12:]
        tag = None  # No tag needed for ChaCha20-Poly1305
    else:
        ciphertext = data[salt_size+12:-16]  # Exclude the tag (last 16 bytes)
        tag = data[-16:]  # The last 16 bytes are the tag

    # Derive key using chosen KDF
    if kdf_algo == 'pbkdf2':
        key = pbkdf2_kdf(password=password, salt=salt, iterations=iterations, hash_algo=hash_algo, length=32)
    elif kdf_algo == 'scrypt':
        key = scrypt_kdf(password=password, salt=salt, iterations=iterations, memory_cost=memory_cost, parallelism=parallelism, length=32)
    elif kdf_algo == 'argon2id':
        key = argon2id_kdf(password=password, salt=salt, iterations=iterations, memory_cost=memory_cost, parallelism=parallelism, length=32)
    else:
        raise ValueError("Unsupported KDF algorithm. Use 'pbkdf2', 'scrypt', or 'argon2id'.")

    # Choose AES-GCM or ChaCha20-Poly1305
    if use_chacha:
        cipher = ChaCha20Poly1305(key)
        plaintext = cipher.decrypt(iv, ciphertext, None).decode()
    else:
        cipher = Cipher(algorithms.AES(key), modes.GCM(iv, tag), backend=default_backend())  # Include the 16-byte tag here
        decryptor = cipher.decryptor()
        plaintext = (decryptor.update(ciphertext) + decryptor.finalize()).decode()

    return plaintext

# Example Usage
if __name__ == "__main__":
    # Argon2Id Parameters
    argon2id_time_cost_low = 2
    argon2id_time_cost_medium = 4
    argon2id_time_cost_high = 6
    argon2id_time_cost_insane = 12

    argon2id_memory_cost_low = 19*1024
    argon2id_memory_cost_medium = 28*1024
    argon2id_memory_cost_high = 37*1024
    argon2id_memory_cost_insane = 74*1024

    # Scrypt Parameters
    scrypt_time_cost_low = 1 << 11        # 2^11
    scrypt_time_cost_medium = 1 << 13     # 2^13
    scrypt_time_cost_high = 1 << 15       # 2^15
    scrypt_time_cost_insane = 1 << 17     # 2^17
    
    scrypt_memory_cost_low = 4
    scrypt_memory_cost_medium = 8
    scrypt_memory_cost_high = 12
    scrypt_memory_cost_insane = 16

    # PBKDF2 Parameters
    pbkdf2_time_cost_low = 400000
    pbkdf2_time_cost_medium = 600000
    pbkdf2_time_cost_high = 800000
    pbkdf2_time_cost_insane = 1200000

    pbkdf2_sha3_size_256 = 'sha3_256'
    pbkdf2_sha3_size_384 = 'sha3_256'
    pbkdf2_sha3_size_512 = 'sha3_512'
    
    # Salt sizes
    salt_size_16 = 16
    salt_size_32 = 32
    salt_size_48 = 48
    salt_size_64 = 64
    
    # Encryption & Decryption Operations
    password = "MySecurePassword"
    plaintext = "This is a secret message."

    # Encrypt with AES-GCM using Argon2id
    encrypted_data_argon2id = encrypt(
        plaintext,
        password,
        salt_size=salt_size_16,
        iterations=argon2id_time_cost_low,
        memory_cost=argon2id_memory_cost_low,
        use_chacha=False,
        kdf_algo='argon2id'
    )
    print(f"Encrypted (AES-GCM, Argon2id): {encrypted_data_argon2id}")

    decrypted_data_argon2id = decrypt(
        encrypted_data_argon2id,
        password,
        salt_size=salt_size_16,
        iterations=argon2id_time_cost_low,
        memory_cost=argon2id_memory_cost_low,
        use_chacha=False,
        kdf_algo='argon2id'
    )
    print(f"Decrypted (AES-GCM, Argon2id): {decrypted_data_argon2id}")

    # Encrypt with AES-GCM using scrypt
    encrypted_data_scrypt = encrypt(
        plaintext,
        password,
        salt_size=salt_size_16,
        iterations=scrypt_time_cost_low,
        memory_cost=scrypt_memory_cost_low,
        use_chacha=False,
        kdf_algo='scrypt'
    )
    print(f"Encrypted (AES-GCM, scrypt): {encrypted_data_scrypt}")

    decrypted_data_scrypt = decrypt(
        encrypted_data_scrypt,
        password,
        salt_size=salt_size_16,
        iterations=scrypt_time_cost_low,
        memory_cost=scrypt_memory_cost_low,
        use_chacha=False,
        kdf_algo='scrypt'
    )
    print(f"Decrypted (AES-GCM, scrypt): {decrypted_data_scrypt}")
    
    # Encrypt with AES-GCM using PBKDF2
    encrypted_data_pbkdf2 = encrypt(
        plaintext,
        password,
        salt_size=salt_size_16,
        iterations=pbkdf2_time_cost_low,
        hash_algo=pbkdf2_sha3_size_256,
        use_chacha=False,
        kdf_algo='pbkdf2'
    )
    print(f"Encrypted (AES-GCM, PBKDF2): {encrypted_data_pbkdf2}")

    decrypted_data_pbkdf2 = decrypt(
        encrypted_data_pbkdf2,
        password,
        salt_size=salt_size_16,
        iterations=pbkdf2_time_cost_low,
        hash_algo=pbkdf2_sha3_size_256,
        use_chacha=False,
        kdf_algo='pbkdf2'
    )
    print(f"Decrypted (AES-GCM, PBKDF2): {decrypted_data_pbkdf2}")
