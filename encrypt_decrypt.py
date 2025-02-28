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

    # Parallelism
    parallelism_argon2id = 1
    parallelism_scrypt = 1




    # Prompt for AES or ChaCha encryption
    print("Choose encryption algorithm:")
    print(f"1. AES")
    print(f"2. ChaCha20")
    cipher_choice = int(input("Enter the number of your choice: "))
    use_chacha = (cipher_choice == 2)

    # Prompt for salt size
    print("Choose salt size:")
    print(f"1. {salt_size_16} bytes")
    print(f"2. {salt_size_32} bytes")
    print(f"3. {salt_size_48} bytes")
    print(f"4. {salt_size_64} bytes")
    salt_choice = int(input("Enter the number of your choice: "))
    salt_size_options = {1: salt_size_16, 2: salt_size_32, 3: salt_size_48, 4: salt_size_64}
    salt_size = salt_size_options.get(salt_choice, salt_size_16)

    # Prompt for KDF function
    print("Choose KDF algorithm:")
    print(f"1. Argon2id")
    print(f"2. Scrypt")
    print(f"3. PBKDF2")
    kdf_choice = int(input("Enter the number of your choice: "))

    # Initialize KDF-specific parameters
    hash_algo = None
    memory_cost = None
    parallelism = None
    iterations = None

    # If Argon2id is chosen, prompt for time cost, memory cost, and parallelism
    if kdf_choice == 1:
        print("Choose time cost for Argon2id:")
        print(f"1. {argon2id_time_cost_low} iterations")
        print(f"2. {argon2id_time_cost_medium} iterations")
        print(f"3. {argon2id_time_cost_high} iterations")
        print(f"4. {argon2id_time_cost_insane} iterations")
        argon2id_time_choice = int(input("Enter the number of your choice: "))
        argon2id_time_options = {
            1: argon2id_time_cost_low,
            2: argon2id_time_cost_medium,
            3: argon2id_time_cost_high,
            4: argon2id_time_cost_insane,
        }
        iterations = argon2id_time_options.get(argon2id_time_choice, argon2id_time_cost_low)

        # Prompt for memory cost for Argon2id
        print("Choose memory cost for Argon2id:")
        print(f"1. {argon2id_memory_cost_low} MiB")
        print(f"2. {argon2id_memory_cost_medium} MiB")
        print(f"3. {argon2id_memory_cost_high} MiB")
        print(f"4. {argon2id_memory_cost_insane} MiB")
        argon2id_memory_choice = int(input("Enter the number of your choice: "))
        argon2id_memory_options = {
            1: argon2id_memory_cost_low,
            2: argon2id_memory_cost_medium,
            3: argon2id_memory_cost_high,
            4: argon2id_memory_cost_insane,
        }
        memory_cost = argon2id_memory_options.get(argon2id_memory_choice, argon2id_memory_cost_low)

        parallelism = parallelism_argon2id

    # If Scrypt is chosen, prompt for memory cost and iterations
    elif kdf_choice == 2:
        print("Choose number of iterations for Scrypt:")
        print(f"1. {scrypt_time_cost_low}")
        print(f"2. {scrypt_time_cost_medium}")
        print(f"3. {scrypt_time_cost_high}")
        print(f"4. {scrypt_time_cost_insane}")
        scrypt_iterations_choice = int(input("Enter the number of your choice: "))
        scrypt_iterations_options = {
            1: scrypt_time_cost_low,
            2: scrypt_time_cost_medium,
            3: scrypt_time_cost_high,
            4: scrypt_time_cost_insane,
        }
        iterations = scrypt_iterations_options.get(scrypt_iterations_choice, scrypt_time_cost_low)

        # Prompt for memory cost for Scrypt
        print("Choose memory cost for Scrypt:")
        print(f"1. {scrypt_memory_cost_low} MiB")
        print(f"2. {scrypt_memory_cost_medium} MiB")
        print(f"3. {scrypt_memory_cost_high} MiB")
        print(f"4. {scrypt_memory_cost_insane} MiB")
        scrypt_memory_choice = int(input("Enter the number of your choice: "))
        scrypt_memory_options = {
            1: scrypt_memory_cost_low,
            2: scrypt_memory_cost_medium,
            3: scrypt_memory_cost_high,
            4: scrypt_memory_cost_insane,
        }
        memory_cost = scrypt_memory_options.get(scrypt_memory_choice, scrypt_memory_cost_low)

        parallelism = parallelism_scrypt

    # If PBKDF2 is chosen, prompt for hash algorithm
    elif kdf_choice == 3:
        print("Choose hashing algorithm for PBKDF2:")
        print(f"1. {pbkdf2_sha3_size_256}")
        print(f"2. {pbkdf2_sha3_size_384}")
        print(f"3. {pbkdf2_sha3_size_512}")
        hash_choice = int(input("Enter the number of your choice: "))
        if hash_choice == 1:
            hash_algo = pbkdf2_sha3_size_256
        elif hash_choice == 2:
            hash_algo = pbkdf2_sha3_size_384
        elif hash_choice == 3:
            hash_algo = pbkdf2_sha3_size_512
        else:
            raise ValueError("Invalid choice for hashing algorithm.")

        # Prompt for PBKDF2 iterations
        print("Choose number of iterations for PBKDF2:")
        print(f"1. {pbkdf2_time_cost_low}")
        print(f"2. {pbkdf2_time_cost_medium}")
        print(f"3. {pbkdf2_time_cost_high}")
        print(f"4. {pbkdf2_time_cost_insane}")
        pbkdf2_iterations_choice = int(input("Enter the number of your choice: "))
        pbkdf2_iterations_options = {
            1: pbkdf2_time_cost_low,
            2: pbkdf2_time_cost_medium,
            3: pbkdf2_time_cost_high,
            4: pbkdf2_time_cost_insane,
        }
        iterations = pbkdf2_iterations_options.get(pbkdf2_iterations_choice, pbkdf2_time_cost_low)

    else:
        raise ValueError("Invalid choice for KDF algorithm.")

    # Prompt for encrypt or decrypt
    print("Choose operation:")
    print(f"1. Encrypt")
    print(f"2. Decrypt")
    operation_choice = int(input("Enter the number of your choice: "))
    operation = "encrypt" if operation_choice == 1 else "decrypt"

    # Prompt for password and input
    password = input("Enter password: ")
    base64_input = input("Enter input data: ")

    # Execute the operation
    if operation == 'encrypt':
        result = encrypt(
            plaintext=base64_input, 
            password=password, 
            salt_size=salt_size, 
            iterations=iterations, 
            hash_algo=hash_algo, 
            use_chacha=use_chacha, 
            kdf_algo=['argon2id', 'scrypt', 'pbkdf2'][kdf_choice-1], 
            memory_cost=memory_cost, 
            parallelism=parallelism
        )
        print(f"Encrypted Data:\n{result}")
    else:
        result = decrypt(
            base64_data=base64_input, 
            password=password, 
            salt_size=salt_size, 
            iterations=iterations, 
            hash_algo=hash_algo, 
            use_chacha=use_chacha, 
            kdf_algo=['argon2id', 'scrypt', 'pbkdf2'][kdf_choice-1], 
            memory_cost=memory_cost, 
            parallelism=parallelism
        )
        print(f"Decrypted Data:\n{result}")
