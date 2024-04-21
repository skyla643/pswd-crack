# password_cracker.py

import itertools
import hashlib

def crack_password(hash_type, target_hash, charset, max_length):
    """
    Cracks a hashed password using various techniques.

    Args:
        hash_type (str): The type of hash algorithm used (e.g., "md5", "sha1").
        target_hash (str): The hashed password to crack.
        charset (str): The character set to use for brute-force attacks.
        max_length (int): The maximum length of passwords to attempt.

    Returns:
        str: The cracked password, or None if not found.
    """
    if hash_type not in hashlib.algorithms_available:
        print("Invalid hash algorithm.")
        return None

    if hash_type == "md5":
        hash_func = hashlib.md5
    elif hash_type == "sha1":
        hash_func = hashlib.sha1
    elif hash_type == "sha256":
        hash_func = hashlib.sha256
    # Add more hash algorithms as needed

    # Dictionary attack
    try:
        with open(r"C:your-flie", "r") as f:
            common_passwords = f.readlines()
            for password in common_passwords:
                password = password.strip()
                if hash_func(password.encode()).hexdigest() == target_hash:
                    return password
    except FileNotFoundError:
        print("The file 'common_passwords.txt' was not found. Please create the file and add a list of common passwords to it.")

    # Brute-force attack
    for length in range(1, max_length + 1):
        for attempt in itertools.product(charset, repeat=length):
            password = "".join(attempt)
            if hash_func(password.encode()).hexdigest() == target_hash:
                return password

    return None
