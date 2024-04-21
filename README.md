Password Cracking Tool
This Python script provides a password cracking tool that helps users test the strength of their passwords by attempting to crack them using various techniques such as dictionary attacks and brute-force attacks.

Usage
The crack_password function takes four arguments:

hash_type: The type of hash algorithm used (e.g., "md5", "sha1").
target_hash: The hashed password to crack.
charset: The character set to use for brute-force attacks.
max_length: The maximum length of passwords to attempt.
To use the tool, follow these steps:

Generate a Hashed Password: Use a hash algorithm (e.g., MD5, SHA1) to generate a hashed password from a plaintext password. You can use the hashlib library in Python to accomplish this.
python
Copy code
import hashlib

plaintext_password = "password"
hash_type = "md5"
hash_obj = hashlib.new(hash_type)
hash_obj.update(plaintext_password.encode())
target_hash = hash_obj.hexdigest()
Prepare Common Passwords: Create a common_passwords.txt file and add a list of common passwords to it, with each password on a separate line.
Run the Script: Call the crack_password function with the appropriate arguments to attempt to crack the hashed password.
python
Copy code
import os

# Replace 'C:your-file' with your own file path
filepath = "C:your-file/common_passwords.txt"
if not os.path.isfile(filepath):
    print("Error: common_passwords.txt file not found. Please create the file and add common passwords to it.")
else:
    cracked_password = crack_password(hash_type, target_hash, "abcdefghijklmnopqrstuvwxyz", 10)
    if cracked_password is not None:
        print("Cracked password:", cracked_password)
    else:
        print("Failed to crack password.")
Functionality
The crack_password function performs the following steps:

Checks if the hash_type argument is a valid hash algorithm supported by the hashlib library. If not, it prints an error message and returns None.
Defines a hash_func variable based on the hash_type argument, which is used to generate hash values using the specified hash algorithm.
Attempts a dictionary attack by reading common passwords from the common_passwords.txt file and checking if any of them match the target hash.
If no match is found in the dictionary attack, it performs a brute-force attack by generating all possible combinations of characters in the charset variable up to a specified maximum length.
Returns the cracked password if found, or None if no match is found.
