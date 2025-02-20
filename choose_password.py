import hashlib
import random

# Supported hash types
HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "ntlm": lambda s: hashlib.new('md4', s.encode('utf-16le'))
}

# Top 200 most common passwords (this is a subset)
all_passwords = [
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "1234567", "111111", "123123",
    "abc123", "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
    "princess", "letmein", "654321", "monkey", "football", "987654", "hunter", "batman", "shadow", "pokemon",
    "baseball", "superman", "password123", "freedom", "trustno1", "football1", "mustang", "harley", "jordan",
    "letmein123", "pepper", "cookie", "monkey123", "summer", "pass123", "maverick", "passw0rd", "sunshine1",
    "monday", "willow", "savannah", "thunder", "pa55w0rd", "bulldog", "loveyou", "rockstar", "ferrari"
]

# Generate all possible variations for a password
def generate_variations(password):
    return [
        password.lower(),  # all lowercase
        password.upper(),  # all uppercase
        password + "123",  # common suffix
        password.replace("o", "0").replace("a", "@").replace("e", "3"),  # leetspeak
        "!" + password,  # prepend symbol
        password + "!"  # append symbol
    ]

def generate_hash(password, hash_type="md5"):
    hash_func = HASH_FUNCTIONS[hash_type]
    return hash_func(password.encode()).hexdigest()

def populate_wordlist():
    """ Generate a full wordlist with all mutations. """
    wordlist = set()  # Use a set to avoid duplicates

    for password in all_passwords:
        wordlist.add(password)  # Add the original password
        wordlist.update(generate_variations(password))  # Add mutations

    # Write full wordlist to file (overwrite mode)
    with open("wordlist.txt", "w") as f:
        for pwd in sorted(wordlist):  # Sort to make it look clean
            f.write(pwd + "\n")

    print(f"[✔] Wordlist generated with {len(wordlist)} entries.")

def user_choose_password():
    selected_passwords = random.sample(all_passwords, 8)
    
    print("\nChoose a password from the list below:")
    for idx, pwd in enumerate(selected_passwords, 1):
        print(f"{idx}. {pwd}")

    choice = input("\nEnter the number of your chosen password: ")
    try:
        chosen_password = selected_passwords[int(choice) - 1]
        mutated_password = random.choice(generate_variations(chosen_password))  # Randomly mutate
        hash_value = generate_hash(mutated_password)

        # Save the chosen password's hash
        with open("hash.txt", "w") as f:
            f.write(hash_value + "\n")

        print(f"\n[✔] Using password: {chosen_password} (mutated to {mutated_password})")
        print(f"[✔] Generated Hash (MD5): {hash_value}")
    except (IndexError, ValueError):
        print("[✘] Invalid choice. Using default password.")
        chosen_password = selected_passwords[0]
        mutated_password = random.choice(generate_variations(chosen_password))
        hash_value = generate_hash(mutated_password)

if __name__ == "__main__":
    populate_wordlist()  # Generate the full wordlist
    user_choose_password()  # Let the user pick a password
