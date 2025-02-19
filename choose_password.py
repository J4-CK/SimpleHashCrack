import hashlib
import random

# Supported hash types
HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "ntlm": lambda s: hashlib.new('md4', s.encode('utf-16le'))
}

# Top 200 most common passwords
all_passwords = [
    "123456", "password", "123456789", "12345", "12345678", "qwerty", "1234567", "111111", "123123",
    "abc123", "password1", "iloveyou", "1q2w3e4r", "000000", "qwerty123", "zaq12wsx", "dragon", "sunshine",
    "princess", "letmein", "654321", "monkey", "football", "987654", "hunter", "batman", "shadow", "pokemon",
    "baseball", "superman", "password123", "freedom", "trustno1", "football1", "mustang", "harley", "jordan",
    "letmein123", "pepper", "cookie", "monkey123", "summer", "pass123", "maverick", "passw0rd", "sunshine1",
    "monday", "willow", "savannah", "thunder", "pa55w0rd", "bulldog", "loveyou", "rockstar", "ferrari"
]

# Mutate password to simulate real-world variations
def mutate_password(password):
    mutations = [
        password.lower(),  # all lowercase
        password.upper(),  # all uppercase
        password + "123",  # common suffix
        password.replace("o", "0").replace("a", "@").replace("e", "3"),  # leetspeak
        "!" + password,  # prepend symbol
        password + "!"  # append symbol
    ]
    return random.choice(mutations)  # Return a random variation

def generate_hash(password, hash_type="md5"):
    hash_func = HASH_FUNCTIONS[hash_type]
    return hash_func(password.encode()).hexdigest()

def user_choose_password():
    selected_passwords = random.sample(all_passwords, 8)
    print("\nChoose a password from the list below:")
    for idx, pwd in enumerate(selected_passwords, 1):
        print(f"{idx}. {pwd}")

    choice = input("\nEnter the number of your chosen password: ")
    try:
        chosen_password = selected_passwords[int(choice) - 1]
        mutated_password = mutate_password(chosen_password)  # Mutate the password
        hash_value = generate_hash(mutated_password)

        # Save the **exact mutated password's hash**
        with open("hash.txt", "w") as f:
            f.write(hash_value + "\n")

        # Append the mutated password to `wordlist.txt`
        with open("wordlist.txt", "a") as f:
            f.write(mutated_password + "\n")

        print(f"\n[✔] Using password: {chosen_password} (mutated to {mutated_password})")
        print(f"[✔] Generated Hash (MD5): {hash_value}")
    except (IndexError, ValueError):
        print("[✘] Invalid choice. Using default password.")
        chosen_password = selected_passwords[0]
        mutated_password = mutate_password(chosen_password)
        hash_value = generate_hash(mutated_password)

if __name__ == "__main__":
    user_choose_password()
