import hashlib
import time

# Supported hash types
HASH_FUNCTIONS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "ntlm": lambda s: hashlib.new('md4', s.encode('utf-16le'))
}

# Load hash from file
def load_hash():
    with open("hash.txt", "r") as f:
        return f.read().strip()

# Dictionary attack
def dictionary_attack(hash_to_crack, wordlist_file, hash_type):
    with open(wordlist_file, "r", encoding="latin-1") as f:
        for word in f:
            time.sleep(0.25)
            word = word.strip()
            hash_func = HASH_FUNCTIONS[hash_type]
            hashed_word = hash_func(word.encode()).hexdigest()

            print(f"[*] Trying: {word} -> {hashed_word}")  # Debugging output

            if hashed_word == hash_to_crack:
                print("\n[✔] Password found:")
                print(f"{word}\n")
                return word
    print("[✘] Password not found in dictionary.")
    return None

# Main function
if __name__ == "__main__":
    hash_to_crack = load_hash()
    hash_type = "md5"

    print("[*] Attempting Dictionary Attack...")
    dictionary_attack(hash_to_crack, "wordlist.txt", hash_type)
