import hashlib
from typing import Set

# File paths
WORDLIST_FILE = "./context/pass.txt"    # File containing passwords (one per line or separated by spaces)




def sha1_hex(text: str) -> str:
    """
    Compute the SHA1 hash of a given string and return the hex digest.
    """
    return hashlib.sha1(text.encode("utf-8", errors="ignore")).hexdigest()


def load_hashes(path: str) -> Set[str]:
    """
    Load SHA1 hashes from a file into a set.

    Only valid SHA1 hashes (40 hex characters) are accepted.
    """
    hashes: Set[str] = set()

    with open(path, "r", encoding="utf-8", errors="ignore") as file:
        for line in file:
            h = line.strip().lower()

            # Validate SHA1 format
            if len(h) == 40 and all(c in "0123456789abcdef" for c in h):
                hashes.add(h)

    return hashes


def crack_hashes(wordlist_file: str) -> None:
    """
    Attempt to match SHA1 hashes from a hash  using a password wordlist.
    """

    targets = input("Enter SHA1 hashes to crack (comma-separated) or press Enter to load from file: ").strip()

    if not targets:
        print("No valid SHA1 hashes found.")
        return

    found = 0

    with open(wordlist_file, "r", encoding="utf-8", errors="ignore") as wordlist:
        for line in wordlist:
            password = line.strip()

            if not password:
                continue

            hash_value = sha1_hex(password)

            if hash_value in targets:
                found += 1
                print(f"MATCH  hash={hash_value}  password={password}")


                if not targets:
                    break

    print(f"\nTotal matches found: {found}")


def main() -> None:
    """
    Main entry point of the program.
    """
    print("SHA1 Wordlist Verification Tool")
    print("--------------------------------")

    crack_hashes(WORDLIST_FILE)


if __name__ == "__main__":
    main()