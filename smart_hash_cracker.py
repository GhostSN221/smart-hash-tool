#!/usr/bin/env python3

import base64
import hashlib
import re
import argparse
import sys


# ==============================
# 🔎 Détection types
# ==============================

def is_hex(s):
    return re.fullmatch(r'[0-9a-fA-F]+', s) is not None


def detect_hash_type(s):
    if len(s) == 32 and is_hex(s):
        return "MD5"
    elif len(s) == 40 and is_hex(s):
        return "SHA1"
    elif len(s) == 64 and is_hex(s):
        return "SHA256"
    return None


# ==============================
# 🔐 Hash Functions
# ==============================

def hash_word(word, hash_type):
    if hash_type == "MD5":
        return hashlib.md5(word.encode()).hexdigest()
    elif hash_type == "SHA1":
        return hashlib.sha1(word.encode()).hexdigest()
    elif hash_type == "SHA256":
        return hashlib.sha256(word.encode()).hexdigest()
    return None


# ==============================
# 🚀 Brute-force dictionnaire
# ==============================

def dictionary_attack(target_hash, hash_type, wordlist):
    print(f"\n🚀 Lancement attaque dictionnaire ({hash_type})...\n")

    try:
        with open(wordlist, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                word = line.strip()
                if hash_word(word, hash_type) == target_hash.lower():
                    print("✅ MOT DE PASSE TROUVÉ :", word)
                    return
        print("❌ Aucun mot trouvé dans la wordlist.")
    except FileNotFoundError:
        print("❌ Wordlist introuvable.")


# ==============================
# 📦 Base64 / Hex decode
# ==============================

def try_base64_decode(s):
    try:
        decoded = base64.b64decode(s, validate=True)
        return decoded.decode("utf-8", errors="ignore")
    except:
        return None


def try_hex_decode(s):
    try:
        decoded = bytes.fromhex(s)
        return decoded.decode("utf-8", errors="ignore")
    except:
        return None


# ==============================
# 🧠 Analyse principale
# ==============================

def analyze_input(user_input, wordlist=None):

    print("\n🔎 Analyse en cours...\n")

    # 1️⃣ Détection Hash
    hash_type = detect_hash_type(user_input)

    if hash_type:
        print(f"🔐 Hash détecté : {hash_type}")

        if wordlist:
            dictionary_attack(user_input, hash_type, wordlist)
        else:
            print("⚠️ Hash non réversible sans dictionnaire.")
        return

    # 2️⃣ Base64
    b64_result = try_base64_decode(user_input)
    if b64_result:
        print("📦 Type détecté : Base64")
        print("✅ Décodé :", b64_result)
        return

    # 3️⃣ Hex
    if is_hex(user_input):
        hex_result = try_hex_decode(user_input)
        if hex_result:
            print("📦 Type détecté : Hex")
            print("✅ Décodé :", hex_result)
            return

    print("⚠️ Format inconnu ou non supporté.")


# ==============================
# 🎯 Main
# ==============================

def main():
    parser = argparse.ArgumentParser(description="Smart Hash Analyzer & Cracker")
    parser.add_argument("-s", "--string", required=True, help="String à analyser")
    parser.add_argument("-w", "--wordlist", help="Wordlist pour brute-force")

    args = parser.parse_args()

    analyze_input(args.string.strip(), args.wordlist)


if __name__ == "__main__":
    main()
