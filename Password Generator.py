import secrets
import string
import hashlib
import base64
import pyperclip
import time
import threading
from zxcvbn import zxcvbn


def generate_password(length=12, use_digits=True, use_special_chars=True):
    if length < 6:
        raise ValueError("Password length should be at least 6 characters.")
    
    characters = string.ascii_letters
    if use_digits:
        characters += string.digits
    if use_special_chars:
        special_chars = "!@#$%^&*()-_=+[]{}|;:'\",.<>?/"
        characters += special_chars
    
    password = ''.join(secrets.choice(characters) for _ in range(length))
    return password


def hash_password(password, algorithm='sha256'):
    if algorithm == 'sha256':
        return hashlib.sha256(password.encode()).hexdigest()
    elif algorithm == 'base64':
        return base64.b64encode(password.encode()).decode()
    else:
        raise ValueError("Unsupported hashing algorithm.")


def check_password_strength(password):
    raw_score = zxcvbn(password)['score']  
    converted_score = raw_score * 2.5  
    return round(converted_score, 1)  


def get_boolean_input(prompt):
    while True:
        response = input(prompt).strip().lower()
        if response in ['y', 'n']:
            return response == 'y'
        print("Invalid input. Please enter 'y' or 'n'.")


def save_password_to_file(password, filename="passwords.txt"):
    with open(filename, "a") as file:
        file.write(f"{password}\n")
    print("Password saved to file.")


def load_saved_passwords(filename="passwords.txt"):
    try:
        with open(filename, "r") as file:
            return file.readlines()
    except FileNotFoundError:
        return []


def copy_to_clipboard(password):
    pyperclip.copy(password)
    print("Password copied to clipboard! It will be cleared in 60 seconds.")

    def clear_clipboard():
        time.sleep(60)
        pyperclip.copy("")
        print("Clipboard cleared for security.")

    threading.Thread(target=clear_clipboard, daemon=True).start()


if __name__ == "__main__":
    while True:
        try:
            password_length = int(input("Enter password length (minimum 6): "))
            if password_length < 6:
                print("Password length should be at least 6 characters.")
                continue
            break
        except ValueError:
            print("Invalid input. Please enter a valid number.")
    
    include_digits = get_boolean_input("Include digits? (y/n): ")
    include_special_chars = get_boolean_input("Include special characters? (y/n): ")
    
    password = generate_password(password_length, include_digits, include_special_chars)
    

    print("\nChoose hashing algorithm:")
    print("1) SHA-256")
    print("2) Base64")
    algo_choice = input("Enter choice (1/2): ").strip()
    algo_dict = {'1': 'sha256', '2': 'base64'}
    selected_algo = algo_dict.get(algo_choice, 'sha256')
    
    password_hash = hash_password(password, selected_algo)
    strength_score = check_password_strength(password) 
    
    print("\nGenerated password:", password)
    print(f"{selected_algo.upper()} Hash:", password_hash)
    print("Password Strength (0-10):", strength_score)  
    
    
    copy_to_clipboard(password)
    
    save_option = get_boolean_input("Do you want to save this password? (y/n): ")
    if save_option:
        save_password_to_file(password)
    
    view_option = get_boolean_input("Do you want to view saved passwords? (y/n): ")
    if view_option:
        saved_passwords = load_saved_passwords()
        print("\nSaved Passwords:")
        for i, saved_password in enumerate(saved_passwords, 1):
            print(f"{i}: {saved_password.strip()}")
