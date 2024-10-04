import secrets
import string
import tkinter as tk
from tkinter import messagebox
import json

# Function to create password
def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="", randomize_length=False):
    min_required_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    
    if randomize_length and length < min_required_length:
        length = min_required_length
    
    if not randomize_length and length < min_required_length:
        raise ValueError(f"Password length is too short. Minimum length required: {min_required_length}.")
    
    if length > 200:
        raise ValueError("Maximum password length = 200.")

    num_ascii_lowercase = length - num_punctuations - num_digits - num_capitals - len(specific_word)
    random_lowercase = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(num_ascii_lowercase))
    capitals = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(num_capitals))
    digits = ''.join(secrets.choice(string.digits) for _ in range(num_digits))
    special_characters = ''.join(secrets.choice(string.punctuation) for _ in range(num_punctuations))
    
    password_list = list(random_lowercase + capitals + digits + special_characters)
    secrets.SystemRandom().shuffle(password_list)
    random_index = secrets.SystemRandom().randint(0, len(password_list))
    password_list.insert(random_index, specific_word)
    final_password = ''.join(password_list)
    return final_password

# Function to save password to a text file
def save_password_to_file(password):
    try:
        with open("generated_passwords.txt", "a") as file:
            file.write(password + "\n")
        messagebox.showinfo("Success", "Password saved to 'generated_passwords.txt'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save password: {e}")

# Function to copy password to clipboard
def copy_to_clipboard(password):
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()

# Function to save configuration
def save_configuration():
    config = {
        "length": length_entry.get(),
        "num_punctuations": specialcharacter_entry.get(),
        "num_digits": digits_entry.get(),
        "num_capitals": capitals_entry.get(),
        "specific_word": specific_word_entry.get()
    }
    try:
        with open("config.txt", "w") as file:
            json.dump(config, file)
        messagebox.showinfo("Success", "Configuration saved to 'config.txt'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save configuration: {e}")

# Function to load configuration
def load_configuration():
    try:
        with open("config.txt", "r") as file:
            config = json.load(file)
        
        # Set the loaded values to the input fields
        length_entry.delete(0, tk.END)
        length_entry.insert(0, config.get("length", ""))
        
        specialcharacter_entry.delete(0, tk.END)
        specialcharacter_entry.insert(0, config.get("num_punctuations", ""))
        
        digits_entry.delete(0, tk.END)
        digits_entry.insert(0, config.get("num_digits", ""))
        
        capitals_entry.delete(0, tk.END)
        capitals_entry.insert(0, config.get("num_capitals", ""))
        
        specific_word_entry.delete(0, tk.END)
        specific_word_entry.insert(0, config.get("specific_word", ""))
        
        messagebox.showinfo("Success", "Configuration loaded from 'config.txt'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to load configuration: {e}")

# Function to generate password
def generate_password():
    try:
        length = length_entry.get()
        num_punctuations = specialcharacter_entry.get()
        num_digits = digits_entry.get()
        num_capitals = capitals_entry.get()

        randomize_length = False
        if length == "":
            length = secrets.choice(range(8, 21))
            randomize_length = True
        else:
            length = int(length)

        if num_punctuations == "":
            num_punctuations = secrets.choice(range(0, length // 4 + 1))
        else:
            num_punctuations = int(num_punctuations)

        if num_digits == "":
            num_digits = secrets.choice(range(0, length // 4 + 1))
        else:
            num_digits = int(num_digits)

        if num_capitals == "":
            num_capitals = secrets.choice(range(0, length // 4 + 1))
        else:
            num_capitals = int(num_capitals)

        specific_word = specific_word_entry.get()

        password = password_creation(length, num_punctuations, num_digits, num_capitals, specific_word, randomize_length)
        message_label.config(text=password)

    except ValueError as e:
        messagebox.showerror("Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Password Generator")

title_label = tk.Label(root, text="Create your custom password:")
title_label.pack(pady=20)

length_label = tk.Label(root, text="Password Length (leave empty for random):")
length_label.pack(pady=5)
length_entry = tk.Entry(root, width=30)
length_entry.pack(pady=10)

special_label = tk.Label(root, text="Number of Special Characters (leave empty for random):")
special_label.pack(pady=5)
specialcharacter_entry = tk.Entry(root, width=30)
specialcharacter_entry.pack(pady=10)

digits_label = tk.Label(root, text="Number of Digits (leave empty for random):")
digits_label.pack(pady=5)
digits_entry = tk.Entry(root, width=30)
digits_entry.pack(pady=10)

capitals_label = tk.Label(root, text="Number of Capital Letters (leave empty for random):")
capitals_label.pack(pady=5)
capitals_entry = tk.Entry(root, width=30)
capitals_entry.pack(pady=10)

specific_word_label = tk.Label(root, text="Specific Word (optional):")
specific_word_label.pack(pady=5)
specific_word_entry = tk.Entry(root, width=30)
specific_word_entry.pack(pady=10)

message_label = tk.Label(root, text="")
message_label.pack(pady=20)

password_button = tk.Button(root, text="Create Password", command=generate_password)
password_button.pack(pady=20)

copy_button = tk.Button(root, text="Copy to clipboard", command=lambda: copy_to_clipboard(message_label.cget("text")))
copy_button.pack(pady=10)

save_button = tk.Button(root, text="Save Password to File", command=lambda: save_password_to_file(message_label.cget("text")))
save_button.pack(pady=10)

save_config_button = tk.Button(root, text="Save Configuration", command=save_configuration)
save_config_button.pack(pady=10)

load_config_button = tk.Button(root, text="Load Configuration", command=load_configuration)
load_config_button.pack(pady=10)

root.mainloop()
