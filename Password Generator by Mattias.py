import secrets
import string
import tkinter as tk
from tkinter import messagebox, filedialog
import json
import os

STARTUP_CONFIG_FILE = "startup_config.json"

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
    
    return ''.join(password_list)

# Function to save password to a text file
def save_password_to_file(password):
    if not password:
        messagebox.showerror("Error", "No password to save.")
        return
    try:
        with open("generated_passwords.txt", "a") as file:
            file.write(password + "\n")
        messagebox.showinfo("Success", "Password saved to 'generated_passwords.txt'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save password: {e}")

# Function to copy password to clipboard
def copy_to_clipboard(password):
    if not password:
        messagebox.showerror("Error", "No password to copy.")
        return
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()
    messagebox.showinfo("Success", "Password copied to clipboard.")

# Function to save configuration to a file
def save_configuration(file_path):
    config = {
        "length": length_entry.get(),
        "num_punctuations": specialcharacter_entry.get(),
        "num_digits": digits_entry.get(),
        "num_capitals": capitals_entry.get(),
        "specific_word": specific_word_entry.get()
    }
    if file_path:
        try:
            with open(file_path, "w") as file:
                json.dump(config, file)
            messagebox.showinfo("Success", f"Configuration saved to '{file_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save configuration: {e}")

# Function to load configuration from a file
def load_configuration(file_path):
    if file_path:
        try:
            with open(file_path, "r") as file:
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

            messagebox.showinfo("Success", f"Configuration loaded from '{file_path}'.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load configuration: {e}")

# Function to generate password
def generate_password():
    try:
        length = length_entry.get()
        num_punctuations = specialcharacter_entry.get()
        num_digits = digits_entry.get()
        num_capitals = capitals_entry.get()
        specific_word = specific_word_entry.get()

        randomize_length = False
        length = int(length) if length else secrets.choice(range(8, 21))
        randomize_length = True if length_entry.get() == "" else False

        num_punctuations = int(num_punctuations) if num_punctuations else secrets.choice(range(0, length // 4 + 1))
        num_digits = int(num_digits) if num_digits else secrets.choice(range(0, length // 4 + 1))
        num_capitals = int(num_capitals) if num_capitals else secrets.choice(range(0, length // 4 + 1))

        password = password_creation(length, num_punctuations, num_digits, num_capitals, specific_word, randomize_length)
        message_label.config(text=password)
        
    except ValueError as e:
        messagebox.showerror("Error", str(e))

# Function to save the current configuration as the startup configuration
def save_startup_config():
    save_configuration(STARTUP_CONFIG_FILE)

# Function to reset the startup configuration (delete the file)
def reset_startup_config():
    try:
        if os.path.exists(STARTUP_CONFIG_FILE):
            os.remove(STARTUP_CONFIG_FILE)
        messagebox.showinfo("Success", "Startup configuration reset.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to reset startup configuration: {e}")

# Load the startup configuration on app startup (if it exists)
def load_startup_config():
    if os.path.exists(STARTUP_CONFIG_FILE):
        load_configuration(STARTUP_CONFIG_FILE)

# Function to reset all input fields
def reset_fields():
    length_entry.delete(0, tk.END)
    specialcharacter_entry.delete(0, tk.END)
    digits_entry.delete(0, tk.END)
    capitals_entry.delete(0, tk.END)
    specific_word_entry.delete(0, tk.END)
    message_label.config(text="")  # Clear the generated password display as well

# Function to exit the application
def exit_application():
    root.destroy()

# Create the main window
root = tk.Tk()
root.title("Password Generator")

# User interface setup
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

# Button Group 1: Create Password, Copy to Clipboard, Reset Fields
button_group1 = tk.Frame(root)
button_group1.pack(pady=10)

password_button = tk.Button(button_group1, text="Create Password", command=generate_password)
password_button.pack(side=tk.LEFT, padx=5)

copy_button = tk.Button(button_group1, text="Copy to clipboard", command=lambda: copy_to_clipboard(message_label.cget("text")))
copy_button.pack(side=tk.LEFT, padx=5)

reset_fields_button = tk.Button(button_group1, text="Reset Fields", command=reset_fields)
reset_fields_button.pack(side=tk.LEFT, padx=5)

# Button Group 2: Save Password, Save Configuration, Load Configuration
button_group2 = tk.Frame(root)
button_group2.pack(pady=10)

save_button = tk.Button(button_group2, text="Save Password to File", command=lambda: save_password_to_file(message_label.cget("text")))
save_button.pack(side=tk.LEFT, padx=5)

save_config_button = tk.Button(button_group2, text="Save Configuration", command=lambda: save_configuration(filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])))
save_config_button.pack(side=tk.LEFT, padx=5)

load_config_button = tk.Button(button_group2, text="Load Configuration", command=lambda: load_configuration(filedialog.askopenfilename(filetypes=[("JSON files", "*.json"), ("All files", "*.*")])))
load_config_button.pack(side=tk.LEFT, padx=5)

# Button Group 3: Save Startup Config, Reset Startup Config
button_group3 = tk.Frame(root)
button_group3.pack(pady=10)

save_startup_config_button = tk.Button(button_group3, text="Save Startup Config", command=save_startup_config)
save_startup_config_button.pack(side=tk.LEFT, padx=5)

reset_startup_config_button = tk.Button(button_group3, text="Reset Startup Config", command=reset_startup_config)
reset_startup_config_button.pack(side=tk.LEFT, padx=5)

# Button Group 4: Exit Application
button_group4 = tk.Frame(root)
button_group4.pack(pady=20)

exit_button = tk.Button(button_group4, text="Exit", command=exit_application)
exit_button.pack(pady=5)

# Load the startup configuration when the app starts
load_startup_config()

root.mainloop()
