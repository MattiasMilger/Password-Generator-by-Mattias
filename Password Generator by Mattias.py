import secrets
import string
import tkinter as tk
from tkinter import messagebox, filedialog
import os

# Constants for file paths and limits
PASSWORD_FILE = "generated_passwords.txt"
MIN_WINDOW_WIDTH = 375
MIN_WINDOW_HEIGHT = 630
MAX_PASSWORD_LENGTH = 200
MAX_PASSWORD_SAVES = 200
ERROR_MESSAGES = {
    "short_password": "Password length is too short. Minimum length required: {}.",
    "max_password_length": f"Maximum password length = {MAX_PASSWORD_LENGTH}.",
    "no_password_to_save": "No password to save.",
    "no_password_to_copy": "No password to copy.",
    "file_save_failed": "Failed to save password: {}",
    "max_password_saves": f"Cannot save more than {MAX_PASSWORD_SAVES} passwords at once."
}

# Helper function to display messages
def show_message(title, message, msg_type="info"):
    if msg_type == "info":
        messagebox.showinfo(title, message)
    elif msg_type == "error":
        messagebox.showerror(title, message)

# New helper function to get and validate entry values
def get_and_validate_entry(entry, default_value=0, max_value=None):
    value = entry.get()
    try:
        value = int(value) if value.isdigit() else default_value
        if max_value and value > max_value:
            show_message("Error", f"Value exceeds maximum of {max_value}.", "error")
            return None
    except ValueError:
        show_message("Error", "Invalid input; must be a number.", "error")
        return None
    return value

# Helper function to create random characters
def create_random_characters(count, char_set):
    return ''.join(secrets.choice(char_set) for _ in range(count))

# Refactored function to create password
def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="", randomize_length=False):
    """Generate a random password based on specified criteria."""
    min_required_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    
    if randomize_length:
        length = max(length, min_required_length)
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

    num_ascii_lowercase = length - (num_punctuations + num_digits + num_capitals + len(specific_word))
    
    random_lowercase = create_random_characters(num_ascii_lowercase, string.ascii_lowercase)
    capitals = create_random_characters(num_capitals, string.ascii_uppercase)
    digits = create_random_characters(num_digits, string.digits)
    special_characters = create_random_characters(num_punctuations, string.punctuation)

    password_list = list(random_lowercase + capitals + digits + special_characters)
    password_list.insert(secrets.randbelow(len(password_list) + 1), specific_word)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)

# Function to save password to a text file with confirmation
def save_password_to_file(password, count=1):
    """Save the password to a file, up to the specified count."""
    if count > MAX_PASSWORD_SAVES:
        if not messagebox.askyesno("Confirm Save", f"You are about to save {count} passwords. Proceed?"):
            return
    try:
        with open(PASSWORD_FILE, "a") as file:
            for _ in range(count):
                file.write(password + "\n")
        show_message("Success", f"{count} password(s) saved to '{os.path.abspath(PASSWORD_FILE)}'.")
    except Exception as e:
        show_message("Error", ERROR_MESSAGES["file_save_failed"].format(e), "error")

# Function to copy password to clipboard
def copy_to_clipboard(password):
    """Copy the password to the system clipboard."""
    if not password:
        show_message("Error", ERROR_MESSAGES["no_password_to_copy"], "error")
        return
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()

# Function to generate password based on user input
def generate_password():
    try:
        length = get_and_validate_entry(length_entry, default_value=12, max_value=MAX_PASSWORD_LENGTH)
        num_punctuations = get_and_validate_entry(specialcharacter_entry, default_value=2)
        num_digits = get_and_validate_entry(digits_entry, default_value=2)
        num_capitals = get_and_validate_entry(capitals_entry, default_value=2)
        specific_word = specific_word_entry.get()
        randomize_length = not length_entry.get()

        password = password_creation(length, num_punctuations, num_digits, num_capitals, specific_word, randomize_length)
        
        message_box.delete(1.0, tk.END)  
        message_box.insert(tk.END, password)
        
    except ValueError as e:
        show_message("Error", str(e), "error")

# Function to reset all input fields
def reset_fields():
    for entry in [length_entry, specialcharacter_entry, digits_entry, capitals_entry, specific_word_entry, num_saves_entry]:
        entry.delete(0, tk.END)
    message_box.delete("1.0", tk.END)

# Function to exit the application
def exit_application():
    if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
        root.destroy()

# Create the main window
root = tk.Tk()
root.title("Password Generator by Mattias")
root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

# User interface setup
length_label = tk.Label(root, text="Password Length:")
length_label.pack(pady=5)
length_entry = tk.Entry(root, width=30)
length_entry.pack(pady=10)

special_label = tk.Label(root, text="Number of Special Characters:")
special_label.pack(pady=5)
specialcharacter_entry = tk.Entry(root, width=30)
specialcharacter_entry.pack(pady=10)

digits_label = tk.Label(root, text="Number of Digits:")
digits_label.pack(pady=5)
digits_entry = tk.Entry(root, width=30)
digits_entry.pack(pady=10)

capitals_label = tk.Label(root, text="Number of Capital Letters:")
capitals_label.pack(pady=5)
capitals_entry = tk.Entry(root, width=30)
capitals_entry.pack(pady=10)

specific_word_label = tk.Label(root, text="Specific Word:")
specific_word_label.pack(pady=5)
specific_word_entry = tk.Entry(root, width=30)
specific_word_entry.pack(pady=10)

# Display field for generated password
message_box = tk.Text(height=4, width=37, bg="#4a4a4a", fg="#ffffff")
message_box.pack(pady=15)

# Button for creating password in its own group
password_group = tk.Frame(root)
password_group.pack(pady=5)
password_button = tk.Button(password_group, height=1, width=25, text="Create Password", command=generate_password)
password_button.pack()

# Button Group 1: Copy to Clipboard, Reset Fields
button_group1 = tk.Frame(root)
button_group1.pack(pady=10)

copy_button = tk.Button(button_group1, text="Copy to clipboard", command=lambda: copy_to_clipboard(message_box.get("1.0", tk.END).strip()))
copy_button.pack(side=tk.LEFT, padx=5)

reset_fields_button = tk.Button(button_group1, text="Reset Fields", command=reset_fields)
reset_fields_button.pack(side=tk.LEFT, padx=5)

# New Button Group: Save Passwords to File with Count Input
save_group = tk.Frame(root)
save_group.pack(pady=5)

num_saves_label = tk.Label(save_group, text="Number of Passwords to Save:")
num_saves_label.pack(side=tk.LEFT)
num_saves_entry = tk.Entry(save_group, width=5)
num_saves_entry.pack(side=tk.LEFT, padx=5)

save_button = tk.Button(save_group, text="Save Password(s) to File", command=lambda: save_password_to_file(message_box.get("1.0", tk.END).strip(), count=get_and_validate_entry(num_saves_entry, default_value=1, max_value=MAX_PASSWORD_SAVES)))
save_button.pack(side=tk.LEFT, padx=5)

# Exit button
exit_button = tk.Button(root, height=1, width=30, text="Exit", command=exit_application)
exit_button.pack(pady=15)

root.mainloop()
