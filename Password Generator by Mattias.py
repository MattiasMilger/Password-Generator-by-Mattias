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

# Function to create password
def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="", randomize_length=False):
    min_required_length = num_punctuations + num_digits + num_capitals + len(specific_word)

    if randomize_length and length < min_required_length:
        length = min_required_length
    if not randomize_length and length < min_required_length:
        raise ValueError(ERROR_MESSAGES["short_password"].format(min_required_length))
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

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
def save_password_to_file(password, count=1):
    if count > MAX_PASSWORD_SAVES:
        show_message("Error", ERROR_MESSAGES["max_password_saves"], "error")
        return
    
    try:
        with open(PASSWORD_FILE, "a") as file:
            for _ in range(count):
                file.write(password_creation(length=int(length_entry.get()) if length_entry.get() else secrets.choice(range(8, 21)),
                                             num_punctuations=int(specialcharacter_entry.get()) if specialcharacter_entry.get() else secrets.choice(range(0, int(length_entry.get() or 12) // 4 + 1)),
                                             num_digits=int(digits_entry.get()) if digits_entry.get() else secrets.choice(range(0, int(length_entry.get() or 12) // 4 + 1)),
                                             num_capitals=int(capitals_entry.get()) if capitals_entry.get() else secrets.choice(range(0, int(length_entry.get() or 12) // 4 + 1)),
                                             specific_word=specific_word_entry.get() or "",
                                             randomize_length=not length_entry.get()) + "\n")
        show_message("Success", f"{count} password(s) saved to '{PASSWORD_FILE}'.")
    except Exception as e:
        show_message("Error", ERROR_MESSAGES["file_save_failed"].format(e), "error")

# Function to copy password to clipboard
def copy_to_clipboard(password):
    if not password:
        show_message("Error", ERROR_MESSAGES["no_password_to_copy"], "error")
        return
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()

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
        
        message_box.delete(1.0, tk.END)  
        message_box.insert(tk.END, password)
        
    except ValueError as e:
        messagebox.showerror("Error", str(e))

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
root.title("Password Generator")

# Set the minimum size of the window
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

save_button = tk.Button(save_group, text="Save Password(s) to File", command=lambda: save_password_to_file(message_box.get("1.0", tk.END).strip(), count=int(num_saves_entry.get()) if num_saves_entry.get().isdigit() else 1))
save_button.pack(side=tk.LEFT, padx=5)

# Exit button
exit_button = tk.Button(root, height=1, width=30, text="Exit", command=exit_application)
exit_button.pack(pady=15)

root.mainloop()
