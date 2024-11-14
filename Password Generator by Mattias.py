import secrets
import string
import tkinter as tk
from tkinter import messagebox

# Constants for limits
MIN_WINDOW_WIDTH = 600
MIN_WINDOW_HEIGHT = 390
MAX_PASSWORD_LENGTH = 200
MAX_PASSWORD_SAVES = 200
ERROR_MESSAGES = {
    "short_password": "Password length is too short. Minimum length required: {}.",
    "max_password_length": f"Maximum password length = {MAX_PASSWORD_LENGTH}.",
    "no_password_to_copy": "No password to copy.",
    "invalid_input_format": "Invalid input format"
}

# Helper function to display messages
def show_message(title, message, msg_type="info"):
    if msg_type == "info":
        messagebox.showinfo(title, message)
    elif msg_type == "error":
        messagebox.showerror(title, message)

# New helper function to get and validate entry values
def get_and_validate_entry(entry, default_value=0, max_value=None):
    value = entry.get().strip()  # Trim whitespace
    if value == "":  # Treat empty input as default value
        return default_value
    try:
        # Check if the value is an integer
        value = int(value)
        
        # Validate against maximum value if specified
        if max_value and value > max_value:
            return None
    except ValueError:
        return None  # Return None if the input is not numeric
    return value

# Helper function to create random characters
def create_random_characters(count, char_set):
    return ''.join(secrets.choice(char_set) for _ in range(count))

# Refactored function to create password
def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="", randomize_length=False):
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
    if specific_word:
        password_list.insert(secrets.randbelow(len(password_list) + 1), specific_word)
    secrets.SystemRandom().shuffle(password_list)
    
    return ''.join(password_list)

# Function to generate and display multiple passwords
def generate_password():
    try:
        # Retrieve and validate entries
        length = get_and_validate_entry(length_entry, default_value=12, max_value=MAX_PASSWORD_LENGTH)
        num_punctuations = get_and_validate_entry(specialcharacter_entry, default_value=2)
        num_digits = get_and_validate_entry(digits_entry, default_value=2)
        num_capitals = get_and_validate_entry(capitals_entry, default_value=2)
        specific_word = specific_word_entry.get()
        randomize_length = not length_entry.get()
        num_passwords = get_and_validate_entry(num_saves_entry, default_value=1, max_value=MAX_PASSWORD_SAVES)

        # Check for any validation errors
        if None in (length, num_punctuations, num_digits, num_capitals, num_passwords):
            show_message("Error", ERROR_MESSAGES["invalid_input_format"], "error")
            return

        passwords = [
            password_creation(length, num_punctuations, num_digits, num_capitals, specific_word, randomize_length)
            for _ in range(num_passwords)
        ]
        
        message_box.config(state=tk.NORMAL)
        message_box.delete(1.0, tk.END)
        message_box.insert(tk.END, "\n".join(passwords))
        message_box.config(state=tk.DISABLED)
        
    except ValueError as e:
        show_message("Error", str(e), "error")

# Function to copy to clipboard
def copy_to_clipboard(password):
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()

# Function to reset all input fields
def reset_fields():
    for entry in [length_entry, specialcharacter_entry, digits_entry, capitals_entry, specific_word_entry, num_saves_entry]:
        entry.delete(0, tk.END)
    message_box.config(state=tk.NORMAL)
    message_box.delete("1.0", tk.END)
    message_box.config(state=tk.DISABLED)

# Function to exit the application
def exit_application():
    if messagebox.askyesno("Confirm Exit", "Are you sure you want to exit?"):
        root.destroy()

# Create the main window
root = tk.Tk()
root.title("Password Generator by Mattias")
root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

# Create a main frame with padding
main_frame = tk.Frame(root, padx=10, pady=10)
main_frame.pack(fill=tk.BOTH, expand=True)

# Configure grid weights for resizing
main_frame.columnconfigure(0, weight=1)
main_frame.columnconfigure(1, weight=1)
main_frame.columnconfigure(2, weight=1)
main_frame.columnconfigure(3, weight=1)

# User interface setup in grid
# Row 0: Password Length and Special Characters
tk.Label(main_frame, text="Password Length:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
length_entry = tk.Entry(main_frame, width=10)
length_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Special Characters:").grid(row=0, column=2, sticky="e", padx=5, pady=5)
specialcharacter_entry = tk.Entry(main_frame, width=10)
specialcharacter_entry.grid(row=0, column=3, sticky="w", padx=5, pady=5)

# Row 1: Digits and Capitals
tk.Label(main_frame, text="Digits:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
digits_entry = tk.Entry(main_frame, width=10)
digits_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Capitals:").grid(row=1, column=2, sticky="e", padx=5, pady=5)
capitals_entry = tk.Entry(main_frame, width=10)
capitals_entry.grid(row=1, column=3, sticky="w", padx=5, pady=5)

# Row 2: Specific Word and Number of Passwords to Generate
tk.Label(main_frame, text="Specific Word:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
specific_word_entry = tk.Entry(main_frame, width=25)
specific_word_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Number of passwords:").grid(row=2, column=2, sticky="e", padx=5, pady=5)
num_saves_entry = tk.Entry(main_frame, width=10)
num_saves_entry.grid(row=2, column=3, sticky="w", padx=5, pady=5)

# Row 3: Buttons (Create, Copy, Reset)
button_frame = tk.Frame(main_frame)
button_frame.grid(row=3, column=0, columnspan=4, pady=10)

password_button = tk.Button(button_frame, height=2, width=20, text="Create Password", command=generate_password)
password_button.pack(side=tk.LEFT, padx=5)

copy_button = tk.Button(button_frame, height=2, width=15, text="Copy to clipboard", command=lambda: copy_to_clipboard(message_box.get("1.0", tk.END).strip()))
copy_button.pack(side=tk.LEFT, padx=5)

reset_fields_button = tk.Button(button_frame, height=2, width=15, text="Reset Fields", command=reset_fields)
reset_fields_button.pack(side=tk.LEFT, padx=5)

# Row 4: Display field for generated passwords
tk.Label(main_frame, text="Generated Passwords:").grid(row=4, column=0, sticky="ne", padx=5, pady=5)
message_box = tk.Text(main_frame, height=8, width=40, bg="#4a4a4a", fg="#ffffff", state=tk.DISABLED)
message_box.grid(row=4, column=1, columnspan=3, sticky="w", padx=5, pady=5)

# Row 5: Exit button
exit_button = tk.Button(main_frame, height=2, width=20, text="Exit", command=exit_application)
exit_button.grid(row=5, column=0, columnspan=4, pady=15)

root.mainloop()
