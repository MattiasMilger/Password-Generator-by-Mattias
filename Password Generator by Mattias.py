import secrets
import string
import tkinter as tk
from tkinter import messagebox

# Constants
MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT = 600, 390
MAX_PASSWORD_LENGTH, MAX_PASSWORD_SAVES = 200, 200
ERROR_MESSAGES = {
    "short_password": "Password length is too short. Minimum length required: {}.",
    "max_password_length": f"Maximum password length = {MAX_PASSWORD_LENGTH}.",
    "no_password_to_copy": "No password to copy.",
    "invalid_input_format": "Invalid input format. Please enter valid numbers.",
}

# Colors and Theme
BACKGROUND_COLOR = "#2b2b2b"
TEXT_COLOR = "#ffffff"
ENTRY_COLOR = "#4a4a4a"
BUTTON_COLOR = "#3a3a3a"

# Helper Functions
def show_message(title, message, msg_type="info"):
    getattr(messagebox, f"show{msg_type}")(title, message)

def get_entry_value(entry, default=0, max_value=None):
    try:
        value = int(entry.get().strip() or default)
        if max_value and value > max_value:
            return None
        return value
    except ValueError:
        return None

def create_random_characters(count, char_set):
    return ''.join(secrets.choice(char_set) for _ in range(count))

def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="", randomize_length=False):
    min_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    length = max(length, min_length) if randomize_length else length
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

    char_sets = {
        string.ascii_lowercase: length - min_length,
        string.ascii_uppercase: num_capitals,
        string.digits: num_digits,
        string.punctuation: num_punctuations,
    }
    password = ''.join(create_random_characters(count, char_set) for char_set, count in char_sets.items())
    password = ''.join(secrets.SystemRandom().sample(password + specific_word, length))
    return password

def update_message_box(content):
    message_box.config(state=tk.NORMAL)
    message_box.delete(1.0, tk.END)
    message_box.insert(tk.END, content)
    message_box.config(state=tk.DISABLED)

def reset_fields():
    for entry in [length_entry, specialcharacter_entry, digits_entry, capitals_entry, specific_word_entry, num_saves_entry]:
        entry.delete(0, tk.END)
    update_message_box("")

# Main Functionality
def generate_password():
    try:
        length = get_entry_value(length_entry, 12, MAX_PASSWORD_LENGTH)
        num_punctuations = get_entry_value(specialcharacter_entry, 2)
        num_digits = get_entry_value(digits_entry, 2)
        num_capitals = get_entry_value(capitals_entry, 2)
        specific_word = specific_word_entry.get().strip()
        randomize_length = not length_entry.get().strip()
        num_passwords = get_entry_value(num_saves_entry, 1, MAX_PASSWORD_SAVES)

        if None in (length, num_punctuations, num_digits, num_capitals, num_passwords):
            show_message("Error", ERROR_MESSAGES["invalid_input_format"], "error")
            return

        # Validate if the total requirements exceed the password length
        min_required_length = num_punctuations + num_digits + num_capitals + len(specific_word)
        if length < min_required_length:
            show_message(
                "Error",
                ERROR_MESSAGES["short_password"].format(min_required_length),
                "error",
            )
            return

        passwords = [
            password_creation(length, num_punctuations, num_digits, num_capitals, specific_word, randomize_length)
            for _ in range(num_passwords)
        ]
        update_message_box("\n".join(passwords))
    except ValueError as e:
        show_message("Error", str(e), "error")

def copy_to_clipboard():
    selected_text = message_box.selection_get() if message_box.tag_ranges("sel") else message_box.get("1.0", tk.END).strip()
    if not selected_text:
        show_message("Error", ERROR_MESSAGES["no_password_to_copy"], "error")
        return
    root.clipboard_clear()
    root.clipboard_append(selected_text)
    root.update()

# Tkinter Setup
root = tk.Tk()
root.title("Password Generator by Mattias")
root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
root.configure(bg=BACKGROUND_COLOR)

main_frame = tk.Frame(root, padx=10, pady=10, bg=BACKGROUND_COLOR)
main_frame.pack(fill=tk.BOTH, expand=True)

# UI Elements and Grid Setup
tk.Label(main_frame, text="Password Length:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=0, column=0, sticky="e", padx=5, pady=5)
length_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
length_entry.grid(row=0, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Special Characters:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=0, column=2, sticky="e", padx=5, pady=5)
specialcharacter_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
specialcharacter_entry.grid(row=0, column=3, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Digits:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=1, column=0, sticky="e", padx=5, pady=5)
digits_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
digits_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Capitals:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=1, column=2, sticky="e", padx=5, pady=5)
capitals_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
capitals_entry.grid(row=1, column=3, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Specific Word:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=2, column=0, sticky="e", padx=5, pady=5)
specific_word_entry = tk.Entry(main_frame, width=25, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
specific_word_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Number of passwords:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=2, column=2, sticky="e", padx=5, pady=5)
num_saves_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
num_saves_entry.grid(row=2, column=3, sticky="w", padx=5, pady=5)

button_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
button_frame.grid(row=3, column=0, columnspan=4, pady=10)

tk.Button(button_frame, text="Create Password", command=generate_password, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=20).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Reset Fields", command=reset_fields, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack(side=tk.LEFT, padx=5)

tk.Label(main_frame, text="Generated Passwords:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=4, column=0, sticky="ne", padx=5, pady=5)
message_box = tk.Text(main_frame, height=8, width=40, bg=ENTRY_COLOR, fg=TEXT_COLOR, state=tk.DISABLED, insertbackground=TEXT_COLOR)
message_box.grid(row=4, column=1, columnspan=3, sticky="w", padx=5, pady=5)

tk.Button(main_frame, text="Exit", command=root.quit, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=20).grid(row=5, column=0, columnspan=4, pady=15)

root.mainloop()
