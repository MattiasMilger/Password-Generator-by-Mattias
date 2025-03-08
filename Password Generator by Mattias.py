import secrets
import string
import tkinter as tk
from tkinter import messagebox

# Constants
MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT = 600, 390
MAX_PASSWORD_LENGTH, MAX_PASSWORD_SAVES = 999, 999
ERROR_MESSAGES = {
    "short_password": "Password length is too short. Minimum length required: {}.",
    "max_password_length": f"Maximum password length = {MAX_PASSWORD_LENGTH}.",
    "no_password_to_copy": "No password to copy.",
    "invalid_input_format": "Invalid input format. Please enter valid numbers.",
    "negative_value": "Values cannot be negative. Please enter 0 or higher.",
}

# Colors and Theme
BACKGROUND_COLOR = "#2b2b2b"
TEXT_COLOR = "#ffffff"
ENTRY_COLOR = "#4a4a4a"
BUTTON_COLOR = "#3a3a3a"

# Helper Functions
def show_message(title, message, msg_type="info"):
    """Display a message box with the given title, message, and type (info, error, etc.)."""
    getattr(messagebox, f"show{msg_type}")(title, message)

def get_entry_value(entry, default=0, max_value=None):
    """Convert entry text to an integer with validation for negatives and max value."""
    try:
        value = int(entry.get().strip() or default)
        if value < 0:
            return None  # Will trigger negative_value error in caller
        if max_value and value > max_value:
            return None
        return value
    except ValueError:
        return None

def create_random_characters(count, char_set):
    """Generate a string of random characters from the given set."""
    return ''.join(secrets.choice(char_set) for _ in range(count))

def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="",
                     randomize_length=False, disambiguate_chars=False, simple_chars=False):
    """
    Create a random password with specified constraints.
    
    Args:
        length: Total length of the password.
        num_punctuations: Number of punctuation characters.
        num_digits: Number of digit characters.
        num_capitals: Number of uppercase letters.
        specific_word: Word to include in the password.
        randomize_length: If True, adjust length to minimum required if too short.
        disambiguate_chars: If True, replace ambiguous characters (e.g., 'I' with '1').
        simple_chars: If True, use only '!', '?', '.' for punctuation.
    """
    # Calculate minimum required length
    min_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    length = max(length, min_length) if randomize_length else length
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

    # Calculate remaining characters for lowercase letters
    num_lowercase = length - min_length

    # Choose punctuation set based on simple_chars option
    punctuation_set = ['!', '@', '.', '_'] if simple_chars else string.punctuation

    # Generate character pools
    lowercase_chars = create_random_characters(num_lowercase, string.ascii_lowercase)
    uppercase_chars = create_random_characters(num_capitals, string.ascii_uppercase)
    digit_chars = create_random_characters(num_digits, string.digits)
    punctuation_chars = create_random_characters(num_punctuations, punctuation_set)

    # Combine all characters except the specific word
    combined_chars = lowercase_chars + uppercase_chars + digit_chars + punctuation_chars

    # Disambiguate characters if requested
    if disambiguate_chars:
        disambiguation_map = str.maketrans("Il0O", "1LQo")
        combined_chars = combined_chars.translate(disambiguation_map)
        specific_word = specific_word.translate(disambiguation_map)

    # Shuffle combined characters
    shuffled_chars = ''.join(secrets.SystemRandom().sample(combined_chars, len(combined_chars)))

    # Insert specific word at a random position
    insert_pos = secrets.SystemRandom().randint(0, len(shuffled_chars))
    password = shuffled_chars[:insert_pos] + specific_word + shuffled_chars[insert_pos:]
    return password

def update_message_box(content):
    """Update the text box with new content and disable editing."""
    message_box.config(state=tk.NORMAL)
    message_box.delete(1.0, tk.END)
    message_box.insert(tk.END, content)
    message_box.config(state=tk.DISABLED)

def reset_fields():
    """Clear all input fields and the message box."""
    for entry in [length_entry, punctuation_entry, digits_entry, capitals_entry, specific_word_entry, num_passwords_entry]:
        entry.delete(0, tk.END)
    update_message_box("")

# Main Functionality
def generate_password():
    """Generate one or more passwords based on user input."""
    try:
        length = get_entry_value(length_entry, 14, MAX_PASSWORD_LENGTH)
        num_punctuations = get_entry_value(punctuation_entry, 2)
        num_digits = get_entry_value(digits_entry, 2)
        num_capitals = get_entry_value(capitals_entry, 2)
        specific_word = specific_word_entry.get().strip()
        randomize_length = not length_entry.get().strip()
        num_passwords = get_entry_value(num_passwords_entry, 1, MAX_PASSWORD_SAVES)

        # Check for invalid (None) values from get_entry_value
        if None in (length, num_punctuations, num_digits, num_capitals, num_passwords):
            if any(get_entry_value(e) is None and e.get().strip() and int(e.get().strip() or 0) < 0 
                   for e in [length_entry, punctuation_entry, digits_entry, capitals_entry, num_passwords_entry]):
                show_message("Error", ERROR_MESSAGES["negative_value"], "error")
            else:
                show_message("Error", ERROR_MESSAGES["invalid_input_format"], "error")
            return

        # Validate minimum length requirement
        min_required_length = num_punctuations + num_digits + num_capitals + len(specific_word)
        if length < min_required_length:
            show_message(
                "Error",
                ERROR_MESSAGES["short_password"].format(min_required_length),
                "error",
            )
            return

        # Get checkbox states
        disambiguate_chars = disambiguate.get()
        simple_chars = simple.get()

        # Generate passwords
        passwords = [
            password_creation(length, num_punctuations, num_digits, num_capitals, specific_word,
                             randomize_length, disambiguate_chars, simple_chars)
            for _ in range(num_passwords)
        ]
        update_message_box("\n".join(passwords))
    except ValueError as e:
        show_message("Error", str(e), "error")

def copy_to_clipboard():
    """Copy selected text or entire message box content to clipboard."""
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

tk.Label(main_frame, text="Punctuation Chars:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=0, column=2, sticky="e", padx=5, pady=5)
punctuation_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
punctuation_entry.grid(row=0, column=3, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Digits:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=1, column=0, sticky="e", padx=5, pady=5)
digits_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
digits_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Capitals:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=1, column=2, sticky="e", padx=5, pady=5)
capitals_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
capitals_entry.grid(row=1, column=3, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Specific Word:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=2, column=0, sticky="e", padx=5, pady=5)
specific_word_entry = tk.Entry(main_frame, width=25, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
specific_word_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

tk.Label(main_frame, text="Number of Passwords:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=2, column=2, sticky="e", padx=5, pady=5)
num_passwords_entry = tk.Entry(main_frame, width=10, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
num_passwords_entry.grid(row=2, column=3, sticky="w", padx=5, pady=5)

button_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
button_frame.grid(row=3, column=0, columnspan=4, pady=10)

tk.Button(button_frame, text="Create Password(s)", command=generate_password, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=20).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack(side=tk.LEFT, padx=5)
tk.Button(button_frame, text="Reset Fields", command=reset_fields, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack(side=tk.LEFT, padx=5)

tk.Label(main_frame, text="Generated Passwords:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR).grid(row=4, column=0, sticky="ne", padx=5, pady=5)
message_box = tk.Text(main_frame, height=8, width=40, bg=ENTRY_COLOR, fg=TEXT_COLOR, state=tk.DISABLED, insertbackground=TEXT_COLOR)
message_box.grid(row=4, column=1, columnspan=3, sticky="nw", padx=5, pady=5)

# Checkboxes
disambiguate = tk.BooleanVar(value=False)
tk.Checkbutton(main_frame, text="Disambiguate", variable=disambiguate, bg=BACKGROUND_COLOR, fg=TEXT_COLOR, selectcolor=BUTTON_COLOR).grid(row=5, column=0, columnspan=4, pady=5)

simple = tk.BooleanVar(value=False)
tk.Checkbutton(main_frame, text="Simple Characters", variable=simple, bg=BACKGROUND_COLOR, fg=TEXT_COLOR, selectcolor=BUTTON_COLOR).grid(row=5, column=2, columnspan=4, pady=5)

# Add Exit Button
exit_button_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
exit_button_frame.grid(row=6, column=0, columnspan=4, pady=10)
tk.Button(exit_button_frame, text="Exit", command=root.quit, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack()

# Run the App
root.mainloop()
