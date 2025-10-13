import secrets
import string
import tkinter as tk
from tkinter import messagebox

# === CONFIGURATION CONSTANTS ===
# Minimum window size constants
MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT = 600, 390
# Maximum password length, number of passwords, and specific word length allowed
MAX_PASSWORD_LENGTH, MAX_PASSWORDS, MAX_SPECIFIC_WORD_LENGTH = 999, 999, 50

# === ERROR MESSAGES ===
# Centralized error messages for user feedback
ERROR_MESSAGES = {
    "short_password": "Password length is too short. Minimum length required: {}.",
    "max_password_length": f"Maximum password length = {MAX_PASSWORD_LENGTH}.",
    "max_passwords": f"Maximum number of passwords allowed is {MAX_PASSWORDS}.",
    "no_password_to_copy": "No password to copy.",
    "invalid_input_format": "Invalid input format. Please enter valid numbers.",
    "negative_value": "Values cannot be negative. Please enter 0 or higher.",
    "invalid_specific_word": f"Specific word must contain only printable ASCII characters and be at most {MAX_SPECIFIC_WORD_LENGTH} characters long."
}

# === STYLE CONSTANTS ===
# Colors used in the GUI
BACKGROUND_COLOR = "#2b2b2b"
TEXT_COLOR = "#ffffff"
ENTRY_COLOR = "#4a4a4a"
BUTTON_COLOR = "#3a3a3a"

# === CHARACTER SETS ===
# Set of ambiguous characters to avoid if disambiguation is on
AMBIGUOUS_CHARS = set("Il0O1o")
# Character sets for password generation
DEFAULT_CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "punctuation": string.punctuation,
    "simple_punctuation": ['!', '?', '.', '_', '@'],
}

# === HELPER FUNCTIONS ===
def show_message(title, message, msg_type="info"):
    # Display a tkinter messagebox with dynamic type (info, warning, error)
    getattr(messagebox, f"show{msg_type}")(title, message)

def get_entry_value(entry, default=0, max_value=None):
    # Retrieve integer from entry with validation and fallback to default if empty
    try:
        value = int(entry.get().strip() or default)
        if value < 0:
            raise ValueError(ERROR_MESSAGES["negative_value"])
        if max_value and value > max_value:
            raise ValueError(f"Value exceeds maximum allowed: {max_value}")
        return value
    except ValueError as e:
        raise ValueError(str(e))

def create_random_characters(count, char_set, disambiguate=False):
    # Generate a list of random characters from a set, re-roll if disambiguation is required
    result = []
    while len(result) < count:
        c = secrets.choice(char_set)
        if disambiguate and c in AMBIGUOUS_CHARS:
            continue
        result.append(c)
    return result

def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="",
                      randomize_length=False, disambiguate_chars=False, simple_chars=False):
    # Core logic for generating a single password with given constraints
    min_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    length = max(length, min_length) if randomize_length else length
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

    num_lowercase = length - min_length
    punctuation_set = DEFAULT_CHARSETS["simple_punctuation"] if simple_chars else DEFAULT_CHARSETS["punctuation"]

    # Build character groups based on requirements
    components = [
        (num_lowercase, DEFAULT_CHARSETS["lower"]),
        (num_capitals, DEFAULT_CHARSETS["upper"]),
        (num_digits, DEFAULT_CHARSETS["digits"]),
        (num_punctuations, punctuation_set),
    ]

    char_list = []
    for count, charset in components:
        char_list.extend(create_random_characters(count, charset, disambiguate_chars))

    secrets.SystemRandom().shuffle(char_list)

    insert_pos = secrets.randbelow(len(char_list) + 1)
    # Insert the specific word at a random position within the generated character list
    password = ''.join(char_list[:insert_pos] + list(specific_word) + char_list[insert_pos:])
    return password

# === MAIN APP LOGIC ===
def setup_ui(root):
    # Setup the main UI layout and input fields
    ui = {}
    main_frame = tk.Frame(root, padx=10, pady=10, bg=BACKGROUND_COLOR)
    main_frame.pack(fill=tk.BOTH, expand=True)

    labels_entries = [
        ("Password Length:", "length_entry"),
        ("Punctuation Chars:", "punctuation_entry"),
        ("Digits:", "digits_entry"),
        ("Capitals:", "capitals_entry"),
        ("Specific Word:", "specific_word_entry"),
        ("Number of Passwords:", "num_passwords_entry"),
    ]

    for i, (label_text, var_name) in enumerate(labels_entries):
        row, col = divmod(i, 2)
        tk.Label(main_frame, text=label_text, bg=BACKGROUND_COLOR, fg=TEXT_COLOR)\
            .grid(row=row, column=col*2, sticky="e", padx=5, pady=5)
        entry = tk.Entry(main_frame, width=25 if "word" in var_name else 10,
                         bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        entry.grid(row=row, column=col*2+1, sticky="w", padx=5, pady=5)
        ui[var_name] = entry

    ui["main_frame"] = main_frame
    return ui

def attach_buttons_and_misc(root, ui, disambiguate, simple, update_message_box, generate_password, reset_fields, copy_to_clipboard, show_info):
    # Attach functional buttons, message box, and checkboxes to the UI
    main_frame = ui["main_frame"]

    button_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
    button_frame.grid(row=3, column=0, columnspan=4, pady=10)

    # Button for generating passwords
    tk.Button(button_frame, text="Create Password(s)", command=generate_password,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=20).pack(side=tk.LEFT, padx=5)
    # Button for copying to clipboard
    tk.Button(button_frame, text="Copy to Clipboard", command=copy_to_clipboard,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack(side=tk.LEFT, padx=5)
    # Button for resetting all fields
    tk.Button(button_frame, text="Reset Fields", command=reset_fields,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack(side=tk.LEFT, padx=5)

    # Label and text box for displaying generated passwords
    tk.Label(main_frame, text="Generated Passwords:", bg=BACKGROUND_COLOR, fg=TEXT_COLOR)\
        .grid(row=4, column=0, sticky="ne", padx=5, pady=5)

    message_box = tk.Text(main_frame, height=8, width=40, bg=ENTRY_COLOR, fg=TEXT_COLOR,
                          state=tk.DISABLED, insertbackground=TEXT_COLOR)
    message_box.grid(row=4, column=1, columnspan=3, sticky="nw", padx=5, pady=5)
    ui["message_box"] = message_box

    checkbox_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
    checkbox_frame.grid(row=5, column=0, columnspan=4, pady=5)

    # Checkboxes for disambiguate and simple characters modes
    tk.Checkbutton(checkbox_frame, text="Disambiguate", variable=disambiguate,
                   bg=BACKGROUND_COLOR, fg=TEXT_COLOR, selectcolor=BUTTON_COLOR)\
        .pack(side=tk.LEFT, padx=(0, 15))

    tk.Checkbutton(checkbox_frame, text="Simple Characters", variable=simple,
                   bg=BACKGROUND_COLOR, fg=TEXT_COLOR, selectcolor=BUTTON_COLOR)\
        .pack(side=tk.LEFT)

    # Info button to show usage information
    tk.Button(checkbox_frame, text="Info", command=show_info,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=6).pack(side=tk.LEFT, padx=10)

    exit_button_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
    exit_button_frame.grid(row=6, column=0, columnspan=4, pady=10)
    tk.Button(exit_button_frame, text="Exit", command=root.quit, bg=BUTTON_COLOR, fg=TEXT_COLOR, width=15).pack()

# === ENTRY POINT ===
def run_app():
    # Entry point to run the password generator application
    root = tk.Tk()
    root.title("Password Generator by Mattias")
    root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
    root.configure(bg=BACKGROUND_COLOR)

    disambiguate = tk.BooleanVar(value=False)
    simple = tk.BooleanVar(value=False)

    ui = setup_ui(root)

    def update_message_box(content):
        # Update the message box with generated passwords
        ui["message_box"].config(state=tk.NORMAL)
        ui["message_box"].delete(1.0, tk.END)
        ui["message_box"].insert(tk.END, content)
        ui["message_box"].config(state=tk.DISABLED)

    def reset_fields():
        # Reset all input fields and clear message box
        for key, entry in ui.items():
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
        update_message_box("")

    def generate_password():
        # Handle the generation of passwords with current settings
        try:
            length = get_entry_value(ui["length_entry"], 14, MAX_PASSWORD_LENGTH)
            num_punctuations = get_entry_value(ui["punctuation_entry"], 2)
            num_digits = get_entry_value(ui["digits_entry"], 2)
            num_capitals = get_entry_value(ui["capitals_entry"], 2)
            specific_word = ui["specific_word_entry"].get().strip()
            # Validate specific word
            if specific_word and (len(specific_word) > MAX_SPECIFIC_WORD_LENGTH or not all(c in string.printable for c in specific_word)):
                raise ValueError(ERROR_MESSAGES["invalid_specific_word"])
            randomize_length = not ui["length_entry"].get().strip()
            num_passwords = get_entry_value(ui["num_passwords_entry"], 1, MAX_PASSWORDS)

            min_required_length = num_punctuations + num_digits + num_capitals + len(specific_word)
            if length < min_required_length:
                show_message("Error", ERROR_MESSAGES["short_password"].format(min_required_length), "error")
                return

            passwords = [
                password_creation(length, num_punctuations, num_digits, num_capitals, specific_word,
                                  randomize_length, disambiguate.get(), simple.get())
                for _ in range(num_passwords)
            ]
            update_message_box("\n".join(passwords))
        except ValueError as e:
            show_message("Error", str(e), "error")

    def copy_to_clipboard():
        # Copy generated passwords or selection to clipboard
        selected_text = ui["message_box"].selection_get() if ui["message_box"].tag_ranges("sel") \
            else ui["message_box"].get("1.0", tk.END).strip()
        if not selected_text:
            show_message("Error", ERROR_MESSAGES["no_password_to_copy"], "error")
            return
        root.clipboard_clear()
        root.clipboard_append(selected_text)
        root.update()

    def show_info():
        # Display an info window with app instructions and explanations
        info_win = tk.Toplevel(root)
        info_win.title("Password Generator Info")
        info_win.configure(bg=BACKGROUND_COLOR)

        tk.Label(info_win, text="Password Generator Info", bg=BACKGROUND_COLOR, fg=TEXT_COLOR,
                 font=("Arial", 14, "bold")).pack(pady=(10, 5))

        msg = (
            "🔐 **Disambiguate Mode**:\n"
            "- Prevents ambiguous characters like I, l, 1, 0, O, o.\n"
            "- These are re-rolled if generated randomly.\n\n"
            "🎯 **Simple Characters Mode**:\n"
            "- Restricts special characters to just: ! ? . _ @ \n\n"
            "📏 **Default Configurations** (if left blank):\n"
            "- Length: 14\n"
            "- Punctuations: 2\n"
            "- Digits: 2\n"
            "- Capitals: 2\n"
            "- Specific Word: (empty)\n"
            "- Passwords Generated: 1\n\n"
            "🚫 **Limits**:\n"
            "- Max number of passwords: 999\n"
            "- Max password length: 999\n"
            "- Max specific word length: 50"
        )

        tk.Message(info_win, text=msg, bg=BACKGROUND_COLOR, fg=TEXT_COLOR, width=480, font=("Arial", 10)).pack(padx=20, pady=10)
        tk.Button(info_win, text="Close", command=info_win.destroy,
                  bg=BUTTON_COLOR, fg=TEXT_COLOR).pack(pady=10)

    attach_buttons_and_misc(root, ui, disambiguate, simple, update_message_box, generate_password, reset_fields, copy_to_clipboard, show_info)
    root.mainloop()

# === RUN ===
if __name__ == "__main__":
    # Run the application if executed directly
    run_app()
