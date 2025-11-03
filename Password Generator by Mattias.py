import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk

# === CONFIGURATION CONSTANTS ===
MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT = 800, 500
MAX_PASSWORD_LENGTH, MAX_PASSWORDS, MAX_SPECIFIC_WORD_LENGTH = 999, 999, 50

# === USER-FRIENDLY ERROR MESSAGES ===
ERROR_MESSAGES = {
    "invalid_number": "Please enter a valid whole number (e.g., 5, 10, 0). Symbols like +, -, letters, or decimals are not allowed.",
    "negative_value": "Please enter 0 or higher. Negative numbers are not allowed.",
    "exceeds_max": "Value is too large. Maximum allowed: {}.",
    "short_password": "Password length is too short. You need at least {} characters to meet the requirements.",
    "max_password_length": f"Maximum password length is {MAX_PASSWORD_LENGTH}.",
    "max_passwords": f"Maximum number of passwords allowed is {MAX_PASSWORD_LENGTH}.",
    "no_password_to_copy": "No password to copy.",
    "invalid_specific_word": f"Specific word must be plain text (letters, numbers, symbols) and no longer than {MAX_SPECIFIC_WORD_LENGTH} characters.",
}

# === STYLE CONSTANTS ===
BACKGROUND_COLOR = "#2b2b2b"
TEXT_COLOR = "#ffffff"
ENTRY_COLOR = "#4a4a4a"
BUTTON_COLOR = "#3a3a3a"
TREEVIEW_BG = "#3a3a3a"
TREEVIEW_FG = "#ffffff"
TREEVIEW_SELECT = "#5a5a5a"

# === CHARACTER SETS ===
AMBIGUOUS_CHARS = set("Il0O1o")
DEFAULT_CHARSETS = {
    "lower": string.ascii_lowercase,
    "upper": string.ascii_uppercase,
    "digits": string.digits,
    "punctuation": string.punctuation,
    "simple_punctuation": ['!', '?', '.', '_', '@'],
}

# === HELPER FUNCTIONS ===
def show_message(title, message, msg_type="error"):
    """Show a user-friendly message box."""
    getattr(messagebox, f"show{msg_type}")(title, message)

def get_entry_value(entry, default=0, max_value=None, field_name=""):
    """
    Safely extract an integer from an entry.
    Returns default if empty. Validates input and shows clear error if invalid.
    """
    raw = entry.get().strip()
    if not raw:
        return default

    if not raw.isdigit():
        raise ValueError(ERROR_MESSAGES["invalid_number"])

    value = int(raw)
    if value < 0:
        raise ValueError(ERROR_MESSAGES["negative_value"])
    if max_value is not None and value > max_value:
        raise ValueError(ERROR_MESSAGES["exceeds_max"].format(max_value))
    return value

def create_random_characters(count, char_set, disambiguate=False):
    result = []
    while len(result) < count:
        c = secrets.choice(char_set)
        if disambiguate and c in AMBIGUOUS_CHARS:
            continue
        result.append(c)
    return result

def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="",
                      randomize_length=False, disambiguate_chars=False, simple_chars=False):
    min_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    length = max(length, min_length) if randomize_length else length
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

    num_lowercase = length - min_length
    punctuation_set = DEFAULT_CHARSETS["simple_punctuation"] if simple_chars else DEFAULT_CHARSETS["punctuation"]

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
    password = ''.join(char_list[:insert_pos] + list(specific_word) + char_list[insert_pos:])
    return password

# === MAIN APP LOGIC ===
def setup_ui(root):
    ui = {}
    main_frame = tk.Frame(root, padx=15, pady=15, bg=BACKGROUND_COLOR)
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
        tk.Label(main_frame, text=label_text, bg=BACKGROUND_COLOR, fg=TEXT_COLOR, anchor="e")\
            .grid(row=row, column=col*2, sticky="e", padx=(0, 5), pady=6)
        width = 30 if "word" in var_name else 12
        entry = tk.Entry(main_frame, width=width, bg=ENTRY_COLOR, fg=TEXT_COLOR, insertbackground=TEXT_COLOR)
        entry.grid(row=row, column=col*2+1, sticky="w", padx=(0, 10), pady=6)
        ui[var_name] = entry

    ui["main_frame"] = main_frame
    return ui

def attach_buttons_and_passwords_display(root, ui, disambiguate, simple, update_passwords_display,
                                         generate_password, reset_fields, copy_to_clipboard, show_info):
    main_frame = ui["main_frame"]

    # === Button Row ===
    button_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
    button_frame.grid(row=3, column=0, columnspan=4, pady=12, sticky="ew")
    button_frame.columnconfigure(0, weight=1)

    tk.Button(button_frame, text="Create Password(s)", command=generate_password,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=18, font=("Arial", 9, "bold")).grid(row=0, column=0, padx=5)
    tk.Button(button_frame, text="Copy Selected", command=lambda: copy_to_clipboard(selected=True),
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=14).grid(row=0, column=1, padx=5)
    tk.Button(button_frame, text="Copy All", command=lambda: copy_to_clipboard(selected=False),
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=14).grid(row=0, column=2, padx=5)
    tk.Button(button_frame, text="Reset Fields", command=reset_fields,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=14).grid(row=0, column=3, padx=5)

    # === Passwords Display using Treeview ===
    display_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
    display_frame.grid(row=4, column=0, columnspan=4, sticky="nsew", pady=(10, 5))
    display_frame.rowconfigure(0, weight=1)
    display_frame.columnconfigure(0, weight=1)

    columns = ("password",)
    tree = ttk.Treeview(display_frame, columns=columns, show="headings", selectmode="extended")
    tree.heading("password", text="Generated Passwords")
    tree.column("password", anchor="w", width=700)

    style = ttk.Style()
    style.theme_use("clam")
    style.configure("Treeview", background=TREEVIEW_BG, foreground=TREEVIEW_FG,
                    fieldbackground=TREEVIEW_BG, rowheight=22, font=("Consolas", 10))
    style.configure("Treeview.Heading", background="#4a4a4a", foreground=TEXT_COLOR, font=("Arial", 10, "bold"))
    style.map("Treeview", background=[("selected", TREEVIEW_SELECT)])

    v_scroll = ttk.Scrollbar(display_frame, orient="vertical", command=tree.yview)
    h_scroll = ttk.Scrollbar(display_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

    tree.grid(row=0, column=0, sticky="nsew")
    v_scroll.grid(row=0, column=1, sticky="ns")
    h_scroll.grid(row=1, column=0, sticky="ew")

    ui["passwords_tree"] = tree

    # === Options Row ===
    options_frame = tk.Frame(main_frame, bg=BACKGROUND_COLOR)
    options_frame.grid(row=5, column=0, columnspan=4, pady=8)

    tk.Checkbutton(options_frame, text="Disambiguate (avoid I,l,1,0,O,o)", variable=disambiguate,
                   bg=BACKGROUND_COLOR, fg=TEXT_COLOR, selectcolor=BUTTON_COLOR, font=("Arial", 9))\
        .pack(side=tk.LEFT, padx=(0, 20))
    tk.Checkbutton(options_frame, text="Simple Punctuation (!?._@)", variable=simple,
                   bg=BACKGROUND_COLOR, fg=TEXT_COLOR, selectcolor=BUTTON_COLOR, font=("Arial", 9))\
        .pack(side=tk.LEFT, padx=(0, 20))
    tk.Button(options_frame, text="Info", command=show_info,
              bg=BUTTON_COLOR, fg=TEXT_COLOR, width=8, font=("Arial", 9)).pack(side=tk.LEFT, padx=10)
    tk.Button(options_frame, text="Exit", command=root.quit,
              bg="#c0392b", fg=TEXT_COLOR, width=8, font=("Arial", 9)).pack(side=tk.LEFT)

    main_frame.rowconfigure(4, weight=1)

def run_app():
    root = tk.Tk()
    root.title("Password Generator by Mattias")
    root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)
    root.configure(bg=BACKGROUND_COLOR)

    disambiguate = tk.BooleanVar(value=False)
    simple = tk.BooleanVar(value=False)
    ui = setup_ui(root)

    def update_passwords_display(passwords):
        tree = ui["passwords_tree"]
        for item in tree.get_children():
            tree.delete(item)
        for idx, pwd in enumerate(passwords, start=1):
            tree.insert("", tk.END, iid=idx, values=(pwd,))

    def reset_fields():
        """Clear all input fields and password list."""
        for entry in ui.values():
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
        update_passwords_display([])

    def generate_password():
        try:
            # Use field-specific defaults and clear error messages
            length = get_entry_value(ui["length_entry"], default=14, max_value=MAX_PASSWORD_LENGTH)
            num_punctuations = get_entry_value(ui["punctuation_entry"], default=2)
            num_digits = get_entry_value(ui["digits_entry"], default=2)
            num_capitals = get_entry_value(ui["capitals_entry"], default=2)
            specific_word = ui["specific_word_entry"].get().strip()

            # Validate specific word
            if specific_word:
                if len(specific_word) > MAX_SPECIFIC_WORD_LENGTH:
                    raise ValueError(ERROR_MESSAGES["invalid_specific_word"])
                if not all(c in string.printable for c in specific_word):
                    raise ValueError(ERROR_MESSAGES["invalid_specific_word"])

            randomize_length = not ui["length_entry"].get().strip()
            num_passwords = get_entry_value(ui["num_passwords_entry"], default=1, max_value=MAX_PASSWORDS)

            min_required = num_punctuations + num_digits + num_capitals + len(specific_word)
            if length < min_required:
                show_message("Not Enough Length", ERROR_MESSAGES["short_password"].format(min_required), "warning")
                return

            passwords = [
                password_creation(length, num_punctuations, num_digits, num_capitals, specific_word,
                                  randomize_length, disambiguate.get(), simple.get())
                for _ in range(num_passwords)
            ]
            update_passwords_display(passwords)

        except ValueError as e:
            show_message("Input Error", str(e), "error")

    def copy_to_clipboard(selected=True):
        tree = ui["passwords_tree"]
        if selected:
            selection = tree.selection()
            if not selection:
                show_message("Nothing Selected", "Please select one or more passwords to copy.", "warning")
                return
            text = "\n".join(tree.item(item, "values")[0] for item in selection)
        else:
            items = tree.get_children()
            if not items:
                show_message("Nothing to Copy", ERROR_MESSAGES["no_password_to_copy"], "warning")
                return
            text = "\n".join(tree.item(item, "values")[0] for item in items)

        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    def show_info():
        info_win = tk.Toplevel(root)
        info_win.title("Password Generator - Help & Info")
        info_win.geometry("580x540")
        info_win.configure(bg=BACKGROUND_COLOR)

        tk.Label(info_win, text="Password Generator - Help & Info", bg=BACKGROUND_COLOR, fg=TEXT_COLOR,
                 font=("Arial", 14, "bold")).pack(pady=(15, 8))

        msg = (
            "How to Use:\n"
            "• Enter numbers in the fields (leave blank for defaults)\n"
            "• Only whole numbers allowed — no +, -, letters, or decimals\n\n"
            "Default Values (when blank):\n"
            "• Length: 14 Punctuation: 2 Digits: 2 Capitals: 2\n"
            "• Specific Word: (none) Generate: 1 password\n\n"
            "Features:\n"
            "• Disambiguate: Avoids confusing characters (I,l,1,0,O,o)\n"
            "• Simple Punctuation: Uses only ! ? . _ @\n"
            "• Random Length: If Length is blank, uses minimum required\n\n"
            "Limits:\n"
            f"• Max passwords: {MAX_PASSWORDS}\n"
            f"• Max length: {MAX_PASSWORD_LENGTH}\n"
            f"• Max specific word: {MAX_SPECIFIC_WORD_LENGTH} chars\n\n"
            "Tips:\n"
            "• Select passwords in the list → 'Copy Selected'\n"
            "• 'Copy All' copies everything\n"
            "• 'Reset Fields' clears all inputs\n"
            "• Restart app to restore default values"
        )

        text_widget = tk.Text(info_win, bg=ENTRY_COLOR, fg=TEXT_COLOR, wrap=tk.WORD, font=("Arial", 10), padx=15, pady=10)
        text_widget.insert(tk.END, msg)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        tk.Button(info_win, text="Close", command=info_win.destroy,
                  bg=BUTTON_COLOR, fg=TEXT_COLOR, width=12).pack(pady=10)

    attach_buttons_and_passwords_display(root, ui, disambiguate, simple, update_passwords_display,
                                         generate_password, reset_fields, copy_to_clipboard, show_info)

    # Set defaults only on first launch
    ui["length_entry"].insert(0, "14")
    ui["punctuation_entry"].insert(0, "2")
    ui["digits_entry"].insert(0, "2")
    ui["capitals_entry"].insert(0, "2")
    ui["num_passwords_entry"].insert(0, "1")

    root.mainloop()

# === RUN ===
if __name__ == "__main__":
    run_app()
