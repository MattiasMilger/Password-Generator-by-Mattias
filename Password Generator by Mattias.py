import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk
import math

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
    "no_password_selected": "Please select a password from the list to evaluate its strength."
}

# === THEME CONFIGURATION ===
THEMES = {
    "Dark": {
        "BACKGROUND": "#2b2b2b",
        "FOREGROUND": "#ffffff",
        "ENTRY_BG": "#4a4a4a",
        "BUTTON_BG": "#3a3a3a",
        "TREEVIEW_BG": "#3a3a3a",
        "TREEVIEW_FG": "#ffffff",
        "TREEVIEW_SELECT": "#5a5a5a",
        "HEADING_BG": "#4a4a4a",
        "ERROR_BUTTON_BG": "#c0392b", # Red for Exit/Error
        "ACCENT_FG": "#2ecc71", # Green for titles/accents
    },
    "Light": {
        "BACKGROUND": "#f0f0f0",
        "FOREGROUND": "#333333",
        "ENTRY_BG": "#ffffff",
        "BUTTON_BG": "#cccccc",
        "TREEVIEW_BG": "#ffffff",
        "TREEVIEW_FG": "#333333",
        "TREEVIEW_SELECT": "#a0a0a0",
        "HEADING_BG": "#e0e0e0",
        "ERROR_BUTTON_BG": "#e74c3c", # Red for Exit/Error
        "ACCENT_FG": "#3498db", # Blue for titles/accents
    }
}
current_theme = "Dark"


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

def get_entry_value(entry, default=0, max_value=None):
    """
    Safely extract an integer from an entry widget.
    
    Returns default if the entry is empty. Validates input to ensure it is a 
    non-negative integer and does not exceed the maximum allowed value.
    Raises ValueError on invalid input.
    """
    raw = entry.get().strip()
    if not raw:
        return default

    # Check for non-digit characters
    if not raw.isdigit():
        raise ValueError(ERROR_MESSAGES["invalid_number"])

    value = int(raw)
    
    if value < 0:
        raise ValueError(ERROR_MESSAGES["negative_value"])
    
    if max_value is not None and value > max_value:
        raise ValueError(ERROR_MESSAGES["exceeds_max"].format(max_value))
        
    return value

def create_random_characters(count, char_set, disambiguate=False):
    """
    Generates a list of cryptographically secure random characters from a set.

    Args:
        count (int): The number of characters to generate.
        char_set (str or list): The pool of characters to choose from.
        disambiguate (bool): If True, avoids ambiguous characters (e.g., 'l', '1').
        
    Returns:
        list: A list of generated characters.
    """
    result = []
    while len(result) < count:
        c = secrets.choice(char_set)
        if disambiguate and c in AMBIGUOUS_CHARS:
            continue
        result.append(c)
    return result

def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word="",
                      randomize_length=False, disambiguate_chars=False, simple_chars=False):
    """
    Generates a single, cryptographically secure password based on the user's requirements.

    Args:
        length (int): The desired total length of the password.
        num_punctuations (int): Minimum count of punctuation characters.
        num_digits (int): Minimum count of digit characters.
        num_capitals (int): Minimum count of uppercase characters.
        specific_word (str): A word or phrase to embed in the password.
        randomize_length (bool): If True, length can be minimum required if initial length is too short.
        disambiguate_chars (bool): If True, excludes visually ambiguous characters.
        simple_chars (bool): If True, restricts punctuation to a simple set.
        
    Returns:
        str: The generated password.
        
    Raises:
        ValueError: If the calculated length exceeds the maximum allowed length.
    """
    # Calculate the minimum required length based on mandatory components
    min_length = num_punctuations + num_digits + num_capitals + len(specific_word)
    
    # Adjust length if randomization is allowed or if it's less than the minimum required
    length = max(length, min_length) if randomize_length else length
    
    if length > MAX_PASSWORD_LENGTH:
        raise ValueError(ERROR_MESSAGES["max_password_length"])

    # Calculate the number of required lowercase letters (the remaining characters)
    num_lowercase = length - min_length
    punctuation_set = DEFAULT_CHARSETS["simple_punctuation"] if simple_chars else DEFAULT_CHARSETS["punctuation"]

    # Define all character components and their required counts
    components = [
        (num_lowercase, DEFAULT_CHARSETS["lower"]),
        (num_capitals, DEFAULT_CHARSETS["upper"]),
        (num_digits, DEFAULT_CHARSETS["digits"]),
        (num_punctuations, punctuation_set),
    ]

    char_list = []
    for count, charset in components:
        # Generate random characters for each component
        char_list.extend(create_random_characters(count, charset, disambiguate_chars))

    # Cryptographically shuffle the character list
    secrets.SystemRandom().shuffle(char_list)

    # Determine a random position to insert the specific word
    insert_pos = secrets.randbelow(len(char_list) + 1)
    
    # Construct the final password
    password = ''.join(char_list[:insert_pos] + list(specific_word) + char_list[insert_pos:])
    return password

# --- STRENGTH EVALUATION FUNCTION ---
def evaluate_strength(password):
    """
    Calculates the password strength based on Shannon Entropy in bits.
    
    Entropy is calculated as E = L * log2(R), where L is the length of the 
    password and R is the size of the total character set used.

    Args:
        password (str): The password string to evaluate.

    Returns:
        tuple: (entropy_value (float), rating_string (str))
    """
    if not password:
        return 0, "No password provided."

    length = len(password)
    charset_size = 0
    
    # Check for character types present to determine the size of the character set (R)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digits = any(c in string.digits for c in password)
    has_symbols = any(c in string.punctuation for c in password)
    
    if has_lower:
        charset_size += len(string.ascii_lowercase) # 26
    if has_upper:
        charset_size += len(string.ascii_uppercase) # 26
    if has_digits:
        charset_size += len(string.digits) # 10
    if has_symbols:
        charset_size += len(string.punctuation) # 32
        
    if charset_size == 0:
        return 0, "Low (No recognizable characters)."

    # Shannon Entropy formula: E = L * log2(R)
    entropy = length * math.log2(charset_size)

    # Determine strength rating based on common thresholds
    if entropy < 28:
        rating = "Very Weak (Instantly crackable)"
    elif entropy < 36:
        rating = "Weak (Crackable in minutes/hours)"
    elif entropy < 60:
        rating = "Reasonable (Crackable in days/weeks)"
    elif entropy < 80:
        rating = "Strong (Crackable in months/years)"
    else:
        rating = "Very Strong (Crackable in decades/centuries)"
        
    return entropy, rating

# --- STRENGTH POPUP FUNCTION ---
def show_strength_popup(root, password, entropy, rating):
    """Shows strength results in a custom Toplevel window."""
    global current_theme
    theme = THEMES[current_theme]
    
    popup = tk.Toplevel(root)
    popup.title("Password Strength Evaluation")
    popup.configure(bg=theme["BACKGROUND"])
    popup.geometry("450x250") 
    popup.transient(root)  # Keep the window on top of the main window
    popup.grab_set()       # Modal window: disables interaction with the main window
    
    frame = tk.Frame(popup, bg=theme["BACKGROUND"], padx=15, pady=15)
    frame.pack(fill="both", expand=True)

    # Title
    tk.Label(frame, text="Strength Analysis", bg=theme["BACKGROUND"], fg=theme["ACCENT_FG"], font=("Arial", 12, "bold"))\
        .pack(pady=(0, 10))

    # Password
    tk.Label(frame, text=f"Password: {password}", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"], font=("Consolas", 10))\
        .pack(anchor="w")
    
    # Rating
    tk.Label(frame, text=f"Rating: {rating}", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"], font=("Arial", 11, "bold"))\
        .pack(anchor="w", pady=(10, 5))
        
    # Entropy
    tk.Label(frame, text=f"Entropy (bits): {entropy:.2f}", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"], font=("Arial", 10))\
        .pack(anchor="w")

    # Close Button
    tk.Button(frame, text="Close", command=popup.destroy, bg=theme["BUTTON_BG"], fg=theme["FOREGROUND"], width=10)\
        .pack(pady=(15, 0))
    
    root.wait_window(popup) # Wait until the popup is closed

# --- MENU BAR SETUP ---
def setup_menu_bar(root, toggle_theme_func, show_info_func):
    """
    Creates the application menu bar and adds Options (Theme) and Help (Info) options.
    Options is placed to the left of Help as requested.
    """
    global current_theme
    theme = THEMES[current_theme]
    
    menubar = tk.Menu(root, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    root.config(menu=menubar)
    
    # 1. Options Menu (for theme toggle)
    style_menu = tk.Menu(menubar, tearoff=0, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    menubar.add_cascade(label="Style", menu=style_menu)
    style_menu.add_command(label="Toggle Dark/Light Mode", command=toggle_theme_func)

    # 2. Help Menu (for info/usage)
    help_menu = tk.Menu(menubar, tearoff=0, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="Info / Usage", command=show_info_func)
    
    # Store references for theme updates
    root.menubar = menubar
    root.help_menu = help_menu
    root.style_menu = style_menu


# === MAIN APP LOGIC ===
def setup_ui(root):
    """Initializes and returns the UI widgets in a dictionary."""
    ui = {}
    
    # Configure root window for scaling
    # We only need one row now, as the exit button is being moved back into the main frame grid
    root.grid_rowconfigure(0, weight=1) 
    root.grid_columnconfigure(0, weight=1)
    
    main_frame = tk.Frame(root, padx=15, pady=15)
    main_frame.grid(row=0, column=0, sticky=tk.NSEW)

    # Configure the main frame grid to allow internal widgets to scale
    for i in range(4): # 4 columns (label-entry pairs)
        main_frame.columnconfigure(i, weight=1)
    main_frame.rowconfigure(4, weight=1) # Row for the password display (Treeview)

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
        label = tk.Label(main_frame, text=label_text, anchor="e")
        label.grid(row=row, column=col*2, sticky="e", padx=(0, 5), pady=6)
        
        width = 30 if "word" in var_name else 12
        entry = tk.Entry(main_frame, width=width)
        entry.grid(row=row, column=col*2+1, sticky="w", padx=(0, 10), pady=6)
        
        ui[var_name] = entry
        ui[f"{var_name}_label"] = label # Store label for theme application

    ui["main_frame"] = main_frame
    return ui

def attach_buttons_and_passwords_display(root, ui, disambiguate, simple, update_passwords_display,
                                         generate_password, reset_fields, copy_to_clipboard, 
                                         evaluate_selected_password):
    """Attaches all buttons, options, and the password display area to the main frame."""
    main_frame = ui["main_frame"]

    # === Button Row (Action Buttons) ===
    button_frame = tk.Frame(main_frame)
    button_frame.grid(row=3, column=0, columnspan=4, pady=12, sticky="ew")
    for i in range(5):
        button_frame.columnconfigure(i, weight=1) # Allow buttons to scale horizontally

    # Create and store buttons for later theme application
    ui["btn_create"] = tk.Button(button_frame, text="Create Password(s)", command=generate_password,
                                 width=18, font=("Arial", 9, "bold"))
    ui["btn_evaluate"] = tk.Button(button_frame, text="Evaluate Strength", command=evaluate_selected_password,
                                   width=16, font=("Arial", 9, "bold"))
    ui["btn_copy_selected"] = tk.Button(button_frame, text="Copy Selected", 
                                        command=lambda: copy_to_clipboard(selected=True), width=14)
    ui["btn_copy_all"] = tk.Button(button_frame, text="Copy All", 
                                   command=lambda: copy_to_clipboard(selected=False), width=14)
    ui["btn_reset"] = tk.Button(button_frame, text="Reset Fields", command=reset_fields, width=14)
    
    ui["btn_create"].grid(row=0, column=0, padx=5, sticky="ew")
    ui["btn_evaluate"].grid(row=0, column=1, padx=5, sticky="ew")
    ui["btn_copy_selected"].grid(row=0, column=2, padx=5, sticky="ew")
    ui["btn_copy_all"].grid(row=0, column=3, padx=5, sticky="ew")
    ui["btn_reset"].grid(row=0, column=4, padx=5, sticky="ew")
    
    ui["button_frame"] = button_frame

    # === Passwords Display using Treeview ===
    display_frame = tk.Frame(main_frame)
    display_frame.grid(row=4, column=0, columnspan=4, sticky="nsew", pady=(10, 5))
    display_frame.rowconfigure(0, weight=1)
    display_frame.columnconfigure(0, weight=1)

    columns = ("password",)
    tree = ttk.Treeview(display_frame, columns=columns, show="headings", selectmode="extended")
    tree.heading("password", text="Generated Passwords")
    tree.column("password", anchor="w", width=700) 

    # Treeview Style setup - Theme-dependent styling will be handled in apply_theme
    style = ttk.Style()
    style.theme_use("clam")
    
    ui["treeview_style"] = style
    ui["passwords_tree"] = tree

    v_scroll = ttk.Scrollbar(display_frame, orient="vertical", command=tree.yview)
    h_scroll = ttk.Scrollbar(display_frame, orient="horizontal", command=tree.xview)
    tree.configure(yscrollcommand=v_scroll.set, xscrollcommand=h_scroll.set)

    tree.grid(row=0, column=0, sticky="nsew")
    v_scroll.grid(row=0, column=1, sticky="ns")
    h_scroll.grid(row=1, column=0, sticky="ew")
    
    ui["v_scroll"] = v_scroll
    ui["h_scroll"] = h_scroll

    # === Options Row (Checkbuttons and Exit Button) ===
    # This row is now responsible for checkbuttons on the left and Exit button on the right
    options_frame = tk.Frame(main_frame)
    # This row is placed in the last available grid slot of the main frame
    options_frame.grid(row=5, column=0, columnspan=4, pady=8, sticky="ew") 
    
    # Configure options frame to push Exit button to the right
    options_frame.columnconfigure(2, weight=1) 

    # Checkbuttons (placed on the left side, columns 0 and 1)
    ui["check_disambiguate"] = tk.Checkbutton(options_frame, text="Disambiguate (avoid I,l,1,0,O,o)", 
                                              variable=disambiguate, font=("Arial", 9))
    ui["check_simple_punc"] = tk.Checkbutton(options_frame, text="Simple Punctuation (!?._@)", 
                                             variable=simple, font=("Arial", 9))
    
    ui["check_disambiguate"].grid(row=0, column=0, sticky="w", padx=(0, 20))
    ui["check_simple_punc"].grid(row=0, column=1, sticky="w", padx=(0, 20))
    
    ui["options_frame"] = options_frame
    
    # Exit Button (placed on the right side, column 3)
    ui["btn_exit"] = tk.Button(options_frame, text="Exit", command=root.quit, width=10, font=("Arial", 9, "bold"))
    ui["btn_exit"].grid(row=0, column=3, sticky="e", padx=(0, 5))


def apply_theme(root, ui, theme_name):
    """
    Applies the specified theme colors to all configured widgets in the UI.
    
    Args:
        root (tk.Tk): The main Tkinter root window.
        ui (dict): The dictionary containing references to all UI widgets.
        theme_name (str): The name of the theme (e.g., "Dark", "Light").
    """
    global current_theme
    current_theme = theme_name
    theme = THEMES[theme_name]
    
    # Update root and main frame background
    root.configure(bg=theme["BACKGROUND"])
    ui["main_frame"].configure(bg=theme["BACKGROUND"])
    
    # Update entry fields and labels
    for key, widget in ui.items():
        if isinstance(widget, tk.Entry):
            widget.configure(bg=theme["ENTRY_BG"], fg=theme["FOREGROUND"], insertbackground=theme["FOREGROUND"])
        elif isinstance(widget, tk.Label):
            if key.endswith("_label"):
                 widget.configure(bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
        elif isinstance(widget, tk.Frame):
            widget.configure(bg=theme["BACKGROUND"])

    # Update standard buttons (using list to easily iterate)
    button_keys = ["btn_create", "btn_evaluate", "btn_copy_selected", "btn_copy_all", "btn_reset"]
    for key in button_keys:
        ui[key].configure(bg=theme["BUTTON_BG"], fg=theme["FOREGROUND"], activebackground=theme["TREEVIEW_SELECT"], activeforeground=theme["FOREGROUND"])
        
    # Update Exit button (uses special error color)
    ui["btn_exit"].configure(bg=theme["ERROR_BUTTON_BG"], fg=theme["FOREGROUND"], activebackground=theme["TREEVIEW_SELECT"], activeforeground=theme["FOREGROUND"])
    
    # Update Checkbuttons
    check_keys = ["check_disambiguate", "check_simple_punc"]
    for key in check_keys:
        ui[key].configure(bg=theme["BACKGROUND"], fg=theme["FOREGROUND"], selectcolor=theme["BUTTON_BG"], activebackground=theme["BACKGROUND"], activeforeground=theme["FOREGROUND"])

    # Update Treeview Style
    style = ui["treeview_style"]
    style.configure("Treeview", background=theme["TREEVIEW_BG"], foreground=theme["TREEVIEW_FG"],
                    fieldbackground=theme["TREEVIEW_BG"], rowheight=22, font=("Consolas", 10))
    style.configure("Treeview.Heading", background=theme["HEADING_BG"], foreground=theme["FOREGROUND"], font=("Arial", 10, "bold"))
    style.map("Treeview", background=[("selected", theme["TREEVIEW_SELECT"])])
    
    # Update Menu Bar Dropdowns (cannot theme the main bar)
    menu_theme_options = {"bg": theme["BACKGROUND"], "fg": theme["FOREGROUND"], 
                          "activebackground": theme["TREEVIEW_SELECT"], "activeforeground": theme["FOREGROUND"]}
    
    if hasattr(root, 'menubar'):
        # Apply theme to dropdown menus
        root.menubar.config(**menu_theme_options) 
        root.help_menu.config(**menu_theme_options)
        root.style_menu.config(**menu_theme_options)


def run_app():
    """Initializes the main application window and starts the event loop."""
    root = tk.Tk()
    root.title("Password Generator")
    root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

    # Boolean variables for options
    disambiguate = tk.BooleanVar(value=False)
    simple = tk.BooleanVar(value=False)
    
    # Setup UI components
    ui = setup_ui(root)

    def toggle_theme():
        """Switches between Dark and Light themes."""
        global current_theme
        new_theme = "Light" if current_theme == "Dark" else "Dark"
        apply_theme(root, ui, new_theme)

    def update_passwords_display(passwords):
        """Clears the Treeview and populates it with new generated passwords."""
        tree = ui["passwords_tree"]
        for item in tree.get_children():
            tree.delete(item)
        for idx, pwd in enumerate(passwords, start=1):
            tree.insert("", tk.END, iid=idx, values=(pwd,))

    def reset_fields():
        """Clear all input fields and the password list display."""
        for entry in ui.values():
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
        update_passwords_display([])
        
        # Re-insert default values (for user convenience)
        ui["length_entry"].insert(0, "14")
        ui["punctuation_entry"].insert(0, "2")
        ui["digits_entry"].insert(0, "2")
        ui["capitals_entry"].insert(0, "2")
        ui["num_passwords_entry"].insert(0, "1")

    def generate_password():
        """Handles reading inputs, validating them, and generating passwords."""
        try:
            # Safely extract integer values using helper function
            length = get_entry_value(ui["length_entry"], default=14, max_value=MAX_PASSWORD_LENGTH)
            num_punctuations = get_entry_value(ui["punctuation_entry"], default=2)
            num_digits = get_entry_value(ui["digits_entry"], default=2)
            num_capitals = get_entry_value(ui["capitals_entry"], default=2)
            specific_word = ui["specific_word_entry"].get().strip()
            num_passwords = get_entry_value(ui["num_passwords_entry"], default=1, max_value=MAX_PASSWORDS)

            # Validate specific word
            if specific_word:
                if len(specific_word) > MAX_SPECIFIC_WORD_LENGTH:
                    raise ValueError(ERROR_MESSAGES["invalid_specific_word"])
                if not all(c in string.printable for c in specific_word):
                    raise ValueError(ERROR_MESSAGES["invalid_specific_word"])

            # Determine if length should be randomized/adjusted
            randomize_length = not ui["length_entry"].get().strip()
            
            # Check for minimum length requirement
            min_required = num_punctuations + num_digits + num_capitals + len(specific_word)
            if length < min_required:
                show_message("Length Too Short", ERROR_MESSAGES["short_password"].format(min_required), "warning")
                return

            # Generate the list of passwords
            passwords = [
                password_creation(length, num_punctuations, num_digits, num_capitals, specific_word,
                                  randomize_length, disambiguate.get(), simple.get())
                for _ in range(num_passwords)
            ]
            update_passwords_display(passwords)

        except ValueError as e:
            show_message("Input Error", str(e), "error")

    def copy_to_clipboard(selected=True):
        """Copies selected or all generated passwords to the system clipboard."""
        tree = ui["passwords_tree"]
        if selected:
            selection = tree.selection()
            if not selection:
                show_message("Nothing Selected", "Please select one or more passwords to copy.", "warning")
                return
            # Join selected passwords with newlines
            text = "\n".join(tree.item(item, "values")[0] for item in selection)
        else:
            items = tree.get_children()
            if not items:
                show_message("Nothing to Copy", ERROR_MESSAGES["no_password_to_copy"], "warning")
                return
            # Join all passwords with newlines
            text = "\n".join(tree.item(item, "values")[0] for item in items)

        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()
        
    def evaluate_selected_password():
        """Evaluates the strength of the currently selected password and displays results in a popup."""
        tree = ui["passwords_tree"]
        selection = tree.selection()
        
        if not selection:
            show_message("No Selection", ERROR_MESSAGES["no_password_selected"], "warning")
            return
        
        # Use the first selected password
        selected_item = selection[0]
        password = tree.item(selected_item, "values")[0]
        
        entropy, rating = evaluate_strength(password)
        
        show_strength_popup(root, password, entropy, rating)

    def show_info():
        """Displays a help and information window."""
        theme = THEMES[current_theme]
        info_win = tk.Toplevel(root)
        info_win.title("Password Generator - Help & Info")
        info_win.geometry("580x540")
        info_win.configure(bg=theme["BACKGROUND"])
        info_win.transient(root) # Keep on top

        tk.Label(info_win, text="Password Generator - Help & Info", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"],
                  font=("Arial", 14, "bold")).pack(pady=(15, 8))

        msg = (
            "How to Use:\n"
            "• Enter numbers in the fields (leave blank for defaults)\n"
            "• Only whole numbers allowed — no +, -, letters, or decimals\n\n"
            "Default Values (when blank):\n"
            "• Length: 14\tPunctuation: 2\tDigits: 2\tCapitals: 2\n"
            "• Specific Word: (none)\tGenerate: 1 password\n\n"
            "Features:\n"
            "• **Evaluate Strength**: Select a password and click to see an estimated strength score (in bits of entropy).\n"
            "• Disambiguate: Avoids confusing characters (I,l,1,0,O,o)\n"
            "• Simple Punctuation: Uses only ! ? . _ @\n"
            "• Random Length: If Length is blank, the length is set to the minimum required characters.\n\n"
            "Limits:\n"
            f"• Max passwords: {MAX_PASSWORDS}\n"
            f"• Max length: {MAX_PASSWORD_LENGTH}\n"
            f"• Max specific word: {MAX_SPECIFIC_WORD_LENGTH} chars\n\n"
            "Tips:\n"
            "• Select passwords in the list → 'Copy Selected'\n"
            "• 'Copy All' copies every generated password\n"
            "• 'Reset Fields' clears all inputs and re-applies defaults\n"
            "• Toggle Theme: Switches between a Dark and Light interface via the **Options** menu."
        )

        text_widget = tk.Text(info_win, bg=theme["ENTRY_BG"], fg=theme["FOREGROUND"], wrap=tk.WORD, font=("Arial", 10), padx=15, pady=10)
        text_widget.insert(tk.END, msg)
        text_widget.config(state=tk.DISABLED)
        text_widget.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        tk.Button(info_win, text="Close", command=info_win.destroy,
                  bg=theme["BUTTON_BG"], fg=theme["FOREGROUND"], width=12).pack(pady=10)


    # Setup the Menu Bar
    setup_menu_bar(root, toggle_theme, show_info)

    # Attach all final components and controls
    attach_buttons_and_passwords_display(root, ui, disambiguate, simple, update_passwords_display,
                                         generate_password, reset_fields, copy_to_clipboard, 
                                         evaluate_selected_password)

    # Apply initial theme (Dark is the default)
    apply_theme(root, ui, "Dark")
    
    # Set default values for entries
    ui["length_entry"].insert(0, "14")
    ui["punctuation_entry"].insert(0, "2")
    ui["digits_entry"].insert(0, "2")
    ui["capitals_entry"].insert(0, "2")
    ui["num_passwords_entry"].insert(0, "1")

    # Start the Tkinter event loop
    root.mainloop()

# === RUN APPLICATION ===
if __name__ == "__main__":
    run_app()
