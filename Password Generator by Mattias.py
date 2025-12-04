# file: password_generator.py
import secrets
import string
import tkinter as tk
from tkinter import messagebox, ttk
import math
import json
import os

# === CONFIGURATION CONSTANTS ===
MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT = 800, 500
MAX_PASSWORD_LENGTH, MAX_PASSWORDS, MAX_SPECIFIC_WORD_LENGTH = 999, 999, 50
DEFAULTS_FILENAME = "defaults.json"

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
        "ERROR_BUTTON_BG": "#c0392b",
        "ACCENT_FG": "#2ecc71",
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
        "ERROR_BUTTON_BG": "#e74c3c",
        "ACCENT_FG": "#3498db",
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

# === FACTORY DEFAULTS ===
FACTORY_DEFAULTS = {
    "length": 14,
    "punctuation": 2,
    "digits": 2,
    "capitals": 2,
    "specific_word": "",
    "num_passwords": 1
}

# === CURRENT DEFAULTS ===
current_defaults = FACTORY_DEFAULTS.copy()

# === HELPER FUNCTIONS ===
def show_message(title, message, msg_type="error"):
    getattr(messagebox, f"show{msg_type}")(title, message)

def get_entry_value_from_text(raw_text, default=0, max_value=None):
    raw = raw_text.strip()
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
    return ''.join(char_list[:insert_pos] + list(specific_word) + char_list[insert_pos:])

def evaluate_strength(password):
    if not password:
        return 0, "No password provided."

    length = len(password)
    charset_size = 0

    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digits = any(c in string.digits for c in password)
    has_symbols = any(c in string.punctuation for c in password)

    if has_lower:
        charset_size += len(string.ascii_lowercase)
    if has_upper:
        charset_size += len(string.ascii_uppercase)
    if has_digits:
        charset_size += len(string.digits)
    if has_symbols:
        charset_size += len(string.punctuation)

    if charset_size == 0:
        return 0, "Low (No recognizable characters)."

    entropy = length * math.log2(charset_size)

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

def show_strength_popup(root, password, entropy, rating):
    global current_theme
    theme = THEMES[current_theme]

    popup = tk.Toplevel(root)
    popup.title("Password Strength Evaluation")
    popup.configure(bg=theme["BACKGROUND"])
    popup.geometry("450x250")
    popup.transient(root)
    popup.grab_set()

    frame = tk.Frame(popup, bg=theme["BACKGROUND"], padx=15, pady=15)
    frame.pack(fill="both", expand=True)

    tk.Label(frame, text="Strength Analysis", bg=theme["BACKGROUND"], fg=theme["ACCENT_FG"],
             font=("Arial", 12, "bold")).pack(pady=(0, 10))

    tk.Label(frame, text=f"Password: {password}", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"],
             font=("Consolas", 10)).pack(anchor="w")

    tk.Label(frame, text=f"Rating: {rating}", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"],
             font=("Arial", 11, "bold")).pack(anchor="w", pady=(10, 5))

    tk.Label(frame, text=f"Entropy (bits): {entropy:.2f}", bg=theme["BACKGROUND"], fg=theme["FOREGROUND"],
             font=("Arial", 10)).pack(anchor="w")

    tk.Button(frame, text="Close", command=popup.destroy, bg=theme["BUTTON_BG"],
              fg=theme["FOREGROUND"], width=10).pack(pady=(15, 0))

    root.wait_window(popup)

def defaults_file_path():
    try:
        base_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        base_dir = os.getcwd()
    return os.path.join(base_dir, DEFAULTS_FILENAME)

def load_defaults_from_file():
    global current_defaults
    path = defaults_file_path()
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in FACTORY_DEFAULTS.items():
                if k not in data:
                    data[k] = v
            current_defaults = data
        except Exception:
            current_defaults = FACTORY_DEFAULTS.copy()
    else:
        current_defaults = FACTORY_DEFAULTS.copy()

def save_defaults_to_file():
    path = defaults_file_path()
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(current_defaults, f, indent=2)
        return True
    except Exception:
        return False

def reset_defaults_to_factory():
    global current_defaults
    current_defaults = FACTORY_DEFAULTS.copy()
    save_defaults_to_file()

# === MENU BAR ===
def setup_menu_bar(root, toggle_theme_func, show_info_func,
                   load_defaults_func, set_defaults_func, reset_defaults_func):
    global current_theme
    theme = THEMES[current_theme]

    menubar = tk.Menu(root, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    root.config(menu=menubar)

    style_menu = tk.Menu(menubar, tearoff=0, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    menubar.add_cascade(label="Style", menu=style_menu)
    style_menu.add_command(label="Toggle Dark/Light Mode", command=toggle_theme_func)

    defaults_menu = tk.Menu(menubar, tearoff=0, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    menubar.add_cascade(label="Defaults", menu=defaults_menu)
    defaults_menu.add_command(label="Load Defaults", command=load_defaults_func)
    defaults_menu.add_command(label="Set Defaults", command=set_defaults_func)
    defaults_menu.add_command(label="Reset Defaults", command=reset_defaults_func)

    help_menu = tk.Menu(menubar, tearoff=0, bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
    menubar.add_cascade(label="Help", menu=help_menu)
    help_menu.add_command(label="Info", command=show_info_func)

    root.menubar = menubar
    root.help_menu = help_menu
    root.style_menu = style_menu
    root.defaults_menu = defaults_menu

# === MAIN UI ===
def setup_ui(root):
    ui = {}
    root.grid_rowconfigure(0, weight=1)
    root.grid_columnconfigure(0, weight=1)

    main_frame = tk.Frame(root, padx=15, pady=15)
    main_frame.grid(row=0, column=0, sticky=tk.NSEW)

    for i in range(4):
        main_frame.columnconfigure(i, weight=1)
    main_frame.rowconfigure(4, weight=1)

    labels_entries = [
        ("Password Length:", "length_entry"),
        ("Punctuation Chars:", "punctuation_entry"),
        ("Digits:", "digits_entry"),
        ("Capitals:", "capitals_entry"),
        ("Specific Word:", "specific_word_entry"),
        ("Number of Passwords:", "num_passwords_entry"),
    ]

    for i, (text, key) in enumerate(labels_entries):
        row, col = divmod(i, 2)
        lbl = tk.Label(main_frame, text=text, anchor="e")
        lbl.grid(row=row, column=col * 2, sticky="e", padx=(0, 5), pady=6)

        width = 30 if "word" in key else 12
        entry = tk.Entry(main_frame, width=width)
        entry.grid(row=row, column=col * 2 + 1, sticky="w", padx=(0, 10), pady=6)

        ui[key] = entry
        ui[f"{key}_label"] = lbl

    ui["main_frame"] = main_frame
    return ui

def attach_buttons_and_passwords_display(root, ui, disambiguate, simple,
                                         update_passwords_display,
                                         generate_password, reset_fields,
                                         copy_to_clipboard, evaluate_selected_password):
    main_frame = ui["main_frame"]

    button_frame = tk.Frame(main_frame)
    button_frame.grid(row=3, column=0, columnspan=4, pady=12, sticky="ew")
    for i in range(5):
        button_frame.columnconfigure(i, weight=1)

    btn_font = ("Arial", 9)

    ui["btn_create"] = tk.Button(button_frame, text="Create Password(s)", command=generate_password,
                                 width=18, font=btn_font)
    ui["btn_evaluate"] = tk.Button(button_frame, text="Evaluate Strength", command=evaluate_selected_password,
                                   width=16, font=btn_font)
    ui["btn_copy_selected"] = tk.Button(button_frame, text="Copy Selected",
                                        command=lambda: copy_to_clipboard(True), width=14, font=btn_font)
    ui["btn_copy_all"] = tk.Button(button_frame, text="Copy All",
                                   command=lambda: copy_to_clipboard(False), width=14, font=btn_font)
    ui["btn_reset"] = tk.Button(button_frame, text="Reset Fields", command=reset_fields,
                                width=14, font=btn_font)

    ui["btn_create"].grid(row=0, column=0, padx=5, sticky="ew")
    ui["btn_evaluate"].grid(row=0, column=1, padx=5, sticky="ew")
    ui["btn_copy_selected"].grid(row=0, column=2, padx=5, sticky="ew")
    ui["btn_copy_all"].grid(row=0, column=3, padx=5, sticky="ew")
    ui["btn_reset"].grid(row=0, column=4, padx=5, sticky="ew")

    ui["button_frame"] = button_frame

    display_frame = tk.Frame(main_frame)
    display_frame.grid(row=4, column=0, columnspan=4, sticky="nsew", pady=(10, 5))
    display_frame.rowconfigure(0, weight=1)
    display_frame.columnconfigure(0, weight=1)

    columns = ("password",)
    tree = ttk.Treeview(display_frame, columns=columns, show="headings", selectmode="extended")
    tree.heading("password", text="Generated Passwords")
    tree.column("password", anchor="w", width=700)

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

    options_frame = tk.Frame(main_frame)
    options_frame.grid(row=5, column=0, columnspan=4, pady=8, sticky="ew")
    options_frame.columnconfigure(2, weight=1)

    ui["check_disambiguate"] = tk.Checkbutton(options_frame,
                                              text="Disambiguate (avoid I,l,1,0,O,o)",
                                              variable=disambiguate, font=("Arial", 9))
    ui["check_simple_punc"] = tk.Checkbutton(options_frame,
                                             text="Simple Punctuation (!?._@)",
                                             variable=simple, font=("Arial", 9))

    ui["check_disambiguate"].grid(row=0, column=0, sticky="w", padx=(0, 20))
    ui["check_simple_punc"].grid(row=0, column=1, sticky="w", padx=(0, 20))

    ui["options_frame"] = options_frame

    ui["btn_exit"] = tk.Button(options_frame, text="Exit",
                               command=root.quit, width=10, font=("Arial", 9))
    ui["btn_exit"].grid(row=0, column=3, sticky="e", padx=(0, 5))

# === APPLY THEME ===
def apply_theme(root, ui, theme_name):
    global current_theme
    current_theme = theme_name
    theme = THEMES[theme_name]

    root.configure(bg=theme["BACKGROUND"])
    ui["main_frame"].configure(bg=theme["BACKGROUND"])

    for key, widget in ui.items():
        if isinstance(widget, tk.Entry):
            widget.configure(bg=theme["ENTRY_BG"], fg=theme["FOREGROUND"],
                             insertbackground=theme["FOREGROUND"])
        elif isinstance(widget, tk.Label):
            if key.endswith("_label"):
                widget.configure(bg=theme["BACKGROUND"], fg=theme["FOREGROUND"])
        elif isinstance(widget, tk.Frame):
            widget.configure(bg=theme["BACKGROUND"])

    for key in ["btn_create", "btn_evaluate", "btn_copy_selected",
                "btn_copy_all", "btn_reset"]:
        if key in ui:
            ui[key].configure(bg=theme["BUTTON_BG"], fg=theme["FOREGROUND"],
                              activebackground=theme["TREEVIEW_SELECT"],
                              activeforeground=theme["FOREGROUND"])

    if "btn_exit" in ui:
        ui["btn_exit"].configure(bg=theme["ERROR_BUTTON_BG"], fg=theme["FOREGROUND"],
                                 activebackground=theme["TREEVIEW_SELECT"],
                                 activeforeground=theme["FOREGROUND"])

    for key in ["check_disambiguate", "check_simple_punc"]:
        if key in ui:
            ui[key].configure(bg=theme["BACKGROUND"], fg=theme["FOREGROUND"],
                              selectcolor=theme["BUTTON_BG"],
                              activebackground=theme["BACKGROUND"],
                              activeforeground=theme["FOREGROUND"])

    style = ui.get("treeview_style")
    if style:
        style.configure("Treeview",
                        background=theme["TREEVIEW_BG"],
                        foreground=theme["TREEVIEW_FG"],
                        fieldbackground=theme["TREEVIEW_BG"],
                        rowheight=22, font=("Consolas", 10))
        style.configure("Treeview.Heading",
                        background=theme["HEADING_BG"],
                        foreground=theme["FOREGROUND"],
                        font=("Arial", 10, "bold"))
        style.map("Treeview", background=[("selected", theme["TREEVIEW_SELECT"])])

    opts = {"bg": theme["BACKGROUND"], "fg": theme["FOREGROUND"],
            "activebackground": theme["TREEVIEW_SELECT"],
            "activeforeground": theme["FOREGROUND"]}

    if hasattr(root, 'menubar'):
        root.menubar.config(**opts)
        root.help_menu.config(**opts)
        root.style_menu.config(**opts)
        root.defaults_menu.config(**opts)

# === RUN APPLICATION ===
def run_app():
    root = tk.Tk()
    root.title("Password Generator by Mattias")
    root.minsize(MIN_WINDOW_WIDTH, MIN_WINDOW_HEIGHT)

    disambiguate = tk.BooleanVar(value=False)
    simple = tk.BooleanVar(value=False)

    ui = setup_ui(root)

    def toggle_theme():
        new = "Light" if current_theme == "Dark" else "Dark"
        apply_theme(root, ui, new)

    def update_passwords_display(passwords):
        tree = ui["passwords_tree"]
        for item in tree.get_children():
            tree.delete(item)
        first = None
        for idx, pwd in enumerate(passwords, start=1):
            iid = tree.insert("", tk.END, iid=idx, values=(pwd,))
            if idx == 1:
                first = iid
        if first:
            tree.selection_set(first)
            tree.focus(first)
            tree.see(first)

    def reset_fields():
        for entry in ui.values():
            if isinstance(entry, tk.Entry):
                entry.delete(0, tk.END)
        update_passwords_display([])

    def generate_password():
        try:
            length_text = ui["length_entry"].get()
            p_text = ui["punctuation_entry"].get()
            d_text = ui["digits_entry"].get()
            c_text = ui["capitals_entry"].get()
            s_text = ui["specific_word_entry"].get().strip()
            n_text = ui["num_passwords_entry"].get()

            length = get_entry_value_from_text(length_text,
                    default=current_defaults["length"], max_value=MAX_PASSWORD_LENGTH)
            punct = get_entry_value_from_text(p_text,
                    default=current_defaults["punctuation"])
            digits = get_entry_value_from_text(d_text,
                    default=current_defaults["digits"])
            caps = get_entry_value_from_text(c_text,
                    default=current_defaults["capitals"])
            num_pw = get_entry_value_from_text(n_text,
                    default=current_defaults["num_passwords"], max_value=MAX_PASSWORDS)

            # FIXED: specific_word now uses default if blank
            if not s_text:
                s_text = current_defaults.get("specific_word", "")

            if len(s_text) > MAX_SPECIFIC_WORD_LENGTH:
                raise ValueError(ERROR_MESSAGES["invalid_specific_word"])
            if not all(c in string.printable for c in s_text):
                raise ValueError(ERROR_MESSAGES["invalid_specific_word"])

            min_len = punct + digits + caps + len(s_text)
            if length < min_len:
                show_message("Length Too Short",
                             ERROR_MESSAGES["short_password"].format(min_len), "warning")
                return

            passwords = [
                password_creation(length, punct, digits, caps, s_text,
                                  False, disambiguate.get(), simple.get())
                for _ in range(num_pw)
            ]
            update_passwords_display(passwords)
        except ValueError as e:
            show_message("Input Error", str(e), "error")

    def copy_to_clipboard(selected):
        tree = ui["passwords_tree"]
        if selected:
            sel = tree.selection()
            if not sel:
                show_message("Nothing Selected", "Please select passwords first.", "warning")
                return
            text = "\n".join(tree.item(i, "values")[0] for i in sel)
        else:
            items = tree.get_children()
            if not items:
                show_message("Nothing to Copy", ERROR_MESSAGES["no_password_to_copy"], "warning")
                return
            text = "\n".join(tree.item(i, "values")[0] for i in items)
        root.clipboard_clear()
        root.clipboard_append(text)
        root.update()

    def evaluate_selected_password():
        tree = ui["passwords_tree"]
        sel = tree.selection()
        if not sel:
            show_message("No Selection", ERROR_MESSAGES["no_password_selected"], "warning")
            return
        pwd = tree.item(sel[0], "values")[0]
        entropy, rating = evaluate_strength(pwd)
        show_strength_popup(root, pwd, entropy, rating)

    def show_info():
        theme = THEMES[current_theme]
        win = tk.Toplevel(root)
        win.title("Password Generator - Help & Info")
        win.geometry("580x540")
        win.configure(bg=theme["BACKGROUND"])
        win.transient(root)

        tk.Label(win, text="Password Generator - Help & Info",
                 bg=theme["BACKGROUND"], fg=theme["FOREGROUND"],
                 font=("Arial", 14, "bold")).pack(pady=(15, 8))

        msg = (
            "How to Use:\n"
            "• Leave fields blank to use saved defaults.\n\n"
            "Current Defaults:\n"
            f"• Length: {current_defaults['length']}  "
            f"Punctuation: {current_defaults['punctuation']}  "
            f"Digits: {current_defaults['digits']}  "
            f"Capitals: {current_defaults['capitals']}\n"
            f"• Specific Word: ({current_defaults['specific_word']})  "
            f"Generate: {current_defaults['num_passwords']} password(s)\n"
            "\n"
            "Other:\n"
        "• Evaluate Strength: Select a password and click to see an estimated strength score (in bits of entropy).\n"
            "• Disambiguate: Avoids confusing characters (I,l,1,0,O,o)\n"
            "• Simple Punctuation: Uses only ! ? . _ @\n"
        )

        txt = tk.Text(win, bg=theme["ENTRY_BG"], fg=theme["FOREGROUND"],
                      wrap=tk.WORD, font=("Arial", 10), padx=15, pady=10)
        txt.insert(tk.END, msg)
        txt.config(state=tk.DISABLED)
        txt.pack(fill=tk.BOTH, expand=True, padx=20, pady=10)

        tk.Button(win, text="Close", command=win.destroy,
                  bg=theme["BUTTON_BG"], fg=theme["FOREGROUND"],
                  width=12).pack(pady=10)

    # === DEFAULT ACTIONS ===
    def load_defaults_into_entries():
        for key in ["length", "punctuation", "digits",
                    "capitals", "specific_word", "num_passwords"]:
            e = ui[f"{key}_entry"]
            e.delete(0, tk.END)
            e.insert(0, str(current_defaults.get(key, "")))

    def set_defaults_from_entries():
        global current_defaults
        try:
            def numeric_or_default(entry, key):
                raw = entry.get().strip()
                if raw == "":
                    return current_defaults[key]
                return get_entry_value_from_text(
                    raw, default=current_defaults[key])

            new = {}
            new["length"] = numeric_or_default(ui["length_entry"], "length")
            new["punctuation"] = numeric_or_default(ui["punctuation_entry"], "punctuation")
            new["digits"] = numeric_or_default(ui["digits_entry"], "digits")
            new["capitals"] = numeric_or_default(ui["capitals_entry"], "capitals")
            new["num_passwords"] = numeric_or_default(ui["num_passwords_entry"], "num_passwords")

            s = ui["specific_word_entry"].get().strip()
            if not s:
                s = current_defaults["specific_word"]
            if len(s) > MAX_SPECIFIC_WORD_LENGTH or not all(c in string.printable for c in s):
                raise ValueError(ERROR_MESSAGES["invalid_specific_word"])
            new["specific_word"] = s

            current_defaults = new
            save_defaults_to_file()
            show_message("Defaults Saved", "Defaults saved successfully.", "info")
        except ValueError as e:
            show_message("Invalid Defaults", str(e), "error")

    def reset_defaults_action():
        reset_defaults_to_factory()
        load_defaults_into_entries()
        show_message("Defaults Reset", "Defaults reset to factory values.", "info")

    # === MENU BAR ===
    setup_menu_bar(root, toggle_theme, show_info,
                   load_defaults_into_entries,
                   set_defaults_from_entries,
                   reset_defaults_action)

    attach_buttons_and_passwords_display(
        root, ui, disambiguate, simple, update_passwords_display,
        generate_password, reset_fields, copy_to_clipboard,
        evaluate_selected_password)

    apply_theme(root, ui, "Dark")

    load_defaults_from_file()
    load_defaults_into_entries()

    root.mainloop()

if __name__ == "__main__":
    run_app()
