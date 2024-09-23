import secrets
import string
import tkinter as tk
from tkinter import messagebox

# Function to create password
def password_creation(length, num_punctuations, num_digits, num_capitals, specific_word=""):
    
    # Error Conditions
    if num_punctuations + num_digits + num_capitals > length:
        raise ValueError("Number of punctuation, digit, and capital letter characters cannot exceed the password length.")
    elif length > 99:
        raise ValueError("Maximum password length = 99.")
    elif len(specific_word) > length - num_punctuations - num_digits - num_capitals:
        raise ValueError("The specific word is too long to fit in the password.")

    # Subtract the length of the specific word from the available length for random characters
    num_ascii_lowercase = length - num_punctuations - num_digits - num_capitals - len(specific_word)

    # Generate random lowercase ASCII letters
    random_lowercase = ''.join(secrets.choice(string.ascii_lowercase) for _ in range(num_ascii_lowercase))

    # Generate random capital letters only if num_capitals > 0
    if num_capitals > 0:
        capitals = ''.join(secrets.choice(string.ascii_uppercase) for _ in range(num_capitals))
    else:
        capitals = ""

    # Generate random digits only if num_digits > 0
    if num_digits > 0:
        digits = ''.join(secrets.choice(string.digits) for _ in range(num_digits))
    else:
        digits = ""

    # Add special characters
    punctuations = string.punctuation
    special_characters = ''.join(secrets.choice(punctuations) for _ in range(num_punctuations))

    # Combine the random parts: lowercase letters, capitals, digits, and special characters
    password_list = list(random_lowercase + capitals + digits + special_characters)

    # Shuffle the password list
    secrets.SystemRandom().shuffle(password_list)

    # Insert the specific word at a random position
    random_index = secrets.SystemRandom().randint(0, len(password_list))
    password_list.insert(random_index, specific_word)

    # Join the password list into the final password string
    final_password = ''.join(password_list)

    return final_password

# Function to save password to a text file
def save_password_to_file(password):
    try:
        # Open the file in append mode to add new passwords without overwriting
        with open("generated_passwords.txt", "a") as file:
            file.write(password + "\n")  # Add the password as a new line
        messagebox.showinfo("Success", "Password saved to 'generated_passwords.txt'.")
    except Exception as e:
        messagebox.showerror("Error", f"Failed to save password: {e}")

# Function to copy password to clipboard
def copy_to_clipboard(password):
    root.clipboard_clear()
    root.clipboard_append(password)
    root.update()

# Function to generate password
def generate_password():
    try:
        # Fetch attributes from input fields
        length = length_entry.get()
        num_punctuations = specialcharacter_entry.get()
        num_digits = digits_entry.get()
        num_capitals = capitals_entry.get()

        # If fields are left empty, assign random values
        if length == "":
            length = secrets.choice(range(8, 21))  # Random password length between 8 and 20 characters
        else:
            length = int(length)

        if num_punctuations == "":
            num_punctuations = secrets.choice(range(0, length // 4 + 1))  # Random punctuations (up to 1/4th of length)
        else:
            num_punctuations = int(num_punctuations)

        if num_digits == "":
            num_digits = secrets.choice(range(0, length // 4 + 1))  # Random digits (up to 1/4th of length)
        else:
            num_digits = int(num_digits)

        if num_capitals == "":
            num_capitals = secrets.choice(range(0, length // 4 + 1))  # Random capital letters (up to 1/4th of length)
        else:
            num_capitals = int(num_capitals)

        specific_word = specific_word_entry.get()

        # Create password with specific attributes
        password = password_creation(length, num_punctuations, num_digits, num_capitals, specific_word)

        # Update the label with the new password
        message_label.config(text=password)

    # Error box
    except ValueError as e:
        messagebox.showerror("Error", str(e))

# Create the main window
root = tk.Tk()
root.title("Password Generator")

# Create a title label
title_label = tk.Label(root, text="Create your custom password:")
title_label.pack(pady=20)

# Create a label to display text above the length input field
length_label = tk.Label(root, text="Password Length (leave empty for random):")
length_label.pack(pady=5)

# Create a length input field (Entry widget)
length_entry = tk.Entry(root, width=30)
length_entry.pack(pady=10)

# Create a label to display text above the special character input field
special_label = tk.Label(root, text="Number of Special Characters (leave empty for random):")
special_label.pack(pady=5)

# Create an input field for special characters
specialcharacter_entry = tk.Entry(root, width=30)
specialcharacter_entry.pack(pady=10)

# Create a label to display text above the digits input field
digits_label = tk.Label(root, text="Number of Digits (leave empty for random):")
digits_label.pack(pady=5)

# Create an input field for digits
digits_entry = tk.Entry(root, width=30)
digits_entry.pack(pady=10)

# Create a label to display text above the capital letters input field
capitals_label = tk.Label(root, text="Number of Capital Letters (leave empty for random):")
capitals_label.pack(pady=5)

# Create an input field for capital letters
capitals_entry = tk.Entry(root, width=30)
capitals_entry.pack(pady=10)

# Create a label for the specific word input field
specific_word_label = tk.Label(root, text="Specific Word (optional):")
specific_word_label.pack(pady=5)

# Create an input field for the specific word
specific_word_entry = tk.Entry(root, width=30)
specific_word_entry.pack(pady=10)

# Create a label to display the generated password
message_label = tk.Label(root, text="")
message_label.pack(pady=20)

# Create a button to generate the password
password_button = tk.Button(root, text="Create Password", command=generate_password)
password_button.pack(pady=20)

# Create a button that lets you copy to clipboard
copy_button = tk.Button(root, text="Copy to clipboard!", command=lambda: copy_to_clipboard(message_label.cget("text")))
copy_button.pack(pady=10)

# Create a button that saves the password to a file
save_button = tk.Button(root, text="Save to file", command=lambda: save_password_to_file(message_label.cget("text")))
save_button.pack(pady=10)

# Run the application
root.mainloop()
