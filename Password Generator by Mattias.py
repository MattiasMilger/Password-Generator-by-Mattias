import secrets
import string
import tkinter as tk
from tkinter import messagebox

# Function to create password
def password_creation(length, num_punctuations, specific_word=""):
    
    # Error Conditions
    if num_punctuations > length:
        raise ValueError("Number of punctuation characters cannot exceed the password length.")
    elif length > 99:
        raise ValueError("Maximum password length = 99.")
    elif len(specific_word) > length - num_punctuations:
        raise ValueError("The specific word is too long to fit in the password.")

    # Subtract the length of the specific word from the available length for random characters
    num_ascii_digits = length - num_punctuations - len(specific_word)

    # Generate random ASCII letters and digits
    ascii_digits = string.ascii_letters + string.digits
    random_part = ''.join(secrets.choice(ascii_digits) for _ in range(num_ascii_digits))

    # Add special characters
    punctuations = string.punctuation
    special_characters = ''.join(secrets.choice(punctuations) for _ in range(num_punctuations))

    # Combine the random part and special characters
    password_list = list(random_part + special_characters)

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
        length = int(length_entry.get())

        # Check if the special characters field is empty and handle accordingly
        num_punctuations = specialcharacter_entry.get()
        if num_punctuations == "":
            num_punctuations = 0
        else:
            num_punctuations = int(num_punctuations)

        specific_word = specific_word_entry.get()

        # Create password with specific attributes
        password = password_creation(length, num_punctuations, specific_word)

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
length_label = tk.Label(root, text="Password Length:")
length_label.pack(pady=5)

# Create a length input field (Entry widget)
length_entry = tk.Entry(root, width=30)
length_entry.pack(pady=10)

# Create a label to display text above the special character input field
special_label = tk.Label(root, text="Number of Special Characters (optional):")
special_label.pack(pady=5)

# Create an input field for special characters
specialcharacter_entry = tk.Entry(root, width=30)
specialcharacter_entry.pack(pady=10)

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
