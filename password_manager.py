from tkinter import *
import random
from tkinter import messagebox
import pyperclip
import json

# ---------------------------- PASSWORD GENERATOR ------------------------------- #
# Generate a secure random password
letters = ['a', 'b', 'c', 'd', 'e', 'f', 'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
           'w', 'x', 'y', 'z',
           'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V',
           'W', 'X', 'Y', 'Z']
numbers = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9']
symbols = ['!', '#', '$', '%', '&', '(', ')', '*', '+']


def generate_password():
    """
    Generates a secure password with a random number of letters, symbols, and numbers.
    It then shuffles the password and inserts it into the password entry field.
    The password is also copied to the clipboard.
    """
    # Define the number of characters to include
    nr_total = random.randint(10, 16)  # Random length between 10 and 16
    nr_symbols = random.randint(2, 4)  # Random number of symbols
    nr_numbers = random.randint(2, 4)  # Random number of numbers

    # Generate the random components of the password
    password_list = (
            [random.choice(letters) for _ in range(nr_total - nr_symbols - nr_numbers)] +
            [random.choice(symbols) for _ in range(nr_symbols)] +
            [random.choice(numbers) for _ in range(nr_numbers)]
    )

    # Shuffle the order of the characters to randomize the password
    random.shuffle(password_list)

    # Combine the list into a string
    password = "".join(password_list)

    # Insert the generated password into the password entry box
    password_entry.insert(0, password)

    # Copy the password to the clipboard for easy access
    pyperclip.copy(password)
    return password


# ---------------------------- SAVE PASSWORD ------------------------------- #
# Write website credentials to a data file
def save():
    website = website_entry.get().strip()
    email = email_entry.get().strip()
    password = password_entry.get().strip()

    if not website or not email or not password:
        messagebox.showwarning(title="Warning", message="Please fill out all fields!")
        return

    new_data = {
        website: {
            "email": email,
            "password": password
        }
    }

    try:
        # Load existing data
        with open("data.json", "r") as data_file:
            data = json.load(data_file)
    except FileNotFoundError:
        # If the file does not exist, start with an empty dictionary
        data = {}

    # Update data
    data.update(new_data)

    try:
        # Save updated data back to the file
        with open("data.json", "w") as data_file:
            json.dump(data, data_file, indent=4)
        messagebox.showinfo(title="Success", message="Info saved!")
        website_entry.delete(0, END)
        password_entry.delete(0, END)
    except Exception as e:
        messagebox.showerror(title="Error", message=f"An error occurred: {str(e)}")


# ---------------------------- RETRIEVE PASSWORD ------------------------------- #
# Retrieve website credentials from the file
def retrieve(query):
    website = query.strip()
    if not website:
        messagebox.showwarning(title="Warning", message="Please enter a website to search for!")
        return

    try:
        with open("data.json", "r") as data_file:
            data = json.load(data_file)

        # Find all keys that partially match the query
        matches = {key: value for key, value in data.items() if website.lower() in key.lower()}

        if matches:
            # Display all matches in a formatted string
            match_results = "\n\n".join([f"Website: {key}\nEmail: {value['email']}\nPassword: {value['password']}"
                                         for key, value in matches.items()])
            messagebox.showinfo(title="Results", message=f"Found the following matches:\n\n{match_results}")
        else:
            messagebox.showwarning(title="Not Found", message=f"No details for {website} exists.")
    except FileNotFoundError:
        messagebox.showerror(title="Error", message="Data file not found.")
    except json.JSONDecodeError:
        messagebox.showerror(title="Error", message="Error reading data file. Data may be corrupted.")



# ---------------------------- UI SETUP ------------------------------- #
# Set up the graphical user interface (GUI)
window = Tk()  # Create the main application window
window.title("Password Manager")  # Set the window title
window.config(padx=50, pady=50)  # Add padding around the window content
window.config(bg="white")  # Set the background color

# Set up the logo
canvas = Canvas(height=200, width=200)
logo_img = PhotoImage(file="logo.png")  # Load the logo image (must exist in the same directory)
canvas.create_image(100, 100, image=logo_img)  # Place logo at the center of the canvas
canvas.grid(column=1, row=1)  # Position the canvas in the grid layout

# Labels
website_label = Label(text="Website:", bg="white")  # Label for the website input
website_label.grid(column=0, row=2)

# Entry fields
website_entry = Entry(width=39)  # Input field for website
website_entry.grid(row=2, column=1, columnspan=2)
website_entry.focus()  # Automatically focus on this field when the app starts

email_label = Label(text="Email/Username:", bg="white")  # Label for email/username input
email_label.grid(column=0, row=3)

email_entry = Entry(width=39)  # Input field for email/username
email_entry.grid(row=3, column=1, columnspan=2)

password_label = Label(text="Password:", bg="white")  # Label for password input
password_label.grid(column=0, row=4)

password_entry = Entry(width=21)  # Input field for password
password_entry.grid(row=4, column=1)

# Buttons
generate_password_button = Button(text="Generate Password", width=14, command=generate_password)
generate_password_button.grid(row=4, column=2)

add_button = Button(text="Add", width=36, command=save)  # Button to save the credentials
add_button.grid(row=5, column=1, columnspan=2)

search_button = Button(text="Search", width=14, command=lambda: retrieve(website_entry.get()))
search_button.grid(row=2, column=3)

# Run the application
window.mainloop()