from tkinter import *
import random
from tkinter import messagebox
import pyperclip

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
    """
    Saves the website, email, and password to a file after validating inputs.
    Ensures that no duplicate website or email entries exist in the file.
    """
    website = website_entry.get().strip()  # Get the website name
    email = email_entry.get().strip()  # Get the email/username
    password = password_entry.get().strip()  # Get the generated password

    # Check if website or email already exists in the file
    with open("data.txt", "r") as data_file:
        my_data = [line for line in data_file if website and email in line]
        # if website in data_file.read():
        if my_data:
            # Display a warning if duplicate entries exist
            messagebox.showwarning(title="Warning", message="Website or email already exists!")
            # Clear the input fields
            website_entry.delete(0, END)
            password_entry.delete(0, END)
            email_entry.delete(0, END)
            return

    # Ensure all fields have data before saving
    if not website or not email or not password:
        messagebox.showwarning(title="Warning", message="Please fill out all fields!")
        return

    # Format the data to write to the file
    new_data = f"{website} {email} {password} \n"

    try:
        # Append the new data to the file
        with open("data.txt", "a") as data_file:
            data_file.write(new_data)
            # Clear the input fields upon successful save
            website_entry.delete(0, END)
            password_entry.delete(0, END)
            success_box = messagebox.showinfo(title="Success", message="Info saved!")
    except Exception as e:
        # Handle file writing errors with a message box
        print(f"An error occurred: {str(e)}")
        error_string = f"An error occurred: {str(e)}"
        error_box = messagebox.showerror(title="Error", message=error_string)
        error_box.pack()


# ---------------------------- RETRIEVE PASSWORD ------------------------------- #
# Retrieve website credentials from the file
def retrieve(string):
    """
    Searches for a specified website in the file and retrieves the corresponding credentials.
    Populates the input fields with the retrieved data if the entry exists.
    """
    with open("data.txt", "r") as data_file:
        string = "nodorks"  # Default search value (should be replaced logically)
        # Search for lines containing the specified string
        my_data = [line for line in data_file if string in line]
        if my_data:
            # Display success message if entry is found
            success_box = messagebox.showinfo(title="Success", message="Info found!")
            website_entry.delete(0, END)  # Clear website entry field
            website = str(my_data).strip("[]'")  # Format retrieved website entry
            website = website.strip("\n")  # Remove newline characters
            list_data = website.split()  # Split the data into list elements
            print(list_data[2])  # Debug print the password
            website_entry.insert(0, list_data[0])  # Populate website field
            password_entry.insert(0, list_data[2])  # Populate password field
            email_entry.insert(0, list_data[1])  # Populate email field

    return None


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