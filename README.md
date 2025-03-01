# Password Manager - README
## Overview
The **Password Manager** application is a Python-based GUI tool designed for securely storing and managing your passwords. It allows users to generate strong random passwords, save them along with website and email credentials, and retrieve stored passwords when needed. The app ensures data organization and simplicity, while leveraging a graphical interface for ease of use.
## Features
- **Password Generator**:
    - Generates strong, secure, and random passwords of customizable length.
    - Includes a mix of uppercase, lowercase, numbers, and special characters.
    - Automatically copies generated passwords to the clipboard for quick access.

- **Save Passwords**:
    - Saves website, email/username, and password entries into a local file (`data.txt`).
    - Checks for duplicate entries to avoid redundancies.
    - Provides validation to ensure no fields are left empty.

- **Retrieve Passwords**:
    - Searches for stored credentials based on the website name.
    - Populates the input fields with the corresponding email and password if found.
    - Displays warnings if no matching entry is found or in case of errors.

- **User-Friendly GUI**:
    - Intuitive and clean interface created using Tkinter.
    - Provides buttons for generating passwords, saving new entries, and searching for existing ones.

## Tech Stack
This application is built with:
- **Python**: Core programming language used for implementing logic, file handling, and GUI components.
- **Tkinter**: Built-in Python library used to create the graphical user interface (GUI).
- **Pyperclip**: A Python library to copy text (e.g., passwords) directly to the clipboard.

## Prerequisites
To run this application, ensure you have the following installed:
1. **Python 3.10 or higher**.
2. Required Python packages:
    - `pyperclip`

Install missing libraries using the following command:
``` bash
   pip install pyperclip
```
## Usage
### 1. Start the Application
Run the script by executing:
``` bash
python password_manager.py
```
### 2. Interface Overview
- **Website Field**: Input the website name (used for retrieving saved passwords).
- **Email/Username Field**: Enter your email or username associated with the account being saved.
- **Password Field**: Manually input a password or use the **Generate Password** button to create a secure one.
- **Generate Password**: Generates a strong, randomized password and copies it to the system clipboard.
- **Add Button**: Saves the entered website, email, and password into the local file (`data.txt`).
- **Search Button**: Searches and retrieves existing credentials for the entered website.

### 3. Key Functionalities:
#### Generate Password
- Click the **Generate Password** button to create a secure, random password with letters, numbers, and symbols.
- The password will be automatically inserted into the password input field and copied to your clipboard.

#### Save Credentials
- Fill out the fields for **Website**, **Email/Username**, and the **Password** (generated or manual).
- Click the **Add** button to save the data. If successful, a message box will confirm the save.

#### Retrieve Credentials
- Input the website name in the **Website** field and click the **Search** button.
- If a matching entry is found, the email and password will populate their respective fields, and a success message will appear.

## File Structure
- **password_manager.py**: The main script containing all functionality, including password generation, saving credentials, retrieving credentials, and UI setup.
- **data.txt**: A plain text file where all the website credentials are stored. Each entry is saved in the format:
``` 
  [Website] [Email/Username] [Password]
```
- **logo.png**: Icon/logo displayed inside the GUI.

## Security Notes
- **Data Storage**: All credentials are stored in plaintext (`data.txt`). While this is functional, it is recommended to encrypt the file content for enhanced security.
- **Password Visibility**: Generated passwords are automatically visible in the password entry field. Use discretion when entering sensitive information in public spaces.
- **Backup Your Data**: Regularly back up the `data.txt` file to ensure no loss of credentials.

## Future Enhancements
Here are some improvements that could further enhance the application:
1. **Data Encryption**:
    - Encrypt the `data.txt` file using libraries like `cryptography` for added security.

2. **Search Improvements**:
    - Enhance search functionality to handle partial matches or case-insensitive searches.

3. **Password Masking**:
    - Mask the password field so the input is hidden by default, with an option to reveal.

4. **Cloud Syncing**:
    - Add functionality to store and sync credentials in a secure cloud database.

## Known Issues
1. Duplicate detection logic may not work correctly under specific cases — needs further refinement.
2. The script assumes that `data.txt` exists. If the file doesn’t exist, the app should auto-create it or handle the error gracefully.

## How to Contribute
Got ideas for improvement? Contributions are welcome! Here's how you can get started:
1. Fork the repository and clone it locally.
2. Create a new feature branch.
3. Commit and push your changes.
4. Submit a pull request and describe the changes you've made.

## Support
If you encounter any issues or have questions, feel free to contact the developer. Create a GitHub issue if you're working in a GitHub repository, or specify your issue in any support forum related to Python projects.
Happy password managing! 🚀
