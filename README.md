# Password Manager - README
## Overview
The **Password Manager** application is a Python-based GUI tool designed for securely storing and managing your passwords. It allows users to generate strong random passwords, save them along with website and email credentials, and retrieve stored passwords when needed. The app ensures data organization and simplicity, while leveraging a graphical interface for ease of use.

## Features
- **Password Generator**:
    - Generates strong, secure, and random passwords of customizable length (10-16 characters).
    - Includes a mix of uppercase, lowercase, numbers, and special characters.
    - Automatically copies generated passwords to the clipboard for quick access.
    - Uses cryptographically secure random number generation.

- **Save Passwords**:
    - Saves website, email/username, and password entries into a JSON file (`data.json`).
    - Checks for duplicate entries to avoid redundancies.
    - Provides validation to ensure no fields are left empty.
    - Supports structured data storage for better organization.

- **Retrieve Passwords**:
    - Searches for stored credentials based on the website name.
    - Supports partial matches and case-insensitive searches.
    - Displays all matching results in a formatted view.
    - Provides clear feedback if no matches are found.

- **User-Friendly GUI**:
    - Intuitive and clean interface created using Tkinter.
    - Provides buttons for generating passwords, saving new entries, and searching for existing ones.
    - Clear error messages and success notifications.
    - Automatic focus on the website field for quick entry.

- **Security Features**:
    - Optional file encryption using the `cryptography` library.
    - PBKDF2 key derivation with 100,000 iterations for strong encryption.
    - Secure random number generation for password creation.
    - Salt-based encryption for enhanced security.

## Tech Stack
This application is built with:
- **Python**: Core programming language used for implementing logic, file handling, and GUI components.
- **Tkinter**: Built-in Python library used to create the graphical user interface (GUI).
- **Pyperclip**: A Python library to copy text (e.g., passwords) directly to the clipboard.
- **Cryptography**: Optional library for file encryption (requires separate installation).

## Prerequisites
To run this application, ensure you have the following installed:
1. **Python 3.10 or higher**.
2. Required Python packages:
    - `pyperclip`
    - `cryptography` (optional, for file encryption)

Install missing libraries using the following command:
```bash
pip install pyperclip cryptography
```

## Usage
### 1. Start the Application
Run the script by executing:
```bash
python password_manager.py
```

### 2. Interface Overview
- **Website Field**: Input the website name (used for retrieving saved passwords).
- **Email/Username Field**: Enter your email or username associated with the account being saved.
- **Password Field**: Manually input a password or use the **Generate Password** button to create a secure one.
- **Generate Password**: Generates a strong, randomized password and copies it to the system clipboard.
- **Add Button**: Saves the entered website, email, and password into the JSON file (`data.json`).
- **Search Button**: Searches and retrieves existing credentials for the entered website.

### 3. Key Functionalities:
#### Generate Password
- Click the **Generate Password** button to create a secure, random password.
- The password will be 10-16 characters long with a mix of letters, numbers, and symbols.
- The password will be automatically inserted into the password input field and copied to your clipboard.

#### Save Credentials
- Fill out the fields for **Website**, **Email/Username**, and the **Password** (generated or manual).
- Click the **Add** button to save the data. If successful, a message box will confirm the save.
- The data is stored in a structured JSON format for better organization.

#### Retrieve Credentials
- Input the website name in the **Website** field and click the **Search** button.
- The search is case-insensitive and supports partial matches.
- All matching results will be displayed in a formatted view.
- If no matches are found, a warning message will be shown.

#### File Encryption (Optional)
- Use the `file_encryption_utils.py` script to encrypt/decrypt the data file.
- Run the script and choose to encrypt (e) or decrypt (d) the file.
- Provide a secure passphrase when prompted.
- The encryption uses PBKDF2 with 100,000 iterations for enhanced security.

## File Structure
- **password_manager.py**: The main script containing all functionality, including password generation, saving credentials, retrieving credentials, and UI setup.
- **data.json**: A JSON file where all the website credentials are stored in a structured format.
- **file_encryption_utils.py**: Optional utility for encrypting/decrypting the data file.
- **logo.png**: Icon/logo displayed inside the GUI.

## Security Notes
- **Data Storage**: Credentials are stored in a structured JSON format (`data.json`).
- **Optional Encryption**: The `file_encryption_utils.py` script provides file encryption capabilities.
- **Password Generation**: Uses cryptographically secure random number generation.
- **Password Visibility**: Generated passwords are automatically visible in the password entry field. Use discretion when entering sensitive information in public spaces.
- **Backup Your Data**: Regularly back up the `data.json` file to ensure no loss of credentials.

## Future Enhancements
Here are some improvements that could further enhance the application:
1. **Password Strength Meter**:
    - Add a visual indicator of password strength when generating or entering passwords.

2. **Categories/Tags**:
    - Add support for categorizing saved credentials with tags.

3. **Password History**:
    - Keep track of previously used passwords for each website.

4. **Cloud Syncing**:
    - Add functionality to store and sync credentials in a secure cloud database.

## Known Issues
1. The encryption utility requires manual intervention - could be integrated into the main GUI.
2. The JSON file structure could be more robust with additional validation.

## How to Contribute
Got ideas for improvement? Contributions are welcome! Here's how you can get started:
1. Fork the repository and clone it locally.
2. Create a new feature branch.
3. Commit and push your changes.
4. Submit a pull request and describe the changes you've made.

## Support
If you encounter any issues or have questions, feel free to contact the developer. Create a GitHub issue if you're working in a GitHub repository, or specify your issue in any support forum related to Python projects.

Happy password managing! 🚀
