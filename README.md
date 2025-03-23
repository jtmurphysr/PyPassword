# PyPassword

A secure and user-friendly password manager built with Python, featuring encryption, master password protection, and a modern interface.

## Features

- 🔐 **Secure Password Storage**
  - Master password protection with bcrypt hashing
  - Fernet encryption for stored passwords
  - Secure password generation

- 🖥️ **User-Friendly Interface**
  - Clean and intuitive GUI
  - Password list with search functionality
  - Right-click context menu for quick actions
  - Keyboard shortcuts

- 📁 **Data Management**
  - Import passwords from JSON
  - Automatic encryption/decryption
  - Duplicate entry handling
  - Secure deletion

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/PyPassword.git
cd PyPassword
```

2. Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python password_manager.py
```

2. First-time setup:
   - Add your first password entry
   - Create a master password when prompted
   - Your master password must be at least 8 characters and include:
     - Uppercase letters
     - Lowercase letters
     - Numbers
     - Special characters

3. Regular usage:
   - Enter the master password to access your passwords
   - Add new entries using the input fields
   - Generate secure passwords with the "Generate Password" button
   - Search entries using the search function
   - Right-click on entries to:
     - Copy username
     - Copy password
     - Delete entry
   - Use Ctrl+C to quickly copy passwords

4. Importing data:
   - Place your `data.json` file in the application directory
   - Use File > Import from data.json
   - Follow the prompts to complete the import

## Security Features

- **Master Password Protection**
  - Bcrypt hashing with salt
  - Minimum complexity requirements
  - Secure storage

- **Data Encryption**
  - Fernet symmetric encryption
  - Secure key generation
  - Protected storage

- **Secure Storage**
  - Encrypted password file
  - Protected master password hash
  - Secure salt storage

## File Structure

- `password_manager.py`: Main application code
- `requirements.txt`: Python dependencies
- `logo.png`: Application logo
- Generated files:
  - `data.enc`: Encrypted password storage
  - `master.hash`: Hashed master password
  - `salt.salt`: Cryptographic salt

## Dependencies

- Python 3.8+
- cryptography==41.0.7
- bcrypt==4.0.1
- pyperclip==1.8.2
- pillow==10.2.0

## Contributing

1. Fork the repository
2. Create your feature branch
3. Commit your changes
4. Push to the branch
5. Create a new Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Security Notice

- Keep your master password secure and never share it
- Regularly backup your encrypted password file
- Use generated passwords for maximum security
- Update dependencies regularly for security patches
