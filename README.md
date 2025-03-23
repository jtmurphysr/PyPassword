# Password Manager

A secure password manager application built with Python, featuring encryption, master password protection, and a user-friendly interface.

## Features

- 🔒 Secure password storage with encryption
- 🔑 Master password protection with bcrypt hashing
- 📝 Password generation with customizable requirements
- 🔍 Search functionality
- 📋 Copy username/password to clipboard
- 📥 Import from JSON (with automatic format conversion)
- 📤 Export to JSON
- 🛡️ Comprehensive error handling and logging
- 🔄 Support for both old and new data formats
- 🔐 PBKDF2 key derivation for enhanced security

## Security

- Master password hashing using bcrypt
- Symmetric encryption for stored passwords using Fernet
- Secure key generation using PBKDF2
- Salt-based password hashing
- Comprehensive error handling and logging
- No plaintext password storage
- Automatic format conversion for backward compatibility
- Secure storage in dedicated data directory
- Runtime-created secure storage with proper permissions

## Requirements

- Python 3.8+
- Required packages:
  - cryptography
  - bcrypt
  - tkinter (usually comes with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/password_manager.git
cd password_manager
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the application:
```bash
python src/main.py
```

2. On first run:
   - A secure `data` directory will be created automatically
   - Create a master password
   - Add passwords using the interface
3. Use the search function to find stored passwords
4. Right-click on entries to copy username/password

Note: All encrypted data and security files are stored in the `data` directory, which is created with secure permissions when the application is first run.

## Development

### Project Structure
```
password_manager/
├── src/
│   ├── assets/         # Application resources
│   │   └── logo.png
│   ├── core/           # Core functionality
│   │   ├── file_manager.py
│   │   └── security.py
│   ├── gui/           # User interface
│   │   └── gui.py
│   └── main.py        # Application entry point
├── tests/            # Test files
│   ├── test_file_manager.py
│   └── test_password_manager.py
├── docs/             # Documentation
│   ├── context.md
│   └── CHANGELOG.md
├── README.md
└── requirements.txt
```

Note: The `data` directory is created at runtime and is not included in the repository.

### Running Tests
```bash
PYTHONPATH=$PYTHONPATH:. python -m unittest discover tests -v
```

### Test Coverage
- File operations
- Error handling
- Encryption/decryption
- Password management
- Import/export functionality
- Logging system
- Edge cases and error conditions

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

See [CHANGELOG.md](docs/CHANGELOG.md) for a list of changes and version history.
