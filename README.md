# Password Manager

A secure password manager application built with Python, featuring encryption, master password protection, and a user-friendly interface.

## Features

- 🔒 Secure password storage with encryption
- 🔑 Master password protection
- 📝 Password generation with customizable requirements
- 🔍 Search functionality
- 📋 Copy username/password to clipboard
- 📥 Import from JSON
- 📤 Export to JSON
- 🛡️ Comprehensive error handling and logging
- 🔄 Support for both old and new data formats

## Security

- Master password hashing using bcrypt
- Symmetric encryption for stored passwords using Fernet
- Secure key generation using PBKDF2
- Salt-based password hashing
- Comprehensive error handling and logging
- No plaintext password storage

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
python main.py
```

2. On first run, create a master password
3. Add passwords using the interface
4. Use the search function to find stored passwords
5. Right-click on entries to copy username/password

## Development

### Project Structure
```
password_manager/
├── src/
│   ├── core/           # Core functionality
│   │   ├── file_manager.py
│   │   └── security.py
│   ├── gui/           # User interface
│   │   └── gui.py
│   └── main.py        # Application entry point
├── tests/             # Test files
│   ├── test_file_manager.py
│   └── test_password_manager.py
├── docs/              # Documentation
│   ├── context.md
│   └── CHANGELOG.md
├── README.md
└── requirements.txt
```

### Running Tests
```bash
python -m unittest tests/test_file_manager.py -v
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes and version history.
