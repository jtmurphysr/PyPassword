# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Comprehensive error handling and logging system
- Support for both old and new data formats
- Automatic format conversion during import
- Unit tests for FileManager class
- Test coverage for error handling and edge cases

### Changed
- Refactored FileManager class for better separation of concerns
- Improved file operation error handling
- Enhanced security with proper key generation
- Updated logging system for better debugging
- Improved test organization and coverage

### Fixed
- Fixed password masking in tree view
- Fixed data format conversion issues
- Fixed error handling in file operations
- Fixed logging implementation

### Security
- Enhanced key generation using PBKDF2
- Improved error handling for security events
- Added logging for security-related operations
- Better handling of encryption/decryption errors

## [0.1.0] - 2024-03-XX

### Added
- Initial release
- Basic password management functionality
- Master password protection
- File encryption/decryption
- User interface with Tkinter
- Password generation
- Search functionality
- Import/Export capabilities

### Security
- Master password hashing with bcrypt
- Fernet encryption for stored passwords
- Salt-based password hashing
- Secure key generation 