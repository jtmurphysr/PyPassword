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
- Project structure reorganization
- Documentation updates
- Assets directory for application resources
- Data directory for secure storage
- Temporary directory support for testing
- Runtime-created secure storage with proper permissions

### Changed
- Refactored FileManager class for better separation of concerns
- Improved file operation error handling
- Enhanced security with proper key generation
- Updated logging system for better debugging
- Improved test organization and coverage
- Reorganized project structure for better maintainability
- Updated import paths to reflect new structure
- Moved application resources to assets directory
- Moved data files to dedicated data directory
- Improved key generation using password and salt
- Enhanced test suite with proper cleanup
- Enhanced password generation requirements

### Fixed
- Fixed password masking in tree view
- Fixed data format conversion issues
- Fixed error handling in file operations
- Fixed logging implementation
- Fixed test imports after project restructuring
- Fixed logger mock paths in tests
- Fixed logo path in GUI
- Fixed geometry manager conflicts in GUI
- Fixed test directory permissions issues
- Fixed key generation and storage approach
- Fixed password generation functionality
- Fixed context menu functionality

### Security
- Improved key generation using password and salt
- Centralized sensitive data storage
- Enhanced file permissions handling
- Better encryption key management
- Secure temporary file handling in tests
- Improved key generation using PBKDF2
- Runtime-created secure storage with proper permissions

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