import unittest
from unittest.mock import patch, mock_open, MagicMock, call
import json
import bcrypt
import os
import base64
import logging
import tempfile
import shutil
from cryptography.fernet import Fernet, InvalidToken
from src.core.file_manager import FileManager

class TestFileManager(unittest.TestCase):
    def setUp(self):
        """Set up test fixtures."""
        # Create a mock logger
        self.mock_logger = MagicMock()
        patcher = patch('src.core.file_manager.logging.getLogger')
        self.mock_get_logger = patcher.start()
        self.mock_get_logger.return_value = self.mock_logger
        self.addCleanup(patcher.stop)

        # Create a temporary directory for testing
        self.test_dir = tempfile.mkdtemp()
        self.file_manager = FileManager(base_dir=self.test_dir)
        self.test_password = "test_password123"
        self.test_salt = bcrypt.gensalt()
        self.test_hash = bcrypt.hashpw(self.test_password.encode(), self.test_salt)
        # Generate a proper Fernet key for testing
        self.test_key = Fernet.generate_key()
        self.test_data = {
            "example.com": {
                "username": "test_user",
                "password": "test_pass"
            }
        }

    def tearDown(self):
        """Clean up test fixtures."""
        # Remove the temporary directory and all its contents
        shutil.rmtree(self.test_dir)

    def test_is_first_time_setup_true(self):
        """Test first time setup detection when files don't exist."""
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = False
            self.assertTrue(self.file_manager.is_first_time_setup())

    def test_is_first_time_setup_false(self):
        """Test first time setup detection when files exist."""
        with patch('os.path.exists') as mock_exists:
            mock_exists.return_value = True
            self.assertFalse(self.file_manager.is_first_time_setup())

    def test_save_master_password(self):
        """Test saving master password and related files."""
        mock_files = {}
        mock_open_obj = mock_open()
        
        with patch('builtins.open', mock_open_obj), \
             patch('bcrypt.gensalt') as mock_gensalt, \
             patch('bcrypt.hashpw') as mock_hashpw, \
             patch('os.path.exists') as mock_exists:
            
            # Setup mocks
            mock_gensalt.return_value = self.test_salt
            mock_hashpw.return_value = self.test_hash
            mock_exists.return_value = False
            
            # Test saving master password
            result = self.file_manager.save_master_password(self.test_password)
            
            # Verify results
            self.assertTrue(result)
            self.assertEqual(mock_open_obj.call_count, 3)  # Called for salt, hash, and key files
            
            # Verify file paths
            calls = [call[0][0] for call in mock_open_obj.call_args_list]
            self.assertIn(self.file_manager.SALT_FILE, calls)
            self.assertIn(self.file_manager.HASH_FILE, calls)
            self.assertIn(self.file_manager.KEY_FILE, calls)

    def test_verify_master_password_success(self):
        """Test successful master password verification."""
        with patch('src.core.file_manager.FileManager._read_file') as mock_read, \
             patch('bcrypt.checkpw') as mock_checkpw:
            
            # Setup mocks
            mock_read.return_value = self.test_hash
            mock_checkpw.return_value = True
            
            # Test verification
            result = self.file_manager.verify_master_password(self.test_password)
            
            # Verify results
            self.assertTrue(result)
            mock_read.assert_called_once_with(self.file_manager.HASH_FILE)
            mock_checkpw.assert_called_once()

    def test_verify_master_password_failure(self):
        """Test failed master password verification."""
        with patch('src.core.file_manager.FileManager._read_file') as mock_read, \
             patch('bcrypt.checkpw') as mock_checkpw:
            
            # Setup mocks
            mock_read.return_value = self.test_hash
            mock_checkpw.return_value = False
            
            # Test verification
            result = self.file_manager.verify_master_password(self.test_password)
            
            # Verify results
            self.assertFalse(result)
            mock_read.assert_called_once_with(self.file_manager.HASH_FILE)
            mock_checkpw.assert_called_once()

    def test_get_encryption_key(self):
        """Test encryption key retrieval."""
        with patch('src.core.file_manager.FileManager._read_file') as mock_read:
            # Setup mock
            mock_read.return_value = self.test_salt
            
            # Test key retrieval
            result = self.file_manager.get_encryption_key(self.test_password)
            
            # Verify results
            self.assertIsNotNone(result)
            mock_read.assert_called_once_with(self.file_manager.SALT_FILE)

    def test_save_load_password_data(self):
        """Test saving and loading password data."""
        with patch('src.core.file_manager.FileManager._read_file') as mock_read, \
             patch('src.core.file_manager.FileManager._write_file') as mock_write:
            
            # Setup mocks
            mock_write.return_value = True
            # Return encrypted test data
            f = Fernet(self.test_key)
            encrypted_data = f.encrypt(json.dumps(self.test_data).encode())
            mock_read.return_value = encrypted_data
            
            # Test saving data
            save_result = self.file_manager.save_password_data(self.test_data, self.test_key)
            self.assertTrue(save_result)
            
            # Test loading data
            load_result = self.file_manager.load_password_data(self.test_key)
            self.assertEqual(load_result, self.test_data)
            
            # Verify file operations
            mock_write.assert_called_once()
            mock_read.assert_called_once_with(self.file_manager.DATA_ENC_FILE)

    def test_import_from_json(self):
        """Test importing data from JSON file."""
        test_json_file = os.path.join(self.test_dir, "test_import.json")
        mock_files = {}
        mock_open_obj = mock_open()
        
        with patch('builtins.open', mock_open_obj), \
             patch('os.path.exists') as mock_exists, \
             patch('src.core.file_manager.FileManager.save_password_data') as mock_save:
            
            # Setup mocks
            mock_exists.return_value = True
            mock_save.return_value = True
            mock_open_obj.return_value.__enter__.return_value.read.return_value = json.dumps(self.test_data)
            
            # Test import
            result = self.file_manager.import_from_json(test_json_file, self.test_key)
            
            # Verify results
            self.assertTrue(result)
            mock_exists.assert_called_once_with(test_json_file)
            mock_save.assert_called_once()

    def test_export_to_json(self):
        """Test exporting data to JSON file."""
        mock_files = {}
        mock_open_obj = mock_open()
        
        with patch('builtins.open', mock_open_obj), \
             patch('src.core.file_manager.FileManager.load_password_data') as mock_load:
            
            # Setup mocks
            mock_load.return_value = self.test_data
            
            # Test export
            result = self.file_manager.export_to_json(self.test_key)
            
            # Verify results
            self.assertTrue(result)
            mock_load.assert_called_once_with(self.test_key)
            mock_open_obj.assert_called_once()

    def test_load_password_data_empty(self):
        """Test loading password data when file doesn't exist."""
        with patch('src.core.file_manager.FileManager._read_file') as mock_read:
            # Setup mock
            mock_read.return_value = None
            
            # Test loading
            result = self.file_manager.load_password_data(self.test_key)
            
            # Verify results
            self.assertEqual(result, {})
            mock_read.assert_called_once_with(self.file_manager.DATA_ENC_FILE)

    def test_import_from_json_file_not_found(self):
        """Test importing when JSON file doesn't exist."""
        test_json_file = os.path.join(self.test_dir, "nonexistent.json")
        
        with patch('os.path.exists') as mock_exists:
            # Setup mock
            mock_exists.return_value = False
            
            # Test import
            result = self.file_manager.import_from_json(test_json_file, self.test_key)
            
            # Verify results
            self.assertFalse(result)
            mock_exists.assert_called_once_with(test_json_file)

    def test_read_file_error_handling(self):
        """Test error handling when reading files."""
        with patch('builtins.open') as mock_open:
            # Simulate file read error
            mock_open.side_effect = IOError("Test read error")
            
            # Test reading file
            result = self.file_manager._read_file("test_file.txt")
            
            # Verify results
            self.assertIsNone(result)
            self.mock_logger.error.assert_called_once()
            self.assertIn("Error reading file", self.mock_logger.error.call_args[0][0])

    def test_write_file_error_handling(self):
        """Test error handling when writing files."""
        with patch('builtins.open') as mock_open:
            # Simulate file write error
            mock_open.side_effect = IOError("Test write error")
            
            # Test writing file
            result = self.file_manager._write_file("test_file.txt", b"test data")
            
            # Verify results
            self.assertFalse(result)
            self.mock_logger.error.assert_called_once()
            self.assertIn("Error writing file", self.mock_logger.error.call_args[0][0])

    def test_save_password_data_encryption_error(self):
        """Test error handling during password data encryption."""
        with patch('cryptography.fernet.Fernet.encrypt') as mock_encrypt:
            # Simulate encryption error
            mock_encrypt.side_effect = Exception("Test encryption error")
            
            # Test saving data
            result = self.file_manager.save_password_data(self.test_data, self.test_key)
            
            # Verify results
            self.assertFalse(result)
            self.mock_logger.error.assert_called_once()
            self.assertIn("Error saving password data", self.mock_logger.error.call_args[0][0])

    def test_load_password_data_decryption_error(self):
        """Test error handling during password data decryption."""
        with patch('src.core.file_manager.FileManager._read_file') as mock_read:
            # Return invalid encrypted data
            mock_read.return_value = b"invalid_encrypted_data"
            
            # Test loading data
            result = self.file_manager.load_password_data(self.test_key)
            
            # Verify results
            self.assertEqual(result, {})
            self.mock_logger.error.assert_called_once()
            self.assertIn("Error loading password data", self.mock_logger.error.call_args[0][0])

    def test_import_json_invalid_format(self):
        """Test error handling when importing invalid JSON format."""
        test_json_file = os.path.join(self.test_dir, "test_import.json")
        
        with patch('builtins.open', mock_open(read_data="invalid json")), \
             patch('os.path.exists') as mock_exists:
            
            mock_exists.return_value = True
            
            # Test import with invalid JSON
            result = self.file_manager.import_from_json(test_json_file, self.test_key)
            
            # Verify results
            self.assertFalse(result)
            self.mock_logger.error.assert_called_once()
            self.assertIn("Error importing from JSON", self.mock_logger.error.call_args[0][0])

    def test_export_json_write_error(self):
        """Test error handling when exporting fails due to write error."""
        with patch('src.core.file_manager.FileManager.load_password_data') as mock_load, \
             patch('builtins.open') as mock_open:
            
            # Setup mocks
            mock_load.return_value = self.test_data
            mock_open.side_effect = IOError("Test write error")
            
            # Test export
            result = self.file_manager.export_to_json(self.test_key)
            
            # Verify results
            self.assertFalse(result)
            self.mock_logger.error.assert_called_once()
            self.assertIn("Error exporting to JSON", self.mock_logger.error.call_args[0][0])

if __name__ == '__main__':
    unittest.main() 