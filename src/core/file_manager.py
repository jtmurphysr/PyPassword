import os
import json
import bcrypt
import base64
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import logging
from typing import Dict, Optional, Any, Tuple

class FileManager:
    """Handles file operations and encryption for password storage."""
    
    def __init__(self, base_dir: str = None):
        """Initialize FileManager with optional base directory for testing."""
        self.base_dir = base_dir or os.path.dirname(os.path.abspath(__file__))
        self.HASH_FILE = os.path.join(self.base_dir, 'master.hash')
        self.SALT_FILE = os.path.join(self.base_dir, 'master.salt')
        self.KEY_FILE = os.path.join(self.base_dir, 'master.key')
        self.DATA_ENC_FILE = os.path.join(self.base_dir, 'data.enc')
        
        # Setup logging
        logging.basicConfig(level=logging.INFO)
        self.logger = logging.getLogger(__name__)

    def _read_file(self, filepath: str) -> Optional[bytes]:
        """Read file contents safely."""
        try:
            if not os.path.exists(filepath):
                return None
            with open(filepath, 'rb') as f:
                return f.read()
        except Exception as e:
            self.logger.error(f"Error reading file {filepath}: {str(e)}")
            return None

    def _write_file(self, filepath: str, data: bytes) -> bool:
        """Write data to file safely."""
        try:
            with open(filepath, 'wb') as f:
                f.write(data)
            return True
        except Exception as e:
            self.logger.error(f"Error writing file {filepath}: {str(e)}")
            return False

    def _generate_key_from_password(self, password: str, salt: bytes) -> bytes:
        """Generate encryption key from password and salt."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def is_first_time_setup(self) -> bool:
        """Check if this is the first time setup."""
        return not os.path.exists(self.HASH_FILE)

    def save_master_password(self, password: str) -> bool:
        """Save master password hash and related files."""
        try:
            # Generate salt and hash
            salt = bcrypt.gensalt()
            password_hash = bcrypt.hashpw(password.encode(), salt)
            
            # Generate encryption key
            key = self._generate_key_from_password(password, salt)
            
            # Save all files
            if not all([
                self._write_file(self.SALT_FILE, salt),
                self._write_file(self.HASH_FILE, password_hash),
                self._write_file(self.KEY_FILE, key)
            ]):
                return False
                
            return True
        except Exception as e:
            self.logger.error(f"Error saving master password: {str(e)}")
            return False

    def verify_master_password(self, password: str) -> bool:
        """Verify master password against stored hash."""
        try:
            stored_hash = self._read_file(self.HASH_FILE)
            if not stored_hash:
                return False
            return bcrypt.checkpw(password.encode(), stored_hash)
        except Exception as e:
            self.logger.error(f"Error verifying master password: {str(e)}")
            return False

    def get_encryption_key(self) -> Optional[bytes]:
        """Get the encryption key from file."""
        return self._read_file(self.KEY_FILE)

    def save_password_data(self, data: Dict[str, Any], key: bytes) -> bool:
        """Save encrypted password data."""
        try:
            f = Fernet(key)
            encrypted_data = f.encrypt(json.dumps(data).encode())
            return self._write_file(self.DATA_ENC_FILE, encrypted_data)
        except Exception as e:
            self.logger.error(f"Error saving password data: {str(e)}")
            return False

    def load_password_data(self, key: bytes) -> Dict[str, Any]:
        """Load and decrypt password data."""
        try:
            encrypted_data = self._read_file(self.DATA_ENC_FILE)
            if not encrypted_data:
                return {}
            
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            self.logger.error(f"Error loading password data: {str(e)}")
            return {}

    def import_from_json(self, json_file: str, key: bytes) -> bool:
        """Import password data from JSON file."""
        try:
            if not os.path.exists(json_file):
                return False
                
            with open(json_file, 'r') as f:
                data = json.load(f)
            
            # Convert old format to new format if needed
            converted_data = {}
            for website, details in data.items():
                if isinstance(details, dict):
                    if 'email' in details:
                        details['username'] = details.pop('email')
                    converted_data[website] = details
            
            return self.save_password_data(converted_data, key)
        except Exception as e:
            self.logger.error(f"Error importing from JSON: {str(e)}")
            return False

    def export_to_json(self, key: bytes) -> bool:
        """Export password data to JSON file."""
        try:
            data = self.load_password_data(key)
            if not data:
                return False
                
            export_file = os.path.join(self.base_dir, 'passwords_export.json')
            with open(export_file, 'w') as f:
                json.dump(data, f, indent=4)
            return True
        except Exception as e:
            self.logger.error(f"Error exporting to JSON: {str(e)}")
            return False 