import unittest
import bcrypt
from cryptography.fernet import Fernet
import json
import string
import random
from src.core.security import SecurityManager

class TestPasswordSecurity(unittest.TestCase):
    """Test class for password security functions without GUI dependencies."""
    
    # Constants from PasswordManager
    MIN_PASSWORD_LENGTH = 10
    MAX_PASSWORD_LENGTH = 32
    DEFAULT_PASSWORD_LENGTH = 16

    def generate_key_from_password(self, password, salt):
        """Generate a Fernet key from a password and salt using PBKDF2."""
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
        import base64
        
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    def encrypt_data(self, data, key):
        """Encrypt data using Fernet encryption."""
        f = Fernet(key)
        encrypted_data = f.encrypt(json.dumps(data).encode())
        return encrypted_data

    def decrypt_data(self, encrypted_data, key):
        """Decrypt data using Fernet encryption."""
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

    def save_master_hash(self, password):
        """Save the hashed master password."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return salt, hashed

    def verify_master_password(self, password, stored_hash):
        """Verify the master password against stored hash."""
        return bcrypt.checkpw(password.encode(), stored_hash)

    def calculate_password_requirements(self, length):
        """Calculate password requirements based on length."""
        base_reqs = {
            'lowercase': 2,
            'uppercase': 2,
            'digits': 2,
            'special': 2
        }
        
        scale = length / 12
        reqs = {k: int(v * scale) for k, v in base_reqs.items()}
        
        total = sum(reqs.values())
        if total < length:
            reqs['lowercase'] += length - total
        elif total > length:
            reqs['lowercase'] -= total - length
        
        return reqs

    def generate_password(self):
        """Generate a secure random password."""
        length = random.randint(self.MIN_PASSWORD_LENGTH, self.MAX_PASSWORD_LENGTH)
        reqs = self.calculate_password_requirements(length)
        
        lowercase = string.ascii_lowercase
        uppercase = string.ascii_uppercase
        digits = string.digits
        special = '!@#$%^&*()_+-=[]{}|;:,.<>?'
        
        password = []
        password.extend(random.choice(lowercase) for _ in range(reqs['lowercase']))
        password.extend(random.choice(uppercase) for _ in range(reqs['uppercase']))
        password.extend(random.choice(digits) for _ in range(reqs['digits']))
        password.extend(random.choice(special) for _ in range(reqs['special']))
        
        random.shuffle(password)
        return ''.join(password)

    def test_generate_key_from_password(self):
        """Test key generation from password and salt."""
        test_password = "TestPassword123!"
        test_salt = bcrypt.gensalt()
        
        key = self.generate_key_from_password(test_password, test_salt)
        
        # Verify the key is valid Fernet key
        self.assertIsInstance(key, bytes)
        self.assertTrue(len(key) > 0)
        # Verify it can be used for encryption
        Fernet(key)

    def test_encrypt_decrypt_data(self):
        """Test data encryption and decryption."""
        test_data = {"website": "test.com", "username": "test", "password": "test123"}
        test_password = "TestPassword123!"
        test_salt = bcrypt.gensalt()
        key = self.generate_key_from_password(test_password, test_salt)
        
        # Test encryption
        encrypted_data = self.encrypt_data(test_data, key)
        self.assertIsInstance(encrypted_data, bytes)
        self.assertNotEqual(encrypted_data, json.dumps(test_data).encode())
        
        # Test decryption
        decrypted_data = self.decrypt_data(encrypted_data, key)
        self.assertEqual(decrypted_data, test_data)

    def test_save_verify_master_password(self):
        """Test master password hashing and verification."""
        test_password = "TestPassword123!"
        
        # Test saving master password
        salt, hashed = self.save_master_hash(test_password)
        
        # Verify the password
        self.assertTrue(self.verify_master_password(test_password, hashed))
        self.assertFalse(self.verify_master_password("WrongPassword", hashed))

    def test_calculate_password_requirements(self):
        """Test password requirement calculations."""
        test_lengths = [10, 16, 20, 32]
        
        for length in test_lengths:
            reqs = self.calculate_password_requirements(length)
            
            # Verify all required character types are present
            self.assertIn('lowercase', reqs)
            self.assertIn('uppercase', reqs)
            self.assertIn('digits', reqs)
            self.assertIn('special', reqs)
            
            # Verify total requirements match length
            total = sum(reqs.values())
            self.assertEqual(total, length)

    def test_generate_password(self):
        """Test password generation."""
        # Test multiple generations to ensure variety
        passwords = set()
        for _ in range(10):
            password = self.generate_password()
            passwords.add(password)
            
            # Verify password length is within bounds
            self.assertTrue(self.MIN_PASSWORD_LENGTH <= len(password) <= self.MAX_PASSWORD_LENGTH)
            
            # Verify password contains required character types
            self.assertTrue(any(c.islower() for c in password))
            self.assertTrue(any(c.isupper() for c in password))
            self.assertTrue(any(c.isdigit() for c in password))
            self.assertTrue(any(not c.isalnum() for c in password))
        
        # Verify we get different passwords
        self.assertTrue(len(passwords) > 1)

if __name__ == '__main__':
    unittest.main() 