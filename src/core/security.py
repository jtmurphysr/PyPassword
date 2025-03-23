import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import json
import string
import random

class SecurityManager:
    """Handles all security-related operations."""
    
    # Password generation constants
    MIN_PASSWORD_LENGTH = 10
    MAX_PASSWORD_LENGTH = 32
    DEFAULT_PASSWORD_LENGTH = 16

    @staticmethod
    def generate_key_from_password(password, salt):
        """Generate a Fernet key from a password and salt using PBKDF2."""
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return key

    @staticmethod
    def encrypt_data(data, key):
        """Encrypt data using Fernet encryption."""
        f = Fernet(key)
        encrypted_data = f.encrypt(json.dumps(data).encode())
        return encrypted_data

    @staticmethod
    def decrypt_data(encrypted_data, key):
        """Decrypt data using Fernet encryption."""
        f = Fernet(key)
        decrypted_data = f.decrypt(encrypted_data)
        return json.loads(decrypted_data.decode())

    @staticmethod
    def save_master_hash(password):
        """Generate salt and hash for master password."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        return salt, hashed

    @staticmethod
    def verify_master_password(password, stored_hash):
        """Verify the master password against stored hash."""
        return bcrypt.checkpw(password.encode(), stored_hash)

    @staticmethod
    def calculate_password_requirements(length):
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

    def validate_master_password(self, password):
        """Validate master password requirements."""
        if len(password) < 8:
            return False, "Password must be at least 8 characters long"
        if not any(c.isupper() for c in password):
            return False, "Password must contain at least one uppercase letter"
        if not any(c.islower() for c in password):
            return False, "Password must contain at least one lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Password must contain at least one number"
        if not any(not c.isalnum() for c in password):
            return False, "Password must contain at least one special character"
        return True, "Password is valid" 