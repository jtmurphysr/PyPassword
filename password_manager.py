from tkinter import *
from tkinter import messagebox
from tkinter import simpledialog
from tkinter.ttk import Treeview
import random
import pyperclip
import json
import bcrypt
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import base64
import string
from pathlib import Path

class PasswordManager:
    # Constants
    KEY_FILE = "key.key"
    SALT_FILE = "salt.salt"
    HASH_FILE = "master.hash"
    DATA_FILE = "data.json"
    DATA_ENC_FILE = "data.enc"

    # Password generation constants
    MIN_PASSWORD_LENGTH = 10
    MAX_PASSWORD_LENGTH = 32
    DEFAULT_PASSWORD_LENGTH = 16

    def __init__(self):
        self.window = Tk()
        self.window.title("Password Manager")
        self.window.config(padx=50, pady=50)
        self.window.config(bg="white")
        
        # Add instance variables for master password and key
        self.master_password = None
        self.current_key = None
        
        self.setup_ui()
        
        # Initial refresh of the tree only if both data and master password exist
        if Path(self.DATA_ENC_FILE).exists() and Path(self.HASH_FILE).exists():
            self.refresh_tree()

    def setup_ui(self):
        """Set up the user interface."""
        # Menu Bar
        menubar = Menu(self.window)
        self.window.config(menu=menubar)
        
        # File Menu
        file_menu = Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Import from data.json", command=self.import_json)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.window.quit)

        # Set up the logo
        canvas = Canvas(self.window, height=200, width=200)
        self.logo_img = PhotoImage(file="logo.png")
        canvas.create_image(100, 100, image=self.logo_img)
        canvas.grid(column=1, row=0)

        # Labels
        website_label = Label(self.window, text="Website:", bg="white")
        website_label.grid(column=0, row=1)

        email_label = Label(self.window, text="Email/Username:", bg="white")
        email_label.grid(column=0, row=2)

        password_label = Label(self.window, text="Password:", bg="white")
        password_label.grid(column=0, row=3)

        # Entry fields
        self.website_entry = Entry(self.window, width=35)
        self.website_entry.grid(row=1, column=1, columnspan=2)
        self.website_entry.focus()

        self.email_entry = Entry(self.window, width=35)
        self.email_entry.grid(row=2, column=1, columnspan=2)

        self.password_entry = Entry(self.window, width=21)
        self.password_entry.grid(row=3, column=1)

        # Buttons
        generate_password_button = Button(self.window, text="Generate Password", command=self.generate_password)
        generate_password_button.grid(row=3, column=2)

        add_button = Button(self.window, text="Add", width=36, command=self.save)
        add_button.grid(row=4, column=1, columnspan=2)

        search_button = Button(self.window, text="Search", width=15, 
                             command=lambda: self.retrieve(self.website_entry.get()))
        search_button.grid(row=1, column=3)

        # Treeview
        tree_frame = Frame(self.window)
        tree_frame.grid(row=5, column=0, columnspan=4, pady=20)

        self.tree = Treeview(tree_frame, columns=('Website', 'Username', 'Password'), show='headings')
        self.tree.heading('Website', text='Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.column('Website', width=200)
        self.tree.column('Username', width=200)
        self.tree.column('Password', width=200)
        self.tree.pack(side='left', fill='y')

        # Scrollbar
        scrollbar = Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Context menu
        self.context_menu = Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="Copy Username", 
                                    command=lambda: self.copy_to_clipboard('username'))
        self.context_menu.add_command(label="Copy Password", 
                                    command=lambda: self.copy_to_clipboard('password'))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Entry", command=self.delete_entry)

        # Bindings
        self.tree.bind('<Button-3>', self.show_context_menu)  # Right-click on Windows/Linux
        self.tree.bind('<Button-2>', self.show_context_menu)  # Right-click on macOS
        self.tree.bind('<Control-c>', lambda e: self.copy_to_clipboard('password'))

    def generate_key_from_password(self, password, salt):
        """Generate a Fernet key from a password and salt using PBKDF2."""
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
        try:
            f = Fernet(key)
            decrypted_data = f.decrypt(encrypted_data)
            return json.loads(decrypted_data.decode())
        except Exception as e:
            messagebox.showerror("Error", f"Failed to decrypt data: {str(e)}")
            return {}

    def save_master_hash(self, password):
        """Save the hashed master password."""
        salt = bcrypt.gensalt()
        hashed = bcrypt.hashpw(password.encode(), salt)
        
        with open(self.HASH_FILE, 'wb') as f:
            f.write(hashed)
        with open(self.SALT_FILE, 'wb') as f:
            f.write(salt)

    def verify_master_password(self, password):
        """Verify the master password against stored hash."""
        try:
            with open(self.HASH_FILE, 'rb') as f:
                stored_hash = f.read()
            return bcrypt.checkpw(password.encode(), stored_hash)
        except FileNotFoundError:
            return False

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
        password = ''.join(password)
        
        self.password_entry.delete(0, END)
        self.password_entry.insert(0, password)
        pyperclip.copy(password)
        return password

    def save(self):
        """Save the password entry."""
        website = self.website_entry.get().strip()
        email = self.email_entry.get().strip()
        password = self.password_entry.get().strip()

        if not website or not email or not password:
            messagebox.showwarning(title="Warning", message="Please fill out all fields!")
            return

        try:
            # First time setup
            if not Path(self.HASH_FILE).exists():
                self.master_password = simpledialog.askstring("Set Master Password", 
                    "First time setup: Please enter a master password\n"
                    "(Must be at least 8 characters with uppercase, lowercase, numbers, and special characters):", 
                    show='*')
                if not self.master_password:
                    return
                
                # Validate master password
                if (len(self.master_password) < 8 or 
                    not any(c.isupper() for c in self.master_password) or
                    not any(c.islower() for c in self.master_password) or
                    not any(c.isdigit() for c in self.master_password) or
                    not any(not c.isalnum() for c in self.master_password)):
                    self.master_password = None
                    messagebox.showerror(title="Error", 
                        message="Master password must be at least 8 characters and contain uppercase, "
                                "lowercase, numbers, and special characters!")
                    return
                
                # Confirm master password
                confirm_password = simpledialog.askstring("Confirm Master Password", 
                    "Please confirm your master password:", show='*')
                if not confirm_password or confirm_password != self.master_password:
                    self.master_password = None
                    messagebox.showerror(title="Error", message="Passwords do not match!")
                    return
                
                # Generate salt and save master password hash
                salt = bcrypt.gensalt()
                self.save_master_hash(self.master_password)
                
                # Generate encryption key and save salt
                self.current_key = self.generate_key_from_password(self.master_password, salt)
                with open(self.SALT_FILE, 'wb') as f:
                    f.write(salt)
                
                # Initialize empty data
                data = {}
            else:
                # Get master password for existing setup if we don't have it
                if not self.master_password:
                    self.master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
                    if not self.master_password:
                        return
                    if not self.verify_master_password(self.master_password):
                        self.master_password = None
                        messagebox.showerror(title="Error", message="Invalid master password!")
                        return
                    
                    # Generate key if we don't have it
                    with open(self.SALT_FILE, 'rb') as f:
                        salt = f.read()
                    self.current_key = self.generate_key_from_password(self.master_password, salt)
                
                # Load existing data if any
                if Path(self.DATA_ENC_FILE).exists():
                    with open(self.DATA_ENC_FILE, 'rb') as f:
                        encrypted_data = f.read()
                    data = self.decrypt_data(encrypted_data, self.current_key)
                else:
                    data = {}

            # Update data with new entry
            new_data = {
                website: {
                    "email": email,
                    "password": password
                }
            }
            data.update(new_data)

            # Encrypt and save updated data
            encrypted_data = self.encrypt_data(data, self.current_key)
            with open(self.DATA_ENC_FILE, 'wb') as f:
                f.write(encrypted_data)

            messagebox.showinfo(title="Success", message="Info saved!")
            self.website_entry.delete(0, END)
            self.password_entry.delete(0, END)
            self.refresh_tree()
            
        except Exception as e:
            self.master_password = None
            self.current_key = None
            messagebox.showerror(title="Error", message=f"An error occurred: {str(e)}")

    def retrieve(self, query):
        """Search for and retrieve password entries."""
        website = query.strip()
        if not website:
            messagebox.showwarning(title="Warning", message="Please enter a website to search for!")
            return

        if not Path(self.DATA_ENC_FILE).exists():
            messagebox.showwarning(title="Warning", message="No saved passwords found!")
            return

        master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
        if not master_password:
            return
        if not self.verify_master_password(master_password):
            messagebox.showerror(title="Error", message="Invalid master password!")
            return

        try:
            with open(self.SALT_FILE, 'rb') as f:
                salt = f.read()
            key = self.generate_key_from_password(master_password, salt)
            
            with open(self.DATA_ENC_FILE, 'rb') as f:
                encrypted_data = f.read()
            data = self.decrypt_data(encrypted_data, key)

            matches = {key: value for key, value in data.items() if website.lower() in key.lower()}

            if matches:
                match_results = "\n\n".join([f"Website: {key}\nEmail: {value['email']}\nPassword: {value['password']}"
                                           for key, value in matches.items()])
                messagebox.showinfo(title="Results", message=f"Found the following matches:\n\n{match_results}")
            else:
                messagebox.showwarning(title="Not Found", message=f"No details for {website} exists.")
        except Exception as e:
            messagebox.showerror(title="Error", message=f"An error occurred: {str(e)}")

    def show_context_menu(self, event):
        """Show context menu on right-click."""
        # Get the item under cursor
        item = self.tree.identify_row(event.y)
        if item:
            # Select the item
            self.tree.selection_set(item)
            # Show the context menu
            self.context_menu.post(event.x_root, event.y_root)
        return "break"  # Prevent the default behavior

    def copy_to_clipboard(self, field):
        """Copy selected field to clipboard."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showerror("Error", "No item selected!")
            return
        
        try:
            item = self.tree.item(selection[0])
            website = item['values'][0]
            
            master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
            if not master_password:
                return
            if not self.verify_master_password(master_password):
                messagebox.showerror(title="Error", message="Invalid master password!")
                return
            
            with open(self.SALT_FILE, 'rb') as f:
                salt = f.read()
            key = self.generate_key_from_password(master_password, salt)
            
            with open(self.DATA_ENC_FILE, 'rb') as f:
                encrypted_data = f.read()
            data = self.decrypt_data(encrypted_data, key)
            
            if website in data:
                if field == 'username':
                    pyperclip.copy(data[website]['email'])
                    messagebox.showinfo("Success", "Username copied to clipboard!")
                else:
                    pyperclip.copy(data[website]['password'])
                    messagebox.showinfo("Success", "Password copied to clipboard!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to copy to clipboard: {str(e)}")

    def delete_entry(self):
        """Delete selected entry."""
        selection = self.tree.selection()
        if not selection:
            messagebox.showerror("Error", "No item selected!")
            return
        
        if not messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            return
        
        try:
            item = self.tree.item(selection[0])
            website = item['values'][0]
            
            master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
            if not master_password:
                return
            if not self.verify_master_password(master_password):
                messagebox.showerror(title="Error", message="Invalid master password!")
                return
            
            with open(self.SALT_FILE, 'rb') as f:
                salt = f.read()
            key = self.generate_key_from_password(master_password, salt)
            
            with open(self.DATA_ENC_FILE, 'rb') as f:
                encrypted_data = f.read()
            data = self.decrypt_data(encrypted_data, key)
            
            if website in data:
                del data[website]
                
                encrypted_data = self.encrypt_data(data, key)
                with open(self.DATA_ENC_FILE, 'wb') as f:
                    f.write(encrypted_data)
                
                self.tree.delete(selection[0])
                messagebox.showinfo("Success", "Entry deleted successfully!")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to delete entry: {str(e)}")

    def refresh_tree(self):
        """Refresh the Treeview with current data."""
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Only proceed if both data and master password files exist
        if not Path(self.DATA_ENC_FILE).exists() or not Path(self.HASH_FILE).exists():
            return
        
        try:
            # Use existing master password if available
            if not self.master_password:
                self.master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
                if not self.master_password:
                    return
                if not self.verify_master_password(self.master_password):
                    self.master_password = None
                    messagebox.showerror(title="Error", message="Invalid master password!")
                    return
                
                # Generate key if we don't have it
                with open(self.SALT_FILE, 'rb') as f:
                    salt = f.read()
                self.current_key = self.generate_key_from_password(self.master_password, salt)
            
            with open(self.DATA_ENC_FILE, 'rb') as f:
                encrypted_data = f.read()
            data = self.decrypt_data(encrypted_data, self.current_key)
            
            for website, info in data.items():
                self.tree.insert('', 'end', values=(website, info['email'], '*' * len(info['password'])))
        except Exception as e:
            self.master_password = None
            self.current_key = None
            messagebox.showerror("Error", f"Failed to refresh list: {str(e)}")

    def import_json(self):
        """Import data from data.json file into encrypted storage."""
        if not Path('data.json').exists():
            messagebox.showerror("Error", "data.json file not found!")
            return

        try:
            # Read the JSON file
            with open('data.json', 'r') as f:
                json_data = json.load(f)

            if not json_data:
                messagebox.showwarning("Warning", "No data found in data.json!")
                return

            # If we don't have a master password set up yet, create one
            if not Path(self.HASH_FILE).exists():
                self.master_password = simpledialog.askstring("Set Master Password", 
                    "First time setup: Please enter a master password\n"
                    "(Must be at least 8 characters with uppercase, lowercase, numbers, and special characters):", 
                    show='*')
                if not self.master_password:
                    return
                
                # Validate master password
                if (len(self.master_password) < 8 or 
                    not any(c.isupper() for c in self.master_password) or
                    not any(c.islower() for c in self.master_password) or
                    not any(c.isdigit() for c in self.master_password) or
                    not any(not c.isalnum() for c in self.master_password)):
                    self.master_password = None
                    messagebox.showerror(title="Error", 
                        message="Master password must be at least 8 characters and contain uppercase, "
                                "lowercase, numbers, and special characters!")
                    return
                
                # Confirm master password
                confirm_password = simpledialog.askstring("Confirm Master Password", 
                    "Please confirm your master password:", show='*')
                if not confirm_password or confirm_password != self.master_password:
                    self.master_password = None
                    messagebox.showerror(title="Error", message="Passwords do not match!")
                    return
                
                # Generate salt and save master password hash
                salt = bcrypt.gensalt()
                self.save_master_hash(self.master_password)
                
                # Generate encryption key and save salt
                self.current_key = self.generate_key_from_password(self.master_password, salt)
                with open(self.SALT_FILE, 'wb') as f:
                    f.write(salt)
            else:
                # Get master password for existing setup if we don't have it
                if not self.master_password:
                    self.master_password = simpledialog.askstring("Master Password", "Enter master password:", show='*')
                    if not self.master_password:
                        return
                    if not self.verify_master_password(self.master_password):
                        self.master_password = None
                        messagebox.showerror(title="Error", message="Invalid master password!")
                        return
                    
                    # Generate key if we don't have it
                    with open(self.SALT_FILE, 'rb') as f:
                        salt = f.read()
                    self.current_key = self.generate_key_from_password(self.master_password, salt)

            # Load existing encrypted data if any
            if Path(self.DATA_ENC_FILE).exists():
                with open(self.DATA_ENC_FILE, 'rb') as f:
                    encrypted_data = f.read()
                existing_data = self.decrypt_data(encrypted_data, self.current_key)
            else:
                existing_data = {}

            # Merge the data
            num_imported = 0
            num_skipped = 0
            for website, info in json_data.items():
                if website in existing_data:
                    num_skipped += 1
                    continue
                existing_data[website] = info
                num_imported += 1

            # Encrypt and save the merged data
            encrypted_data = self.encrypt_data(existing_data, self.current_key)
            with open(self.DATA_ENC_FILE, 'wb') as f:
                f.write(encrypted_data)

            # Show results and refresh the tree
            messagebox.showinfo("Import Complete", 
                f"Successfully imported {num_imported} entries.\n"
                f"Skipped {num_skipped} duplicate entries.")
            self.refresh_tree()

        except json.JSONDecodeError:
            messagebox.showerror("Error", "Invalid JSON format in data.json!")
        except Exception as e:
            self.master_password = None
            self.current_key = None
            messagebox.showerror("Error", f"An error occurred during import: {str(e)}")

    def run(self):
        """Start the application."""
        self.window.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()