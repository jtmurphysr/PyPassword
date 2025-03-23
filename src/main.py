import tkinter as tk
from tkinter import messagebox, simpledialog
from core.security import SecurityManager
from core.file_manager import FileManager
from gui.gui import PasswordManagerGUI

class PasswordManager:
    """Main password manager application class."""
    
    def __init__(self):
        # Initialize components
        self.security = SecurityManager()
        self.file_manager = FileManager()
        self.current_key = None  # Initialize current_key
        
        # Create main window
        self.window = tk.Tk()
        
        # Initialize GUI with callbacks
        self.gui = PasswordManagerGUI(
            self.window,
            on_save=self.save,
            on_search=self.retrieve,
            on_delete=self.delete_entry,
            on_generate_password=self.generate_password,
            on_get_data=self.get_current_data
        )
        
        # Set up import/export callbacks
        self.gui.set_callbacks(self.import_json, self.export_json)
        
        # Check for first-time setup
        if self.file_manager.is_first_time_setup():
            self.setup_master_password()
        else:
            self.verify_and_load_data()

    def setup_master_password(self):
        """Handle first-time master password setup."""
        while True:
            password = simpledialog.askstring(
                "Set Master Password",
                "First time setup: Please enter a master password\n"
                "(Must be at least 8 characters with uppercase, lowercase, numbers, and special characters):",
                show='*'
            )
            
            if not password:
                self.window.quit()
                return
            
            # Validate master password
            is_valid, message = self.security.validate_master_password(password)
            if is_valid:
                self.file_manager.save_master_password(password)
                break
            else:
                messagebox.showerror("Error", message)

    def verify_and_load_data(self):
        """Verify master password and load data."""
        while True:
            password = simpledialog.askstring(
                "Master Password",
                "Please enter your master password:",
                show='*'
            )
            
            if not password:
                self.window.quit()
                return
            
            if self.file_manager.verify_master_password(password):
                self.current_key = self.file_manager.get_encryption_key(password)
                self.load_data()
                break
            else:
                messagebox.showerror("Error", "Invalid master password!")

    def load_data(self):
        """Load password data and refresh the display."""
        data = self.file_manager.load_password_data(self.current_key)
        
        # Convert old format to new format if needed
        converted_data = {}
        for website, details in data.items():
            converted_data[website] = {
                'username': details.get('username', details.get('email', '')),  # Handle both formats
                'password': details.get('password', '')
            }
        
        self.gui.refresh_tree(converted_data)

    def save(self):
        """Save a new password entry."""
        values = self.gui.get_entry_values()
        
        if not all(values.values()):
            messagebox.showwarning("Warning", "Please fill out all fields!")
            return
        
        # Load existing data
        data = self.file_manager.load_password_data(self.current_key)
        
        # Convert old format to new format if needed
        converted_data = {}
        for website, details in data.items():
            converted_data[website] = {
                'username': details.get('username', details.get('email', '')),
                'password': details.get('password', '')
            }
        
        # Add new entry
        website = values['website']
        converted_data[website] = {
            'username': values['username'],
            'password': values['password']
        }
        
        # Save updated data
        self.file_manager.save_password_data(converted_data, self.current_key)
        
        # Update display
        self.gui.refresh_tree(converted_data)
        self.gui.clear_entries()
        
        messagebox.showinfo("Success", "Password saved successfully!")

    def retrieve(self, website):
        """Retrieve password for a website."""
        if not website:
            messagebox.showwarning("Warning", "Please enter a website!")
            return
        
        data = self.file_manager.load_password_data(self.current_key)
        
        if website in data:
            details = data[website]
            username = details.get('username', details.get('email', ''))
            password = details.get('password', '')
            
            self.gui.clear_entries()
            self.gui.website_entry.insert(0, website)
            self.gui.email_entry.insert(0, username)
            self.gui.password_entry.insert(0, password)
        else:
            messagebox.showinfo("Not Found", f"No password found for {website}")

    def delete_entry(self):
        """Delete selected password entry."""
        selected = self.gui.tree.selection()
        if not selected:
            messagebox.showwarning("Warning", "Please select an entry to delete!")
            return
        
        if messagebox.askyesno("Confirm Delete", "Are you sure you want to delete this entry?"):
            item = self.gui.tree.item(selected[0])
            website = item['values'][0]
            
            # Load and update data
            data = self.file_manager.load_password_data(self.current_key)
            if website in data:
                del data[website]
                self.file_manager.save_password_data(data, self.current_key)
                self.gui.refresh_tree(data)
                self.gui.clear_entries()

    def generate_password(self):
        """Generate a secure password."""
        password = self.security.generate_password()
        self.gui.password_entry.delete(0, tk.END)
        self.gui.password_entry.insert(0, password)
        return password

    def import_json(self):
        """Import passwords from JSON file."""
        if self.file_manager.import_from_json(self.current_key):
            self.load_data()
            messagebox.showinfo("Success", "Passwords imported successfully!")
        else:
            messagebox.showerror("Error", "Failed to import passwords!")

    def export_json(self):
        """Export passwords to JSON file."""
        if self.file_manager.export_to_json(self.current_key):
            messagebox.showinfo("Success", "Passwords exported successfully!")
        else:
            messagebox.showerror("Error", "Failed to export passwords!")

    def get_current_data(self):
        """Get the current password data."""
        data = self.file_manager.load_password_data(self.current_key)
        # Convert old format to new format if needed
        converted_data = {}
        for website, details in data.items():
            converted_data[website] = {
                'username': details.get('username', details.get('email', '')),
                'password': details.get('password', '')
            }
        return converted_data

    def run(self):
        """Start the application."""
        self.window.mainloop()

if __name__ == "__main__":
    app = PasswordManager()
    app.run()