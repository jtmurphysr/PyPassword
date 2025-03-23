import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pyperclip
import os
from PIL import Image, ImageTk

class PasswordManagerGUI:
    """Handles all GUI-related operations for the password manager."""
    
    def __init__(self, parent, on_save, on_search, on_delete, on_generate_password, on_get_data):
        self.window = parent
        self.window.title("Password Manager")
        self.window.config(padx=50, pady=50)
        self.window.config(bg="white")
        
        # Callback functions
        self.on_save = on_save
        self.on_search = on_search
        self.on_delete = on_delete
        self.on_generate_password = on_generate_password
        self.on_get_data = on_get_data
        
        self.setup_ui()

    def setup_ui(self):
        """Set up the GUI elements"""
        # Configure grid weights
        self.window.grid_columnconfigure(1, weight=1)
        self.window.grid_rowconfigure(2, weight=1)
        
        # Create main container
        main_container = ttk.Frame(self.window)
        main_container.grid(row=0, column=0, sticky="nsew", padx=10, pady=10)
        
        # Configure main container grid
        main_container.grid_columnconfigure(1, weight=1)
        main_container.grid_rowconfigure(2, weight=1)
        
        # Logo
        logo_path = os.path.join(os.path.dirname(__file__), "..", "assets", "logo.png")
        try:
            logo_image = Image.open(logo_path)
            logo_photo = ImageTk.PhotoImage(logo_image)
            logo_label = ttk.Label(main_container, image=logo_photo)
            logo_label.image = logo_photo  # Keep a reference
            logo_label.grid(column=0, row=0, columnspan=2, pady=(0, 10))
        except Exception as e:
            print(f"Error loading logo: {e}")
        
        # Website entry
        website_label = ttk.Label(main_container, text="Website:")
        website_label.grid(column=0, row=1, sticky="e", padx=(0, 5))
        
        self.website_var = tk.StringVar()
        self.website_entry = ttk.Entry(main_container, textvariable=self.website_var)
        self.website_entry.grid(column=1, row=1, sticky="ew", padx=(0, 5))
        
        # Username entry
        username_label = ttk.Label(main_container, text="Username:")
        username_label.grid(column=0, row=2, sticky="e", padx=(0, 5))
        
        self.username_var = tk.StringVar()
        self.username_entry = ttk.Entry(main_container, textvariable=self.username_var)
        self.username_entry.grid(column=1, row=2, sticky="ew", padx=(0, 5))
        
        # Password entry
        password_label = ttk.Label(main_container, text="Password:")
        password_label.grid(column=0, row=3, sticky="e", padx=(0, 5))
        
        self.password_var = tk.StringVar()
        self.password_entry = ttk.Entry(main_container, textvariable=self.password_var, show="*")
        self.password_entry.grid(column=1, row=3, sticky="ew", padx=(0, 5))
        
        # Buttons frame
        button_frame = ttk.Frame(main_container)
        button_frame.grid(column=0, row=4, columnspan=2, pady=10)
        
        # Add button
        add_button = ttk.Button(button_frame, text="Add", command=self.on_save)
        add_button.grid(column=0, row=0, padx=5)
        
        # Update button
        update_button = ttk.Button(button_frame, text="Update", command=self.on_save)
        update_button.grid(column=1, row=0, padx=5)
        
        # Delete button
        delete_button = ttk.Button(button_frame, text="Delete", command=self.on_delete)
        delete_button.grid(column=2, row=0, padx=5)
        
        # Tree view
        self.tree = ttk.Treeview(main_container, columns=("Website", "Username", "Password"), show="headings")
        self.tree.grid(column=0, row=5, columnspan=2, sticky="nsew", pady=10)
        
        # Configure tree columns
        self.tree.heading("Website", text="Website")
        self.tree.heading("Username", text="Username")
        self.tree.heading("Password", text="Password")
        
        self.tree.column("Website", width=150)
        self.tree.column("Username", width=150)
        self.tree.column("Password", width=100)
        
        # Bind selection event
        self.tree.bind("<<TreeviewSelect>>", self.on_select)
        
        # Load initial data
        self.load_data()

    def on_select(self, event):
        """Handle selection of an item in the tree."""
        selected = self.tree.selection()
        if not selected:
            return
        
        item = self.tree.item(selected[0])
        values = item['values']
        
        # Update entry fields with selected values
        self.website_var.set(values[0])
        self.username_var.set(values[1])
        self.password_var.set(values[2])

    def load_data(self):
        """Load data from the parent class and refresh the tree."""
        if hasattr(self, 'on_get_data'):
            data = self.on_get_data()
            self.refresh_tree(data)

    def show_context_menu(self, event):
        """Show the context menu on right-click."""
        item = self.tree.identify_row(event.y)
        if item:
            self.tree.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def copy_to_clipboard(self, field):
        """Copy selected item's field to clipboard."""
        selected = self.tree.selection()
        if not selected:
            return
        
        item = self.tree.item(selected[0])
        website = item['values'][0]
        
        # Get the actual data from the parent class
        if hasattr(self, 'on_get_data'):
            data = self.on_get_data()
            if website in data:
                if field == 'username':
                    pyperclip.copy(data[website]['username'])
                else:  # password
                    pyperclip.copy(data[website]['password'])

    def get_entry_values(self):
        """Get values from entry fields."""
        return {
            'website': self.website_entry.get().strip(),
            'username': self.username_entry.get().strip(),
            'password': self.password_entry.get().strip()
        }

    def clear_entries(self):
        """Clear all entry fields."""
        self.website_entry.delete(0, tk.END)
        self.username_entry.delete(0, tk.END)
        self.password_entry.delete(0, tk.END)

    def refresh_tree(self, data):
        """Refresh the treeview with new data."""
        # Clear existing items
        for item in self.tree.get_children():
            self.tree.delete(item)
        
        # Add new items with masked passwords
        for website, details in data.items():
            # Store actual password but display masked version
            masked_password = '•' * len(details['password'])
            self.tree.insert('', 'end', values=(website, details['username'], masked_password))

    def on_import(self):
        """Handle import from JSON."""
        if messagebox.askyesno("Import", "Import passwords from data.json?"):
            self.on_import_callback()

    def on_export(self):
        """Handle export to JSON."""
        if messagebox.askyesno("Export", "Export passwords to data.json?"):
            self.on_export_callback()

    def set_callbacks(self, import_callback, export_callback):
        """Set callbacks for import/export operations."""
        self.on_import_callback = import_callback
        self.on_export_callback = export_callback 