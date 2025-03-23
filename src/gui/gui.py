import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import pyperclip

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
        """Set up the user interface."""
        # Menu Bar
        menubar = tk.Menu(self.window)
        self.window.config(menu=menubar)
        
        # File Menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Import from data.json", command=self.on_import)
        file_menu.add_command(label="Export to data.json", command=self.on_export)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.window.quit)

        # Set up the logo
        canvas = tk.Canvas(self.window, height=200, width=200)
        self.logo_img = tk.PhotoImage(file="logo.png")
        canvas.create_image(100, 100, image=self.logo_img)
        canvas.grid(column=1, row=0)

        # Labels
        website_label = tk.Label(self.window, text="Website:", bg="white")
        website_label.grid(column=0, row=1)

        email_label = tk.Label(self.window, text="Email/Username:", bg="white")
        email_label.grid(column=0, row=2)

        password_label = tk.Label(self.window, text="Password:", bg="white")
        password_label.grid(column=0, row=3)

        # Entry fields
        self.website_entry = tk.Entry(self.window, width=35)
        self.website_entry.grid(row=1, column=1, columnspan=2)
        self.website_entry.focus()

        self.email_entry = tk.Entry(self.window, width=35)
        self.email_entry.grid(row=2, column=1, columnspan=2)

        self.password_entry = tk.Entry(self.window, width=21)
        self.password_entry.grid(row=3, column=1)

        # Buttons
        generate_password_button = tk.Button(self.window, text="Generate Password", 
                                          command=self.on_generate_password)
        generate_password_button.grid(row=3, column=2)

        add_button = tk.Button(self.window, text="Add", width=36, command=self.on_save)
        add_button.grid(row=4, column=1, columnspan=2)

        search_button = tk.Button(self.window, text="Search", width=15, 
                               command=lambda: self.on_search(self.website_entry.get()))
        search_button.grid(row=1, column=3)

        # Treeview
        tree_frame = tk.Frame(self.window)
        tree_frame.grid(row=5, column=0, columnspan=4, pady=20)

        self.tree = ttk.Treeview(tree_frame, columns=('Website', 'Username', 'Password'), show='headings')
        self.tree.heading('Website', text='Website')
        self.tree.heading('Username', text='Username')
        self.tree.heading('Password', text='Password')
        self.tree.column('Website', width=200)
        self.tree.column('Username', width=200)
        self.tree.column('Password', width=200)
        self.tree.pack(side='left', fill='y')

        # Scrollbar
        scrollbar = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        scrollbar.pack(side='right', fill='y')
        self.tree.configure(yscrollcommand=scrollbar.set)

        # Context menu
        self.context_menu = tk.Menu(self.window, tearoff=0)
        self.context_menu.add_command(label="Copy Username", 
                                    command=lambda: self.copy_to_clipboard('username'))
        self.context_menu.add_command(label="Copy Password", 
                                    command=lambda: self.copy_to_clipboard('password'))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Delete Entry", command=self.on_delete)

        # Bindings
        self.tree.bind('<Button-3>', self.show_context_menu)  # Right-click on Windows/Linux
        self.tree.bind('<Button-2>', self.show_context_menu)  # Right-click on macOS
        self.tree.bind('<Control-c>', lambda e: self.copy_to_clipboard('password'))

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
            'username': self.email_entry.get().strip(),
            'password': self.password_entry.get().strip()
        }

    def clear_entries(self):
        """Clear all entry fields."""
        self.website_entry.delete(0, tk.END)
        self.email_entry.delete(0, tk.END)
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