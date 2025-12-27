"""

Main application file containing the GUI and program entry point.
This module creates the graphical user interface using Tkinter.
"""

import tkinter as tk
from tkinter import messagebox, scrolledtext
from file_manager import ensure_files_exist, load_rsa_keys
from auth_service import register_user, login_user


class CryptoAuthGUI:
    """
    Main GUI class for the Multi-Layer Encryption Authentication System.
    Handles user interface, events, and interactions.
    """
    
    def __init__(self, root):
        """
        Initialize the GUI application.
        
                                    """
        self.root = root
        self.root.title("Multi-Layer Encryption Authentication System")
        self.root.geometry("900x700")
        self.root.configure(bg="#1e293b")
        
        # Initialize files and load RSA keys
        ensure_files_exist()
        self.rsa_keys = load_rsa_keys()
        self.public_key = self.rsa_keys.publickey()
        self.private_key = self.rsa_keys
        
        # Encryption keys 
        self.des_key = b'ThisDESkey'
        self.aes_key = b'ThisAESkey'
        
        # Login security tracking
        self.login_attempts = 0
        self.max_attempts = 3
        self.is_locked = False
        
        # Password visibility toggle state
        self.password_visible = False
        
        # Create all GUI widgets
        self.create_widgets()
    
    def create_widgets(self):
        """
        Create and arrange all GUI widgets 
        """
        #  HEADER SECTION 
        header_frame = tk.Frame(self.root, bg="#0f172a", pady=20)
        header_frame.pack(fill=tk.X)
        
        title_label = tk.Label(
            header_frame,
            text="🔐 Multi-Layer Encryption System",
            font=("Arial", 24, "bold"),
            bg="#0f172a",
            fg="#60a5fa"
        )
        title_label.pack()
        
        subtitle_label = tk.Label(
            header_frame,
            text="SHA-256 → DES → AES → RSA Authentication",
            font=("Arial", 12),
            bg="#0f172a",
            fg="#94a3b8"
        )
        subtitle_label.pack()
        
        #  MAIN CONTAINER 
        main_frame = tk.Frame(self.root, bg="#1e293b")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        #  LEFT PANEL: INPUT FORM 
        left_frame = tk.Frame(main_frame, bg="#334155", relief=tk.RAISED, bd=2)
        left_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 10))
        
        # Mode selection (Register/Login)
        mode_frame = tk.Frame(left_frame, bg="#334155", pady=10)
        mode_frame.pack(fill=tk.X, padx=20, pady=10)
        
        self.mode_var = tk.StringVar(value="register")
        
        register_btn = tk.Radiobutton(
            mode_frame,
            text="Register",
            variable=self.mode_var,
            value="register",
            font=("Arial", 12, "bold"),
            bg="#3b82f6",
            fg="white",
            selectcolor="#2563eb",
            activebackground="#1d4ed8",
            activeforeground="white",
            indicatoron=0,
            width=15,
            pady=10,
            command=self.clear_form
        )
        register_btn.pack(side=tk.LEFT, padx=5)
        
        login_btn = tk.Radiobutton(
            mode_frame,
            text="Login",
            variable=self.mode_var,
            value="login",
            font=("Arial", 12, "bold"),
            bg="#3b82f6",
            fg="white",
            selectcolor="#2563eb",
            activebackground="#1d4ed8",
            activeforeground="white",
            indicatoron=0,
            width=15,
            pady=10,
            command=self.clear_form
        )
        login_btn.pack(side=tk.LEFT, padx=5)
        
        # Input fields container
        input_frame = tk.Frame(left_frame, bg="#334155", pady=20)
        input_frame.pack(fill=tk.BOTH, expand=True, padx=20)
        
        # Username input
        tk.Label(
            input_frame,
            text="👤 Username:",
            font=("Arial", 11, "bold"),
            bg="#334155",
            fg="#e2e8f0"
        ).pack(anchor=tk.W, pady=(0, 5))
        
        self.username_entry = tk.Entry(
            input_frame,
            font=("Arial", 12),
            bg="#475569",
            fg="white",
            insertbackground="white",
            relief=tk.FLAT,
            bd=5
        )
        self.username_entry.pack(fill=tk.X, pady=(0, 15))
        
        # Password input with visibility toggle
        tk.Label(
            input_frame,
            text="🔒 Password:",
            font=("Arial", 11, "bold"),
            bg="#334155",
            fg="#e2e8f0"
        ).pack(anchor=tk.W, pady=(0, 5))
        
        password_container = tk.Frame(input_frame, bg="#334155")
        password_container.pack(fill=tk.X, pady=(0, 10))
        
        self.password_entry = tk.Entry(
            password_container,
            font=("Arial", 12),
            bg="#475569",
            fg="white",
            insertbackground="white",
            show="*",
            relief=tk.FLAT,
            bd=5
        )
        self.password_entry.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Eye icon button for password visibility
        self.eye_button = tk.Button(
            password_container,
            text="👁",
            font=("Arial", 14),
            bg="#475569",
            fg="white",
            activebackground="#64748b",
            activeforeground="white",
            relief=tk.FLAT,
            bd=5,
            width=3,
            command=self.toggle_password_visibility,
            cursor="hand2"
        )
        self.eye_button.pack(side=tk.RIGHT, padx=(2, 0))
        
        tk.Label(
            input_frame,
            text="(Min 8 characters, 1 special character required)",
            font=("Arial", 9),
            bg="#334155",
            fg="#94a3b8"
        ).pack(anchor=tk.W)
        
        # Action button (Register/Login)
        self.action_button = tk.Button(
            input_frame,
            text="🔒 REGISTER USER",
            font=("Arial", 13, "bold"),
            bg="#3b82f6",
            fg="white",
            activebackground="#2563eb",
            activeforeground="white",
            relief=tk.FLAT,
            bd=0,
            pady=15,
            command=self.handle_action,
            cursor="hand2"
        )
        self.action_button.pack(fill=tk.X, pady=(20, 10))
        
        # Status message label
        self.status_label = tk.Label(
            input_frame,
            text="",
            font=("Arial", 10),
            bg="#334155",
            fg="#22c55e",
            wraplength=350,
            justify=tk.LEFT
        )
        self.status_label.pack(pady=10)
        
        # System information panel
        info_frame = tk.Frame(left_frame, bg="#475569", relief=tk.SUNKEN, bd=2)
        info_frame.pack(fill=tk.X, padx=20, pady=10)
        
        tk.Label(
            info_frame,
            text="📊 System Status",
            font=("Arial", 10, "bold"),
            bg="#475569",
            fg="#e2e8f0"
        ).pack(pady=(5, 0))
        
        self.info_label = tk.Label(
            info_frame,
            text="• RSA Keys: Loaded ✓\n• Status: Active ✓",
            font=("Arial", 9),
            bg="#475569",
            fg="#cbd5e1",
            justify=tk.LEFT
        )
        self.info_label.pack(pady=5)
        
        #  RIGHT PANEL: LOG DISPLAY 
        right_frame = tk.Frame(main_frame, bg="#334155", relief=tk.RAISED, bd=2)
        right_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        tk.Label(
            right_frame,
            text="🔑 Encryption/Decryption Log",
            font=("Arial", 14, "bold"),
            bg="#334155",
            fg="#60a5fa",
            pady=15
        ).pack()
        
        self.log_display = scrolledtext.ScrolledText(
            right_frame,
            font=("Courier", 9),
            bg="#1e293b",
            fg="#22c55e",
            insertbackground="white",
            relief=tk.FLAT,
            bd=5,
            wrap=tk.WORD
        )
        self.log_display.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 10))
        
        clear_btn = tk.Button(
            right_frame,
            text="Clear Log",
            font=("Arial", 10),
            bg="#ef4444",
            fg="white",
            activebackground="#dc2626",
            relief=tk.FLAT,
            command=self.clear_log,
            cursor="hand2"
        )
        clear_btn.pack(pady=(0, 10))
        
        # Update button text when mode changes
        self.mode_var.trace("w", self.update_button_text)
    
    def toggle_password_visibility(self):
        """
        Toggle between showing and hiding password text.

        """
        if self.password_visible:
            self.password_entry.config(show="*")
            self.eye_button.config(text="👁")
            self.password_visible = False
        else:
            self.password_entry.config(show="")
            self.eye_button.config(text="🙈")
            self.password_visible = True
    
    def update_button_text(self, *args):
        """
        Update action button text based on selected mode.
        Called automatically when mode changes.
        """
        mode = self.mode_var.get()
        if mode == "register":
            self.action_button.config(text="🔒 REGISTER USER")
        else:
            self.action_button.config(text="🔓 LOGIN")
    
    def log(self, message):
        """
        Add a message to the log display area.
        
        """
        self.log_display.insert(tk.END, message + "\n")
        self.log_display.see(tk.END)
    
    def clear_log(self):
        """
        Clear all text from the log display area.
        """
        self.log_display.delete(1.0, tk.END)
    
    def clear_form(self):
        """
        Clear input fields and reset form state.
        Called when switching between Register/Login modes.
        """
        self.password_entry.delete(0, tk.END)
        self.status_label.config(text="")
        
        # Reset password visibility
        self.password_entry.config(show="*")
        self.eye_button.config(text="👁")
        self.password_visible = False
        
        # Clear username only in register mode
        if self.mode_var.get() == "register":
            self.username_entry.delete(0, tk.END)
            self.is_locked = False
            self.login_attempts = 0
    
    def handle_action(self):
        """
        Handle the main action button click.
        Routes to register or login based on selected mode.
        """
        mode = self.mode_var.get()
        username = self.username_entry.get().strip()
        password = self.password_entry.get()
        
        # Validate inputs
        if not username or not password:
            self.status_label.config(
                text="⚠ Please enter both username and password!", 
                fg="#ef4444"
            )
            return
        
        # Route to appropriate function
        if mode == "register":
            self.handle_register(username, password)
        else:
            self.handle_login(username, password)
    
    def handle_register(self, username, password):
        """
        Handle user registration process.

        """
        self.clear_log()
        self.log("=" * 50)
        self.log("STARTING REGISTRATION PROCESS")
        self.log("=" * 50 + "\n")
        
        # Call registration service
        success, message = register_user(
            username, 
            password, 
            self.des_key, 
            self.aes_key, 
            self.public_key,
            self.log
        )
        
        if success:
            self.status_label.config(text=f"✓ {message}", fg="#22c55e")
            self.password_entry.delete(0, tk.END)
            
            # Reset password visibility
            self.password_entry.config(show="*")
            self.eye_button.config(text="👁")
            self.password_visible = False
        else:
            self.status_label.config(text=f"✗ {message}", fg="#ef4444")
    
    def handle_login(self, username, password):
        """
        Handle user login/authentication process.
        Includes attempt limiting for security.
        
        """
        # Check if system is locked
        if self.is_locked:
            messagebox.showerror(
                "System Locked", 
                "Too many failed attempts! Please restart the application."
            )
            return
        
        self.clear_log()
        self.log("=" * 50)
        self.log("STARTING LOGIN PROCESS")
        self.log("=" * 50 + "\n")
        
        # Call login service
        success, message = login_user(
            username, 
            password, 
            self.des_key, 
            self.aes_key, 
            self.private_key,
            self.log
        )
        
        if success:
            self.status_label.config(text=f" {message} Welcome!", fg="#22c55e")
            self.login_attempts = 0
            messagebox.showinfo("Success", "Login Successful! Access Granted.")
        else:
            self.login_attempts += 1
            remaining = self.max_attempts - self.login_attempts
            
            if remaining > 0:
                self.status_label.config(
                    text=f" {message} ({remaining} attempts remaining)", 
                    fg="#ef4444"
                )
            else:
                self.is_locked = True
                self.status_label.config(text="🔒 SYSTEM LOCKED!", fg="#ef4444")
                messagebox.showerror("Locked", "Too many failed attempts! System locked.")


#  MAIN PROGRAM ENTRY POINT 

if __name__ == "__main__":
    """
    Main entry point of the application.
    Creates the root window and starts the GUI.
    """
    root = tk.Tk()
    app = CryptoAuthGUI(root)
    root.mainloop()