import os
import config
import sys
import shutil
import threading
import sqlite3
import re
from tkinter import filedialog
from datetime import datetime
from PIL import Image
from io import BytesIO
import pyotp
import qrcode
import base64

import customtkinter as ctk

# Local module imports
import auth
import otp_handler
import captcha_handler
import encryptor
import backup_handler
import custom_dialogs

def resource_path(relative_path):
    # Get absolute path to resource, for dev and for PyInstaller
    try:
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

# --- CONFIG ---
INACTIVITY_TIMEOUT_MINUTES = 10
UPLOAD_FOLDER = config.UPLOAD_FOLDER
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
MAX_FILE_SIZE = 5 * 1024 * 1024  # 5 MB

# --- MAIN APP ---
class VaultApp(ctk.CTk):
    def __init__(self, dev_mode=False, dev_user=None): # Initializes the main application window and state
        super().__init__()
        self.title("SecureVault")
        
        window_width = 800
        window_height = 600
        screen_width = self.winfo_screenwidth()
        screen_height = self.winfo_screenheight()
        center_x = int(screen_width / 2 - window_width / 2)
        center_y = int(screen_height / 2 - window_height / 2)
        self.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        self.configure(fg_color="#1e1e1e")
        self.resizable(False, False)

        self.current_user = None
        self.generated_otp = None
        self.fp_generated_otp = None
        self.signup_otp_attempts = 0
        self.fp_otp_attempts = 0
        self.pwd_visible = False
        self.signup_pwd_visible = False
        self.db_lock = threading.Lock()
        self.inactivity_timer_id = None

        self.bind_all("<KeyPress>", self.reset_inactivity_timer)
        self.bind_all("<Motion>", self.reset_inactivity_timer)

        if dev_mode and dev_user:
            if auth.get_user_mfa_secret(dev_user):
                print("--- DEVELOPMENT MODE: AUTO-LOGIN ENABLED ---")
                print(f"--- Logged in as: {dev_user} ---")
                self.current_user = dev_user
                self.create_vault_ui()
            else:
                print(f"DEV MODE ERROR: Test user '{dev_user}' not found or MFA not set up.")
                self.create_login_ui()
        else:
            self.create_login_ui()

    def _show_document_viewer(self, title, file_path):
        try:
            # Use the new helper function to find the correct path
            with open(resource_path(file_path), 'r', encoding='utf-8') as f:
                content = f.read()
        except FileNotFoundError:
            content = f"Error: The document file '{file_path}' was not found."
        
        doc_window = ctk.CTkToplevel(self)
        doc_window.title(title)
        doc_window.geometry("800x600")
        doc_window.transient(self); doc_window.grab_set()

        ctk.CTkLabel(doc_window, text=title, font=("Arial", 18, "bold")).pack(pady=10)

        textbox = ctk.CTkTextbox(doc_window, wrap="word", font=("Arial", 12))
        textbox.pack(expand=True, fill="both", padx=10, pady=10)
        textbox.insert("1.0", content)
        textbox.configure(state="disabled")

        ctk.CTkButton(doc_window, text="Close", command=doc_window.destroy).pack(pady=10)

    def show_user_guide(self): # Opens the user guide document viewer
        self._show_document_viewer("Secure Vault - User Guide", "user_guide.txt")

    def show_disclaimer(self): # Opens the disclaimer document viewer
        self._show_document_viewer("Disclaimer & Privacy Policy", "disclaimer.txt")

    def create_login_ui(self): # Builds the main login screen widgets
        self.clear_window()
        ctk.CTkLabel(self, text="SecureVault", font=("Arial", 28, "bold")).pack(pady=(40, 20))
        
        self.username_entry = ctk.CTkEntry(self, placeholder_text="Username", width=400, justify="center")
        self.username_entry.pack(pady=5)
        
        pwd_frame = ctk.CTkFrame(self, fg_color="transparent")
        pwd_frame.pack(pady=5)
        self.password_entry = ctk.CTkEntry(pwd_frame, placeholder_text="Password", show="*", width=360, justify="center")
        self.password_entry.pack(side="left")
        ctk.CTkButton(pwd_frame, text="👁️", width=40, command=self.toggle_password_visibility).pack(side="left", padx=5)
        
        self.captcha = captcha_handler.generate_captcha()
        cap_frame = ctk.CTkFrame(self, fg_color="transparent")
        cap_frame.pack(pady=5)
        self.captcha_label = ctk.CTkLabel(cap_frame, text=f"Captcha: {self.captcha}", font=("Arial", 14))
        self.captcha_label.pack(side="left")
        ctk.CTkButton(cap_frame, text="Refresh", width=80, command=self.refresh_captcha).pack(side="left", padx=5)
        
        self.captcha_entry = ctk.CTkEntry(self, placeholder_text="Enter Captcha", width=400, justify="center")
        self.captcha_entry.pack(pady=5)
        
        ctk.CTkButton(self, text="Login", width=200, command=self.login).pack(pady=(20, 10))
        
        ctk.CTkButton(self, text="New user? Sign Up", width=200, command=self.create_signup_ui, fg_color="gray50").pack(pady=5)
        ctk.CTkButton(self, text="Forgot Password?", width=200, command=self.create_forgot_ui, fg_color="gray50").pack(pady=5)

        bottom_frame = ctk.CTkFrame(self, fg_color="transparent")
        bottom_frame.pack(side="bottom", fill="x", padx=10, pady=(20, 10))

        reset_button = ctk.CTkButton(bottom_frame, text="Factory Reset", width=120, command=self.create_factory_reset_window, fg_color="#5f1a1a", hover_color="#a8321e")
        reset_button.pack(side="left", padx=10, pady=5)

        disclaimer_button = ctk.CTkButton(bottom_frame, text="Disclaimer", width=120, command=self.show_disclaimer)
        disclaimer_button.pack(side="right", padx=10, pady=5)

        guide_button = ctk.CTkButton(bottom_frame, text="User Guide", width=120, command=self.show_user_guide)
        guide_button.pack(side="right", padx=10, pady=5)

    def create_signup_ui(self): # Builds the user registration screen
        self.clear_window()
        self.signup_otp_attempts = 0
        ctk.CTkLabel(self, text="Create Account", font=("Arial", 28, "bold")).pack(pady=(20, 10))

        scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        scroll_frame.pack(fill="both", expand=True, padx=20)
        
        self.new_username = ctk.CTkEntry(scroll_frame, placeholder_text="Username", width=400, justify="center")
        self.new_username.pack(pady=(10, 5))

        pwd_frame = ctk.CTkFrame(scroll_frame, fg_color="transparent")
        pwd_frame.pack(pady=5)
        
        self.new_password = ctk.CTkEntry(pwd_frame, placeholder_text="Password", show="*", width=360, justify="center")
        self.new_password.bind("<KeyRelease>", self._update_signup_password_strength)
        self.new_password.pack(side="left")
        ctk.CTkButton(pwd_frame, text="👁️", width=40, command=self.toggle_signup_password_visibility).pack(side="left", padx=5)
        
        self.strength_feedback_label = ctk.CTkLabel(scroll_frame, text="", font=("Arial", 12))
        self.strength_feedback_label.pack(pady=(0, 10))
        
        self.email = ctk.CTkEntry(scroll_frame, placeholder_text="Email", width=400, justify="center")
        self.email.pack(pady=5)
        
        self.send_otp_button = ctk.CTkButton(scroll_frame, text="Send OTP", width=200, command=self.send_signup_otp)
        self.send_otp_button.pack(pady=10)
        self.send_otp_button.configure(state="disabled")

        self.otp_entry = ctk.CTkEntry(scroll_frame, placeholder_text="Enter OTP from email", width=400, justify="center")
        self.otp_entry.pack(pady=5)
        
        ctk.CTkButton(scroll_frame, text="Sign Up", width=200, command=self.signup).pack(pady=10)
        ctk.CTkButton(scroll_frame, text="Back to Login", width=200, command=self.create_login_ui).pack(pady=5)

    def _update_signup_password_strength(self, event=None): # Provides real-time password strength feedback
        password = self.new_password.get()
        strength = {"score": 0, "suggestions": []}

        if len(password) >= 8:
            strength["score"] += 1
        else:
            strength["suggestions"].append("be at least 8 characters")
            
        if re.search(r'[a-z]', password):
            strength["score"] += 1
        else:
            strength["suggestions"].append("a lowercase letter")

        if re.search(r'[0-9]', password):
            strength["score"] += 1
        else:
            strength["suggestions"].append("a number")

        if re.search(r'[^A-Za-z0-9]', password):
            strength["score"] += 1
        else:
            strength["suggestions"].append("a special character")
        
        message, color, is_strong = "", "gray", False
        
        if password:
            if strength["score"] < 4:
                suggestions_text = ", ".join(strength["suggestions"])
                message = f"Requires: {suggestions_text}"
                color = "#E55451" if strength["score"] <= 2 else "#FFC700"
            else:
                message, color, is_strong = "Strong", "#50C878", True
        
        self.strength_feedback_label.configure(text=message, text_color=color)
        self.send_otp_button.configure(state="normal" if is_strong else "disabled")

    def create_change_password_window(self): # Builds the change password dialog
        self.cp_dialog = ctk.CTkToplevel(self)
        self.cp_dialog.title("Change Password")
        self.cp_dialog.geometry("450x350")
        self.cp_dialog.transient(self); self.cp_dialog.grab_set()

        ctk.CTkLabel(self.cp_dialog, text="Change Your Password", font=("Arial", 18, "bold")).pack(pady=10)

        ctk.CTkLabel(self.cp_dialog, text="Current Password").pack(anchor="w", padx=20)
        self.cp_current_pass_entry = ctk.CTkEntry(self.cp_dialog, placeholder_text="Enter your current password", show="*", width=400)
        self.cp_current_pass_entry.pack()

        ctk.CTkLabel(self.cp_dialog, text="New Password").pack(anchor="w", padx=20, pady=(10, 0))
        self.cp_new_pass_entry = ctk.CTkEntry(self.cp_dialog, placeholder_text="Enter new password", show="*", width=400)
        self.cp_new_pass_entry.bind("<KeyRelease>", self._update_change_password_strength)
        self.cp_new_pass_entry.pack()

        self.cp_strength_label = ctk.CTkLabel(self.cp_dialog, text="", font=("Arial", 12))
        self.cp_strength_label.pack(anchor="w", padx=20, pady=(0, 10))

        ctk.CTkLabel(self.cp_dialog, text="Confirm New Password").pack(anchor="w", padx=20)
        self.cp_confirm_pass_entry = ctk.CTkEntry(self.cp_dialog, placeholder_text="Confirm new password", show="*", width=400)
        self.cp_confirm_pass_entry.bind("<KeyRelease>", self._update_change_password_strength)
        self.cp_confirm_pass_entry.pack()

        self.cp_change_button = ctk.CTkButton(self.cp_dialog, text="Change Password", command=self.execute_password_change)
        self.cp_change_button.pack(pady=20)
        self.cp_change_button.configure(state="disabled")

    def create_factory_reset_window(self): # Builds the factory reset dialog flow
        email_dialog = custom_dialogs.CustomAskString(title="Admin Verification", prompt="To initiate a factory reset, please enter the admin email address:")
        entered_email = email_dialog.get_result()

        if not entered_email:
            return

        if entered_email.strip().lower() != otp_handler.EMAIL_ADDRESS.lower():
            return custom_dialogs.CustomMessagebox(title="Error", message="The entered email is not the designated admin email.")
        
        otp = otp_handler.generate_otp()
        try:
            otp_handler.send_factory_reset_otp(entered_email, otp)
        except Exception as e:
            return custom_dialogs.CustomMessagebox(title="Error", message=f"Failed to send OTP: {e}")

        otp_dialog = custom_dialogs.CustomAskString(title="Admin Verification", prompt=f"A critical warning OTP has been sent to {entered_email}.\nPlease enter it below to proceed:")
        entered_otp = otp_dialog.get_result()

        if not entered_otp or entered_otp.strip() != otp:
            return custom_dialogs.CustomMessagebox(title="Error", message="Invalid OTP. Factory reset has been cancelled.")
        
        self.execute_factory_reset()

    def _update_change_password_strength(self, event=None): # Provides real-time feedback for changing a password
        password = self.cp_new_pass_entry.get()
        confirm_password = self.cp_confirm_pass_entry.get()
        
        strength = {"score": 0, "suggestions": []}

        if len(password) >= 8:
            strength["score"] += 1
        else:
            strength["suggestions"].append("be at least 8 characters")
            
        if re.search(r'[a-z]', password):
            strength["score"] += 1
        else:
            strength["suggestions"].append("a lowercase letter")

        if re.search(r'[0-9]', password):
            strength["score"] += 1
        else:
            strength["suggestions"].append("a number")

        if re.search(r'[^A-Za-z0-9]', password):
            strength["score"] += 1
        else:
            strength["suggestions"].append("a special character")
        
        message, color, is_strong = "", "gray", False
        
        if password:
            if strength["score"] < 4:
                suggestions_text = ", ".join(strength["suggestions"])
                message = f"Requires: {suggestions_text}"
                color = "#E55451" if strength["score"] <= 2 else "#FFC700"
            else:
                message, color, is_strong = "Strong", "#50C878", True
        
        self.cp_strength_label.configure(text=message, text_color=color)
        
        if is_strong and password and (password == confirm_password):
            self.cp_change_button.configure(state="normal")
        else:
            self.cp_change_button.configure(state="disabled")

    def execute_password_change(self): # Executes the final password change
        current_pass = self.cp_current_pass_entry.get()
        new_pass = self.cp_new_pass_entry.get()
        
        success, msg = auth.change_password(self.current_user, current_pass, new_pass)

        if success:
            self.cp_dialog.destroy()
            custom_dialogs.CustomMessagebox(title="Success", message=msg + "\n\nPlease log in again.")
            self.logout()
        else:
            custom_dialogs.CustomMessagebox(title="Error", message=msg)

    def create_forgot_ui(self): # Builds the forgot password screen
        self.clear_window()
        self.fp_otp_attempts = 0
        ctk.CTkLabel(self, text="Forgot Password", font=("Arial", 28, "bold")).pack(pady=(20, 10))
        self.fp_email = ctk.CTkEntry(self, placeholder_text="Email", width=400, justify="center")
        self.fp_email.pack(pady=5)
        ctk.CTkButton(self, text="Send OTP", width=200, command=self.send_fp_otp).pack(pady=5)
        self.fp_otp_entry = ctk.CTkEntry(self, placeholder_text="Enter OTP", width=400, justify="center")
        self.fp_otp_entry.pack(pady=5)
        self.new_fp_password = ctk.CTkEntry(self, placeholder_text="New Password", show="*", width=400, justify="center")
        self.new_fp_password.pack(pady=5)
        ctk.CTkButton(self, text="Reset Password", width=200, command=self.reset_fp_password).pack(pady=10)
        ctk.CTkButton(self, text="Back to Login", width=200, command=self.create_login_ui).pack(pady=5)

    def create_vault_ui(self): # Builds the main vault screen after login
        self.clear_window()
        self.reset_inactivity_timer()
        bottom_frame = ctk.CTkFrame(self)
        bottom_frame.pack(side="bottom", fill="x", padx=10, pady=10)
        delete_button = ctk.CTkButton(bottom_frame, text="Delete Account", command=self.create_delete_account_window, fg_color="#c23b22", hover_color="#a8321e")
        delete_button.pack(side="right", padx=10, pady=5)
        top_frame = ctk.CTkFrame(self, fg_color="transparent")
        top_frame.pack(side="top", fill="x", padx=20, pady=(20, 0))
        ctk.CTkLabel(top_frame, text=f"Welcome, {self.current_user}!", font=("Arial", 20, "bold")).pack()
        button_scroll_frame = ctk.CTkScrollableFrame(self, fg_color="transparent")
        button_scroll_frame.pack(pady=10, padx=20, fill="both", expand=True)
        button_map = [
            ("Upload File to Encrypt", self.upload_file),
            ("List Files", self.create_list_view_window),
            ("Delete Encrypted Files", self.create_delete_window),
            ("Retrieve File", self.create_retrieve_window),
            ("Backup Vault", self.gui_backup),
            ("Restore Vault", self.gui_restore),
            ("Change Password", self.create_change_password_window),
            ("View Activity Log", self.create_log_view_window),
            ("Logout", self.logout),
        ]
        for label, cmd in button_map:
            ctk.CTkButton(button_scroll_frame, text=label, width=300, height=40, command=cmd).pack(pady=10, padx=20)

    def login(self): # Handles the user login process
        if self.captcha_entry.get() != self.captcha:
            return custom_dialogs.CustomMessagebox(title="Error", message="Invalid Captcha")
        user = self.username_entry.get().strip()
        pwd = self.password_entry.get()
        ok, msg = auth.verify_user(user, pwd)
        if not ok:
            return custom_dialogs.CustomMessagebox(title="Error", message=msg)
        secret = auth.get_user_mfa_secret(user)
        if not secret:
            return custom_dialogs.CustomMessagebox(title="Error", message="MFA not set up for this user.")
        pad = (8 - len(secret) % 8) % 8
        totp = pyotp.TOTP(secret + "=" * pad)
        code_dialog = custom_dialogs.CustomAskString(title="MFA Required", prompt="Enter your 6-digit MFA code:")
        code = code_dialog.get_result()
        if not code or not totp.verify(code):
            return custom_dialogs.CustomMessagebox(title="Error", message="Invalid MFA code.")
        self.current_user = user
        auth.log_event(self.current_user, "login")
        custom_dialogs.CustomMessagebox(title="Success", message="Login successful")
        self.create_vault_ui()
    
    def signup(self): # Handles the user registration process
        otp = self.otp_entry.get().strip()
        if not self.generated_otp or otp != self.generated_otp:
            self.signup_otp_attempts += 1
            if self.signup_otp_attempts > 2:
                custom_dialogs.CustomMessagebox(title="Error", message="Too many invalid OTP attempts. Returning to login screen for security.")
                self.create_login_ui()
                return
            return custom_dialogs.CustomMessagebox(title="Error", message="Invalid OTP. Please try again or request a new one.")
        self.generated_otp = None
        self.signup_otp_attempts = 0
        user = self.new_username.get().strip()
        pwd = self.new_password.get()
        email = self.email.get().strip()
        ok, msg = auth.validate_password(pwd)
        if not ok: return custom_dialogs.CustomMessagebox(title="Error", message=msg)
        success, msg = auth.create_user(user, email, pwd)
        if not success: return custom_dialogs.CustomMessagebox(title="Error", message=msg)
        self.clear_window()
        ctk.CTkLabel(self, text="Registration Successful!", font=("Arial", 24, "bold")).pack(pady=20)
        ctk.CTkLabel(self, text="Final Step: Please set up your authenticator app.", font=("Arial", 14)).pack(pady=10)
        secret = auth.generate_mfa_secret(user)
        self._show_mfa_qr_window(user, secret)

    def _show_mfa_qr_window(self, username, secret): # Displays the MFA QR code for setup
        mfa_window = ctk.CTkToplevel(self)
        mfa_window.title("MFA Setup Required")
        mfa_window.geometry("350x450")
        mfa_window.transient(self); mfa_window.grab_set()
        ctk.CTkLabel(mfa_window, text="Scan QR Code", font=("Arial", 20, "bold")).pack(pady=10)
        ctk.CTkLabel(mfa_window, text="Scan with your authenticator app\n(e.g., Google Authenticator) to continue.", wraplength=330).pack(pady=5)
        uri = pyotp.TOTP(secret).provisioning_uri(name=username, issuer_name="SecureDigitalVault")
        qr_img = qrcode.make(uri)
        qr_image_pil = qr_img.convert("RGB")
        qr_image_ctk = ctk.CTkImage(light_image=qr_image_pil, dark_image=qr_image_pil, size=(250, 250))
        qr_label = ctk.CTkLabel(mfa_window, image=qr_image_ctk, text="")
        qr_label.pack(pady=10)
        def close_and_return_to_login():
            mfa_window.destroy()
            custom_dialogs.CustomMessagebox(title="Success", message="Account created! Please log in to continue.")
            self.create_login_ui()
        ctk.CTkButton(mfa_window, text="Done", command=close_and_return_to_login).pack(pady=10)
        auth.log_event(username, "signup", "Account created & MFA configured")
        
    def send_fp_otp(self): # Handles sending the OTP for password reset
        email = self.fp_email.get().strip()
        if not auth.is_valid_email(email):
            return custom_dialogs.CustomMessagebox(title="Error", message="Enter a valid email from: " + ", ".join(sorted(auth.ALLOWED_DOMAINS)))
        if not auth.user_exists(email):
            return custom_dialogs.CustomMessagebox(title="Error", message="No user registered with this email.")
        self.fp_generated_otp = otp_handler.generate_otp()
        otp_handler.send_otp(email, self.fp_generated_otp)
        custom_dialogs.CustomMessagebox(title="OTP Sent", message=f"OTP sent to {email}")

    def reset_fp_password(self): # Handles the password reset process
        email = self.fp_email.get().strip()
        otp = self.fp_otp_entry.get().strip()

        if otp != self.fp_generated_otp:
            self.fp_otp_attempts += 1
            if self.fp_otp_attempts > 2:
                custom_dialogs.CustomMessagebox(title="Error", message="Too many invalid OTP attempts. Returning to login screen.")
                self.create_login_ui()
                return
            return custom_dialogs.CustomMessagebox(title="Error", message="Invalid OTP")

        new_pwd = self.new_fp_password.get()
        ok, msg = auth.validate_password(new_pwd)
        if not ok:
            return custom_dialogs.CustomMessagebox(title="Error", message=msg)

        auth.update_password(email, new_pwd)
        
        username = auth.get_username_by_email(email)
        success_message = f"Password reset successfully for username: {username}\n\nPlease log in."
        
        custom_dialogs.CustomMessagebox(title="Success", message=success_message)
        self.create_login_ui()
    
    def logout(self): # Logs the user out
        if hasattr(self, 'inactivity_timer_id') and self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
        self.current_user = None
        self.inactivity_timer_id = None
        self.create_login_ui()

    def create_change_password_window(self): # Builds the change password dialog
        self.cp_dialog = ctk.CTkToplevel(self)
        self.cp_dialog.title("Change Password")
        self.cp_dialog.geometry("450x350")
        self.cp_dialog.transient(self); self.cp_dialog.grab_set()
        ctk.CTkLabel(self.cp_dialog, text="Change Your Password", font=("Arial", 18, "bold")).pack(pady=10)
        ctk.CTkLabel(self.cp_dialog, text="Current Password").pack(anchor="w", padx=20)
        self.cp_current_pass_entry = ctk.CTkEntry(self.cp_dialog, placeholder_text="Enter your current password", show="*", width=400)
        self.cp_current_pass_entry.pack()
        ctk.CTkLabel(self.cp_dialog, text="New Password").pack(anchor="w", padx=20, pady=(10, 0))
        self.cp_new_pass_entry = ctk.CTkEntry(self.cp_dialog, placeholder_text="Enter new password", show="*", width=400)
        self.cp_new_pass_entry.bind("<KeyRelease>", self._update_change_password_strength)
        self.cp_new_pass_entry.pack()
        self.cp_strength_label = ctk.CTkLabel(self.cp_dialog, text="", font=("Arial", 12))
        self.cp_strength_label.pack(anchor="w", padx=20, pady=(0, 10))
        ctk.CTkLabel(self.cp_dialog, text="Confirm New Password").pack(anchor="w", padx=20)
        self.cp_confirm_pass_entry = ctk.CTkEntry(self.cp_dialog, placeholder_text="Confirm new password", show="*", width=400)
        self.cp_confirm_pass_entry.bind("<KeyRelease>", self._update_change_password_strength)
        self.cp_confirm_pass_entry.pack()
        self.cp_change_button = ctk.CTkButton(self.cp_dialog, text="Change Password", command=self.execute_password_change)
        self.cp_change_button.pack(pady=20)
        self.cp_change_button.configure(state="disabled")

    def upload_file(self): # Handles the entire file upload process
        file_path = filedialog.askopenfilename(title="Select file to encrypt")
        if not file_path: return
        filename = os.path.basename(file_path)
        if '.' not in filename or filename.startswith('.'):
            return custom_dialogs.CustomMessagebox(title="Error", message="Invalid filename.")
        size = os.path.getsize(file_path)
        if size > MAX_FILE_SIZE:
            return custom_dialogs.CustomMessagebox(title="Error", message="File size cannot exceed 5 MB.")
        if auth.file_exists(self.current_user, filename):
            dialog = custom_dialogs.CustomAskOverwrite(title="Duplicate File", message=f"'{filename}' already exists. What would you like to do?")
            choice = dialog.get_result()
            if choice == "overwrite":
                auth.delete_file_record_by_name(self.current_user, filename)
                auth.log_event(self.current_user, "overwrite", f"Overwrote file: {filename}")
            elif choice == "copy":
                filename = self.get_new_filename(filename)
            else:
                return
        passphrase_dialog = custom_dialogs.CustomAskString("Encrypt while uploading", "Enter passphrase to encrypt:", show="*")
        passphrase = passphrase_dialog.get_result()
        if not passphrase:
            return custom_dialogs.CustomMessagebox(title="Error", message="Passphrase is required.")
        self._run_upload_with_progress(file_path, filename, passphrase, size)

    def _run_upload_with_progress(self, file_path, filename, passphrase, size): # Runs upload in a background thread
        progress_dialog = ctk.CTkToplevel(self)
        progress_dialog.title("Uploading...")
        progress_dialog.geometry("300x100")
        progress_dialog.transient(self); progress_dialog.grab_set()
        ctk.CTkLabel(progress_dialog, text=f"Encrypting {os.path.basename(filename)}...").pack(pady=10)
        progress_bar = ctk.CTkProgressBar(progress_dialog, width=280)
        progress_bar.pack(pady=10)
        progress_bar.set(0)
        def safe_ui_update(success, message):
            if progress_dialog.winfo_exists():
                progress_dialog.destroy()
                if success:
                    custom_dialogs.CustomMessagebox(title="Success", message=message)
                else:
                    custom_dialogs.CustomMessagebox(title="Error", message=message)
        def worker_thread():
            try:
                dest_path = os.path.join(UPLOAD_FOLDER, filename)
                shutil.copy(file_path, dest_path)
                if progress_dialog.winfo_exists():
                    self.after(0, lambda: progress_bar.set(0.5) if progress_bar.winfo_exists() else None)
                enc_path, salt = encryptor.encrypt_file(dest_path, passphrase)
                os.remove(dest_path)
                with self.db_lock:
                    conn = sqlite3.connect('vault.db', timeout=10)
                    cur = conn.cursor()
                    user_id = auth.get_user_id(self.current_user)
                    if user_id:
                        cur.execute(
                            "INSERT INTO files (user_id, filename, path, salt, size_kb, date_added) VALUES (?, ?, ?, ?, ?, ?)",
                            (user_id, filename, enc_path, salt.hex(), size / 1024.0, datetime.now().strftime("%Y-%m-%d %H:%M"))
                        )
                        auth.log_event_with_cursor(cur, self.current_user, "upload", filename)
                    conn.commit()
                    conn.close()
                self.after(0, lambda: safe_ui_update(True, "File uploaded successfully!"))
            except Exception as e:
                self.after(0, lambda: safe_ui_update(False, f"Upload failed: {e}"))
        threading.Thread(target=worker_thread, daemon=True).start()
    
    def create_log_view_window(self): # Creates the activity log window
        logs = auth.get_audit_logs(self.current_user)
        if not logs:
            return custom_dialogs.CustomMessagebox(title="Activity Log", message="No activity has been recorded for your account yet.")

        log_window = ctk.CTkToplevel(self)
        log_window.title("Account Activity Log")
        log_window.geometry("900x600")
        log_window.transient(self); log_window.grab_set()

        ctk.CTkLabel(log_window, text="Your Recent Account Activity", font=("Arial", 16, "bold")).pack(pady=10)
        
        scrollable_frame = ctk.CTkScrollableFrame(log_window)
        scrollable_frame.pack(expand=True, fill="both", padx=10, pady=10)
        
        scrollable_frame.grid_columnconfigure(0, weight=1, uniform="group1")
        scrollable_frame.grid_columnconfigure(1, weight=2, uniform="group1")
        scrollable_frame.grid_columnconfigure(2, weight=1, uniform="group1")

        header_font = ("Arial", 12, "bold")
        headers = ["Action", "Details", "Timestamp"]
        for i, header_text in enumerate(headers):
            ctk.CTkLabel(scrollable_frame, text=header_text, font=header_font, fg_color="#333333").grid(row=0, column=i, sticky="ew", padx=1, pady=1)

        for i, log_entry in enumerate(logs):
            action, details, timestamp = log_entry
            ctk.CTkLabel(scrollable_frame, text=action, anchor="w").grid(row=i + 1, column=0, sticky="ew", padx=5)
            details_label = ctk.CTkLabel(scrollable_frame, text=details, anchor="w", justify="left", wraplength=400)
            details_label.grid(row=i + 1, column=1, sticky="ew", padx=5)
            ctk.CTkLabel(scrollable_frame, text=timestamp, anchor="w").grid(row=i + 1, column=2, sticky="ew", padx=5)

    def create_list_view_window(self): # Creates the file list window with search
        files = auth.get_user_files(self.current_user)
        if not files:
            return custom_dialogs.CustomMessagebox(title="Files", message="You have no files uploaded.")
        list_window = ctk.CTkToplevel(self)
        list_window.title("My Files")
        list_window.geometry("950x600")
        list_window.transient(self); list_window.grab_set()
        search_entry = ctk.CTkEntry(list_window, placeholder_text="Type to filter files...")
        search_entry.pack(fill="x", padx=10, pady=10)
        main_frame = ctk.CTkScrollableFrame(list_window)
        main_frame.pack(expand=True, fill="both", padx=10, pady=10)
        main_frame.grid_columnconfigure(0, weight=0, minsize=50)
        main_frame.grid_columnconfigure(1, weight=3, minsize=400)
        main_frame.grid_columnconfigure(2, weight=0, minsize=100)
        main_frame.grid_columnconfigure(3, weight=0, minsize=120)
        main_frame.grid_columnconfigure(4, weight=1, minsize=180)
        header_font = ("Arial", 12, "bold")
        headers = ["#", "Filename", "Type", "Size", "Date Added"]
        for i, header_text in enumerate(headers):
            ctk.CTkLabel(main_frame, text=header_text, font=header_font, fg_color="#333333", height=30).grid(row=0, column=i, sticky="nsew", padx=1, pady=1)
        no_results_label = ctk.CTkLabel(main_frame, text="No results found.", font=("Arial", 14), text_color="gray")
        file_widgets_data = []
        for i, file_record in enumerate(files):
            _id, filename, _, _, size_kb, date_added = file_record
            file_type = filename.split('.')[-1].upper() if '.' in filename else "N/A"
            size_str = f"{size_kb:.2f} KB" if size_kb else "N/A"
            display_name = (filename[:50] + '...') if len(filename) > 50 else filename
            num_label = ctk.CTkLabel(main_frame, text=str(i + 1), anchor="center")
            filename_label = ctk.CTkLabel(main_frame, text=display_name, anchor="w")
            type_label = ctk.CTkLabel(main_frame, text=file_type, anchor="w")
            size_label = ctk.CTkLabel(main_frame, text=size_str, anchor="w")
            date_label = ctk.CTkLabel(main_frame, text=date_added, anchor="w")
            row_widgets = [num_label, filename_label, type_label, size_label, date_label]
            file_widgets_data.append({'filename': filename.lower(), 'widgets': row_widgets})
            for col_idx, widget in enumerate(row_widgets):
                widget.grid(row=i + 1, column=col_idx, sticky="ew", padx=5, pady=2)
        def filter_files(event=None):
            search_term = search_entry.get().lower()
            visible_count = 0
            no_results_label.grid_forget()
            for data in file_widgets_data:
                if search_term in data['filename']:
                    visible_count += 1
                    data['widgets'][0].configure(text=str(visible_count))
                    for col_idx, widget in enumerate(data['widgets']):
                        widget.grid(row=visible_count, column=col_idx, sticky="ew", padx=5, pady=2)
                else:
                    for widget in data['widgets']:
                        widget.grid_forget()
            if visible_count == 0 and len(file_widgets_data) > 0:
                no_results_label.grid(row=1, column=0, columnspan=5, pady=20)
        search_entry.bind("<KeyRelease>", filter_files)
        ctk.CTkButton(list_window, text="Close", command=list_window.destroy).pack(pady=10, side="bottom")

    def create_delete_window(self): # Creates the multi-select file deletion window
        files = auth.get_user_files(self.current_user)
        if not files:
            return custom_dialogs.CustomMessagebox(title="Info", message="You have no files to delete.")
        delete_window = ctk.CTkToplevel(self)
        delete_window.title("Delete Files")
        delete_window.geometry("700x550")
        delete_window.transient(self); delete_window.grab_set()
        header_frame = ctk.CTkFrame(delete_window, fg_color="#5f1a1a")
        header_frame.pack(fill="x", padx=10, pady=10)
        ctk.CTkLabel(header_frame, text="⚠️ Select Files to Permanently Delete", font=("Arial", 16, "bold")).pack(pady=10)
        scrollable_frame = ctk.CTkScrollableFrame(delete_window)
        scrollable_frame.pack(expand=True, fill="both", padx=10, pady=5)
        file_entries = []
        for file_record in files:
            file_id, filename, path, *_ = file_record
            cb = ctk.CTkCheckBox(scrollable_frame, text=filename)
            cb.pack(anchor="w", padx=10, pady=5)
            file_entries.append({'id': file_id, 'path': path, 'checkbox': cb, 'filename': filename})
        action_frame = ctk.CTkFrame(delete_window, fg_color="transparent")
        action_frame.pack(fill="x", padx=10, pady=10)
        def update_delete_button_state():
            is_any_selected = any(entry['checkbox'].get() for entry in file_entries)
            delete_button.configure(state="normal" if is_any_selected else "disabled")
        for entry in file_entries:
            entry['checkbox'].configure(command=update_delete_button_state)
        def select_all():
            for entry in file_entries: entry['checkbox'].select()
            update_delete_button_state()
        def deselect_all():
            for entry in file_entries: entry['checkbox'].deselect()
            update_delete_button_state()
        ctk.CTkButton(action_frame, text="Select All", command=select_all).pack(side="left", padx=5)
        ctk.CTkButton(action_frame, text="Deselect All", command=deselect_all).pack(side="left", padx=5)
        def execute_delete():
            selected_files = [e for e in file_entries if e['checkbox'].get()]
            if not selected_files: return
            dialog = custom_dialogs.CustomAskYesNo("Confirm Deletion", f"Are you sure you want to permanently delete the {len(selected_files)} selected file(s)?\n\nThis action cannot be undone.")
            if not dialog.get_result(): return
            delete_button.configure(state="disabled")
            def deletion_thread():
                with self.db_lock:
                    conn = sqlite3.connect('vault.db', timeout=10)
                    cur = conn.cursor()
                    deleted_count = 0
                    for file_to_delete in selected_files:
                        try:
                            if os.path.exists(file_to_delete['path']):
                                os.remove(file_to_delete['path'])
                            cur.execute("DELETE FROM files WHERE id = ?", (file_to_delete['id'],))
                            auth.log_event_with_cursor(cur, self.current_user, "delete", f"Deleted: {file_to_delete['filename']}")
                            deleted_count += 1
                        except Exception as e:
                            auth.log_event_with_cursor(cur, self.current_user, "delete_error", f"Failed to delete {file_to_delete['filename']}: {e}")
                    conn.commit()
                    conn.close()
                self.after(0, delete_window.destroy)
                self.after(1, lambda: custom_dialogs.CustomMessagebox(title="Success", message=f"Successfully deleted {deleted_count} file(s)."))
            threading.Thread(target=deletion_thread, daemon=True).start()
        delete_button = ctk.CTkButton(delete_window, text="Delete Selected Files", command=execute_delete, fg_color="#c23b22", hover_color="#a8321e")
        delete_button.pack(pady=10, padx=10, fill="x")
        delete_button.configure(state="disabled")

    def create_retrieve_window(self): # Creates the file retrieval window
        files = auth.get_user_files(self.current_user)
        if not files:
            return custom_dialogs.CustomMessagebox(title="Info", message="You have no files to retrieve.")
        retrieve_window = ctk.CTkToplevel(self)
        retrieve_window.title("Retrieve Encrypted File")
        retrieve_window.geometry("800x600")
        retrieve_window.transient(self); retrieve_window.grab_set()
        search_entry = ctk.CTkEntry(retrieve_window, placeholder_text="Type to filter files...")
        search_entry.pack(fill="x", padx=10, pady=10)
        scrollable_frame = ctk.CTkScrollableFrame(retrieve_window)
        scrollable_frame.pack(expand=True, fill="both", padx=10, pady=10)
        selected_file_var = ctk.StringVar(value="")
        file_data_map = {}
        row_widgets = []
        for file_record in files:
            file_id, filename, enc_path, salt, size_kb, _ = file_record
            file_data_map[str(file_id)] = {'path': enc_path, 'salt': salt, 'filename': filename}
            row_frame = ctk.CTkFrame(scrollable_frame)
            ctk.CTkRadioButton(row_frame, text=filename, variable=selected_file_var, value=str(file_id)).pack(side="left", padx=10, pady=5, expand=True, fill="x")
            row_widgets.append({'frame': row_frame, 'filename': filename.lower()})
        def filter_files(event=None):
            search_term = search_entry.get().lower()
            for widget_info in row_widgets:
                if search_term in widget_info['filename']:
                    widget_info['frame'].pack(fill="x", padx=10, pady=5)
                else:
                    widget_info['frame'].pack_forget()
        search_entry.bind("<KeyRelease>", filter_files)
        filter_files()
        def on_selection_change(*args):
            retrieve_button.configure(state="normal" if selected_file_var.get() else "disabled")
        selected_file_var.trace_add("write", on_selection_change)
        retrieve_button = ctk.CTkButton(retrieve_window, text="Retrieve Selected File", command=lambda: self.retrieve_file_action(file_data_map.get(selected_file_var.get()), retrieve_window))
        retrieve_button.pack(pady=10, padx=10, fill="x")
        retrieve_button.configure(state="disabled")

    def retrieve_file_action(self, file_info, parent_window): # Handles decrypting and saving a selected file
        if not file_info: return
        passphrase_dialog = custom_dialogs.CustomAskString("Decrypt Passphrase", "Enter the passphrase for this file:", show="*")
        passphrase = passphrase_dialog.get_result()
        if not passphrase: return
        try:
            salt_as_bytes = bytes.fromhex(file_info['salt'])
            decrypted_bytes = encryptor.decrypt_file_in_memory(file_info['path'], salt_as_bytes, passphrase)
        except Exception as e:
            print(f"DEBUG: Decryption failed. Error: {e}")
            return custom_dialogs.CustomMessagebox("Decryption Failed", "Could not decrypt the file.\nCheck passphrase and file integrity.")
        save_to_path = filedialog.asksaveasfilename(initialfile=file_info['filename'], parent=parent_window)
        if not save_to_path: return
        try:
            with open(save_to_path, 'wb') as f:
                f.write(decrypted_bytes)
            auth.log_event(self.current_user, "retrieve", file_info['filename'])
            parent_window.destroy()
            self.show_success_with_open_option(f"File successfully saved to:\n{save_to_path}", save_to_path)
        except Exception as e:
            custom_dialogs.CustomMessagebox("Error", f"Could not save file: {e}")
    
    def open_admin_login(self): # Opens the admin login dialog
        admin_dialog = ctk.CTkToplevel(self)
        admin_dialog.title("Admin Login")
        admin_dialog.geometry("400x200")
        admin_dialog.transient(self); admin_dialog.grab_set()
        ctk.CTkLabel(admin_dialog, text="Enter Admin Credentials").pack(pady=10)
        user_entry = ctk.CTkEntry(admin_dialog, placeholder_text="Admin Username", width=300)
        user_entry.pack(pady=5)
        pass_entry = ctk.CTkEntry(admin_dialog, placeholder_text="Admin Password", show="*", width=300)
        pass_entry.pack(pady=5)
        def attempt_login():
            username = user_entry.get()
            password = pass_entry.get()
            is_valid, _ = auth.verify_user(username, password)
            if is_valid and auth.is_admin(username):
                admin_dialog.destroy()
                self.create_admin_panel()
            else:
                custom_dialogs.CustomMessagebox(title="Error", message="Invalid credentials or not an admin account.")
        ctk.CTkButton(admin_dialog, text="Login", command=attempt_login).pack(pady=10)

    def create_admin_panel(self): # Creates the main admin panel
        admin_panel = ctk.CTkToplevel(self)
        admin_panel.title("Administrator Panel")
        admin_panel.geometry("500x300")
        admin_panel.transient(self); admin_panel.grab_set()
        ctk.CTkLabel(admin_panel, text="Factory Reset", font=("Arial", 18, "bold")).pack(pady=10)
        warning_text = "This will permanently delete ALL users, ALL encrypted files, and the entire database."
        ctk.CTkLabel(admin_panel, text=warning_text, wraplength=480, text_color="#f29d9d").pack(pady=10, padx=10)
        ctk.CTkButton(admin_panel, text="Perform Factory Reset", command=self.execute_factory_reset, fg_color="#c23b22", hover_color="#a8321e").pack(pady=20)

    def create_delete_account_window(self): # Creates the multi-step account deletion window
        confirm_dialog = ctk.CTkToplevel(self)
        confirm_dialog.title("Confirm Account Deletion")
        confirm_dialog.geometry("450x250")
        confirm_dialog.transient(self); confirm_dialog.grab_set()
        warning_text = "WARNING:\nThis will permanently delete your account, all your encrypted files, and all audit logs. Your existing backups will become unusable.\n\nThis action cannot be undone."
        ctk.CTkLabel(confirm_dialog, text=warning_text, wraplength=430, justify="center", text_color="#f29d9d").pack(pady=10, padx=10)
        prompt_text = f"To proceed, please type your username ({self.current_user}) below:"
        ctk.CTkLabel(confirm_dialog, text=prompt_text).pack(pady=5)
        confirm_entry = ctk.CTkEntry(confirm_dialog, width=300)
        confirm_entry.pack(pady=5)
        def check_confirmation(*args):
            next_button.configure(state="normal" if confirm_entry.get() == self.current_user else "disabled")
        confirm_entry.bind("<KeyRelease>", check_confirmation)
        def open_final_verification():
            confirm_dialog.destroy()
            self.execute_account_deletion()
        next_button = ctk.CTkButton(confirm_dialog, text="Next", command=open_final_verification, state="disabled")
        next_button.pack(pady=10)
        
    def execute_account_deletion(self): # Handles the final account deletion logic
        verify_dialog = ctk.CTkToplevel(self)
        verify_dialog.title("Final Verification")
        verify_dialog.geometry("400x250")
        verify_dialog.transient(self); verify_dialog.grab_set()
        ctk.CTkLabel(verify_dialog, text="Enter your password and MFA code to permanently delete your account.", wraplength=380).pack(pady=10, padx=10)
        password_entry = ctk.CTkEntry(verify_dialog, placeholder_text="Enter Password", show="*", width=300)
        password_entry.pack(pady=10)
        mfa_entry = ctk.CTkEntry(verify_dialog, placeholder_text="Enter 6-digit MFA Code", width=300)
        mfa_entry.pack(pady=10)
        def on_final_delete():
            password = password_entry.get()
            mfa_code = mfa_entry.get()
            if not password or not mfa_code:
                return custom_dialogs.CustomMessagebox(title="Error", message="Password and MFA code are required.")
            delete_button.configure(state="disabled")
            def worker():
                with self.db_lock:
                    success, msg = auth.delete_user_account(self.current_user, password, mfa_code)
                def final_ui_update():
                    if verify_dialog.winfo_exists():
                        verify_dialog.destroy()
                    if success:
                        custom_dialogs.CustomMessagebox(title="Success", message="Your account has been permanently deleted.")
                        self.logout()
                    else:
                        custom_dialogs.CustomMessagebox(title="Error", message=f"Deletion failed: {msg}")
                self.after(0, final_ui_update)
            threading.Thread(target=worker, daemon=True).start()
        delete_button = ctk.CTkButton(verify_dialog, text="Permanently Delete Account", command=on_final_delete, fg_color="#c23b22", hover_color="#a8321e")
        delete_button.pack(pady=10)

    def execute_factory_reset(self):
        confirm_dialog = custom_dialogs.CustomAskResetConfirmation(
            title="Final Confirmation",
            warning_text="This will erase EVERYTHING: all users, all files, and the database.",
            prompt="To confirm, type 'RESET ALL DATA' in the box below."
        )
        if confirm_dialog.get_result() == "RESET ALL DATA":
            try:
                with self.db_lock:
                    if os.path.exists(config.DB_PATH):
                        os.remove(config.DB_PATH)
                    if os.path.exists(config.UPLOAD_FOLDER):
                        shutil.rmtree(config.UPLOAD_FOLDER)
                    if os.path.exists('__pycache__'):
                        shutil.rmtree('__pycache__')
                custom_dialogs.CustomMessagebox(title="Success", message="Factory reset complete. The application will now close.")
                sys.exit(0)
            except Exception as e:
                custom_dialogs.CustomMessagebox(title="Error", message=f"An error occurred during reset: {e}")
        else:
            custom_dialogs.CustomMessagebox(title="Cancelled", message="Reset was not confirmed and has been cancelled.")
            
    def gui_backup(self): # Handles the backup process
        passphrase_dialog = custom_dialogs.CustomAskString("Set Backup Password", "Enter a strong password to encrypt the backup file:", show="*")
        backup_passphrase = passphrase_dialog.get_result()
        if not backup_passphrase:
            return custom_dialogs.CustomMessagebox("Cancelled", "Backup requires a password.")
        save_dir = filedialog.askdirectory(title="Select a folder to save the backup file", parent=self)
        if not save_dir: return
        progress_dialog = ctk.CTkToplevel(self)
        progress_dialog.title("Backup in Progress")
        progress_dialog.geometry("300x100")
        progress_dialog.transient(self); progress_dialog.grab_set()
        ctk.CTkLabel(progress_dialog, text="Creating secure backup...").pack(pady=20)
        def worker():
            try:
                with self.db_lock:
                    backup_path = backup_handler.create_backup(self.current_user, backup_passphrase, save_dir)
                auth.log_event(self.current_user, "backup_success", os.path.basename(backup_path))
                self.after(0, progress_dialog.destroy)
                self.after(1, lambda: custom_dialogs.CustomMessagebox("Success", f"Backup created successfully!\n\nSaved to:\n{backup_path}"))
            except Exception as e:
                auth.log_event(self.current_user, "backup_failed", str(e))
                self.after(0, progress_dialog.destroy)
                self.after(1, lambda exc=e: custom_dialogs.CustomMessagebox("Error", f"Backup failed: {exc}"))
        threading.Thread(target=worker, daemon=True).start()

    def gui_restore(self): # Handles the restore process
        backup_path = filedialog.askopenfilename(
            title="Select a Secure Vault Backup (.sbu)", 
            filetypes=[("Secure Backup Unit", "*.sbu")], 
            parent=self
        )
        if not backup_path: return
        passphrase_dialog = custom_dialogs.CustomAskString("Enter Backup Password", "Enter the password for this backup file:", show="*")
        backup_passphrase = passphrase_dialog.get_result()
        if not backup_passphrase: return
        dialog = custom_dialogs.CustomAskYesNo("Confirm Restore", "WARNING: Restoring will ERASE all files currently in your vault.\nThis action cannot be undone. Are you sure?")
        if not dialog.get_result(): return
        progress_dialog = ctk.CTkToplevel(self)
        progress_dialog.title("Restore in Progress")
        progress_dialog.geometry("300x100")
        progress_dialog.transient(self); progress_dialog.grab_set()
        ctk.CTkLabel(progress_dialog, text="Restoring from backup...").pack(pady=20)
        def worker():
            try:
                with self.db_lock:
                    success, message = backup_handler.restore_backup(self.current_user, backup_path, backup_passphrase)
                self.after(0, progress_dialog.destroy)
                if success:
                    auth.log_event(self.current_user, "restore_success")
                    self.after(1, lambda: custom_dialogs.CustomMessagebox("Success", message))
                else:
                    auth.log_event(self.current_user, "restore_failed", message)
                    self.after(1, lambda: custom_dialogs.CustomMessagebox("Error", f"Restore failed: {message}"))
            except Exception as e:
                auth.log_event(self.current_user, "restore_failed", str(e))
                self.after(0, progress_dialog.destroy)
                self.after(1, lambda exc=e: custom_dialogs.CustomMessagebox("Error", f"A critical error occurred: {exc}"))
        threading.Thread(target=worker, daemon=True).start()
    
    def auto_logout(self): # Handles auto-logout on inactivity
        if self.current_user:
            custom_dialogs.CustomMessagebox(title="Session Expired", message="You have been automatically logged out due to inactivity.")
            self.logout()
            
    def reset_inactivity_timer(self, event=None): # Resets the auto-logout timer
        if hasattr(self, 'inactivity_timer_id') and self.inactivity_timer_id:
            self.after_cancel(self.inactivity_timer_id)
        timeout_ms = INACTIVITY_TIMEOUT_MINUTES * 60 * 1000
        self.inactivity_timer_id = self.after(timeout_ms, self.auto_logout)

    def show_success_with_open_option(self, message, file_path): # Shows a success dialog with an "Open File" button
        dialog = ctk.CTkToplevel(self)
        dialog.title("Success")
        dialog.geometry("400x150")
        dialog.transient(self); dialog.grab_set()
        ctk.CTkLabel(dialog, text=message, wraplength=380, justify="center").pack(pady=20, padx=10, expand=True)
        button_frame = ctk.CTkFrame(dialog, fg_color="transparent")
        button_frame.pack(pady=10, fill="x")
        def open_action():
            try: os.startfile(file_path)
            except Exception as e: custom_dialogs.CustomMessagebox("Error", f"Could not open file: {e}")
            dialog.destroy()
        ctk.CTkButton(button_frame, text="Open File", command=open_action).pack(side="left", padx=20, expand=True)
        ctk.CTkButton(button_frame, text="Close", command=dialog.destroy).pack(side="right", padx=20, expand=True)
        
    def refresh_captcha(self): # Refreshes the captcha on the login screen
        self.captcha = captcha_handler.generate_captcha()
        self.captcha_label.configure(text=f"Captcha: {self.captcha}")

    def toggle_password_visibility(self): # Toggles password visibility on the login screen
        self.pwd_visible = not self.pwd_visible
        self.password_entry.configure(show="" if self.pwd_visible else "*")

    def toggle_signup_password_visibility(self): # Toggles password visibility on the signup screen
        self.signup_pwd_visible = not self.signup_pwd_visible
        self.new_password.configure(show="" if self.signup_pwd_visible else "*")

    def send_signup_otp(self): # Handles sending the OTP for registration
        email = self.email.get().strip()
        if not auth.is_valid_email(email):
            return custom_dialogs.CustomMessagebox(title="Error", message="Enter a valid email from: " + ", ".join(sorted(auth.ALLOWED_DOMAINS)))
        if auth.user_exists(email):
            return custom_dialogs.CustomMessagebox(title="Error", message="Email already registered")
        self.generated_otp = otp_handler.generate_otp()
        otp_handler.send_otp(email, self.generated_otp)
        custom_dialogs.CustomMessagebox(title="OTP Sent", message=f"OTP sent to {email}")
        
    def file_exists(self, filename): # Checks if a file exists for the current user
        return auth.file_exists(self.current_user, filename)

    def get_new_filename(self, filename): # Gets a new filename for a copy
        name, ext = os.path.splitext(filename)
        counter = 1
        new_filename = f"{name} ({counter}){ext}"
        while self.file_exists(new_filename):
            counter += 1
            new_filename = f"{name} ({counter}){ext}"
        return new_filename
        
    def delete_file_by_name(self, filename): # Deletes a file record by name (for overwriting)
        auth.delete_file_record_by_name(self.current_user, filename)

    def _calculate_aspect_ratio(self, original_size, max_size): # Calculates aspect ratio for image previews
        orig_w, orig_h = original_size
        max_w, max_h = max_size
        ratio = min(max_w / orig_w, max_h / orig_h)
        return (int(orig_w * ratio), int(orig_h * ratio))

    def clear_window(self): # Clears all widgets from the main window
        for w in self.winfo_children():
            # Do not destroy the background label if it exists
            if hasattr(self, 'bg_label') and w == self.bg_label:
                continue
            w.destroy()
