# Secure Vault - Desktop Application

A secure, multi-user desktop application for encrypting and managing local files. Built with Python and CustomTkinter.

## Features

- **Secure User Authentication:** User registration with email OTP, login protected by CAPTCHA and mandatory Two-Factor Authentication (MFA).
- **Encrypted File Storage:** Strong Fernet encryption for individual files using user-provided passphrases.
- **Full Vault Functionality:** A modern UI for uploading, listing (with search), retrieving (with file preview), deleting files, and changing passwords.
- **Data Safety:** Secure, user-specific Backup and Restore feature.
- **Administration:** Admin panel for the first registered user to perform a full Factory Reset.
- **Security Polish:** Secure account deletion, user-specific activity log viewer, and auto-logout on inactivity.

---

## How to Run from Source Code (for Developers)

### 1. Prerequisites

- **Python 3.11+:** Must be installed from **[python.org](https://www.python.org/downloads/)**. The Microsoft Store version will cause build errors. During installation, make sure to check **"Add python.exe to PATH"**.
- **Git:** Must be installed on your system.

### 2. Clone the Repository in a directory, ex: C:/ or D:/ (Preferred to use Vs Code IDE)

    git clone https://github.com/MonishV0017/secure-vault.git
    cd secure-vault

### 3. Set Up the Environment

    # Create and activate a virtual environment
    python -m venv venv
    .\venv\Scripts\Activate.ps1

    # Install all required libraries
    python -m pip install -r requirements.txt

### 4. Update the `otp_handler.py` File

This project requires to update this file file in the root directory to handle sending OTP emails. This email account also acts as the admin for the Factory Reset feature. In this file, Update your credentials.

**Important:** For Gmail, you must use a **Google App Password** in manage app passwords in the google account you want to setup as admin email, not your regular password.

    EMAIL_ADDRESS='your-email@gmail.com'
    EMAIL_PASSWORD='your-16-character-google-app-password'

### 5. Run the Application

    python main.py

---

## How to Build the Standalone Application (.exe)

After following the setup steps above, you can package the application into a standalone executable.

### 1. Build the Executable

Make sure your `venv` is active, then run the following single, direct command. This will build the application and automatically create the necessary spec file.

    python -m PyInstaller --noconsole --name SecureVault --add-data "user_guide.txt;." --add-data "disclaimer.txt;." --noupx main.py

### 2. Find the Application

The finished application will be located in the **`dist/SecureVault`** folder. The issuer can zip this SecureVault folder and move it to other directory to use in same laptop for many users to create and use thier own account in the same GUI.

NOTE: The main admin is the email that sends otp to all end users for account creation and for factory reset, that we had setup in otp_handler.py file. Make sure the distributor/developer of .exe must setup the admin email before sharing it to end user.

---

## Troubleshooting

If you encounter errors when building the `.exe`, the cause is almost always one of the following:

- **Python from Microsoft Store:** The build will fail. You must uninstall it and use the version from **python.org**. Also Recommended turn off App execution aliases for App installer (python.exe and python3.exe) in Settings.
- **Project in a Cloud-Synced Folder:** Building from a OneDrive, Dropbox, or Google Drive folder can cause errors. Move the project to a simple local path like `C:\Projects\` and rebuild.
- **Antivirus:** Your antivirus software may flag the newly created `.exe` file. If this happens, you may need to temporarily disable your antivirus for the build or add an exception for your project folder.
