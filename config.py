import os
import sys

APP_NAME = "SecureVault"

def get_data_root():
    # Detects the OS and returns the standard data folder path
    if sys.platform == "win32":
        # Windows
        return os.path.join(os.getenv('APPDATA'), APP_NAME)
    elif sys.platform == "darwin":
        # macOS
        return os.path.join(os.path.expanduser('~/Library/Application Support'), APP_NAME)
    else:
        # Linux and other OSes
        return os.path.join(os.path.expanduser('~/.config'), APP_NAME)

# --- Define Final Paths ---
DATA_ROOT = get_data_root()
os.makedirs(DATA_ROOT, exist_ok=True)

DB_PATH = os.path.join(DATA_ROOT, 'vault.db')
UPLOAD_FOLDER = os.path.join(DATA_ROOT, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)