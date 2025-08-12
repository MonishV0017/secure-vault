import os

APP_NAME = "SecureVault"
APPDATA_PATH = os.path.join(os.getenv('APPDATA'), APP_NAME)
os.makedirs(APPDATA_PATH, exist_ok=True)

DB_PATH = os.path.join(APPDATA_PATH, 'vault.db')
UPLOAD_FOLDER = os.path.join(APPDATA_PATH, 'uploads')
os.makedirs(UPLOAD_FOLDER, exist_ok=True)