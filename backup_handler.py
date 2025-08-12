import os
import sqlite3
import tarfile
import json
import tempfile
import shutil
from datetime import datetime

import auth
from auth import DatabaseConnection
import encryptor
from config import UPLOAD_FOLDER

def create_backup(username, backup_passphrase, save_directory):
    user_id = auth.get_user_id(username)
    if not user_id:
        raise ValueError(f"User '{username}' not found.")

    with DatabaseConnection() as cur:
        cur.execute("SELECT filename, path, salt, size_kb, date_added FROM files WHERE user_id = ?", (user_id,))
        records = cur.fetchall()

    if not records:
        raise ValueError("No valid files to back up (database records may be orphaned).")

    with tempfile.TemporaryDirectory() as temp_dir:
        file_records = []
        for rec in records:
            filename, path, salt, size_kb, date_added = rec
            if os.path.exists(path):
                shutil.copy(path, os.path.join(temp_dir, os.path.basename(path)))
                file_records.append({'filename': filename, 'salt': salt, 'size_kb': size_kb, 'date_added': date_added})
        
        if not file_records:
            raise ValueError("No valid files found to back up.")
        
        manifest = {"owner_username": username, "owner_id": user_id, "files": file_records}
        with open(os.path.join(temp_dir, 'manifest.json'), 'w') as f:
            json.dump(manifest, f)

        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        archive_name = f"vault_backup_{username}_{timestamp}.tar"
        archive_path = os.path.join(temp_dir, archive_name)
        with tarfile.open(archive_path, "w") as tar:
            tar.add(temp_dir, arcname="backup_content")
        
        salt = os.urandom(16)
        key = encryptor.generate_key(backup_passphrase, salt)
        f = encryptor.Fernet(key)
        with open(archive_path, 'rb') as f_in:
            tar_data = f_in.read()
        encrypted_tar_data = f.encrypt(tar_data)
        backup_filename = f"vault_backup_{username}_{timestamp}.sbu"
        final_backup_path = os.path.join(save_directory, backup_filename)
        with open(final_backup_path, 'wb') as f_out:
            f_out.write(salt)
            f_out.write(encrypted_tar_data)
    return final_backup_path

def restore_backup(username, backup_path, backup_passphrase):
    try:
        current_user_id = auth.get_user_id(username)
        if not current_user_id:
            return (False, f"User '{username}' not found.")
            
        with open(backup_path, 'rb') as f:
            salt = f.read(16)
            encrypted_tar_data = f.read()
        key = encryptor.generate_key(backup_passphrase, salt)
        f = encryptor.Fernet(key)
        try:
            decrypted_tar_data = f.decrypt(encrypted_tar_data)
        except Exception:
            return (False, "Invalid backup password or corrupted file.")
        with tempfile.TemporaryDirectory() as temp_dir:
            decrypted_tar_path = os.path.join(temp_dir, "decrypted_backup.tar")
            with open(decrypted_tar_path, 'wb') as f_out:
                f_out.write(decrypted_tar_data)
            with tarfile.open(decrypted_tar_path) as tar:
                tar.extractall(path=temp_dir)
            extracted_dirs = [d for d in os.listdir(temp_dir) if os.path.isdir(os.path.join(temp_dir, d))]
            if not extracted_dirs or "backup_content" not in extracted_dirs:
                return (False, "Backup archive is invalid.")
            backup_content_path = os.path.join(temp_dir, "backup_content")
            manifest_path = os.path.join(backup_content_path, 'manifest.json')
            with open(manifest_path, 'r') as f:
                manifest = json.load(f)
            if manifest.get("owner_id") != current_user_id:
                return (False, "This backup belongs to a different user account.")
            with DatabaseConnection(commit=True) as cur:
                cur.execute("SELECT path FROM files WHERE user_id = ?", (current_user_id,))
                for row in cur.fetchall():
                    if os.path.exists(row[0]): os.remove(row[0])
                cur.execute("DELETE FROM files WHERE user_id = ?", (current_user_id,))
                for item in manifest["files"]:
                    original_filename = item['filename']
                    encrypted_filename = f"{original_filename}.enc"
                    src_path = os.path.join(backup_content_path, encrypted_filename)
                    dest_path = os.path.join(UPLOAD_FOLDER, encrypted_filename)
                    shutil.copy(src_path, dest_path)
                    cur.execute(
                        "INSERT INTO files (user_id, filename, path, salt, size_kb, date_added) VALUES (?, ?, ?, ?, ?, ?)",
                        (current_user_id, original_filename, dest_path, item['salt'], item['size_kb'], item['date_added'])
                    )
            return (True, "Vault restored successfully!")
    except Exception as e:
        return (False, f"A critical error occurred: {e}")