from database import setup_db
from gui import VaultApp
import customtkinter as ctk

DEV_MODE_AUTO_LOGIN = True
DEV_TEST_USERNAME = "a"

setup_db()

if __name__ == "__main__":
    ctk.set_appearance_mode("dark")
    ctk.set_default_color_theme("blue")
    
    app = VaultApp(
        dev_mode=DEV_MODE_AUTO_LOGIN, 
        dev_user=DEV_TEST_USERNAME
    )
    app.mainloop()
