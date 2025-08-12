import customtkinter as ctk

class _BaseDialog(ctk.CTkToplevel): # Base class for all modal dialogs
    def __init__(self, title="Dialog"): # Sets up the basic dialog window properties
        super().__init__()
        self.title(title)
        self.resizable(False, False)
        self.transient()
        self.grab_set()
        self._result = None
        self.after(20, self._center_window)

    def _center_window(self): # Centers the dialog on the parent window
        try:
            self.update_idletasks()
            main_window = self.master
            main_w = main_window.winfo_width()
            main_h = main_window.winfo_height()
            main_x = main_window.winfo_x()
            main_y = main_window.winfo_y()
            dialog_w = self.winfo_width()
            dialog_h = self.winfo_height()
            x = main_x + (main_w // 2) - (dialog_w // 2)
            y = main_y + (main_h // 2) - (dialog_h // 2)
            self.geometry(f"+{x}+{y}")
        except Exception:
            pass

    def get_result(self): # Waits for and returns the user's choice
        self.wait_window()
        return self._result

class CustomMessagebox(_BaseDialog): # A simple messagebox with an OK button
    def __init__(self, title="Message", message=""): # Initializes the messagebox UI
        super().__init__(title=title)
        self.geometry("400x150")
        label = ctk.CTkLabel(self, text=message, wraplength=380, justify="center")
        label.pack(padx=20, pady=20, expand=True, fill="both")
        ok_button = ctk.CTkButton(self, text="OK", command=self.destroy, width=100)
        ok_button.pack(pady=10)
        self.wait_window()

class CustomAskYesNo(_BaseDialog): # A dialog with Yes and No buttons
    def __init__(self, title="Confirm", message="Are you sure?"): # Initializes the Yes/No dialog UI
        super().__init__(title=title)
        self.geometry("400x150")
        label = ctk.CTkLabel(self, text=message, wraplength=380, justify="center")
        label.pack(padx=20, pady=20, expand=True, fill="both")
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=10, fill="x", expand=True)
        ctk.CTkButton(button_frame, text="Yes", command=self._on_yes, width=100).pack(side="left", padx=50, expand=True)
        ctk.CTkButton(button_frame, text="No", command=self._on_no, width=100).pack(side="right", padx=50, expand=True)

    def _on_yes(self): # Sets the result to True when 'Yes' is clicked
        self._result = True
        self.destroy()

    def _on_no(self): # Sets the result to False when 'No' is clicked
        self._result = False
        self.destroy()

class CustomAskString(_BaseDialog): # A dialog that prompts for a string input
    def __init__(self, title="Input", prompt="", show=None): # Initializes the string input dialog UI
        super().__init__(title=title)
        self.geometry("400x160")
        prompt_label = ctk.CTkLabel(self, text=prompt, wraplength=380)
        prompt_label.pack(padx=20, pady=10)
        self.entry = ctk.CTkEntry(self, show=show, width=360, justify="center")
        self.entry.pack(padx=20, pady=5)
        self.entry.bind("<Return>", self._on_ok)
        self.after(50, self.entry.focus_set)
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=10, fill="x", expand=True)
        ctk.CTkButton(button_frame, text="OK", command=self._on_ok, width=100).pack(side="left", padx=50, expand=True)
        ctk.CTkButton(button_frame, text="Cancel", command=self._on_cancel, width=100).pack(side="right", padx=50, expand=True)

    def _on_ok(self, event=None): # Sets the result to the entered text
        self._result = self.entry.get()
        self.destroy()

    def _on_cancel(self): # Sets the result to None when 'Cancel' is clicked
        self._result = None
        self.destroy()

class CustomAskOverwrite(_BaseDialog): # A dialog with Overwrite, Save as Copy, and Cancel options
    def __init__(self, title="Duplicate", message="File already exists."): # Initializes the overwrite dialog UI
        super().__init__(title=title)
        self.geometry("400x160")
        self._result = "cancel"
        label = ctk.CTkLabel(self, text=message, wraplength=380, justify="center")
        label.pack(padx=20, pady=15, expand=True, fill="both")
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=10, fill="x", expand=True)
        ctk.CTkButton(button_frame, text="Overwrite", command=self._on_overwrite).pack(side="left", padx=10, expand=True)
        ctk.CTkButton(button_frame, text="Save as Copy", command=self._on_copy).pack(side="left", padx=10, expand=True)
        ctk.CTkButton(button_frame, text="Cancel", command=self._on_cancel).pack(side="left", padx=10, expand=True)

    def _on_overwrite(self): # Sets the result to 'overwrite'
        self._result = "overwrite"
        self.destroy()

    def _on_copy(self): # Sets the result to 'copy'
        self._result = "copy"
        self.destroy()

    def _on_cancel(self): # Sets the result to 'cancel'
        self._result = "cancel"
        self.destroy()

class CustomAskResetConfirmation(_BaseDialog): # A dialog for factory reset confirmation
    def __init__(self, title="Final Confirmation", warning_text="", prompt=""): # Initializes the reset confirmation dialog UI
        super().__init__(title=title)
        self.geometry("500x250")
        warning_label = ctk.CTkLabel(self, text=warning_text, wraplength=480, text_color="#E55451", font=("Arial", 14, "bold"))
        warning_label.pack(padx=20, pady=(10, 5))
        prompt_label = ctk.CTkLabel(self, text=prompt, wraplength=480)
        prompt_label.pack(padx=20, pady=5)
        self.entry = ctk.CTkEntry(self, width=360, justify="center")
        self.entry.pack(padx=20, pady=10)
        self.entry.bind("<Return>", self._on_ok)
        self.after(50, self.entry.focus_set)
        button_frame = ctk.CTkFrame(self, fg_color="transparent")
        button_frame.pack(pady=10, fill="x", expand=True)
        ok_button = ctk.CTkButton(button_frame, text="Confirm Reset", command=self._on_ok, fg_color="#c23b22", hover_color="#a8321e")
        ok_button.pack(side="left", padx=50, expand=True)
        cancel_button = ctk.CTkButton(button_frame, text="Cancel", command=self._on_cancel)
        cancel_button.pack(side="right", padx=50, expand=True)

    def _on_ok(self, event=None): # Sets the result to the entered text
        self._result = self.entry.get()
        self.destroy()

    def _on_cancel(self): # Sets the result to None
        self._result = None
        self.destroy()