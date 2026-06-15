import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from .widgets.password_entry import PasswordEntry
from core.config import ConfigManager
from core.crypto.authentication import AuthenticationService

class SetupWizard(tk.Toplevel):
    """
    Мастер первоначальной настройки.
    Требование: GUI-3
    """
    def __init__(self, parent, config: ConfigManager):
        super().__init__(parent)
        self.config = config
        self.title("Начальная настройка CryptoSafe")
        self.geometry("400x300")
        self.resizable(False, False)
        
        self.db_path_var = tk.StringVar(value=config.db_path)
        
        self.db_path = None
        self.password = None
        self.completed = False
        
        self.create_widgets()
        
        self.transient(parent)
        self.grab_set()

    def create_widgets(self):
        """Создает widgets."""
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Вкладка 1: База данных
        tab_db = ttk.Frame(notebook, padding=10)
        notebook.add(tab_db, text="База данных")
        
        ttk.Label(tab_db, text="Расположение файла БД:").pack(anchor=tk.W)
        ttk.Entry(tab_db, textvariable=self.db_path_var).pack(fill=tk.X, pady=5)
        ttk.Button(tab_db, text="Обзор...", command=self.browse_db).pack(anchor=tk.W)
        
        # Вкладка 2: Мастер-пароль
        tab_pass = ttk.Frame(notebook, padding=10)
        notebook.add(tab_pass, text="Безопасность")
        
        ttk.Label(tab_pass, text="Создайте мастер-пароль:").pack(anchor=tk.W, pady=(0, 5))
        self.pass_entry = PasswordEntry(tab_pass)
        self.pass_entry.pack(fill=tk.X, pady=5)
        
        ttk.Label(tab_pass, text="Подтвердите пароль:").pack(anchor=tk.W, pady=(10, 5))
        self.pass_confirm = PasswordEntry(tab_pass)
        self.pass_confirm.pack(fill=tk.X, pady=5)
        
        # Подсказка требований (улучшение UX)
        hint_text = "Требования: минимум 12 символов, заглавные и строчные буквы, цифры."
        ttk.Label(tab_pass, text=hint_text, foreground="gray").pack(anchor=tk.W, pady=(5, 0))

        # Вкладка 3: Настройки шифрования (Заглушка)
        tab_crypto = ttk.Frame(notebook, padding=10)
        notebook.add(tab_crypto, text="Шифрование")
        crypto_text = (
            "Используется: AES-256-GCM.\n\n"
            "Ключ шифрования формируется из мастер-пароля с солью и параметрами сложности.\n"
            "Мастер-пароль не хранится в открытом виде, а записи сохраняются только зашифрованными."
        )
        ttk.Label(tab_crypto, text=crypto_text, wraplength=340, justify=tk.LEFT).pack(anchor=tk.W)

        # Кнопки
        btn_frame = ttk.Frame(self)
        btn_frame.pack(fill=tk.X, pady=10, padx=10)
        ttk.Button(btn_frame, text="Готово", command=self.on_complete).pack(side=tk.RIGHT)

    def browse_db(self):
        """Описывает публичное действие browse db."""
        path = filedialog.asksaveasfilename(defaultextension=".db", filetypes=[("SQLite DB", "*.db")])
        if path:
            self.db_path_var.set(path)

    def on_complete(self):
        """Описывает публичное действие on complete."""
        path = self.db_path_var.get()
        p1 = self.pass_entry.get()
        p2 = self.pass_confirm.get()

        if not path:
            messagebox.showerror("Ошибка", "Укажите путь к базе данных.")
            return
            
        if p1 != p2:
            messagebox.showerror("Ошибка", "Пароли не совпадают.")
            return

        # ИЗМЕНЕНО: Используем AuthenticationService для строгой проверки (HASH-4)
        auth_service = AuthenticationService()
        is_valid, msg = auth_service.validate_password_strength(p1)
        
        if not is_valid:
            messagebox.showerror("Слабый пароль", msg)
            return
        
        # Сохраняем результаты как обычные строки
        self.db_path = path
        self.password = p1
        
        self.completed = True
        self.destroy()
