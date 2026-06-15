import tkinter as tk
from tkinter import ttk, messagebox

class LoginDialog(tk.Toplevel):
    """Описывает публичный класс LoginDialog."""
    def __init__(self, parent, key_manager, secure_desktop: bool = False):
        super().__init__(parent)
        self.title("Вход в хранилище")
        self.geometry("350x200")
        self.resizable(False, False)
        
        self.key_manager = key_manager
        self.success = False
        self.secure_desktop = secure_desktop
        
        self.transient(parent)
        self.grab_set()
        self._apply_secure_prompt_mode()
        
        self.create_widgets()
        self.center_window(parent)
        
        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def _apply_secure_prompt_mode(self):
        if not self.secure_desktop:
            return
        try:
            self.attributes("-topmost", True)
            self.focus_force()
        except tk.TclError:
            pass

    def create_widgets(self):
        """Создает widgets."""
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        ttk.Label(frame, text="Введите мастер-пароль:").pack(anchor=tk.W)
        
        self.password_entry = ttk.Entry(frame, show="*", width=30)
        self.password_entry.pack(fill=tk.X, pady=(5, 15))
        self.password_entry.bind("<Return>", self.on_login)
        self.password_entry.focus()

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)

        self.login_btn = ttk.Button(btn_frame, text="Войти", command=self.on_login)
        self.login_btn.pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Выход", command=self.on_cancel).pack(side=tk.RIGHT)

    def center_window(self, parent):
        """Описывает публичное действие center window."""
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")

    def on_login(self, event=None):
        # Проверка блокировки ПЕРЕД любыми действиями
        """Описывает публичное действие on login."""
        if self.key_manager.auth.is_locked_out():
            remaining = self.key_manager.auth.get_remaining_lockout_time()
            messagebox.showwarning("Блокировка", 
                f"Слишком много попыток.\nПодождите {remaining} сек.", parent=self)
            return

        password = self.password_entry.get()
        if not password:
            return

        try:
            self.login_btn.config(state=tk.DISABLED)
            
            if self.key_manager.unlock(password):
                self.success = True
                self.destroy()
            else:
                messagebox.showerror("Ошибка", "Неверный пароль.", parent=self)
                self.password_entry.delete(0, tk.END)
                self.password_entry.focus()
        except PermissionError as e:
             # Это исключение выбрасывается, если unlock обнаружил блокировку внутри.
             # Мы проверили это выше, но оставляем обработку на случай гонки условий:
             remaining = self.key_manager.auth.get_remaining_lockout_time()
             messagebox.showwarning("Блокировка", f"Вход заблокирован.\nПодождите {remaining} сек.", parent=self)
        finally:
            if self.winfo_exists():
                self.login_btn.config(state=tk.NORMAL)

    def on_cancel(self):
        """Описывает публичное действие on cancel."""
        self.success = False
        self.destroy()
