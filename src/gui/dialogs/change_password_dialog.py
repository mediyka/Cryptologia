
import tkinter as tk
from tkinter import ttk, messagebox
import logging
from ..widgets.password_entry import PasswordEntry
from ..ux import translate_error_text

# ИНИЦИАЛИЗАЦИЯ ЛОГГЕРА
logger = logging.getLogger("ChangePasswordDialog")

class ChangePasswordDialog(tk.Toplevel):
    """Описывает публичный класс ChangePasswordDialog."""
    def __init__(self, parent, key_manager, entry_manager, crypto_service):
        super().__init__(parent)
        self.title("Смена мастер-пароля")
        self.geometry("450x300")
        self.resizable(False, False)

        self.key_manager = key_manager
        self.entry_manager = entry_manager
        self.crypto_service = crypto_service
        
        self.transient(parent)
        self.grab_set()
        
        self.create_widgets()
        self.protocol("WM_DELETE_WINDOW", self.destroy)

    def create_widgets(self):
        """Создает widgets."""
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Текущий пароль
        ttk.Label(frame, text="Текущий пароль:").pack(anchor=tk.W)
        self.old_pass = PasswordEntry(frame)
        self.old_pass.pack(fill=tk.X, pady=(0, 10))

        # Новый пароль
        ttk.Label(frame, text="Новый пароль:").pack(anchor=tk.W, pady=(5, 0))
        self.new_pass = PasswordEntry(frame)
        self.new_pass.pack(fill=tk.X, pady=(0, 10))

        # Подтверждение
        ttk.Label(frame, text="Подтвердите новый пароль:").pack(anchor=tk.W)
        self.confirm_pass = PasswordEntry(frame)
        self.confirm_pass.pack(fill=tk.X, pady=(0, 10))

        # Подсказка
        hint_text = "Минимум 12 символов: заглавные, строчные, цифры, спецсимволы."
        ttk.Label(frame, text=hint_text, foreground="gray", font=("Arial", 8)).pack(anchor=tk.W, pady=(0, 10))

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(10, 0))
        ttk.Button(btn_frame, text="Отмена", command=self.destroy).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Сменить пароль", command=self.on_change).pack(side=tk.RIGHT)

    def on_change(self):
        """Описывает публичное действие on change."""
        old_p = self.old_pass.get()
        new_p = self.new_pass.get()
        conf_p = self.confirm_pass.get()

        # 1. Проверка заполнения полей
        if not old_p or not new_p:
            messagebox.showerror("Ошибка", "Заполните все поля.", parent=self)
            return

        if new_p != conf_p:
            messagebox.showerror("Ошибка", "Новые пароли не совпадают.", parent=self)
            return

        if old_p == new_p:
            messagebox.showerror("Ошибка", "Новый пароль должен отличаться от текущего.", parent=self)
            return

        # 2. Валидация нового пароля (не закрываем окно при ошибке)
        is_valid, msg = self.key_manager.auth.validate_password_strength(new_p)
        if not is_valid:
            messagebox.showerror("Слабый пароль", msg, parent=self)
            return

        try:
            self.config(cursor="watch")
            self.update()

            self.key_manager.change_password(
                old_p,
                new_p,
                self.entry_manager,
                self.crypto_service,
            )
            messagebox.showinfo("Успех", "Мастер-пароль успешно изменен.", parent=self)
            self.destroy()

        except ValueError as e:
            messagebox.showerror("Ошибка", translate_error_text(e), parent=self)
        except Exception as e:
            logger.error(f"Change password error: {e}")
            messagebox.showerror("Критическая ошибка", f"Не удалось сменить пароль:\n{translate_error_text(e)}", parent=self)
        finally:
            try:
                self.config(cursor="")
            except tk.TclError:
                pass
