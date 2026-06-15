"""
Entry Dialog — диалог создания/редактирования записей хранилища.
Реализует требования DIALOG-1 — DIALOG-3:
  DIALOG-1: Все поля, validation, strength meter, generate button
  DIALOG-2: Валидация обязательных полей, URL format, password strength
  DIALOG-3: Auto-fill suggestions по домену
"""

import tkinter as tk
from tkinter import ttk, messagebox
from typing import Optional, Dict, Any, Callable
import re

from core.vault.password_generator import PasswordGenerator, PasswordStrength
from gui.ux import translate_error_text


class PasswordGeneratorPopup(tk.Toplevel):
    """Всплывающее окно конфигурации генератора паролей (DIALOG-1)."""

    def __init__(self, parent, callback: Callable):
        super().__init__(parent)
        self.title("Генератор паролей")
        self.geometry("380x400")
        self.resizable(False, False)
        self.transient(parent)
        self.grab_set()

        self.callback = callback
        self.generator = PasswordGenerator()

        self._create_widgets()
        self.center_window(parent)

    def _create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Длина
        ttk.Label(frame, text="Длина пароля:").pack(anchor=tk.W)
        self.length_var = tk.IntVar(value=16)
        length_scale = ttk.Scale(frame, from_=8, to=64, variable=self.length_var, orient=tk.HORIZONTAL)
        length_scale.pack(fill=tk.X, pady=(0, 5))

        self.length_label = ttk.Label(frame, text="16")
        self.length_label.pack(anchor=tk.W)
        length_scale.config(command=self._update_length_label)

        # Наборы символов
        ttk.Label(frame, text="Наборы символов:").pack(anchor=tk.W, pady=(10, 5))

        self.use_upper = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Заглавные (A-Z)", variable=self.use_upper).pack(anchor=tk.W)

        self.use_lower = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Строчные (a-z)", variable=self.use_lower).pack(anchor=tk.W)

        self.use_digits = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Цифры (0-9)", variable=self.use_digits).pack(anchor=tk.W)

        self.use_symbols = tk.BooleanVar(value=True)
        ttk.Checkbutton(frame, text="Символы (!@#$%)", variable=self.use_symbols).pack(anchor=tk.W)

        self.exclude_ambiguous = tk.BooleanVar(value=False)
        ttk.Checkbutton(frame, text="Исключить неоднозначные (l, I, 1, 0, O)",
                        variable=self.exclude_ambiguous).pack(anchor=tk.W)

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X, pady=(15, 0))

        ttk.Button(btn_frame, text="Использовать пароль", command=self._use_password).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Сгенерировать", command=self._generate).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self.destroy).pack(side=tk.RIGHT)

        # Превью пароля
        ttk.Label(frame, text="Результат:").pack(anchor=tk.W, pady=(10, 5))
        self.password_preview = ttk.Entry(frame, width=40, font=("Consolas", 10))
        self.password_preview.pack(fill=tk.X, pady=(0, 5))

        self.strength_label = ttk.Label(frame, text="")
        self.strength_label.pack(anchor=tk.W)

    def _update_length_label(self, value):
        self.length_label.config(text=f"{int(float(value))}")

    def _generate(self):
        try:
            password = self.generator.generate(
                length=int(self.length_var.get()),
                use_uppercase=self.use_upper.get(),
                use_lowercase=self.use_lower.get(),
                use_digits=self.use_digits.get(),
                use_symbols=self.use_symbols.get(),
                exclude_ambiguous=self.exclude_ambiguous.get(),
            )

            self.password_preview.delete(0, tk.END)
            self.password_preview.insert(0, password)

            score, label = self.generator.get_strength(password)
            self.strength_label.config(text=f"Сложность: {label} ({score}/4)")

        except ValueError as e:
            messagebox.showerror("Ошибка", translate_error_text(e), parent=self)

    def _on_copy(self):
        password = self.password_preview.get()
        if password:
            self.clipboard_clear()
            self.clipboard_append(password)
            self.callback(password)
            self.destroy()

    def _use_password(self):
        password = self.password_preview.get()
        if not password:
            messagebox.showinfo("Генератор паролей", "Сначала сгенерируйте пароль.", parent=self)
            return
        self.callback(password)
        self.destroy()

    def center_window(self, parent):
        """Описывает публичное действие center window."""
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")


class EntryDialog(tk.Toplevel):
    """
    Диалог создания/редактирования записей (DIALOG-1 — DIALOG-3).
    """

    def __init__(self, parent, entry_data: Optional[Dict[str, Any]] = None,
                 on_save: Optional[Callable] = None):
        super().__init__(parent)

        self.is_edit_mode = entry_data is not None
        self.entry_data = entry_data or {}
        self.on_save_callback = on_save

        self.title("Редактирование записи" if self.is_edit_mode else "Новая запись")
        self.geometry("450x550")
        self.resizable(False, False)

        self.transient(parent)
        self.grab_set()

        self.generator = PasswordGenerator()

        self._create_widgets()
        self._load_data()
        self.center_window(parent)

        self.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.wait_window(self)

    def _create_widgets(self):
        frame = ttk.Frame(self, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)

        # Название (обязательное)
        ttk.Label(frame, text="Название *").pack(anchor=tk.W)
        self.title_entry = ttk.Entry(frame, width=50)
        self.title_entry.pack(fill=tk.X, pady=(0, 10))
        self.title_entry.focus()

        # Имя пользователя
        ttk.Label(frame, text="Логин / Email").pack(anchor=tk.W)
        self.username_entry = ttk.Entry(frame, width=50)
        self.username_entry.pack(fill=tk.X, pady=(0, 10))

        # Пароль (обязательное)
        ttk.Label(frame, text="Пароль *").pack(anchor=tk.W)

        pwd_frame = ttk.Frame(frame)
        pwd_frame.pack(fill=tk.X, pady=(0, 5))

        self.password_entry = ttk.Entry(pwd_frame, width=40, show="*")
        self.password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)

        # Переключение видимости
        self.show_pwd_var = tk.BooleanVar(value=False)
        toggle_btn = ttk.Checkbutton(pwd_frame, text="👁", variable=self.show_pwd_var,
                                      command=self._toggle_password_visibility)
        toggle_btn.pack(side=tk.RIGHT, padx=(5, 0))

        # Кнопка генерации
        gen_btn = ttk.Button(pwd_frame, text="Сгенерировать", command=self._show_generator)
        gen_btn.pack(side=tk.RIGHT)

        # Индикатор сложности пароля (DIALOG-1)
        from gui.widgets.password_strength_meter import PasswordStrengthMeter
        self.strength_meter = PasswordStrengthMeter(frame)
        self.strength_meter.pack(fill=tk.X, pady=(0, 10))

        # Привязка изменений пароля к индикатору сложности
        self.password_entry.bind("<KeyRelease>", lambda e: self._update_strength())

        # Адрес сайта
        ttk.Label(frame, text="URL").pack(anchor=tk.W)
        self.url_entry = ttk.Entry(frame, width=50)
        self.url_entry.pack(fill=tk.X, pady=(0, 10))
        self.url_entry.bind("<FocusOut>", self._on_url_focus_out)  # DIALOG-3: автозаполнение

        # Заметки
        ttk.Label(frame, text="Заметки").pack(anchor=tk.W)
        self.notes_text = tk.Text(frame, width=50, height=4)
        self.notes_text.pack(fill=tk.X, pady=(0, 10))

        # Категория
        ttk.Label(frame, text="Категория").pack(anchor=tk.W)
        self.category_entry = ttk.Entry(frame, width=50)
        self.category_entry.pack(fill=tk.X, pady=(0, 10))

        # Теги
        ttk.Label(frame, text="Теги (через запятую)").pack(anchor=tk.W)
        self.tags_entry = ttk.Entry(frame, width=50)
        self.tags_entry.pack(fill=tk.X, pady=(0, 15))

        # Кнопки
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill=tk.X)

        ttk.Button(btn_frame, text="Сохранить", command=self._on_save).pack(side=tk.RIGHT, padx=5)
        ttk.Button(btn_frame, text="Отмена", command=self.on_cancel).pack(side=tk.RIGHT)

    def _load_data(self):
        """Загрузить данные при редактировании."""
        if self.is_edit_mode:
            self.title_entry.insert(0, self.entry_data.get("title", ""))
            self.username_entry.insert(0, self.entry_data.get("username", ""))
            self.password_entry.insert(0, self.entry_data.get("password", ""))
            self.url_entry.insert(0, self.entry_data.get("url", ""))
            self.notes_text.insert("1.0", self.entry_data.get("notes", ""))
            self.category_entry.insert(0, self.entry_data.get("category", ""))
            tags = self.entry_data.get("tags", [])
            self.tags_entry.insert(0, ", ".join(tags) if isinstance(tags, list) else tags)

    def _toggle_password_visibility(self):
        """GUI-3: Переключить видимость пароля."""
        if self.show_pwd_var.get():
            self.password_entry.config(show="")
        else:
            self.password_entry.config(show="*")

    def _update_strength(self):
        """DIALOG-1: Обновить индикатор сложности пароля."""
        password = self.password_entry.get()
        score = PasswordStrength.calculate(password)
        self.strength_meter.update_strength(score)

    def _show_generator(self):
        """DIALOG-1: Показать диалог генератора паролей."""
        popup = PasswordGeneratorPopup(self, callback=self._apply_generated_password)

    def _apply_generated_password(self, password: str):
        """Вставить сгенерированный пароль."""
        self.password_entry.delete(0, tk.END)
        self.password_entry.insert(0, password)
        self._update_strength()

    def _on_url_focus_out(self, event):
        """DIALOG-3: Автозаполнение имени пользователя по домену."""
        url = self.url_entry.get().strip()
        if url and not self.username_entry.get():
            # Извлекаем домен и предлагаем как username
            domain = url.split("://")[-1].split("/")[0].split(":")[0]
            if domain:
                self.username_entry.insert(0, f"user@{domain}")

    def _validate(self) -> tuple:
        """
        DIALOG-2: Валидация формы.

        Returns:
            (bool, str) — (успех, сообщение об ошибке)
        """
        title = self.title_entry.get().strip()
        password = self.password_entry.get()
        url = self.url_entry.get().strip()

        # Обязательные поля
        if not title:
            return False, "Поле 'Название' обязательно"

        if not password:
            return False, "Поле 'Пароль' обязательно"

        # DIALOG-2: Проверка формата URL
        if url and not re.match(r'^(https?://)?[\w.-]+\.\w{2,}', url):
            return False, "Неверный формат URL"

        # DIALOG-2: Проверка сложности пароля (если не сгенерирован)
        score = PasswordStrength.calculate(password)
        if score < 2:
            return False, f"Пароль слишком слабый (оценка: {score}/4). Используйте сгенерированный или усложните."

        return True, ""

    def _on_save(self):
        """Обработчик кнопки сохранения."""
        valid, error_msg = self._validate()
        if not valid:
            messagebox.showwarning("Ошибка валидации", error_msg, parent=self)
            return

        # Собираем данные
        tags_str = self.tags_entry.get().strip()
        tags = [t.strip() for t in tags_str.split(",") if t.strip()] if tags_str else []

        data = {
            "title": self.title_entry.get().strip(),
            "username": self.username_entry.get().strip(),
            "password": self.password_entry.get(),
            "url": self.url_entry.get().strip(),
            "notes": self.notes_text.get("1.0", tk.END).strip(),
            "category": self.category_entry.get().strip(),
            "tags": tags,
        }

        if self.on_save_callback:
            self.on_save_callback(data)

        self.destroy()

    def on_cancel(self):
        """Отмена."""
        self.destroy()

    def center_window(self, parent):
        """Описывает публичное действие center window."""
        self.update_idletasks()
        x = parent.winfo_x() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_y() + (parent.winfo_height() - self.winfo_height()) // 2
        self.geometry(f"+{x}+{y}")
