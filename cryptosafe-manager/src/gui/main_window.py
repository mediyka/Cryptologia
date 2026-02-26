"""
Главное окно приложения.
"""
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime

from ..core.config import config
from ..core.events import event_bus, EventType, AuditLogger
from ..core.key_manager import KeyManager
from ..core.crypto.placeholder import XORPlaceholder
from ..database.db import db
from ..database.models import VaultEntry
from .widgets.password_entry import PasswordEntry


class MainWindow:
    """Главное окно приложения."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title(f"{config.APP_NAME} v{config.APP_VERSION}")
        self.root.geometry("1000x600")
        
        self.key_manager = KeyManager()
        self.crypto = XORPlaceholder()
        self.audit_logger = AuditLogger()
        self.current_key = None
        self.unlocked = False
        
        self._create_menu()
        self._create_toolbar()
        self._create_main_area()
        self._create_status_bar()
        
        self._center_window()
        self.root.protocol("WM_DELETE_WINDOW", self._on_closing)
        
        # Проверяем первый запуск
        self.root.after(100, self._check_first_run)
    
    def _center_window(self):
        self.root.update_idletasks()
        width, height = 1000, 600
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f'{width}x{height}+{x}+{y}')
    
    def _create_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Файл", menu=file_menu)
        file_menu.add_command(label="Заблокировать", command=self._lock_vault)
        file_menu.add_separator()
        file_menu.add_command(label="Выход", command=self._on_closing)
        
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Правка", menu=edit_menu)
        edit_menu.add_command(label="Добавить запись", command=self._add_entry)
        edit_menu.add_command(label="Изменить запись", command=self._edit_entry)
        edit_menu.add_command(label="Удалить запись", command=self._delete_entry)
        
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Справка", menu=help_menu)
        help_menu.add_command(label="О программе", command=self._show_about)
    
    def _create_toolbar(self):
        toolbar = ttk.Frame(self.root)
        toolbar.pack(side=tk.TOP, fill=tk.X, padx=5, pady=5)
        
        ttk.Button(toolbar, text="➕ Добавить", command=self._add_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="✏️ Изменить", command=self._edit_entry).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🗑️ Удалить", command=self._delete_entry).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        ttk.Button(toolbar, text="🔓 Разблокировать", command=self._unlock_vault).pack(side=tk.LEFT, padx=2)
        ttk.Button(toolbar, text="🔒 Заблокировать", command=self._lock_vault).pack(side=tk.LEFT, padx=2)
        
        ttk.Separator(toolbar, orient=tk.VERTICAL).pack(side=tk.LEFT, padx=10, fill=tk.Y)
        
        ttk.Button(toolbar, text="🔄 Обновить", command=self._refresh_entries).pack(side=tk.LEFT, padx=2)
    
    def _create_main_area(self):
        # Таблица записей
        columns = ('id', 'title', 'username', 'url', 'updated')
        
        self.tree = ttk.Treeview(
            self.root,
            columns=columns,
            show='headings',
            selectmode='browse'
        )
        
        self.tree.column('id', width=50, anchor='center')
        self.tree.column('title', width=200)
        self.tree.column('username', width=150)
        self.tree.column('url', width=200)
        self.tree.column('updated', width=150)
        
        self.tree.heading('id', text='ID')
        self.tree.heading('title', text='Название')
        self.tree.heading('username', text='Имя пользователя')
        self.tree.heading('url', text='URL')
        self.tree.heading('updated', text='Обновлено')
        
        scrollbar = ttk.Scrollbar(self.root, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scrollbar.set)
        
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(5, 0), pady=5)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 5), pady=5)
        
        self.tree.bind('<Double-1>', lambda e: self._edit_entry())
    
    def _create_status_bar(self):
        status_bar = ttk.Frame(self.root)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        self.status_lock = ttk.Label(status_bar, text="🔒 Заблокировано")
        self.status_lock.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(status_bar, text=f"v{config.APP_VERSION}").pack(side=tk.RIGHT, padx=5)
    
    def _check_first_run(self):
        key_data = db.get_key('master')
        if not key_data:
            self._show_first_run_wizard()
    
    def _show_first_run_wizard(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Первоначальная настройка")
        dialog.geometry("400x300")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Создайте мастер-пароль:", font=('Arial', 12)).pack(pady=20)
        
        frame = ttk.Frame(dialog)
        frame.pack(pady=20)
        
        ttk.Label(frame, text="Пароль:").grid(row=0, column=0, pady=5)
        password1 = PasswordEntry(frame, width=25)
        password1.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="Подтверждение:").grid(row=1, column=0, pady=5)
        password2 = PasswordEntry(frame, width=25)
        password2.grid(row=1, column=1, pady=5)
        
        def create_vault():
            p1 = password1.get()
            p2 = password2.get()
            
            if not p1:
                messagebox.showerror("Ошибка", "Введите пароль")
                return
            
            if p1 != p2:
                messagebox.showerror("Ошибка", "Пароли не совпадают")
                return
            
            if len(p1) < config.MIN_PASSWORD_LENGTH:
                messagebox.showerror("Ошибка", f"Пароль должен быть не менее {config.MIN_PASSWORD_LENGTH} символов")
                return
            
            key, salt = self.key_manager.derive_key(p1)
            self.key_manager.store_key('master', key, salt)
            db.store_key('master', salt, key)
            
            self.current_key = key
            self.unlocked = True
            self.status_lock.config(text="🔓 Разблокировано")
            
            event_bus.emit(EventType.USER_LOGGED_IN, {'user': 'master'})
            dialog.destroy()
            messagebox.showinfo("Успех", "Хранилище создано!")
        
        ttk.Button(dialog, text="Создать", command=create_vault).pack(pady=20)
    
    def _unlock_vault(self):
        if self.unlocked:
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Разблокировка")
        dialog.geometry("300x150")
        dialog.transient(self.root)
        dialog.grab_set()
        
        ttk.Label(dialog, text="Введите мастер-пароль:").pack(pady=20)
        
        password = PasswordEntry(dialog, width=20)
        password.pack(pady=10)
        password.focus()
        
        def check_password():
            key_data = db.get_key('master')
            if not key_data:
                messagebox.showerror("Ошибка", "Хранилище не найдено")
                dialog.destroy()
                return
            
            key, _ = self.key_manager.derive_key(password.get(), key_data['salt'])
            
            # В реальном приложении здесь сравнение хешей
            self.current_key = key
            self.unlocked = True
            self.status_lock.config(text="🔓 Разблокировано")
            event_bus.emit(EventType.USER_LOGGED_IN, {'user': 'master'})
            dialog.destroy()
            self._refresh_entries()
        
        password.entry.bind('<Return>', lambda e: check_password())
        ttk.Button(dialog, text="Разблокировать", command=check_password).pack(pady=10)
    
    def _lock_vault(self):
        self.unlocked = False
        self.current_key = None
        self.key_manager.clear_key()
        self.status_lock.config(text="🔒 Заблокировано")
        event_bus.emit(EventType.USER_LOGGED_OUT)
        
        for row in self.tree.get_children():
            self.tree.delete(row)
    
    def _refresh_entries(self):
        for row in self.tree.get_children():
            self.tree.delete(row)
        
        if not self.unlocked:
            return
        
        entries = db.get_all_entries()
        for entry in entries:
            updated = entry.updated_at
            if isinstance(updated, datetime):
                updated = updated.strftime('%d.%m.%Y %H:%M')
            
            self.tree.insert('', tk.END, iid=str(entry.id), values=(
                entry.id, entry.title, entry.username, entry.url, updated
            ))
    
    def _add_entry(self):
        if not self.unlocked:
            messagebox.showwarning("Внимание", "Сначала разблокируйте хранилище")
            return
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Добавить запись")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Название:").grid(row=0, column=0, sticky=tk.W, pady=5)
        title = ttk.Entry(frame, width=30)
        title.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="Имя пользователя:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username = ttk.Entry(frame, width=30)
        username.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Пароль:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password = PasswordEntry(frame, width=30)
        password.grid(row=2, column=1, pady=5)
        
        ttk.Label(frame, text="URL:").grid(row=3, column=0, sticky=tk.W, pady=5)
        url = ttk.Entry(frame, width=30)
        url.grid(row=3, column=1, pady=5)
        
        ttk.Label(frame, text="Заметки:").grid(row=4, column=0, sticky=tk.W, pady=5)
        notes = tk.Text(frame, width=30, height=5)
        notes.grid(row=4, column=1, pady=5)
        
        def save():
            encrypted_pass = self.crypto.encrypt(
                password.get().encode('utf-8'),
                self.current_key
            )
            
            entry = VaultEntry(
                title=title.get(),
                username=username.get(),
                encrypted_password=encrypted_pass,
                url=url.get(),
                notes=notes.get(1.0, tk.END).strip()
            )
            
            db.add_entry(entry)
            dialog.destroy()
            self._refresh_entries()
        
        ttk.Button(frame, text="Сохранить", command=save).grid(row=5, column=0, columnspan=2, pady=20)
    
    def _edit_entry(self):
        if not self.unlocked:
            return
        
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Выберите запись для редактирования")
            return
        
        entry_id = int(selected[0])
        entry = db.get_entry(entry_id)
        if not entry:
            return
        
        # Расшифровываем пароль
        decrypted_pass = self.crypto.decrypt(
            entry.encrypted_password,
            self.current_key
        ).decode('utf-8')
        
        dialog = tk.Toplevel(self.root)
        dialog.title("Редактировать запись")
        dialog.geometry("400x350")
        dialog.transient(self.root)
        dialog.grab_set()
        
        frame = ttk.Frame(dialog, padding=20)
        frame.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(frame, text="Название:").grid(row=0, column=0, sticky=tk.W, pady=5)
        title = ttk.Entry(frame, width=30)
        title.insert(0, entry.title)
        title.grid(row=0, column=1, pady=5)
        
        ttk.Label(frame, text="Имя пользователя:").grid(row=1, column=0, sticky=tk.W, pady=5)
        username = ttk.Entry(frame, width=30)
        username.insert(0, entry.username)
        username.grid(row=1, column=1, pady=5)
        
        ttk.Label(frame, text="Пароль:").grid(row=2, column=0, sticky=tk.W, pady=5)
        password = PasswordEntry(frame, width=30)
        password.set(decrypted_pass)
        password.grid(row=2, column=1, pady=5)
        
        ttk.Label(frame, text="URL:").grid(row=3, column=0, sticky=tk.W, pady=5)
        url = ttk.Entry(frame, width=30)
        url.insert(0, entry.url or '')
        url.grid(row=3, column=1, pady=5)
        
        ttk.Label(frame, text="Заметки:").grid(row=4, column=0, sticky=tk.W, pady=5)
        notes = tk.Text(frame, width=30, height=5)
        if entry.notes:
            notes.insert(1.0, entry.notes)
        notes.grid(row=4, column=1, pady=5)
        
        def save():
            encrypted_pass = self.crypto.encrypt(
                password.get().encode('utf-8'),
                self.current_key
            )
            
            entry.title = title.get()
            entry.username = username.get()
            entry.encrypted_password = encrypted_pass
            entry.url = url.get()
            entry.notes = notes.get(1.0, tk.END).strip()
            
            db.update_entry(entry)
            dialog.destroy()
            self._refresh_entries()
        
        ttk.Button(frame, text="Сохранить", command=save).grid(row=5, column=0, columnspan=2, pady=20)
    
    def _delete_entry(self):
        if not self.unlocked:
            return
        
        selected = self.tree.selection()
        if not selected:
            messagebox.showwarning("Внимание", "Выберите запись для удаления")
            return
        
        if messagebox.askyesno("Подтверждение", "Удалить запись?"):
            entry_id = int(selected[0])
            db.delete_entry(entry_id)
            self._refresh_entries()
    
    def _show_about(self):
        messagebox.showinfo(
            "О программе",
            f"{config.APP_NAME} v{config.APP_VERSION}\n\n"
            "Лабораторная работа по криптографии\n"
            "Демонстрация безопасного хранения паролей"
        )
    
    def _on_closing(self):
        self.key_manager.clear_key()
        self.root.destroy()
    
    def run(self):
        self.root.mainloop()
