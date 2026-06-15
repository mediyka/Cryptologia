import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from typing import Dict, List, Optional

from core.import_export import ExportOptions, VaultExporter
from gui.ux import translate_error_text


class ExportDialog(tk.Toplevel):
    """Описывает публичный класс ExportDialog."""
    def __init__(self, parent, entry_manager, selected_entry_ids: Optional[List[str]] = None):
        super().__init__(parent)
        self.parent = parent
        self.entry_manager = entry_manager
        self.selected_entry_ids = set(selected_entry_ids or [])
        self._entry_rows: Dict[str, str] = {}

        self.title("Экспорт хранилища")
        self.geometry("760x620")
        self.transient(parent)
        self.grab_set()

        self._build_variables()
        self._create_widgets()
        self._load_entries()

    def _build_variables(self):
        self.format_var = tk.StringVar(value="encrypted_json")
        self.scope_var = tk.StringVar(value="selected" if self.selected_entry_ids else "full")
        self.output_path_var = tk.StringVar()
        self.password_var = tk.StringVar()
        self.password_confirm_var = tk.StringVar()
        self.master_password_var = tk.StringVar()
        self.encrypt_var = tk.BooleanVar(value=True)
        self.allow_plaintext_var = tk.BooleanVar(value=False)
        self.compression_var = tk.BooleanVar(value=False)
        self.strength_var = tk.IntVar(value=256)
        self.include_notes_var = tk.BooleanVar(value=True)
        self.include_url_var = tk.BooleanVar(value=True)
        self.include_category_var = tk.BooleanVar(value=True)
        self.include_tags_var = tk.BooleanVar(value=True)

    def _create_widgets(self):
        shell = ttk.Frame(self)
        shell.pack(fill=tk.BOTH, expand=True)
        root = self._create_scrollable_content(shell)

        top = ttk.Frame(root)
        top.pack(fill=tk.X)

        ttk.Label(top, text="Формат").grid(row=0, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        format_box = ttk.Combobox(
            top,
            textvariable=self.format_var,
            values=[
                "encrypted_json",
                "csv",
                "bitwarden_json",
                "bitwarden_encrypted_json",
                "lastpass_csv",
                "lastpass_json",
            ],
            state="readonly",
            width=24,
        )
        format_box.grid(row=0, column=1, sticky=tk.W, pady=3)
        format_box.bind("<<ComboboxSelected>>", lambda event: self._on_format_changed())

        ttk.Label(top, text="Файл").grid(row=1, column=0, sticky=tk.W, padx=(0, 6), pady=3)
        ttk.Entry(top, textvariable=self.output_path_var).grid(row=1, column=1, columnspan=3, sticky=tk.EW, pady=3)
        ttk.Button(top, text="Выбрать", command=self._choose_output_path).grid(row=1, column=4, padx=(6, 0), pady=3)
        top.columnconfigure(3, weight=1)

        options = ttk.LabelFrame(root, text="Параметры", padding=8)
        options.pack(fill=tk.X, pady=8)
        ttk.Radiobutton(options, text="Все записи", value="full", variable=self.scope_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(options, text="Выбранные записи", value="selected", variable=self.scope_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Checkbutton(options, text="Шифровать экспорт", variable=self.encrypt_var).grid(row=1, column=0, sticky=tk.W, pady=4)
        ttk.Checkbutton(options, text="Разрешить plaintext", variable=self.allow_plaintext_var).grid(row=1, column=1, sticky=tk.W, pady=4)
        ttk.Checkbutton(options, text="GZIP-сжатие", variable=self.compression_var).grid(row=1, column=2, sticky=tk.W, pady=4)
        ttk.Label(options, text="AES").grid(row=2, column=0, sticky=tk.W, pady=4)
        ttk.Combobox(options, textvariable=self.strength_var, values=[128, 256], state="readonly", width=8).grid(row=2, column=1, sticky=tk.W)

        security = ttk.LabelFrame(root, text="Подтверждение и ключи", padding=8)
        security.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(security, text="Мастер-пароль").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(security, textvariable=self.master_password_var, show="*").grid(row=0, column=1, sticky=tk.EW, pady=3)
        ttk.Label(security, text="Пароль экспорта").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(security, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky=tk.EW, pady=3)
        ttk.Label(security, text="Повтор пароля экспорта").grid(row=2, column=0, sticky=tk.W, pady=3)
        ttk.Entry(security, textvariable=self.password_confirm_var, show="*").grid(row=2, column=1, sticky=tk.EW, pady=3)
        security.columnconfigure(1, weight=1)

        fields = ttk.LabelFrame(root, text="Поля", padding=8)
        fields.pack(fill=tk.X, pady=(0, 8))
        ttk.Checkbutton(fields, text="URL", variable=self.include_url_var).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(fields, text="Заметки", variable=self.include_notes_var).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(fields, text="Категория", variable=self.include_category_var).pack(side=tk.LEFT, padx=(0, 14))
        ttk.Checkbutton(fields, text="Теги", variable=self.include_tags_var).pack(side=tk.LEFT, padx=(0, 14))

        entries_frame = ttk.LabelFrame(root, text="Записи", padding=8)
        entries_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.entries_tree = ttk.Treeview(entries_frame, columns=("use", "title", "username"), show="headings", height=9)
        self.entries_tree.heading("use", text="")
        self.entries_tree.heading("title", text="Название")
        self.entries_tree.heading("username", text="Логин")
        self.entries_tree.column("use", width=42, stretch=False, anchor=tk.CENTER)
        self.entries_tree.column("title", width=260)
        self.entries_tree.column("username", width=220)
        self.entries_tree.pack(fill=tk.BOTH, expand=True)
        self.entries_tree.bind("<Button-1>", self._toggle_tree_checkbox)

        footer = ttk.Frame(shell, padding=10)
        footer.pack(fill=tk.X)
        ttk.Button(footer, text="Предпросмотр", command=self._preview).pack(side=tk.LEFT)
        ttk.Button(footer, text="Экспорт", command=self._export).pack(side=tk.RIGHT, padx=(6, 0))
        ttk.Button(footer, text="Закрыть", command=self.destroy).pack(side=tk.RIGHT)

    def _create_scrollable_content(self, parent):
        container = ttk.Frame(parent)
        container.pack(fill=tk.BOTH, expand=True)
        canvas = tk.Canvas(container, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient=tk.VERTICAL, command=canvas.yview)
        content = ttk.Frame(canvas, padding=10)
        window_id = canvas.create_window((0, 0), window=content, anchor=tk.NW)

        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        def update_scroll_region(_event=None):
            canvas.configure(scrollregion=canvas.bbox("all"))

        def update_content_width(event):
            canvas.itemconfigure(window_id, width=event.width)

        def on_mousewheel(event):
            delta = -1 if event.delta > 0 else 1
            canvas.yview_scroll(delta * 3, "units")

        content.bind("<Configure>", update_scroll_region)
        canvas.bind("<Configure>", update_content_width)
        canvas.bind("<Enter>", lambda _event: canvas.bind_all("<MouseWheel>", on_mousewheel))
        canvas.bind("<Leave>", lambda _event: canvas.unbind_all("<MouseWheel>"))
        return content

    def _load_entries(self):
        entries = self.entry_manager.get_all_entries(include_decrypted_password=True)
        for entry in entries:
            entry_id = entry.get("id")
            checked = entry_id in self.selected_entry_ids
            self._entry_rows[entry_id] = "1" if checked else "0"
            self.entries_tree.insert("", tk.END, iid=entry_id, values=("☑" if checked else "☐", entry.get("title", ""), entry.get("username", "")))

    def _toggle_tree_checkbox(self, event):
        row_id = self.entries_tree.identify_row(event.y)
        column_id = self.entries_tree.identify_column(event.x)
        if row_id and column_id == "#1":
            checked = self._entry_rows.get(row_id) != "1"
            self._entry_rows[row_id] = "1" if checked else "0"
            self.entries_tree.set(row_id, "use", "☑" if checked else "☐")
            return "break"
        return None

    def _on_format_changed(self):
        self.encrypt_var.set(self.format_var.get() in {"encrypted_json", "bitwarden_encrypted_json"})

    def _choose_output_path(self):
        ext = ".csv" if self.format_var.get() in {"csv", "lastpass_csv"} else ".json"
        path = filedialog.asksaveasfilename(parent=self, defaultextension=ext)
        if path:
            self.output_path_var.set(path)

    def _selected_ids(self) -> Optional[List[str]]:
        if self.scope_var.get() == "full":
            return None
        return [entry_id for entry_id, checked in self._entry_rows.items() if checked == "1"]

    def _exclude_fields(self) -> List[str]:
        excluded = []
        if not self.include_url_var.get():
            excluded.append("url")
        if not self.include_notes_var.get():
            excluded.append("notes")
        if not self.include_category_var.get():
            excluded.append("category")
        if not self.include_tags_var.get():
            excluded.append("tags")
        return excluded

    def _build_export_options(self) -> ExportOptions:
        return ExportOptions(
            format=self.format_var.get(),
            entry_ids=self._selected_ids(),
            exclude_fields=self._exclude_fields(),
            encrypt=self.encrypt_var.get(),
            allow_plaintext=self.allow_plaintext_var.get(),
            encryption_strength=int(self.strength_var.get()),
            compression=self.compression_var.get(),
            encryption_password=self.password_var.get() or None,
            master_password=self.master_password_var.get() or None,
        )

    def _validate_export_password(self) -> bool:
        if not self.encrypt_var.get() and self.format_var.get() != "bitwarden_encrypted_json":
            return True

        password = self.password_var.get()
        confirmation = self.password_confirm_var.get()
        if not password:
            messagebox.showerror("Экспорт", "Введите пароль экспорта.", parent=self)
            return False
        if password != confirmation:
            messagebox.showerror("Экспорт", "Пароли экспорта не совпадают.", parent=self)
            return False
        return True

    def _preview(self):
        ids = self._selected_ids()
        count = len(ids) if ids is not None else len(self.entries_tree.get_children())
        fields = ", ".join(self._exclude_fields()) or "нет"
        messagebox.showinfo(
            "Предпросмотр экспорта",
            f"Формат: {self.format_var.get()}\nЗаписей: {count}\nИсключены поля: {fields}\nШифрование: {'да' if self.encrypt_var.get() else 'нет'}",
            parent=self,
        )

    def _export(self):
        path = self.output_path_var.get().strip()
        if not path:
            messagebox.showerror("Экспорт", "Выберите файл для сохранения.", parent=self)
            return
        if not self._validate_export_password():
            return
        try:
            result = VaultExporter(self.entry_manager).export_to_file(path, self._build_export_options())
            messagebox.showinfo("Экспорт", f"Экспортировано записей: {result.entry_count}\nSHA-256: {result.checksum}", parent=self)
            self.destroy()
        except Exception as exc:
            messagebox.showerror("Экспорт", f"Не удалось выполнить экспорт:\n{translate_error_text(exc)}", parent=self)
