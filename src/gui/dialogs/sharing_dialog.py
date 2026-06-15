import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from core.import_export import KeyExchangeService, ShareOptions, SharingService
from gui.ux import translate_error_text
from .qr_dialog import QRCodeDialog


class SharingDialog(tk.Toplevel):
    """Описывает публичный класс SharingDialog."""
    def __init__(self, parent, entry_manager, entry_id: str):
        super().__init__(parent)
        self.parent = parent
        self.entry_manager = entry_manager
        self.entry_id = entry_id
        self.last_package = None

        self.title("Поделиться записью")
        self.geometry("680x520")
        self.transient(parent)
        self.grab_set()

        self._build_variables()
        self._create_widgets()
        self._load_entry_info()

    def _build_variables(self):
        self.recipient_var = tk.StringVar()
        self.method_var = tk.StringVar(value="password")
        self.password_var = tk.StringVar()
        self.public_key_path_var = tk.StringVar()
        self.expiration_var = tk.IntVar(value=7)
        self.edit_var = tk.BooleanVar(value=False)
        self.delivery_var = tk.StringVar(value="file")
        self.output_path_var = tk.StringVar()

    def _create_widgets(self):
        shell = ttk.Frame(self)
        shell.pack(fill=tk.BOTH, expand=True)
        root = self._create_scrollable_content(shell)

        self.entry_label = ttk.Label(root, text="Запись: --")
        self.entry_label.pack(anchor=tk.W)

        main = ttk.LabelFrame(root, text="Получатель и доступ", padding=8)
        main.pack(fill=tk.X, pady=8)
        ttk.Label(main, text="Получатель").grid(row=0, column=0, sticky=tk.W, pady=3)
        ttk.Entry(main, textvariable=self.recipient_var).grid(row=0, column=1, sticky=tk.EW, pady=3)
        ttk.Label(main, text="Срок, дней").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Spinbox(main, from_=1, to=30, textvariable=self.expiration_var, width=8).grid(row=1, column=1, sticky=tk.W, pady=3)
        ttk.Checkbutton(main, text="Разрешить редактирование", variable=self.edit_var).grid(row=2, column=1, sticky=tk.W, pady=3)
        main.columnconfigure(1, weight=1)

        crypto = ttk.LabelFrame(root, text="Шифрование", padding=8)
        crypto.pack(fill=tk.X, pady=(0, 8))
        ttk.Radiobutton(crypto, text="Пароль", value="password", variable=self.method_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(crypto, text="Публичный ключ", value="public_key", variable=self.method_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(crypto, text="Пароль").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(crypto, textvariable=self.password_var, show="*").grid(row=1, column=1, sticky=tk.EW, pady=3)
        ttk.Label(crypto, text="Public key PEM").grid(row=2, column=0, sticky=tk.W, pady=3)
        ttk.Entry(crypto, textvariable=self.public_key_path_var).grid(row=2, column=1, sticky=tk.EW, pady=3)
        ttk.Button(crypto, text="Выбрать", command=self._choose_public_key).grid(row=2, column=2, padx=(6, 0), pady=3)
        crypto.columnconfigure(1, weight=1)

        delivery = ttk.LabelFrame(root, text="Доставка", padding=8)
        delivery.pack(fill=tk.X, pady=(0, 8))
        ttk.Radiobutton(delivery, text="Файл", value="file", variable=self.delivery_var).grid(row=0, column=0, sticky=tk.W)
        ttk.Radiobutton(delivery, text="QR", value="qr", variable=self.delivery_var).grid(row=0, column=1, sticky=tk.W)
        ttk.Label(delivery, text="Файл").grid(row=1, column=0, sticky=tk.W, pady=3)
        ttk.Entry(delivery, textvariable=self.output_path_var).grid(row=1, column=1, sticky=tk.EW, pady=3)
        ttk.Button(delivery, text="Выбрать", command=self._choose_output_file).grid(row=1, column=2, padx=(6, 0), pady=3)
        delivery.columnconfigure(1, weight=1)

        history = ttk.LabelFrame(root, text="История и статус", padding=8)
        history.pack(fill=tk.BOTH, expand=True, pady=(0, 8))
        self.history_text = tk.Text(history, height=8, wrap=tk.WORD)
        self.history_text.pack(fill=tk.BOTH, expand=True)
        self._load_share_history()

        footer = ttk.Frame(shell, padding=10)
        footer.pack(fill=tk.X)
        ttk.Button(footer, text="Создать пакет", command=self._create_share).pack(side=tk.RIGHT, padx=(6, 0))
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

    def _load_entry_info(self):
        try:
            entry = self.entry_manager.get_entry(self.entry_id)
            self.entry_label.config(text=f"Запись: {entry.get('title', self.entry_id)}")
        except Exception:
            self.entry_label.config(text=f"Запись: {self.entry_id}")

    def _load_share_history(self):
        self.history_text.delete("1.0", tk.END)
        db = getattr(self.entry_manager, "db", None)
        if not db:
            return
        rows = db.fetchall(
            """
            SELECT shared_id, recipient_info, encryption_method, shared_at, expires_at
            FROM shared_entries
            WHERE original_entry_id = ?
            ORDER BY shared_at DESC
            """,
            (self.entry_id,),
        )
        if not rows:
            self.history_text.insert("1.0", "История пуста.")
            return
        for row in rows:
            self.history_text.insert(tk.END, f"{row[3]} -> {row[1]} ({row[2]}) до {row[4]} [{row[0]}]\n")

    def _choose_public_key(self):
        path = filedialog.askopenfilename(parent=self, filetypes=[("PEM", "*.pem"), ("Все файлы", "*.*")])
        if path:
            self.public_key_path_var.set(path)

    def _choose_output_file(self):
        path = filedialog.asksaveasfilename(parent=self, defaultextension=".cshare")
        if path:
            self.output_path_var.set(path)

    def _public_key_bytes(self):
        path = self.public_key_path_var.get().strip()
        if not path:
            return None
        with open(path, "rb") as file:
            return file.read()

    def _share_options(self):
        return ShareOptions(
            method=self.method_var.get(),
            recipient_info=self.recipient_var.get().strip(),
            password=self.password_var.get() or None,
            recipient_public_key=self._public_key_bytes(),
            permissions={"read": True, "edit": self.edit_var.get()},
            expires_in_days=int(self.expiration_var.get()),
        )

    def _create_share(self):
        try:
            package = SharingService(self.entry_manager).share_entry(self.entry_id, self._share_options())
            self.last_package = package
            if self.delivery_var.get() == "qr":
                payload = KeyExchangeService().create_encrypted_entry_payload(package.content)
                bundle = KeyExchangeService().generate_qr_codes(payload)
                QRCodeDialog(self, bundle)
            else:
                path = self.output_path_var.get().strip()
                if not path:
                    messagebox.showerror("Обмен", "Выберите файл для сохранения.", parent=self)
                    return
                with open(path, "wb") as file:
                    file.write(package.content)
            self._load_share_history()
            messagebox.showinfo("Обмен", f"Пакет создан.\nShare ID: {package.shared_id}", parent=self)
        except Exception as exc:
            messagebox.showerror("Обмен", f"Не удалось создать пакет:\n{translate_error_text(exc)}", parent=self)
