"""
GUI 1-4
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, List, Dict, Any, Set


class SecureTable(ttk.Treeview):
    """Таблица для отображения записей хранилища."""

    def __init__(self, parent, **kwargs):
        columns = ("title", "username", "password", "toggle", "url", "updated_at", "category")
        super().__init__(parent, columns=columns, show="headings", **kwargs)

        self._visible_password_ids: Set[str] = set()
        self._entries_data: Dict[str, Dict[str, Any]] = {}
        self._on_entry_selected_callback = None
        self._on_context_action_callback = None
        self._password_reveal_callback = None
        self.configure(takefocus=True)
        setattr(self, "accessible_name", "Vault entries table")

        self.heading("title", text="🔐 Название", command=lambda: self._sort_by_column("title"))
        self.heading("username", text="👤 Логин", command=lambda: self._sort_by_column("username"))
        self.heading("password", text="🔑 Пароль", command=lambda: self._sort_by_column("password"))
        self.heading("toggle", text="👁", command=lambda: None)
        self.heading("url", text="🌐 Сайт", command=lambda: self._sort_by_column("url"))
        self.heading("updated_at", text="🕒 Изменён", command=lambda: self._sort_by_column("updated_at"))
        self.heading("category", text="🏷 Категория", command=lambda: self._sort_by_column("category"))

        self.column("title", width=240, minwidth=130)
        self.column("username", width=170, minwidth=100)
        self.column("password", width=170, minwidth=120)
        self.column("toggle", width=58, minwidth=50, stretch=False, anchor=tk.CENTER)
        self.column("url", width=220, minwidth=120)
        self.column("updated_at", width=140, minwidth=95, stretch=False)
        self.column("category", width=140, minwidth=80)

        scrollbar = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.yview)
        self.configure(yscrollcommand=scrollbar.set)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Открыть", command=self._on_open)
        self.context_menu.add_command(label="Редактировать", command=self._on_edit)
        self.context_menu.add_command(label="Копировать логин", command=self._on_copy_username)
        self.context_menu.add_command(label="Копировать пароль", command=self._on_copy_password)
        self.context_menu.add_command(label="Копировать всё", command=self._on_copy_all)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Поделиться", command=self._on_share)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Удалить", command=self._on_delete)
        self.context_menu.add_command(label="Удалить навсегда", command=self._on_permanent_delete)

        self.bind("<Button-1>", self._on_left_click, add="+")
        self.bind("<Button-3>", self._show_context_menu)
        self.bind("<Double-1>", self._on_double_click)
        self.bind("<Return>", lambda event: self._on_open())
        self.bind("<space>", lambda event: self.toggle_password_visibility())
        style = ttk.Style(self)
        style.configure("Treeview", rowheight=34, font=("Segoe UI", 10))
        style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), padding=(8, 8))
        self.tag_configure("odd", background="#0f172a")
        self.tag_configure("even", background="#111827")
        self.tag_configure("clipboard_active", background="#713f12")

    def load_data(self, data: List[Dict[str, Any]]):
        """Загрузить данные записей в таблицу."""
        self.clear_data()
        self.append_data(data)

    def clear_data(self):
        """Очистить текущие строки, сохранив обратные вызовы и настройки таблицы."""
        self.delete(*self.get_children())
        self._entries_data.clear()
        self._visible_password_ids.clear()

    def append_data(self, data: List[Dict[str, Any]]):
        """Добавить пачку записей; используется для пошаговой загрузки больших хранилищ."""
        valid_ids = {item.get("id", "") for item in data if item.get("id", "")}
        self._visible_password_ids.intersection_update(valid_ids)

        for item in data:
            self._insert_entry(item)

    def load_data_incremental(self, data: List[Dict[str, Any]], batch_size: int, schedule: Callable, on_done: Callable):
        """Загружать строки небольшими пачками, чтобы интерфейс оставался отзывчивым."""
        self.clear_data()
        total = len(data)
        batches = [data[index : index + batch_size] for index in range(0, total, max(1, batch_size))]

        def load_batch(index: int = 0):
            if index >= len(batches):
                if on_done:
                    on_done(total)
                return
            self.append_data(batches[index])
            schedule(1, lambda: load_batch(index + 1))

        load_batch()

    def _insert_entry(self, item: Dict[str, Any]):
        entry_id = item.get("id", "")
        if not entry_id:
            entry_id = f"row-{len(self._entries_data) + 1}"
        self._entries_data[entry_id] = item

        username = self._mask_username(item.get("username", ""))
        password = self._format_password(entry_id, item.get("password", ""))
        toggle = self._toggle_icon(entry_id)
        url_display = self._extract_domain(item.get("url", ""))
        updated_at = self._format_date(item.get("updated_at", ""))

        row_index = len(self._entries_data)
        self.insert(
            "",
            tk.END,
            iid=entry_id,
            values=(
                item.get("title", ""),
                username,
                password,
                toggle,
                url_display,
                updated_at,
                item.get("category", ""),
            ),
            tags=("even" if row_index % 2 == 0 else "odd",),
        )

    def set_clipboard_entry(self, entry_id: str = None):
        """Подсветить строку, данные которой сейчас находятся в буфере обмена."""
        for index, item_id in enumerate(self.get_children()):
            base_tag = "even" if index % 2 == 0 else "odd"
            tags = ("clipboard_active",) if entry_id and item_id == entry_id else (base_tag,)
            self.item(item_id, tags=tags)

    def get_selected_entries(self) -> List[Dict[str, Any]]:
        """Вернуть данные выбранных записей."""
        selected_iids = self.selection()
        return [self._entries_data.get(iid, {}) for iid in selected_iids if iid in self._entries_data]

    def get_selected_ids(self) -> List[str]:
        """Вернуть идентификаторы выбранных записей."""
        return list(self.selection())

    def toggle_password_visibility(self):
        """Переключить видимость паролей для выбранных строк."""
        selected_ids = self.get_selected_ids()
        if not selected_ids:
            return False

        hidden_exists = any(entry_id not in self._visible_password_ids for entry_id in selected_ids)
        if hidden_exists:
            for entry_id in selected_ids:
                if entry_id not in self._visible_password_ids and self._ensure_password_loaded(entry_id):
                    self._visible_password_ids.add(entry_id)
        else:
            for entry_id in selected_ids:
                self._visible_password_ids.discard(entry_id)

        self._refresh_password_column()
        return any(entry_id in self._visible_password_ids for entry_id in selected_ids)

    def passwords_visible(self) -> bool:
        """Проверить, показан ли сейчас хотя бы один выбранный пароль."""
        selected_ids = self.get_selected_ids()
        return any(entry_id in self._visible_password_ids for entry_id in selected_ids)

    def set_selection_callback(self, callback: Callable):
        """Установить обратный вызов выбора строки."""
        self._on_entry_selected_callback = callback
        self.bind("<<TreeviewSelect>>", self._on_select)

    def set_context_callback(self, callback: Callable):
        """Установить обратный вызов действия из контекстного меню."""
        self._on_context_action_callback = callback

    def set_password_reveal_callback(self, callback: Callable):
        """Установить обратный вызов для ленивой загрузки расшифрованного пароля."""
        self._password_reveal_callback = callback

    def _mask_username(self, username: str) -> str:
        if not username:
            return ""
        if len(username) <= 4:
            return username
        return username[:4] + "•" * min(len(username) - 4, 10)

    def _is_password_visible_for_entry(self, entry_id: str) -> bool:
        return entry_id in self._visible_password_ids

    def _format_password(self, entry_id: str, password: str) -> str:
        if self._is_password_visible_for_entry(entry_id):
            return password
        return "\u2022" * 8

    def _toggle_icon(self, entry_id: str) -> str:
        return "🙈" if self._is_password_visible_for_entry(entry_id) else "👁"

    def _refresh_password_column(self):
        for item_id in self.get_children():
            entry = self._entries_data.get(item_id, {})
            self.set(item_id, "password", self._format_password(item_id, entry.get("password", "")))
            self.set(item_id, "toggle", self._toggle_icon(item_id))

    def _ensure_password_loaded(self, entry_id: str) -> bool:
        entry = self._entries_data.get(entry_id)
        if not entry:
            return False
        if entry.get("password"):
            return True
        if not self._password_reveal_callback:
            return False

        password = self._password_reveal_callback(entry_id)
        if not password:
            return False
        entry["password"] = password
        return True

    def _toggle_entry_password_visibility(self, entry_id: str):
        if not entry_id or entry_id not in self._entries_data:
            return

        if entry_id in self._visible_password_ids:
            self._visible_password_ids.remove(entry_id)
        else:
            if not self._ensure_password_loaded(entry_id):
                return
            self._visible_password_ids.add(entry_id)

        entry = self._entries_data.get(entry_id, {})
        self.set(entry_id, "password", self._format_password(entry_id, entry.get("password", "")))
        self.set(entry_id, "toggle", self._toggle_icon(entry_id))

    @staticmethod
    def _extract_domain(url: str) -> str:
        if not url:
            return ""
        domain = url.split("://")[-1] if "://" in url else url
        domain = domain.split("/")[0]
        domain = domain.split(":")[0]
        return domain if len(domain) <= 30 else domain[:27] + "..."

    @staticmethod
    def _format_date(date_str: str) -> str:
        if not date_str:
            return ""
        if "T" in date_str:
            return date_str.replace("T", " ")[:16]
        return date_str[:16] if len(date_str) > 16 else date_str

    def _sort_by_column(self, column: str):
        items = [(self.set(k, column), k) for k in self.get_children()]
        items.sort(key=lambda x: x[0].lower() if isinstance(x[0], str) else x[0])

        reverse = getattr(self, f"_sort_reverse_{column}", False)
        items.reverse() if reverse else items
        setattr(self, f"_sort_reverse_{column}", not reverse)

        for index, (_, iid) in enumerate(items):
            self.move(iid, "", index)

    def _show_context_menu(self, event):
        item = self.identify_row(event.y)
        if item:
            self.selection_set(item)
            self.context_menu.post(event.x_root, event.y_root)

    def _on_left_click(self, event):
        row_id = self.identify_row(event.y)
        column_id = self.identify_column(event.x)
        if row_id and column_id == "#4":
            self.selection_set(row_id)
            self._toggle_entry_password_visibility(row_id)
            return "break"
        return None

    def _on_open(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("open", selected[0])

    def _on_edit(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("edit", selected[0])

    def _on_copy_password(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("copy_password", selected[0])

    def _on_copy_username(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("copy_username", selected[0])

    def _on_copy_all(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("copy_all", selected[0])

    def _on_share(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("share", selected[0])

    def _on_delete(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("delete", selected[0])

    def _on_permanent_delete(self):
        selected = self.get_selected_entries()
        if selected and self._on_context_action_callback:
            self._on_context_action_callback("permanent_delete", selected[0])

    def _on_double_click(self, event):
        row_id = self.identify_row(event.y)
        column_id = self.identify_column(event.x)
        if row_id and column_id == "#4":
            return "break"
        if row_id:
            self.selection_set(row_id)
            self._on_open()
        return None

    def _on_select(self, event):
        if self._on_entry_selected_callback:
            selected = self.get_selected_entries()
            if selected:
                self._on_entry_selected_callback(selected[0])
