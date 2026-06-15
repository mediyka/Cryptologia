"""
Search Widget - виджет поиска с real-time фильтрацией.
Реализует требования SEARCH-1 - SEARCH-3:
  SEARCH-1: Full-text search, fuzzy matching, field-specific filters
  SEARCH-2: Real-time обновление при вводе
  SEARCH-3: GUI-фильтры для демо по тегам, датам и силе пароля
"""

import tkinter as tk
from tkinter import ttk
from typing import Callable, Optional, List, Dict, Any


class SearchWidget(ttk.Frame):
    """Виджет поиска записей с real-time фильтрацией."""

    PLACEHOLDER = "Поиск (название, логин, URL, заметки...)"

    def __init__(self, parent, on_search: Optional[Callable] = None, **kwargs):
        super().__init__(parent, **kwargs)

        self.on_search_callback = on_search
        self._search_history: List[str] = []
        self._max_history = 10  # SEARCH-4: размер истории поиска

        search_frame = ttk.Frame(self)
        search_frame.pack(fill=tk.X, padx=5, pady=5)

        ttk.Label(search_frame, text="Поиск:").pack(side=tk.LEFT, padx=(0, 5))

        self.search_var = tk.StringVar()
        self.search_entry = ttk.Entry(search_frame, textvariable=self.search_var, width=42)
        self.search_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        self.search_entry.configure(takefocus=True)
        setattr(self.search_entry, "accessible_name", "Search vault entries")
        self.search_entry.insert(0, self.PLACEHOLDER)
        self.search_entry.bind("<FocusIn>", self._on_focus_in)
        self.search_entry.bind("<FocusOut>", self._on_focus_out)
        self.search_var.trace_add("write", self._on_search_changed)

        clear_btn = ttk.Button(search_frame, text="Очистить", command=self.clear)
        clear_btn.pack(side=tk.RIGHT, padx=(5, 0))

        self.history_btn = ttk.Button(search_frame, text="История", command=self._show_history)
        self.history_btn.pack(side=tk.RIGHT, padx=(0, 5))
        self.history_btn.pack_forget()

        filter_frame = ttk.Frame(self)
        filter_frame.pack(fill=tk.X, padx=5, pady=(0, 5))

        ttk.Label(filter_frame, text="Категория:").pack(side=tk.LEFT, padx=(0, 5))
        self.category_var = tk.StringVar(value="Все")
        self.category_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.category_var,
            width=14,
            state="readonly",
        )
        self.category_combo["values"] = ["Все", "Работа", "Личное", "Финансы", "Соцсети", "Другое"]
        self.category_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.category_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)

        ttk.Label(filter_frame, text="Тег:").pack(side=tk.LEFT, padx=(0, 5))
        self.tag_var = tk.StringVar()
        self.tag_entry = ttk.Entry(filter_frame, textvariable=self.tag_var, width=12)
        self.tag_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.tag_entry.bind("<Return>", self._on_filter_changed)

        ttk.Label(filter_frame, text="С даты:").pack(side=tk.LEFT, padx=(0, 5))
        self.start_date_var = tk.StringVar()
        self.start_date_entry = ttk.Entry(filter_frame, textvariable=self.start_date_var, width=16)
        self.start_date_entry.pack(side=tk.LEFT, padx=(0, 5))
        self.start_date_entry.bind("<Return>", self._on_filter_changed)

        ttk.Label(filter_frame, text="По дату:").pack(side=tk.LEFT, padx=(0, 5))
        self.end_date_var = tk.StringVar()
        self.end_date_entry = ttk.Entry(filter_frame, textvariable=self.end_date_var, width=16)
        self.end_date_entry.pack(side=tk.LEFT, padx=(0, 10))
        self.end_date_entry.bind("<Return>", self._on_filter_changed)

        ttk.Label(filter_frame, text="Сила:").pack(side=tk.LEFT, padx=(0, 5))
        self.strength_var = tk.StringVar(value="Любая")
        self.strength_combo = ttk.Combobox(
            filter_frame,
            textvariable=self.strength_var,
            width=9,
            state="readonly",
        )
        self.strength_combo["values"] = ["Любая", ">= 1", ">= 2", ">= 3", ">= 4"]
        self.strength_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.strength_combo.bind("<<ComboboxSelected>>", self._on_filter_changed)

        ttk.Button(filter_frame, text="Применить", command=self._trigger_search).pack(side=tk.LEFT, padx=(0, 5))
        ttk.Button(filter_frame, text="Сбросить фильтры", command=self.clear_filters).pack(side=tk.LEFT)

        self.bind_all("<Escape>", lambda event: self.clear())

    def _on_focus_in(self, event):
        current = self.search_var.get()
        if current == self.PLACEHOLDER:
            self.search_var.set("")

    def _on_focus_out(self, event):
        current = self.search_var.get()
        if not current:
            self.search_var.set(self.PLACEHOLDER)

    def _on_search_changed(self, *args):
        query = self.search_var.get().strip()
        if query and query != self.PLACEHOLDER:
            if query not in self._search_history:
                self._search_history.append(query)
                if len(self._search_history) > self._max_history:
                    self._search_history.pop(0)
                self.history_btn.pack(side=tk.RIGHT, padx=(0, 5))

        self._trigger_search()

    def _on_filter_changed(self, event=None):
        self._trigger_search()

    def _trigger_search(self):
        if self.on_search_callback:
            self.on_search_callback(self.get_filters())

    def _show_history(self):
        if not self._search_history:
            return

        popup = tk.Toplevel(self)
        popup.title("История поиска")
        popup.geometry("300x200")
        popup.transient(self.winfo_toplevel())

        listbox = tk.Listbox(popup)
        listbox.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)

        for item in reversed(self._search_history):
            listbox.insert(tk.END, item)

        listbox.bind("<Double-1>", lambda e: self._select_history(listbox, popup))

    def _select_history(self, listbox: tk.Listbox, popup: tk.Toplevel):
        selection = listbox.curselection()
        if selection:
            query = listbox.get(selection[0])
            self.search_var.set(query)
            popup.destroy()

    def clear(self):
        """Описывает публичное действие clear."""
        self.search_var.set("")
        self.clear_filters()

    def focus_search(self):
        """Описывает публичное действие focus search."""
        self.search_entry.focus_set()
        self.search_entry.selection_range(0, tk.END)

    def clear_filters(self):
        """Очищает filters."""
        self.category_var.set("Все")
        self.tag_var.set("")
        self.start_date_var.set("")
        self.end_date_var.set("")
        self.strength_var.set("Любая")
        self._trigger_search()

    def get_query(self) -> str:
        """Возвращает данные для query."""
        query = self.search_var.get().strip()
        return "" if query == self.PLACEHOLDER else query

    def get_filters(self) -> Dict[str, Any]:
        """Возвращает данные для filters."""
        strength_map = {
            "Любая": None,
            ">= 1": 1,
            ">= 2": 2,
            ">= 3": 3,
            ">= 4": 4,
        }
        category = self.category_var.get().strip()
        return {
            "query": self.get_query(),
            "category": "" if category == "Все" else category,
            "tag": self.tag_var.get().strip(),
            "start_date": self.start_date_var.get().strip(),
            "end_date": self.end_date_var.get().strip(),
            "min_strength": strength_map.get(self.strength_var.get(), None),
        }

    def set_categories(self, categories: List[str]):
        """Сохраняет или обновляет значение categories."""
        values = ["Все"] + categories
        self.category_combo["values"] = values
