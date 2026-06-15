import json
import os
import tkinter as tk
from tkinter import ttk, messagebox, filedialog, simpledialog
from datetime import datetime, timedelta, timezone

from core.audit import AuditLogExporter
from gui.ux import translate_error_text


class AuditLogViewer(ttk.Frame):
    """Окно просмотра журнала аудита Sprint 5."""

    PAGE_SIZE = 50

    def __init__(self, parent, db=None, audit_manager=None, key_manager=None, on_entry_select=None):
        super().__init__(parent)
        self.db = db
        self.audit_manager = audit_manager
        self.key_manager = key_manager
        self.on_entry_select = on_entry_select
        self.page = 0
        self.sort_column = "sequence_number"
        self.sort_desc = True
        self.rows = []
        self.filtered_rows = []
        self.total_rows = 0
        self.filtered_total_rows = 0

        self._build_filters()
        self._build_dashboard()
        self._build_table()
        self._build_details()
        self._build_pager()
        self._build_context_menu()
        self.refresh()

    def _build_filters(self):
        filters = ttk.Frame(self)
        filters.pack(fill=tk.X, padx=6, pady=(6, 2))

        ttk.Label(filters, text="Тип").grid(row=0, column=0, sticky=tk.W)
        self.event_type_var = tk.StringVar()
        self.event_type_box = ttk.Combobox(filters, textvariable=self.event_type_var, width=18, state="readonly")
        self.event_type_box.grid(row=0, column=1, padx=(4, 10), sticky=tk.W)

        ttk.Label(filters, text="Уровень").grid(row=0, column=2, sticky=tk.W)
        self.severity_var = tk.StringVar()
        self.severity_box = ttk.Combobox(
            filters,
            textvariable=self.severity_var,
            values=["", "INFO", "WARN", "ERROR", "CRITICAL"],
            width=10,
            state="readonly",
        )
        self.severity_box.grid(row=0, column=3, padx=(4, 10), sticky=tk.W)

        ttk.Label(filters, text="Пользователь").grid(row=0, column=4, sticky=tk.W)
        self.user_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.user_var, width=16).grid(row=0, column=5, padx=(4, 10), sticky=tk.W)

        ttk.Label(filters, text="С").grid(row=1, column=0, sticky=tk.W, pady=(4, 0))
        self.date_from_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.date_from_var, width=18).grid(row=1, column=1, padx=(4, 10), sticky=tk.W, pady=(4, 0))

        ttk.Label(filters, text="По").grid(row=1, column=2, sticky=tk.W, pady=(4, 0))
        self.date_to_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.date_to_var, width=18).grid(row=1, column=3, padx=(4, 10), sticky=tk.W, pady=(4, 0))

        ttk.Label(filters, text="Поиск").grid(row=1, column=4, sticky=tk.W, pady=(4, 0))
        self.search_var = tk.StringVar()
        ttk.Entry(filters, textvariable=self.search_var, width=24).grid(row=1, column=5, padx=(4, 10), sticky=tk.W, pady=(4, 0))

        ttk.Button(filters, text="Применить", command=self.apply_filters).grid(row=0, column=6, padx=2)
        ttk.Button(filters, text="Сброс", command=self.reset_filters).grid(row=1, column=6, padx=2, pady=(4, 0))
        ttk.Button(filters, text="Проверить", command=self.verify_logs).grid(row=0, column=7, padx=2)
        ttk.Button(filters, text="Экспорт", command=self.export_logs).grid(row=1, column=7, padx=2, pady=(4, 0))
        ttk.Button(filters, text="Report", command=self.export_verification_report).grid(row=0, column=8, padx=2)
        ttk.Button(filters, text="Schedules", command=self.manage_export_schedules).grid(row=1, column=8, padx=2, pady=(4, 0))

        filters.columnconfigure(9, weight=1)

    def _build_dashboard(self):
        dashboard = ttk.Frame(self)
        dashboard.pack(fill=tk.X, padx=6, pady=2)

        metrics = ttk.Frame(dashboard)
        metrics.pack(side=tk.LEFT, fill=tk.X, expand=True)

        self.stats_var = tk.StringVar(value="Записей: 0")
        self.size_var = tk.StringVar(value="Размер журнала: 0 байт")
        self.integrity_var = tk.StringVar(value="Целостность: не проверялась")
        ttk.Label(metrics, textvariable=self.stats_var).pack(anchor=tk.W)
        ttk.Label(metrics, textvariable=self.size_var).pack(anchor=tk.W, pady=(2, 0))
        ttk.Label(metrics, textvariable=self.integrity_var).pack(anchor=tk.W, pady=(2, 0))

        graph_controls = ttk.Frame(dashboard)
        graph_controls.pack(side=tk.RIGHT, fill=tk.Y)
        ttk.Label(graph_controls, text="Период").pack(anchor=tk.W)
        self.graph_period_var = tk.StringVar(value="7")
        self.graph_period_box = ttk.Combobox(
            graph_controls,
            textvariable=self.graph_period_var,
            values=["7", "30", "90"],
            width=5,
            state="readonly",
        )
        self.graph_period_box.pack(anchor=tk.W)
        self.graph_period_box.bind("<<ComboboxSelected>>", lambda _event: self._draw_frequency_graph())

        self.graph_canvas = tk.Canvas(dashboard, width=260, height=70, highlightthickness=1, highlightbackground="#c8c8c8")
        self.graph_canvas.pack(side=tk.RIGHT, padx=(12, 0), fill=tk.Y)

    def _build_table(self):
        table_frame = ttk.Frame(self)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=6, pady=4)

        columns = ("sequence_number", "timestamp", "event_type", "severity", "user_id", "source", "entry_id")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", height=12)
        labels = {
            "sequence_number": "#",
            "timestamp": "Время",
            "event_type": "Событие",
            "severity": "Уровень",
            "user_id": "Пользователь",
            "source": "Источник",
            "entry_id": "Запись",
        }
        widths = {
            "sequence_number": 60,
            "timestamp": 170,
            "event_type": 180,
            "severity": 80,
            "user_id": 120,
            "source": 100,
            "entry_id": 160,
        }
        for column in columns:
            self.table.heading(column, text=labels[column], command=lambda c=column: self.sort_by(c))
            self.table.column(column, width=widths[column], minwidth=50)

        scrollbar = ttk.Scrollbar(table_frame, orient=tk.VERTICAL, command=self.table.yview)
        self.table.configure(yscrollcommand=scrollbar.set)
        self.table.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        self.table.bind("<<TreeviewSelect>>", self.on_select)
        self.table.bind("<Double-1>", lambda _event: self.highlight_selected_entry())
        self.table.bind("<Button-3>", self.show_context_menu)

    def _build_details(self):
        panel = ttk.LabelFrame(self, text="Детали записи")
        panel.pack(fill=tk.BOTH, expand=False, padx=6, pady=(0, 4))

        self.verification_var = tk.StringVar(value="Подпись: --")
        self.chain_var = tk.StringVar(value="Цепочка: --")
        ttk.Label(panel, textvariable=self.verification_var).pack(anchor=tk.W, padx=6, pady=(4, 0))
        ttk.Label(panel, textvariable=self.chain_var).pack(anchor=tk.W, padx=6)

        self.details_text = tk.Text(panel, height=8, wrap=tk.WORD)
        self.details_text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)
        self.details_text.config(state=tk.DISABLED)

    def _build_pager(self):
        pager = ttk.Frame(self)
        pager.pack(fill=tk.X, padx=6, pady=(0, 6))
        ttk.Button(pager, text="Назад", command=self.prev_page).pack(side=tk.LEFT)
        ttk.Button(pager, text="Вперёд", command=self.next_page).pack(side=tk.LEFT, padx=4)
        self.page_var = tk.StringVar(value="Страница 1")
        ttk.Label(pager, textvariable=self.page_var).pack(side=tk.LEFT, padx=8)
        ttk.Button(pager, text="Обновить", command=self.refresh).pack(side=tk.RIGHT)

    def _build_context_menu(self):
        self.context_menu = tk.Menu(self, tearoff=0)
        self.context_menu.add_command(label="Показать детали", command=self.show_selected_details)
        self.context_menu.add_command(label="Выделить запись хранилища", command=self.highlight_selected_entry)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Проверить целостность", command=self.verify_logs)
        self.context_menu.add_command(label="Export verification report", command=self.export_verification_report)

    def refresh(self):
        """Описывает публичное действие refresh."""
        if self.audit_manager and hasattr(self.audit_manager, "flush_async"):
            self.audit_manager.flush_async()
        if not self.db:
            self.rows = []
            self.total_rows = 0
            self.filtered_total_rows = 0
            self.filtered_rows = []
            self._load_page()
            self._update_stats()
            self._draw_frequency_graph()
            return

        where_clause, params = self._build_query_filters()
        count_row = self.db.fetchone(f"SELECT COUNT(*) FROM audit_log {where_clause}", tuple(params))
        self.filtered_total_rows = int(count_row[0] or 0) if count_row else 0
        total_row = self.db.fetchone("SELECT COUNT(*) FROM audit_log")
        self.total_rows = int(total_row[0] or 0) if total_row else 0
        total_pages = max(1, (self.filtered_total_rows + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.page = min(self.page, total_pages - 1)
        offset = self.page * self.PAGE_SIZE

        query = """
            SELECT sequence_number, timestamp, COALESCE(event_type, action), details,
                   entry_id, entry_data, entry_hash, signature, previous_hash
            FROM audit_log
            {where_clause}
            ORDER BY sequence_number DESC, timestamp DESC
            LIMIT ? OFFSET ?
        """
        page_rows = self.db.fetchall(query.format(where_clause=where_clause), tuple(params + [self.PAGE_SIZE, offset]))
        self.rows = [self._row_to_dict(row, offset + index) for index, row in enumerate(page_rows)]
        self.filtered_rows = self._sort_rows(self.rows)
        self._update_event_types()
        self._load_page()
        self._update_stats()
        self._draw_frequency_graph()

    def _build_query_filters(self):
        conditions = []
        params = []
        event_type = self.event_type_var.get().strip()
        severity = self.severity_var.get().strip()
        user = self.user_var.get().strip()
        search = self.search_var.get().strip()
        date_from = self._normalized_filter_date(self.date_from_var.get(), end_of_day=False)
        date_to = self._normalized_filter_date(self.date_to_var.get(), end_of_day=True)

        if event_type:
            conditions.append("COALESCE(event_type, action) = ?")
            params.append(event_type)
        if severity:
            conditions.append("CAST(entry_data AS TEXT) LIKE ?")
            params.append(f'%"severity":"{severity}"%')
        if user:
            conditions.append("CAST(entry_data AS TEXT) LIKE ?")
            params.append(f"%{user}%")
        if date_from:
            conditions.append("timestamp >= ?")
            params.append(date_from)
        if date_to:
            conditions.append("timestamp <= ?")
            params.append(date_to)
        if search:
            conditions.append(
                "(COALESCE(details, '') LIKE ? OR COALESCE(entry_id, '') LIKE ? OR CAST(entry_data AS TEXT) LIKE ?)"
            )
            params.extend([f"%{search}%", f"%{search}%", f"%{search}%"])

        where_clause = f"WHERE {' AND '.join(conditions)}" if conditions else ""
        return where_clause, params

    def _row_to_dict(self, row, index):
        sequence_number, timestamp, event_type, details, entry_id, entry_data, entry_hash, signature, previous_hash = row
        entry = self._decode_entry_data(entry_data)
        details_json = self._decode_json(details)
        return {
            "viewer_id": f"audit-row-{index}-{sequence_number if sequence_number is not None else 'legacy'}",
            "sequence_number": sequence_number,
            "timestamp": timestamp,
            "event_type": event_type or entry.get("event_type", ""),
            "severity": entry.get("severity", ""),
            "user_id": entry.get("user_id", ""),
            "source": entry.get("source", ""),
            "entry_id": entry_id or entry.get("entry_id", ""),
            "details": entry.get("details", details_json),
            "entry_data": None,
            "search_text": json.dumps(entry.get("details", details_json), ensure_ascii=False).lower(),
            "entry_data_size": len(entry_data or b""),
            "entry_hash": entry_hash,
            "signature": signature,
            "previous_hash": previous_hash,
        }

    def _update_event_types(self):
        if self.db:
            rows = self.db.fetchall(
                "SELECT DISTINCT COALESCE(event_type, action) FROM audit_log "
                "WHERE COALESCE(event_type, action) IS NOT NULL ORDER BY 1"
            )
            values = [row[0] for row in rows if row[0]]
        else:
            values = sorted({row["event_type"] for row in self.rows if row["event_type"]})
        self.event_type_box["values"] = [""] + values

    def apply_filters(self, reset_page=False):
        """Применяет filters."""
        if reset_page:
            self.page = 0
        self.refresh()

    def reset_filters(self):
        """Описывает публичное действие reset filters."""
        for var in (self.event_type_var, self.severity_var, self.user_var, self.date_from_var, self.date_to_var, self.search_var):
            var.set("")
        self.page = 0
        self.refresh()

    def sort_by(self, column):
        """Описывает публичное действие sort by."""
        if self.sort_column == column:
            self.sort_desc = not self.sort_desc
        else:
            self.sort_column = column
            self.sort_desc = False
        self.refresh()

    def _sort_rows(self, rows):
        return sorted(rows, key=self._sort_key, reverse=self.sort_desc)

    def _sort_key(self, item):
        value = item.get(self.sort_column)
        if self.sort_column == "sequence_number":
            return value if value is not None else -1
        return str(value or "").lower()

    def _load_page(self):
        self.table.delete(*self.table.get_children())
        total_pages = max(1, (self.filtered_total_rows + self.PAGE_SIZE - 1) // self.PAGE_SIZE)
        self.page = min(self.page, total_pages - 1)
        start = self.page * self.PAGE_SIZE

        for row in self.filtered_rows:
            self.table.insert(
                "",
                tk.END,
                iid=row["viewer_id"],
                values=(
                    row["sequence_number"],
                    row["timestamp"],
                    row["event_type"],
                    row["severity"],
                    row["user_id"],
                    row["source"],
                    row["entry_id"] or "--",
                ),
            )

        shown_from = 0 if not self.filtered_rows else start + 1
        shown_to = min(start + len(self.filtered_rows), self.filtered_total_rows)
        self.page_var.set(f"Страница {self.page + 1} из {total_pages} | {shown_from}-{shown_to} из {self.filtered_total_rows}")

    def _update_stats(self):
        if self.db:
            failed_row = self.db.fetchone(
                "SELECT COUNT(*) FROM audit_log WHERE COALESCE(event_type, action) IN ('LoginFailed', 'FailedAuthAttempt')"
            )
            suspicious_row = self.db.fetchone(
                "SELECT COUNT(*) FROM audit_log "
                "WHERE COALESCE(event_type, action) LIKE '%Suspicious%' OR CAST(entry_data AS TEXT) LIKE '%\"source\":\"security\"%'"
            )
            size_row = self.db.fetchone(
                "SELECT COALESCE(SUM(LENGTH(entry_data) + LENGTH(COALESCE(signature, '')) + LENGTH(COALESCE(entry_hash, ''))), 0) FROM audit_log"
            )
            failed_logins = int(failed_row[0] or 0) if failed_row else 0
            suspicious = int(suspicious_row[0] or 0) if suspicious_row else 0
            log_size = int(size_row[0] or 0) if size_row else 0
        else:
            failed_logins = sum(1 for row in self.rows if row["event_type"] in {"LoginFailed", "FailedAuthAttempt"})
            suspicious = sum(1 for row in self.rows if row["source"] == "security" or "Suspicious" in row["event_type"])
            log_size = sum(row["entry_data_size"] + len(row["signature"] or "") + len(row["entry_hash"] or "") for row in self.rows)
        self.stats_var.set(
            f"Записей: {self.total_rows} | Отфильтровано: {self.filtered_total_rows} | "
            f"Ошибок входа: {failed_logins} | Подозрительных: {suspicious}"
        )

        self.size_var.set(f"Размер журнала: {self._format_size(log_size)}")

        status = self.audit_manager.verifier.get_status() if self.audit_manager and hasattr(self.audit_manager, "verifier") else {}
        verified = status.get("verified")
        checked_at = status.get("checked_at")
        suffix = f" ({checked_at})" if checked_at else ""
        if verified is True:
            self.integrity_var.set(f"Целостность: OK{suffix}")
        elif verified is False:
            self.integrity_var.set(f"Целостность: нарушена{suffix}")
        else:
            self.integrity_var.set("Целостность: не проверялась")

    def _draw_frequency_graph(self):
        self.graph_canvas.delete("all")
        days = int(self.graph_period_var.get() or 7)
        now = datetime.now(timezone.utc)
        start_day = (now - timedelta(days=days - 1)).date()
        buckets = {start_day + timedelta(days=offset): 0 for offset in range(days)}

        for row in self.rows:
            row_dt = self._parse_date(row["timestamp"])
            if row_dt and row_dt.date() in buckets:
                buckets[row_dt.date()] += 1

        width = max(1, int(self.graph_canvas["width"]))
        height = max(1, int(self.graph_canvas["height"]))
        max_count = max(buckets.values()) if buckets else 0
        self.graph_canvas.create_text(6, 8, text=f"События за {days} дней", anchor=tk.W, fill="#333333")

        if max_count == 0:
            self.graph_canvas.create_text(width // 2, height // 2 + 8, text="нет данных", fill="#666666")
            return

        left = 8
        right = width - 8
        bottom = height - 8
        top = 20
        bar_gap = 2 if days <= 30 else 1
        bar_width = max(1, (right - left - (days - 1) * bar_gap) / days)

        for index, count in enumerate(buckets.values()):
            x1 = left + index * (bar_width + bar_gap)
            x2 = x1 + bar_width
            bar_height = 0 if max_count == 0 else (bottom - top) * count / max_count
            y1 = bottom - bar_height
            self.graph_canvas.create_rectangle(x1, y1, x2, bottom, fill="#2f6fed", outline="")

    def prev_page(self):
        """Описывает публичное действие prev page."""
        if self.page > 0:
            self.page -= 1
            self.refresh()

    def next_page(self):
        """Описывает публичное действие next page."""
        if (self.page + 1) * self.PAGE_SIZE < self.filtered_total_rows:
            self.page += 1
            self.refresh()

    def on_select(self, _event=None):
        """Описывает публичное действие on select."""
        row = self._selected_row()
        if row:
            self._show_details(row)

    def show_selected_details(self):
        """Показывает selected details."""
        row = self._selected_row()
        if row:
            self._show_details(row)

    def _show_details(self, row):
        details = self._load_entry_data(row) or {"details": row["details"]}
        text = json.dumps(details, ensure_ascii=False, indent=2, sort_keys=True)
        self.details_text.config(state=tk.NORMAL)
        self.details_text.delete("1.0", tk.END)
        self.details_text.insert(tk.END, text)
        self.details_text.config(state=tk.DISABLED)

        if self.audit_manager and hasattr(self.audit_manager, "verifier") and row["sequence_number"] is not None:
            result = self.audit_manager.verifier.verify_integrity(
                row["sequence_number"],
                row["sequence_number"],
                publish_on_tamper=False,
            )
            if result["verified"]:
                self.verification_var.set("Подпись: корректна")
            else:
                reason = result["invalid_entries"][0]["reason"] if result.get("invalid_entries") else "ошибка"
                self.verification_var.set(f"Подпись: ошибка ({reason})")
        else:
            self.verification_var.set("Подпись: --")

        prev_hash = (row["previous_hash"] or "")[:12]
        entry_hash = (row["entry_hash"] or "")[:12]
        self.chain_var.set(f"Цепочка: {prev_hash or '--'} -> {entry_hash or '--'}")

    def _load_entry_data(self, row):
        if row.get("sequence_number") is None or not self.db:
            return row.get("entry_data") or {}
        db_row = self.db.fetchone(
            "SELECT entry_data FROM audit_log WHERE sequence_number = ?",
            (row["sequence_number"],),
        )
        return self._decode_entry_data(db_row[0]) if db_row else {}

    def verify_logs(self):
        """Проверяет logs."""
        if not self.audit_manager:
            messagebox.showwarning("Аудит", "Проверка недоступна: AuditManager не подключён.", parent=self)
            return
        report = self.audit_manager.verify_manual()
        self._update_stats()
        if report["verified"]:
            messagebox.showinfo("Аудит", "Целостность журнала подтверждена.", parent=self)
        else:
            messagebox.showerror("Аудит", "Обнаружено нарушение целостности журнала.", parent=self)

    def export_verification_report(self):
        """Описывает публичное действие export verification report."""
        if not self.audit_manager:
            messagebox.showwarning("Аудит", "Проверка недоступна: AuditManager не подключён.", parent=self)
            return
        output_path = filedialog.asksaveasfilename(
            parent=self,
            title="Сохранить отчёт проверки",
            defaultextension=".json",
            filetypes=[("JSON report", "*.json"), ("All files", "*.*")],
        )
        if not output_path:
            return
        try:
            report = self.audit_manager.verify_manual(export_path=output_path)
            self._update_stats()
            status = "OK" if report.get("verified") else "FAILED"
            messagebox.showinfo(
                "Аудит",
                f"Отчёт проверки сохранён.\nСтатус: {status}\nЗаписей: {report.get('total_entries', 0)}",
                parent=self,
            )
        except Exception as error:
            messagebox.showerror("Аудит", f"Не удалось сохранить отчёт проверки:\n{translate_error_text(error)}", parent=self)

    def export_logs(self):
        """Описывает публичное действие export logs."""
        if not self.db or not self.audit_manager or not self.key_manager:
            messagebox.showwarning("Аудит", "Экспорт недоступен: журнал или ключи не подключены.", parent=self)
            return

        export_format = simpledialog.askstring(
            "Экспорт аудита",
            "Формат экспорта: json, csv, pdf или cef",
            initialvalue="json",
            parent=self,
        )
        if not export_format:
            return

        export_format = export_format.lower().lstrip(".")
        if export_format not in AuditLogExporter.SUPPORTED_FORMATS:
            messagebox.showerror("Экспорт аудита", "Поддерживаются только форматы json, csv, pdf и cef.", parent=self)
            return

        default_extension = f".{export_format}.enc"
        output_path = filedialog.asksaveasfilename(
            parent=self,
            title="Сохранить экспорт аудита",
            defaultextension=default_extension,
            filetypes=[
                ("Encrypted audit export", f"*{default_extension}"),
                ("All files", "*.*"),
            ],
        )
        if not output_path:
            return

        exporter = AuditLogExporter(self.db, key_manager=self.key_manager, audit_logger=self.audit_manager)
        try:
            if hasattr(self.audit_manager, "flush_async"):
                self.audit_manager.flush_async()
            result = exporter.export(
                output_path=output_path,
                export_format=export_format,
                exporter="default_user",
                start_date=self._normalized_filter_date(self.date_from_var.get(), end_of_day=False),
                end_date=self._normalized_filter_date(self.date_to_var.get(), end_of_day=True),
                encrypt=True,
                confirm_password=self._confirm_master_password,
            )
            messagebox.showinfo(
                "Экспорт аудита",
                f"Экспорт готов: {result['entries']} записей.\nФайл зашифрован AES-256-GCM.",
                parent=self,
            )
        except PermissionError:
            messagebox.showwarning("Экспорт аудита", "Мастер-пароль не подтверждён.", parent=self)
        except Exception as error:
            if self.audit_manager:
                self.audit_manager.log_event(
                    "AuditExportFailed",
                    severity="ERROR",
                    source="audit",
                    details={"format": export_format, "reason": str(error)},
                )
            messagebox.showerror("Экспорт аудита", f"Не удалось выполнить экспорт:\n{translate_error_text(error)}", parent=self)

    def _confirm_master_password(self) -> bool:
        password = simpledialog.askstring(
            "Подтверждение экспорта",
            "Введите мастер-пароль для экспорта журнала:",
            show="*",
            parent=self,
        )
        if not password:
            return False
        try:
            return bool(self.key_manager.unlock(password))
        except Exception:
            return False

    def manage_export_schedules(self):
        """Описывает публичное действие manage export schedules."""
        if not self.db or not self.audit_manager or not self.key_manager:
            messagebox.showwarning("Аудит", "Расписание экспорта недоступно: журнал или ключи не подключены.", parent=self)
            return

        window = tk.Toplevel(self)
        window.title("Расписание экспорта аудита")
        window.geometry("880x320")

        columns = ("id", "name", "format", "frequency", "enabled", "next_run_at", "last_run_at", "output_dir")
        tree = ttk.Treeview(window, columns=columns, show="headings", height=10)
        labels = {
            "id": "ID",
            "name": "Name",
            "format": "Format",
            "frequency": "Frequency",
            "enabled": "Enabled",
            "next_run_at": "Next run",
            "last_run_at": "Last run",
            "output_dir": "Directory",
        }
        widths = {
            "id": 50,
            "name": 130,
            "format": 70,
            "frequency": 90,
            "enabled": 70,
            "next_run_at": 160,
            "last_run_at": 160,
            "output_dir": 230,
        }
        for column in columns:
            tree.heading(column, text=labels[column])
            tree.column(column, width=widths[column], minwidth=40)
        tree.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        actions = ttk.Frame(window)
        actions.pack(fill=tk.X, padx=8, pady=(0, 8))

        def refresh_schedules():
            tree.delete(*tree.get_children())
            rows = self.db.fetchall(
                """
                SELECT id, name, export_format, frequency, enabled, next_run_at, last_run_at, output_dir
                FROM audit_export_schedule
                ORDER BY id
                """
            )
            for row in rows:
                tree.insert("", tk.END, values=row)

        ttk.Button(actions, text="Add", command=lambda: self.create_export_schedule(on_done=refresh_schedules)).pack(side=tk.LEFT)
        ttk.Button(actions, text="Run due", command=lambda: self.run_due_export_schedules(on_done=refresh_schedules)).pack(side=tk.LEFT, padx=4)
        ttk.Button(actions, text="Refresh", command=refresh_schedules).pack(side=tk.LEFT)
        ttk.Button(actions, text="Close", command=window.destroy).pack(side=tk.RIGHT)

        refresh_schedules()

    def create_export_schedule(self, on_done=None):
        """Создает export schedule."""
        if not self.db or not self.key_manager:
            messagebox.showwarning("Аудит", "Расписание экспорта недоступно.", parent=self)
            return
        name = simpledialog.askstring("Расписание экспорта", "Название расписания:", initialvalue="daily", parent=self)
        if not name:
            return
        output_dir = filedialog.askdirectory(parent=self, title="Папка для экспорта аудита")
        if not output_dir:
            return
        export_format = simpledialog.askstring(
            "Расписание экспорта",
            "Формат: json, csv, pdf или cef",
            initialvalue="json",
            parent=self,
        )
        if not export_format:
            return
        frequency = simpledialog.askstring(
            "Расписание экспорта",
            "Период: daily, weekly или monthly",
            initialvalue="daily",
            parent=self,
        )
        if not frequency:
            return
        retention_days = simpledialog.askinteger(
            "Расписание экспорта",
            "Хранить экспортированные файлы, дней:",
            initialvalue=30,
            minvalue=1,
            parent=self,
        )
        if not retention_days:
            return
        try:
            exporter = AuditLogExporter(self.db, key_manager=self.key_manager, audit_logger=self.audit_manager)
            exporter.create_schedule(
                name=name,
                output_dir=os.path.abspath(output_dir),
                export_format=export_format,
                frequency=frequency,
                retention_days=retention_days,
                enabled=True,
            )
            if on_done:
                on_done()
            messagebox.showinfo("Расписание экспорта", "Расписание добавлено.", parent=self)
        except Exception as error:
            messagebox.showerror("Расписание экспорта", f"Не удалось добавить расписание:\n{translate_error_text(error)}", parent=self)

    def run_due_export_schedules(self, on_done=None):
        """Описывает публичное действие run due export schedules."""
        if not self.db or not self.audit_manager or not self.key_manager:
            messagebox.showwarning("Аудит", "Расписание экспорта недоступно.", parent=self)
            return
        try:
            if hasattr(self.audit_manager, "flush_async"):
                self.audit_manager.flush_async()
            exporter = AuditLogExporter(self.db, key_manager=self.key_manager, audit_logger=self.audit_manager)
            results = exporter.run_due_schedules(confirm_password=self._confirm_master_password)
            if on_done:
                on_done()
            messagebox.showinfo("Расписание экспорта", f"Выполнено экспортов: {len(results)}", parent=self)
        except PermissionError:
            messagebox.showwarning("Расписание экспорта", "Мастер-пароль не подтверждён.", parent=self)
        except Exception as error:
            messagebox.showerror("Расписание экспорта", f"Не удалось выполнить расписание:\n{translate_error_text(error)}", parent=self)

    def highlight_selected_entry(self):
        """Описывает публичное действие highlight selected entry."""
        row = self._selected_row()
        if not row or not row["entry_id"]:
            messagebox.showinfo("Журнал аудита", "У выбранного события нет связанной записи хранилища.", parent=self)
            return
        if self.on_entry_select:
            self.on_entry_select(row["entry_id"])

    def show_context_menu(self, event):
        """Показывает context menu."""
        item_id = self.table.identify_row(event.y)
        if item_id:
            self.table.selection_set(item_id)
        self.context_menu.tk_popup(event.x_root, event.y_root)

    def _selected_row(self):
        selected = self.table.selection()
        if not selected:
            return None
        selected_id = selected[0]
        for row in self.filtered_rows:
            if row["viewer_id"] == selected_id:
                return row
        return None

    @staticmethod
    def _decode_entry_data(value):
        if not value:
            return {}
        try:
            raw = value if isinstance(value, bytes) else str(value).encode("utf-8")
            return json.loads(raw.decode("utf-8"))
        except Exception:
            return {}

    @staticmethod
    def _decode_json(value):
        if not value:
            return {}
        try:
            return json.loads(value)
        except Exception:
            return {"raw": value}

    @staticmethod
    def _parse_date(value, end_of_day=False):
        if not value:
            return None
        text = str(value).strip()
        if not text:
            return None
        if len(text) == 10:
            text = f"{text}T23:59:59+00:00" if end_of_day else f"{text}T00:00:00+00:00"
        elif text.endswith("Z"):
            text = text[:-1] + "+00:00"
        try:
            parsed = datetime.fromisoformat(text)
            if parsed.tzinfo is None:
                return parsed.replace(tzinfo=timezone.utc)
            return parsed.astimezone(timezone.utc)
        except ValueError:
            return None

    @classmethod
    def _normalized_filter_date(cls, value, end_of_day=False):
        parsed = cls._parse_date(value, end_of_day=end_of_day)
        return parsed.isoformat() if parsed else None

    @staticmethod
    def _format_size(size):
        if size < 1024:
            return f"{size} байт"
        if size < 1024 * 1024:
            return f"{size / 1024:.1f} КБ"
        return f"{size / (1024 * 1024):.1f} МБ"

    def log(self, message):
        # Совместимость со старым кодом, который добавлял строки вручную.
        """Описывает публичное действие log."""
        self.details_text.config(state=tk.NORMAL)
        self.details_text.insert(tk.END, message + "\n")
        self.details_text.config(state=tk.DISABLED)
