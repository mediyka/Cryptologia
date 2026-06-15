import tkinter as tk
from tkinter import ttk, messagebox


class QRCodeDialog(tk.Toplevel):
    """Описывает публичный класс QRCodeDialog."""
    def __init__(self, parent, bundle):
        super().__init__(parent)
        self.bundle = bundle

        self.title("QR-код")
        self.geometry("760x560")
        self.transient(parent)
        self.grab_set()

        self._create_widgets()

    def _create_widgets(self):
        root = ttk.Frame(self, padding=10)
        root.pack(fill=tk.BOTH, expand=True)

        info = ttk.LabelFrame(root, text="Данные QR", padding=8)
        info.pack(fill=tk.X)
        ttk.Label(info, text=f"Тип: {self.bundle.payload_type}").pack(anchor=tk.W)
        ttk.Label(info, text=f"ID: {self.bundle.payload_id}").pack(anchor=tk.W)
        ttk.Label(info, text=f"Истекает: {self.bundle.expires_at}").pack(anchor=tk.W)
        ttk.Label(info, text=f"SHA-256: {self.bundle.checksum}").pack(anchor=tk.W)

        chunks = ttk.LabelFrame(root, text="Фрагменты QR", padding=8)
        chunks.pack(fill=tk.BOTH, expand=True, pady=8)
        self.canvas = tk.Canvas(chunks, width=280, height=280, background="white", highlightthickness=1, highlightbackground="#888")
        self.canvas.pack(anchor=tk.CENTER, pady=(0, 8))
        self.chunk_list = tk.Listbox(chunks, height=6)
        self.chunk_list.pack(fill=tk.X)
        for chunk in self.bundle.chunks:
            svg_note = " + SVG" if chunk.image_svg else ""
            self.chunk_list.insert(tk.END, f"{chunk.index}/{chunk.total} {chunk.checksum[:12]}{svg_note}")
        self.chunk_list.bind("<<ListboxSelect>>", lambda event: self._show_selected_chunk())

        self.text = tk.Text(chunks, height=12, wrap=tk.WORD)
        self.text.pack(fill=tk.BOTH, expand=True, pady=(8, 0))
        if self.bundle.chunks:
            self.chunk_list.selection_set(0)
            self._show_selected_chunk()

        footer = ttk.Frame(root)
        footer.pack(fill=tk.X)
        ttk.Button(footer, text="Копировать фрагмент", command=self._copy_selected_chunk).pack(side=tk.LEFT)
        ttk.Button(footer, text="Копировать все", command=self._copy_all_chunks).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(footer, text="Закрыть", command=self.destroy).pack(side=tk.RIGHT)

    def _selected_chunk(self):
        selection = self.chunk_list.curselection()
        if not selection:
            return None
        return self.bundle.chunks[selection[0]]

    def _show_selected_chunk(self):
        chunk = self._selected_chunk()
        self.text.delete("1.0", tk.END)
        if chunk:
            self.text.insert("1.0", chunk.encoded_text)
            self._draw_qr(chunk.encoded_text)

    def _draw_qr(self, encoded_text: str):
        self.canvas.delete("all")
        try:
            import qrcode
        except Exception:
            self.canvas.create_text(140, 140, text="Отрисовка QR недоступна", fill="#555")
            return

        qr = qrcode.QRCode(version=1, error_correction=qrcode.constants.ERROR_CORRECT_M, border=2)
        qr.add_data(encoded_text)
        qr.make(fit=True)
        matrix = qr.get_matrix()
        if not matrix:
            return
        size = min(270 // len(matrix), 10)
        offset = (280 - len(matrix) * size) // 2
        for y, row in enumerate(matrix):
            for x, enabled in enumerate(row):
                if enabled:
                    x1 = offset + x * size
                    y1 = offset + y * size
                    self.canvas.create_rectangle(x1, y1, x1 + size, y1 + size, outline="", fill="black")

    def _copy_selected_chunk(self):
        chunk = self._selected_chunk()
        if not chunk:
            return
        self.clipboard_clear()
        self.clipboard_append(chunk.encoded_text)
        messagebox.showinfo("QR", "Фрагмент скопирован.", parent=self)

    def _copy_all_chunks(self):
        text = "\n".join(chunk.encoded_text for chunk in self.bundle.chunks)
        self.clipboard_clear()
        self.clipboard_append(text)
        messagebox.showinfo("QR", "Все фрагменты скопированы.", parent=self)
