"""
Password Strength Meter — виджет оценки сложности пароля.
"""

import tkinter as tk
from tkinter import ttk


class PasswordStrengthMeter(ttk.Frame):
    """Виджет отображения оценки пароля (DIALOG-1)."""

    COLORS = ["#ff4444", "#ff8800", "#ffcc00", "#44cc44", "#00cc00"]
    LABELS = ["Очень слабый", "Слабый", "Средний", "Сильный", "Очень сильный"]

    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)

        self.progress = ttk.Progressbar(self, orient=tk.HORIZONTAL, length=200, mode='determinate')
        self.progress.pack(fill=tk.X, padx=5, pady=2)

        self.label = ttk.Label(self, text="", font=("Arial", 8))
        self.label.pack(anchor=tk.W, padx=5)

    def update_strength(self, score: int):
        """Обновить индикатор оценки (0-4)."""
        score = max(0, min(4, score))
        self.progress['value'] = (score + 1) * 20
        self.label.config(text=self.LABELS[score], foreground=self.COLORS[score])

    def reset(self):
        """Сбросить индикатор."""
        self.progress['value'] = 0
        self.label.config(text="")
