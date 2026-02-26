"""
Виджет для ввода пароля.
"""
import tkinter as tk
from tkinter import ttk


class PasswordEntry(ttk.Frame):
    """Поле ввода пароля с кнопкой показа."""
    
    def __init__(self, master, **kwargs):
        super().__init__(master)
        
        self.show_password = tk.BooleanVar(value=False)
        self.width = kwargs.pop('width', 20)
        
        self._create_widgets()
        self.show_password.trace('w', self._toggle_show)
    
    def _create_widgets(self):
        self.entry = ttk.Entry(
            self,
            show="*",
            width=self.width
        )
        self.entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        self.show_btn = ttk.Button(
            self,
            text="👁",
            width=3,
            command=self._toggle_show_click
        )
        self.show_btn.pack(side=tk.RIGHT, padx=(2, 0))
    
    def _toggle_show_click(self):
        self.show_password.set(not self.show_password.get())
    
    def _toggle_show(self, *args):
        if self.show_password.get():
            self.entry.config(show="")
            self.show_btn.config(text="👁‍🗨")
        else:
            self.entry.config(show="*")
            self.show_btn.config(text="👁")
    
    def get(self) -> str:
        return self.entry.get()
    
    def set(self, value: str):
        self.entry.delete(0, tk.END)
        self.entry.insert(0, value)
    
    def clear(self):
        self.entry.delete(0, tk.END)
    
    def focus(self):
        self.entry.focus()
