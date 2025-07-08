# gui/components.py

import tkinter as tk
from tkinter import ttk, scrolledtext

class StatusBar(ttk.Frame):
    """
    A reusable status bar widget for displaying app-wide messages.
    """
    def __init__(self, parent, **kwargs):
        super().__init__(parent, **kwargs)
        self.label = ttk.Label(self, text="Ready", anchor="w", padding=5)
        self.label.pack(fill="both", expand=True)

    def set(self, message: str, fg="black", bg=None, auto_clear_ms=None):
        self.label.config(text=message, foreground=fg)
        if bg:
            self.label.config(background=bg)
        if auto_clear_ms:
            self.after(auto_clear_ms, self.clear)


class ScrolledConsoleOutput(scrolledtext.ScrolledText):
    """
    A styled scrolled text area for logging and console-style output.
    """
    def __init__(self, parent, **kwargs):
        super().__init__(parent, wrap=tk.WORD, height=12, font=("Courier New", 10), **kwargs)
        self.configure(state='disabled', background="#111", foreground="#0f0", insertbackground="white")

    def log(self, message: str):
        self.configure(state='normal')
        self.insert(tk.END, message + '\n')
        self.see(tk.END)
        self.configure(state='disabled')

    def log_with_level(self, message: str, level="INFO"):
        self.configure(state='normal')
        color = {"INFO": "#0f0", "ERROR": "#f00", "WARNING": "#ff0"}.get(level, "#0f0")
        self.insert(tk.END, f"{message}\n", level)
        self.tag_config(level, foreground=color)
        self.see(tk.END)
        self.configure(state='disabled')
    def clear(self):
        self.configure(state='normal')
        self.delete('1.0', tk.END)
        self.configure(state='disabled')


class ExpandablePanel(ttk.Frame):
    """
    A collapsible panel with a toggle button.
    Useful for organizing advanced options or grouped widgets.
    """
    def __init__(self, parent, title="Section", expanded=True, **kwargs):
        super().__init__(parent, **kwargs)
        self._expanded = expanded

        self.toggle_button = ttk.Button(self, text=f"[-] {title}", command=self._toggle)
        self.toggle_button.pack(fill="x")

        self.container = ttk.Frame(self)
        self.container.pack(fill="both", expand=True)

    def _toggle(self):
        if self._expanded:
            self.container.forget()
            self.toggle_button.config(text=f"[+] {self._title}")
        else:
            self.container.pack(fill="both", expand=True)
            self.toggle_button.config(text=f"[-] {self._title}")


    def get_container(self):
        return self.container

class ThreatLevelIndicator(ttk.Frame):
    """
    A visual indicator showing threat level (Low, Medium, High, Critical).
    """
    COLORS = {
        "Low": "#4CAF50",
        "Medium": "#FFC107",
        "High": "#FF5722",
        "Critical": "#F44336"
    }

    def __init__(self, parent, level="Low", **kwargs):
        super().__init__(parent, **kwargs)
        self.label = ttk.Label(self, text=f"Threat Level: {level}", foreground=self.COLORS.get(level, "black"))
        self.label.pack(padx=5, pady=5)

    def update_level(self, level: str):
        self.label.config(text=f"Threat Level: {level}", foreground=self.COLORS.get(level, "black"))
    def update_level(self, level: str):
        color = self.COLORS.get(level)
        if not color:
            logging.warning(f"Unknown threat level: {level}")
            color = "#999"
        self.label.config(text=f"Threat Level: {level}", foreground=color)
