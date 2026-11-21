"""Local Tkinter desktop interface; no web server or telemetry."""
import json
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from .__main__ import load_events
from .analyzer import analyze
from .anomaly import score_sources


def main():
    root = tk.Tk()
    root.title("KING SHIELD AI | DR Disso King")
    root.geometry("900x570")
    root.minsize(680, 400)
    root.configure(bg="#111827")
    frame = ttk.Frame(root, padding=16)
    frame.pack(fill="both", expand=True)
    ttk.Label(frame, text="KING SHIELD AI", font=("Segoe UI", 20, "bold")).pack(anchor="w")
    ttk.Label(frame, text="Offline Windows / Active Directory event analysis").pack(anchor="w")
    status = tk.StringVar(value="Open a normalized JSONL file to begin")
    ttk.Label(frame, textvariable=status).pack(anchor="w", pady=(12, 8))
    columns = ("severity", "event_id", "source", "reason")
    table = ttk.Treeview(frame, columns=columns, show="headings")
    for col, width in zip(columns, (95, 90, 150, 470)):
        table.heading(col, text=col.replace("_", " ").title())
        table.column(col, width=width, minwidth=70)
    table.pack(fill="both", expand=True)
    bar = ttk.Frame(frame)
    bar.pack(fill="x", pady=12)
    def open_file():
        path = filedialog.askopenfilename(filetypes=[("JSON Lines", "*.jsonl"), ("All files", "*.*")])
        if not path:
            return
        try:
            events = load_events(__import__("pathlib").Path(path))
            findings = analyze(events)
            anomalies = score_sources(events)
            table.delete(*table.get_children())
            for item in findings:
                table.insert("", "end", values=(item["severity"], item["event_id"], item["source"], item["reason"]))
            for item in anomalies:
                table.insert("", "end", values=("medium", "anomaly", item["source"], item["reason"]))
            status.set(f"{len(events)} events | {len(findings)} rules | {len(anomalies)} heuristic anomalies")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Analysis failed", str(exc))
    ttk.Button(bar, text="Open JSONL and analyze", command=open_file).pack(side="left")
    ttk.Label(bar, text="Local only | Read-only | No cloud uploads").pack(side="right")
    root.mainloop()


if __name__ == "__main__":
    main()
