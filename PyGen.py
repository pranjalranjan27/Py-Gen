import random
import string
import time
import tkinter as tk
from tkinter import ttk, messagebox

CHARSETS = (
    ("lowercase", string.ascii_lowercase),
    ("uppercase", string.ascii_uppercase),
    ("digits", string.digits),
    ("symbols", "!@#$%^&*()-_=+[]{}<>?/"),
)
AMBIGUOUS = set("l1I0O")

def build_charset(use_lower, use_upper, use_digits, use_symbols, avoid_ambiguous):
    chars = []

    if use_lower:
        chars += list(string.ascii_lowercase)
    if use_upper:
        chars += list(string.ascii_uppercase)
    if use_digits:
        chars += list(string.digits)
    if use_symbols:
        chars += list("!@#$%^&*()-_=+[]{}<>?/")

    if avoid_ambiguous:
        chars = [c for c in chars if c not in AMBIGUOUS]

    if not chars:
        chars = list(string.ascii_lowercase)

    return "".join(chars)

def generate_password(length, pool):
    if length <= 0:
        length = 8
    return "".join(random.choice(pool) for _ in range(length))

def analyze_password(pwd):
    length = len(pwd)

    classes = {
        "lower": any(c.islower() for c in pwd),
        "upper": any(c.isupper() for c in pwd),
        "digit": any(c.isdigit() for c in pwd),
        "symbol": any(c in CHARSETS[3][1] for c in pwd),
    }

    unique_chars = len(set(pwd))
    repeats = length - unique_chars

    score = 0
    reasons = []

    if length >= 16:
        score += 40
    elif length >= 12:
        score += 30
    elif length >= 8:
        score += 20
    else:
        score += 10
        reasons.append("Too short (< 8)")

    diversity = sum(classes.values())
    score += diversity * 15

    if diversity == 1:
        reasons.append("Only one character type")
    elif diversity == 2:
        reasons.append("Consider adding more types")
    elif diversity >= 3:
        reasons.append("Good variety")

    if repeats >= 4:
        score -= 15
        reasons.append("Too many repeated characters")

    score = max(0, min(100, score))

    if score >= 80:
        verdict = "Strong"
    elif score >= 60:
        verdict = "Good"
    elif score >= 40:
        verdict = "Fair"
        reasons.append("Low entropy, try mixing more characters")
    else:
        verdict = "Weak"

    return {
        "length": length,
        "classes": classes,
        "unique": unique_chars,
        "repeats": repeats,
        "score": score,
        "verdict": verdict,
        "reasons": reasons,
    }

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Password Generator — Python Tkinter")
        self.geometry("620x390")
        self.resizable(False, False)

        self.var_length = tk.IntVar(value=12)
        self.var_lower = tk.BooleanVar(value=True)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=False)
        self.var_avoid_amb = tk.BooleanVar(value=True)

        self._last_report = None
        self._build_ui()

    def _build_ui(self):
        pad = {'padx': 10, 'pady': 6}
        frame = ttk.Frame(self)
        frame.pack(fill="both", expand=True, **pad)

        ttk.Label(frame, text="Length:").grid(row=0, column=0, sticky="w")
        spin = ttk.Spinbox(frame, from_=4, to=64, textvariable=self.var_length, width=6)
        spin.grid(row=0, column=1, sticky="w")

        ttk.Checkbutton(frame, text="Include lowercase", variable=self.var_lower).grid(row=1, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(frame, text="Include UPPERCASE", variable=self.var_upper).grid(row=2, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(frame, text="Include digits (0-9)", variable=self.var_digits).grid(row=3, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(frame, text="Include symbols (!@#$...)", variable=self.var_symbols).grid(row=4, column=0, columnspan=2, sticky="w")
        ttk.Checkbutton(frame, text="Avoid ambiguous (l,1,I,0,O)", variable=self.var_avoid_amb).grid(row=5, column=0, columnspan=2, sticky="w")

        ttk.Button(frame, text="Generate", command=self.on_generate).grid(row=0, column=3, rowspan=2, sticky="e", padx=10)

        ttk.Label(frame, text="Password:").grid(row=6, column=0, sticky="w", pady=(12, 0))
        self.out_pwd = ttk.Entry(frame, width=48)
        self.out_pwd.grid(row=6, column=1, columnspan=3, sticky="we", pady=(12, 0))

        btns = ttk.Frame(frame)
        btns.grid(row=6, column=4, sticky="w", padx=5, pady=(12, 0))

        ttk.Button(btns, text="Check", command=self.on_check).grid(row=0, column=0, padx=(0, 6))
        ttk.Button(btns, text="Copy", command=self.on_copy).grid(row=0, column=1)

        ttk.Label(frame, text="Strength:").grid(row=7, column=0, sticky="w")
        self.pb = ttk.Progressbar(frame, orient="horizontal", mode="determinate", length=250, maximum=100, value=0)
        self.pb.grid(row=7, column=1, columnspan=2, sticky="we")

        self.lbl_verdict = ttk.Label(frame, text="-")
        self.lbl_verdict.grid(row=7, column=3, sticky="w")

        self.btn_save = ttk.Button(frame, text="Save", command=self.on_save, state="disabled")
        self.btn_save.grid(row=7, column=4, sticky="w", padx=5)

        self.txt = tk.Text(frame, height=10, width=72)
        self.txt.grid(row=8, column=0, columnspan=5, sticky="we", pady=(8, 0))

        for c in range(5):
            frame.grid_columnconfigure(c, weight=1)

        self._clear_report(prompt=True)

    def on_generate(self):
        length = self.var_length.get()

        if length < 8:
            messagebox.showwarning("Length too small", "Minimum length is 8.")
            self.var_length.set(8)
            length = 8

        pool = build_charset(
            use_lower=self.var_lower.get(),
            use_upper=self.var_upper.get(),
            use_digits=self.var_digits.get(),
            use_symbols=self.var_symbols.get(),
            avoid_ambiguous=self.var_avoid_amb.get()
        )

        pwd = generate_password(length, pool)
        self.out_pwd.delete(0, tk.END)
        self.out_pwd.insert(0, pwd)
        self._clear_report(prompt=True)

    def on_check(self):
        pwd = self.out_pwd.get()

        if not pwd:
            messagebox.showinfo("Nothing to check", "Enter or generate a password first.")
            return

        report = analyze_password(pwd)
        self._last_report = report
        self._show_report(report)
        self.btn_save.config(state="normal")

    def on_copy(self):
        pwd = self.out_pwd.get()

        if not pwd:
            messagebox.showinfo("Nothing to copy", "Generate or type a password first.")
            return

        self.clipboard_clear()
        self.clipboard_append(pwd)
        messagebox.showinfo("Copied", "Password copied to clipboard.")

    def on_save(self):
        if not self._last_report:
            messagebox.showinfo("Nothing to save", "Click Check first.")
            return

        pwd = self.out_pwd.get()

        if not pwd:
            messagebox.showinfo("Nothing to save", "Enter or generate a password first.")
            return

        try:
            with open("passwords.txt", "a", encoding="utf-8") as f:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                f.write(f"[{ts}] {pwd}  |  score={self._last_report['score']} verdict={self._last_report['verdict']}\n")

            messagebox.showinfo("Saved", "Saved to passwords.txt")

        except OSError as e:
            messagebox.showerror("Save failed", str(e))

    def _clear_report(self, prompt=False):
        self._last_report = None
        self.btn_save.config(state="disabled")
        self.pb["value"] = 0
        self.lbl_verdict.config(text="-" if not prompt else "Click Check to analyze")
        self.txt.delete("1.0", tk.END)

        if prompt:
            self.txt.insert(tk.END, "Enter or generate a password, then click “Check”.")
   
    def _show_report(self, report):
        self.pb["value"] = report["score"]
        self.lbl_verdict.config(text=f"{report['verdict']} ({report['score']}/100)")

        lines = []
        lines.append(f"Length: {report['length']}")
        present = [k for k, v in report["classes"].items() if v]
        lines.append("Classes: " + (", ".join(present) if present else "none"))
        lines.append(f"Unique chars: {report['unique']}  |  Repeats: {report['repeats']}")

        if report["reasons"]:
            lines.append("Notes:")
            for r in report["reasons"]:
                lines.append(f"  - {r}")

        self.txt.delete("1.0", tk.END)
        self.txt.insert(tk.END, "\n".join(lines))

if __name__ == "__main__":
    random.seed()
    app = App()
    app.mainloop()