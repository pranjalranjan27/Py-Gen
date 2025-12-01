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

EMAIL_DOMAINS = [
    "@gmail.com",
    "@yahoo.com",
    "@hotmail.com",
    "@outlook.com",
    "@edu.in",
    "Custom..."
]

FIRST_NAMES = [
    "pranjal", "samar", "aman", "aditya", "mike", "naitik", "nikhil", "simran", 
    "deepak", "maaya", "jatin", "abhishek", "robert", "eshita", "william",
    "osil", "shekhar", "shikha", "suraksha", "ruchi", "akshara", "divya",
    "aniket", "khushi", "satish", "akriti", "rehan", "hopper", "kunal",
    "kuldeep", "brian", "grace", "jason", "chloe", "peter", "victoria"
]

LAST_NAMES = [
    "kumar", "singh", "kumari", "yadav", "raj", "sharma", "srivastav",
    "jha", "pathak", "thakur", "anand", "taylor", "kohli",
    "chawla", "luthra", "khan", "lee", "chauhan", "suryavanshi", "kapoor",
    "rathore", "lewis", "harrington", "wheeler", "byers", "allen", "king",
    "wright", "scott", "torres", "nguyen", "hill", "flores", "green"
]


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


def generate_random_email(length, domain, include_digits=True):
    """Generate a completely random email address."""
    chars = string.ascii_lowercase
    if include_digits:
        chars += string.digits
    
    username = "".join(random.choice(chars) for _ in range(length))
    return username + domain


def generate_name_based_email(domain, use_dot=True, add_numbers=True, custom_first="", custom_last=""):
    """Generate a name-based email address."""
    first = custom_first.lower().strip() if custom_first.strip() else random.choice(FIRST_NAMES)
    last = custom_last.lower().strip() if custom_last.strip() else random.choice(LAST_NAMES)
    
    first = ''.join(c for c in first if c.isalnum())
    last = ''.join(c for c in last if c.isalnum())
    
    if not first:
        first = random.choice(FIRST_NAMES)
    if not last:
        last = random.choice(LAST_NAMES)
    
    formats = [
        f"{first}{last}",          
        f"{first}.{last}",          
        f"{first}_{last}",          
        f"{first[0]}{last}",        
        f"{first}{last[0]}",        
        f"{last}{first}",           
        f"{last}.{first}",         
        f"{first}{last[:3]}",       
    ]
    
    username = random.choice(formats)
    
    if add_numbers:
        num_style = random.choice([
            str(random.randint(1, 99)),
            str(random.randint(100, 999)),
            str(random.randint(1990, 2010)),
            str(random.randint(1, 9)) + str(random.randint(1, 9)),
        ])
        username += num_style
    
    return username + domain


def analyze_email(email):
    """Analyze the generated email for various properties."""
    info = {
        "total_length": len(email),
        "username": "",
        "domain": "",
        "username_length": 0,
        "has_numbers": False,
        "has_special": False,
        "format_type": "random",
    }
    
    if "@" in email:
        parts = email.split("@")
        info["username"] = parts[0]
        info["domain"] = "@" + parts[1]
        info["username_length"] = len(parts[0])
        info["has_numbers"] = any(c.isdigit() for c in parts[0])
        info["has_special"] = any(c in "._-" for c in parts[0])
        
        if "." in parts[0] or "_" in parts[0]:
            info["format_type"] = "name-based"
        elif any(name in parts[0].lower() for name in FIRST_NAMES + LAST_NAMES):
            info["format_type"] = "name-based"
        else:
            info["format_type"] = "random"
    
    return info


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("PYGEN")
        self.geometry("700x580")
        self.resizable(False, False)

        self.var_length = tk.IntVar(value=12)
        self.var_lower = tk.BooleanVar(value=True)
        self.var_upper = tk.BooleanVar(value=True)
        self.var_digits = tk.BooleanVar(value=True)
        self.var_symbols = tk.BooleanVar(value=False)
        self.var_avoid_amb = tk.BooleanVar(value=True)

        self.var_email_style = tk.StringVar(value="random")
        self.var_email_length = tk.IntVar(value=10)
        self.var_email_domain = tk.StringVar(value="@gmail.com")
        self.var_custom_domain = tk.StringVar(value="")
        self.var_email_digits = tk.BooleanVar(value=True)
        self.var_email_numbers = tk.BooleanVar(value=True)
        self.var_first_name = tk.StringVar(value="")
        self.var_last_name = tk.StringVar(value="")

        self._last_report = None
        self._last_email_info = None
        self._build_ui()

    def _build_ui(self):
        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.password_frame = ttk.Frame(self.notebook)
        self.email_frame = ttk.Frame(self.notebook)

        self.notebook.add(self.password_frame, text="  Password Generator  ")
        self.notebook.add(self.email_frame, text="  Email Generator  ")

        self._build_password_tab()
        self._build_email_tab()

    def _build_password_tab(self):
        """Build the password generator tab."""
        frame = self.password_frame
        pad = {'padx': 8, 'pady': 4}

        options_frame = ttk.LabelFrame(frame, text="Password Options", padding=10)
        options_frame.pack(fill="x", padx=10, pady=(10, 5))

        length_frame = ttk.Frame(options_frame)
        length_frame.pack(fill="x", pady=2)
        ttk.Label(length_frame, text="Length:").pack(side="left")
        spin = ttk.Spinbox(length_frame, from_=4, to=64, textvariable=self.var_length, width=6)
        spin.pack(side="left", padx=5)
        ttk.Button(length_frame, text="Generate", command=self.on_generate).pack(side="right", padx=5)

        ttk.Checkbutton(options_frame, text="Include lowercase", variable=self.var_lower).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Include UPPERCASE", variable=self.var_upper).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Include digits (0-9)", variable=self.var_digits).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Include symbols (!@#$...)", variable=self.var_symbols).pack(anchor="w")
        ttk.Checkbutton(options_frame, text="Avoid ambiguous (l,1,I,0,O)", variable=self.var_avoid_amb).pack(anchor="w")

        output_frame = ttk.LabelFrame(frame, text="Generated Password", padding=10)
        output_frame.pack(fill="x", padx=10, pady=5)

        pwd_row = ttk.Frame(output_frame)
        pwd_row.pack(fill="x", pady=2)
        ttk.Label(pwd_row, text="Password:").pack(side="left")
        self.out_pwd = ttk.Entry(pwd_row, width=40)
        self.out_pwd.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(pwd_row, text="Check", command=self.on_check).pack(side="left", padx=2)
        ttk.Button(pwd_row, text="Copy", command=self.on_copy).pack(side="left", padx=2)

        strength_row = ttk.Frame(output_frame)
        strength_row.pack(fill="x", pady=5)
        ttk.Label(strength_row, text="Strength:").pack(side="left")
        self.pb = ttk.Progressbar(strength_row, orient="horizontal", mode="determinate", length=200, maximum=100, value=0)
        self.pb.pack(side="left", padx=5)
        self.lbl_verdict = ttk.Label(strength_row, text="Click Check to analyze")
        self.lbl_verdict.pack(side="left", padx=5)
        self.btn_save = ttk.Button(strength_row, text="Save", command=self.on_save, state="disabled")
        self.btn_save.pack(side="right", padx=5)

        txt_frame = ttk.Frame(frame)
        txt_frame.pack(fill="both", padx=10, pady=5, expand=True)
        
        self.txt = tk.Text(txt_frame, height=10, width=75, wrap="word")
        txt_scrollbar = ttk.Scrollbar(txt_frame, orient="vertical", command=self.txt.yview)
        self.txt.configure(yscrollcommand=txt_scrollbar.set)
        
        self.txt.pack(side="left", fill="both", expand=True)
        txt_scrollbar.pack(side="right", fill="y")

        self._clear_report(prompt=True)

    def _build_email_tab(self):
        """Build the email generator tab."""
        frame = self.email_frame

        style_frame = ttk.LabelFrame(frame, text="Email Style", padding=10)
        style_frame.pack(fill="x", padx=10, pady=(10, 5))

        style_row = ttk.Frame(style_frame)
        style_row.pack(fill="x", pady=2)
        ttk.Radiobutton(style_row, text="Random String", variable=self.var_email_style, 
                        value="random", command=self._on_style_change).pack(side="left", padx=10)
        ttk.Radiobutton(style_row, text="Name-Based", variable=self.var_email_style, 
                        value="name", command=self._on_style_change).pack(side="left", padx=10)

        self.random_options_frame = ttk.Frame(style_frame)
        self.random_options_frame.pack(fill="x", pady=5)
        ttk.Label(self.random_options_frame, text="Username Length:").pack(side="left")
        self.email_length_spin = ttk.Spinbox(self.random_options_frame, from_=5, to=20, 
                                              textvariable=self.var_email_length, width=6)
        self.email_length_spin.pack(side="left", padx=5)
        ttk.Checkbutton(self.random_options_frame, text="Include digits", 
                        variable=self.var_email_digits).pack(side="left", padx=10)

        self.name_options_frame = ttk.Frame(style_frame)
        
        name_row1 = ttk.Frame(self.name_options_frame)
        name_row1.pack(fill="x", pady=2)
        ttk.Label(name_row1, text="First Name:").pack(side="left")
        self.first_name_entry = ttk.Entry(name_row1, textvariable=self.var_first_name, width=15)
        self.first_name_entry.pack(side="left", padx=5)
        ttk.Label(name_row1, text="Last Name:").pack(side="left", padx=(10, 0))
        self.last_name_entry = ttk.Entry(name_row1, textvariable=self.var_last_name, width=15)
        self.last_name_entry.pack(side="left", padx=5)
        
        name_row2 = ttk.Frame(self.name_options_frame)
        name_row2.pack(fill="x", pady=2)
        ttk.Checkbutton(name_row2, text="Add numbers at end", 
                        variable=self.var_email_numbers).pack(side="left", padx=5)
        ttk.Label(name_row2, text="(Leave names empty for random)", 
                  foreground="gray").pack(side="left", padx=10)

        domain_frame = ttk.LabelFrame(frame, text="Email Domain", padding=10)
        domain_frame.pack(fill="x", padx=10, pady=5)

        domain_row = ttk.Frame(domain_frame)
        domain_row.pack(fill="x", pady=2)
        ttk.Label(domain_row, text="Domain:").pack(side="left")
        self.domain_combo = ttk.Combobox(domain_row, textvariable=self.var_email_domain, 
                                          values=EMAIL_DOMAINS, state="readonly", width=20)
        self.domain_combo.pack(side="left", padx=5)
        self.domain_combo.bind("<<ComboboxSelected>>", self._on_domain_change)

        self.custom_domain_frame = ttk.Frame(domain_frame)
        ttk.Label(self.custom_domain_frame, text="Custom Domain:").pack(side="left")
        self.custom_domain_entry = ttk.Entry(self.custom_domain_frame, textvariable=self.var_custom_domain, width=25)
        self.custom_domain_entry.pack(side="left", padx=5)
        ttk.Label(self.custom_domain_frame, text="(e.g., @company.com)").pack(side="left")

        btn_frame = ttk.Frame(domain_frame)
        btn_frame.pack(fill="x", pady=10)
        ttk.Button(btn_frame, text="Generate Email", command=self.on_generate_email).pack(side="right")

        email_output_frame = ttk.LabelFrame(frame, text="Generated Email", padding=10)
        email_output_frame.pack(fill="x", padx=10, pady=5)

        email_row = ttk.Frame(email_output_frame)
        email_row.pack(fill="x", pady=2)
        ttk.Label(email_row, text="Email:").pack(side="left")
        self.out_email = ttk.Entry(email_row, width=45)
        self.out_email.pack(side="left", padx=5, fill="x", expand=True)
        ttk.Button(email_row, text="Copy", command=self.on_copy_email).pack(side="left", padx=2)
        self.btn_save_email = ttk.Button(email_row, text="Save", command=self.on_save_email)
        self.btn_save_email.pack(side="left", padx=2)

        email_txt_frame = ttk.Frame(frame)
        email_txt_frame.pack(fill="both", padx=10, pady=5, expand=True)
        
        self.email_txt = tk.Text(email_txt_frame, height=12, width=75, wrap="word")
        email_scrollbar = ttk.Scrollbar(email_txt_frame, orient="vertical", command=self.email_txt.yview)
        self.email_txt.configure(yscrollcommand=email_scrollbar.set)
        
        self.email_txt.pack(side="left", fill="both", expand=True)
        email_scrollbar.pack(side="right", fill="y")

        self._clear_email_info(prompt=True)

    def _on_style_change(self):
        """Handle email style change."""
        style = self.var_email_style.get()
        if style == "random":
            self.name_options_frame.pack_forget()
            self.random_options_frame.pack(fill="x", pady=5)
        else:
            self.random_options_frame.pack_forget()
            self.name_options_frame.pack(fill="x", pady=5)

    def _on_domain_change(self, event=None):
        """Handle domain selection change."""
        domain = self.var_email_domain.get()
        if domain == "Custom...":
            self.custom_domain_frame.pack(fill="x", pady=5)
        else:
            self.custom_domain_frame.pack_forget()

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
            self.txt.insert(tk.END, 'Enter or generate a password, then click "Check".')
   
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

    def on_generate_email(self):
        """Generate a random email address."""
        style = self.var_email_style.get()
        domain = self.var_email_domain.get()
        
        if domain == "Custom...":
            domain = self.var_custom_domain.get().strip()
            if not domain:
                messagebox.showwarning("No Domain", "Please enter a custom domain.")
                return
            if not domain.startswith("@"):
                domain = "@" + domain
        
        if style == "random":
            length = self.var_email_length.get()
            if length < 5:
                messagebox.showwarning("Length too small", "Minimum username length is 5.")
                self.var_email_length.set(5)
                length = 5
            include_digits = self.var_email_digits.get()
            email = generate_random_email(length, domain, include_digits)
        else:
            add_numbers = self.var_email_numbers.get()
            first_name = self.var_first_name.get()
            last_name = self.var_last_name.get()
            email = generate_name_based_email(domain, add_numbers=add_numbers, 
                                               custom_first=first_name, custom_last=last_name)
        
        self.out_email.delete(0, tk.END)
        self.out_email.insert(0, email)
        
        info = analyze_email(email)
        self._last_email_info = info
        self._show_email_info(info)

    def on_copy_email(self):
        """Copy email to clipboard."""
        email = self.out_email.get()

        if not email:
            messagebox.showinfo("Nothing to copy", "Generate an email first.")
            return

        self.clipboard_clear()
        self.clipboard_append(email)
        messagebox.showinfo("Copied", "Email copied to clipboard.")

    def on_save_email(self):
        """Save email to file."""
        email = self.out_email.get()

        if not email:
            messagebox.showinfo("Nothing to save", "Generate an email first.")
            return

        try:
            with open("emails.txt", "a", encoding="utf-8") as f:
                ts = time.strftime("%Y-%m-%d %H:%M:%S")
                style = self.var_email_style.get()
                f.write(f"[{ts}] {email}  |  type={style}\n")

            messagebox.showinfo("Saved", "Saved to emails.txt")

        except OSError as e:
            messagebox.showerror("Save failed", str(e))

    def _clear_email_info(self, prompt=False):
        """Clear email info display."""
        self._last_email_info = None
        self.email_txt.delete("1.0", tk.END)

        if prompt:
            self.email_txt.insert(tk.END, 'Select your options and click "Generate Email".\n\n')
            self.email_txt.insert(tk.END, "Email Styles:\n")
            self.email_txt.insert(tk.END, "  • Random String: Creates a random alphanumeric username\n")
            self.email_txt.insert(tk.END, "    Example: xk7m9p2q@gmail.com\n\n")
            self.email_txt.insert(tk.END, "  • Name-Based: Creates realistic-looking usernames\n")
            self.email_txt.insert(tk.END, "    Example: john.smith1234@gmail.com\n")

    def _show_email_info(self, info):
        """Display email information."""
        self.email_txt.delete("1.0", tk.END)

        lines = []
        lines.append("═══════════════════════════════════════")
        lines.append("              EMAIL ANALYSIS")
        lines.append("═══════════════════════════════════════")
        lines.append("")
        lines.append(f"  Total Length:     {info['total_length']} characters")
        lines.append(f"  Username:         {info['username']}")
        lines.append(f"  Username Length:  {info['username_length']} characters")
        lines.append(f"  Domain:           {info['domain']}")
        lines.append(f"  Format Type:      {info['format_type'].title()}")
        lines.append(f"  Contains Numbers: {'Yes' if info['has_numbers'] else 'No'}")
        lines.append(f"  Contains Special: {'Yes' if info['has_special'] else 'No'}")
        lines.append("")
        lines.append("═══════════════════════════════════════")

        self.email_txt.insert(tk.END, "\n".join(lines))


if __name__ == "__main__":
    random.seed()
    app = App()
    app.mainloop()