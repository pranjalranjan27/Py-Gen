# PyGen

A lightweight **Password & Email Generator** desktop application built with pure **Python** and **Tkinter**.

Designed as an educational project to learn about GUI development, modular code organization, and practical utility building in Python.



## Features
- Generate randomized or custom emails & secure passwords
- Select character types (lower, upper, digits, symbols)
- Set your name and the domain you want and that's all
- Analyze password strength
- Copy desired results directly to you clipboard
- Save them in separate files


### Password Generator
- Generate secure random passwords with customizable length (8–64 characters)
- Select character types: lowercase, uppercase, digits, symbols
- Option to avoid ambiguous characters (l, 1, I, 0, O)
- Real-time password strength analysis with score and verdict
- Copy to clipboard and save to file

### Email Generator
- **Random mode** — generates fully random alphanumeric usernames
- **Name-based mode** — creates realistic usernames from name pools or custom input
- Choose from preset domains or enter a custom domain
- Email analysis report (username breakdown, format detection, etc.)
- Copy to clipboard and save to file

---

## How to Run

**Prerequisites:** Python 3.x with Tkinter (included in most Python installations)

```bash
# Clone the repository
git clone https://github.com/your-username/PyGen.git
cd PyGen

# Run the application
python pygen.py
```

> **Note:** On some Linux distributions, Tkinter may need to be installed separately:
> ```bash
> sudo apt install python3-tk        # Debian/Ubuntu
> sudo dnf install python3-tkinter   # Fedora
> ```

---

## Project Structure

```
PyGen/
├── pygen.py                      # Application entry point
├── ui/
│   └── main_window.py            # Tkinter UI — window, tabs, event handlers
├── core/
│   ├── password_generator.py     # Password generation logic
│   ├── password_analyzer.py      # Password strength analysis
│   ├── email_generator.py        # Email generation (random & name-based)
│   └── email_analyzer.py         # Email property analysis
├── utils/
│   ├── constants.py              # Shared data — charsets, domains, name pools
│   └── file_handler.py           # Save-to-file utilities
├── data/                         # Generated output files (auto-created)
│   ├── passwords.txt
│   └── emails.txt
├── requirements.txt              # Dependencies (stdlib only)
└── README.md
```

---

## Technologies Used

- **Python 3** — core language
- **Tkinter** — GUI framework (standard library)
- **No external dependencies** — runs out of the box

---