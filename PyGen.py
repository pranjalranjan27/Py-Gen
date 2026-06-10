"""
PyGen — Password & Email Generator

Entry point for the application.
Launch with:  python pygen.py
"""

import random
from ui.main_window import App


def main():
    random.seed()
    app = App()
    app.mainloop()


if __name__ == "__main__":
    main()