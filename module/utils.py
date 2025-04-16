import secrets
import string
import os
import pandas as pd
from datetime import datetime
from PyQt5.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import QTextEdit
import time

def get_desktop_path() -> str:
    """Get desktop path"""
    desktop_path = os.path.expanduser("~/Desktop")
    if not os.path.exists(desktop_path):
        return os.getcwd()
    return desktop_path

def get_log_path(suffix: str) -> str:
    """Generate log file path"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    if suffix == "success":
        filename = f"NASecurity_en_Log_{date_str}.xlsx"
    else:
        filename = f"NASecurity_en_Error_Log_{date_str}.xlsx"
    full_path = os.path.join(get_desktop_path(), filename)
    return full_path

def generate_random_password(length: int = 12, exclude_chars: str = "") -> str:
    """Generate random password"""
    alphabet = ''.join(c for c in string.ascii_letters + string.digits + string.punctuation if c not in exclude_chars)
    pwd = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ] + [secrets.choice(alphabet) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(pwd)
    return ''.join(pwd)

class LogManager:
    """Log manager"""
    def __init__(self):
        self.success_logs = []
        self.error_logs = []
        self.success_file = get_log_path("success")
        self.error_file = get_log_path("error")
        self.success_cols = ["Date", "Accout", "ID", "Name", "Results", "Changed Password"]
        self.error_cols = ["Date", "Accout", "ID", "Name", "Error Messages"]

    def add_log(self, account: str, emp_id: str, name: str, result: str, new_password: str = "", is_error: bool = False):
        """Add log field"""
        entry = {
            "Date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "Accout": account,
            "ID": emp_id if pd.notna(emp_id) else "Unknown ID",
            "Name": name if pd.notna(name) else "Unknown Name",
        }
        if is_error:
            entry["Error Messages"] = result
            self.error_logs.append(entry)
        else:
            entry["Results"] = result
            entry["Changed Password"] = new_password if "successfully" in result.lower() else ""
            self.success_logs.append(entry)

    def save_to_file(self):
        """Save logs to file"""
        for logs, filename, columns in [
            (self.success_logs, self.success_file, self.success_cols),
            (self.error_logs, self.error_file, self.error_cols)
        ]:
            if not logs:
                continue
            for attempt in range(3):
                try:
                    df = pd.read_excel(filename) if os.path.exists(filename) else pd.DataFrame(columns=columns)
                    df = pd.concat([df, pd.DataFrame(logs)], ignore_index=True)
                    df.to_excel(filename, index=False)
                    logs.clear()
                    break
                except PermissionError:
                    time.sleep(1)
                except Exception as e:
                    if attempt == 2:
                        raise

def append_colored_text(text_widget: QTextEdit, message: str, color: str):
    """Add colored text to text box"""
    cursor = text_widget.textCursor()
    cursor.movePosition(QTextCursor.End)
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(color))
    cursor.insertText(f"{message}\n", fmt)
    text_widget.setTextCursor(cursor)
    text_widget.ensureCursorVisible()