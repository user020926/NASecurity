import secrets
import string
import os
import pandas as pd
from datetime import datetime
from PyQt5.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import QTextEdit
import time

def get_desktop_path() -> str:
    """獲取當前使用者的桌面路徑
    Returns:
        桌面路徑，若不存在則返回當前工作目錄
    """
    desktop_path = os.path.expanduser("~/Desktop")
    if not os.path.exists(desktop_path):
        return os.getcwd()
    return desktop_path

def get_log_path(suffix: str) -> str:
    """生成日誌檔案的儲存路徑
    Args:
        suffix: 日誌類型（success 或 error）
    Returns:
        日誌檔案的完整路徑
    """
    date_str = datetime.now().strftime("%Y-%m-%d-%H_%M_%S")
    if suffix == "success":
        filename = f"NASecurity_Log_{date_str}.xlsx"
    else:
        filename = f"NASecurity_Error_Log_{date_str}.xlsx"
    full_path = os.path.join(get_desktop_path(), filename)
    return full_path

def generate_random_password(length: int = 12, exclude_chars: str = "") -> str:
    """生成符合安全要求的隨機密碼
    Args:
        length: 密碼長度（預設12）
        exclude_chars: 要排除的字符
    Returns:
        生成的隨機密碼
    """
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
    """管理成功和錯誤日誌的記錄與儲存"""
    def __init__(self):
        """初始化日誌管理器"""
        self.success_logs = []
        self.error_logs = []
        self.success_file = get_log_path("success")
        self.error_file = get_log_path("error")
        self.success_cols = ["時間", "帳號", "工號", "姓名", "執行結果", "更改後密碼"]
        self.error_cols = ["時間", "帳號", "工號", "姓名", "錯誤訊息"]

    def add_log(self, account: str, emp_id: str, name: str, result: str, new_password: str = "", is_error: bool = False):
        """添加日誌條目到成功或錯誤日誌
        Args:
            account: 帳號
            emp_id: 員工編號
            name: 姓名
            result: 執行結果或錯誤訊息
            new_password: 新密碼（僅成功日誌使用）
            is_error: 是否為錯誤日誌
        """
        entry = {
            "時間": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "帳號": account,
            "工號": emp_id if pd.notna(emp_id) else "未知工號",
            "姓名": name if pd.notna(name) else "未知姓名",
        }
        if is_error:
            entry["錯誤訊息"] = result
            self.error_logs.append(entry)
        else:
            entry["執行結果"] = result
            entry["更改後密碼"] = new_password if "成功" in result else ""
            self.success_logs.append(entry)

    def save_to_file(self):
        """將日誌儲存到Excel檔案
        Raises:
            Exception: 儲存失敗時拋出錯誤
        """
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
    """在QTextEdit中添加帶指定顏色的文字
    Args:
        text_widget: 目標QTextEdit控件
        message: 要顯示的訊息
        color: 文字顏色
    """
    cursor = text_widget.textCursor()
    cursor.movePosition(QTextCursor.End)
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(color))
    cursor.insertText(f"{message}\n", fmt)
    text_widget.setTextCursor(cursor)
    text_widget.ensureCursorVisible()