import secrets
import string
import os
import pandas as pd
from datetime import datetime
from PyQt5.QtGui import QColor, QTextCharFormat, QTextCursor
from PyQt5.QtWidgets import QTextEdit
# import logging
import time

# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
# logger = logging.getLogger(__name__)

def get_desktop_path() -> str:
    """獲取桌面路徑"""
    desktop_path = os.path.expanduser("~/Desktop")
    if not os.path.exists(desktop_path):
        # logger.warning(f"桌面路徑 {desktop_path} 不存在，使用當前工作目錄")
        return os.getcwd()
    return desktop_path

def get_log_path(suffix: str) -> str:
    """生成日誌檔案路徑"""
    date_str = datetime.now().strftime("%Y-%m-%d")
    if suffix == "success":
        filename = f"NASecurity_Log_{date_str}.xlsx"
    else:
        filename = f"NASecurity_Error_Log_{date_str}.xlsx"
    full_path = os.path.join(get_desktop_path(), filename)
    # logger.info(f"生成日誌路徑: {full_path}")
    return full_path

def generate_random_password(length: int = 12, exclude_chars: str = "") -> str:
    """生成隨機密碼"""
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
    """日誌管理器"""
    def __init__(self):
        self.success_logs = []
        self.error_logs = []
        self.success_file = get_log_path("success")
        self.error_file = get_log_path("error")
        self.success_cols = ["時間", "帳號", "工號", "姓名", "執行結果", "更改後密碼"]
        self.error_cols = ["時間", "帳號", "工號", "姓名", "錯誤訊息"]

    def add_log(self, account: str, emp_id: str, name: str, result: str, new_password: str = "", is_error: bool = False):
        """添加日誌條目"""
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
        """將日誌保存到檔案"""
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
                    # logger.info(f"保存 {len(logs)} 條日誌到 {filename}")
                    logs.clear()
                    break
                except PermissionError:
                    # logger.warning(f"權限拒絕，重試保存: {filename}")
                    time.sleep(1)
                except Exception as e:
                    # logger.error(f"保存日誌失敗: {filename} - {str(e)}")
                    if attempt == 2:
                        raise

def append_colored_text(text_widget: QTextEdit, message: str, color: str):
    """在文本框中添加帶顏色的文字"""
    cursor = text_widget.textCursor()
    cursor.movePosition(QTextCursor.End)
    fmt = QTextCharFormat()
    fmt.setForeground(QColor(color))
    cursor.insertText(f"{message}\n", fmt)
    text_widget.setTextCursor(cursor)
    text_widget.ensureCursorVisible()