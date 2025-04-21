import sys
import os
import re
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox, QProgressDialog, QSpacerItem, QSizePolicy)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from api import NASClient
from utils import LogManager, generate_random_password, append_colored_text, get_desktop_path
# import logging
from typing import Dict, Any

# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
# logger = logging.getLogger(__name__)

def resource_path(relative_path):
    """獲取資源路徑"""
    if hasattr(sys, '_MEIPASS'):
        base_path = sys._MEIPASS
    else:
        base_path = os.path.dirname(os.path.abspath(__file__))
        base_path = os.path.dirname(base_path)
    return os.path.join(base_path, relative_path)

class WorkerThread(QThread):
    status_update = pyqtSignal(str, str)
    progress_update = pyqtSignal(int)
    finished = pyqtSignal()

    def __init__(self, nas_client: NASClient, filepath: str, log_manager: 'LogManager'):
        super().__init__()
        self.nas_client = nas_client
        self.filepath = filepath
        self.log_manager = log_manager
        self.is_canceled = False

    def run(self):
        """執行緒主邏輯，處理 Excel 中的用戶操作"""
        try:
            df = pd.read_excel(self.filepath)
            df.columns = df.columns.str.strip()
            required_cols = {"帳號", "作業需求"}
            if not required_cols.issubset(df.columns):
                missing = required_cols - set(df.columns)
                self.status_update.emit(f"缺少必要欄位: {', '.join(missing)}", "red")
                self.log_manager.add_log("", "", "", f"缺少必要欄位: {', '.join(missing)}", is_error=True)
                return

            df = df.dropna(subset=["帳號"])

            for i, row in df.iterrows():
                if self.is_canceled:
                    self.status_update.emit("操作已取消", "red")
                    self.log_manager.add_log("", "", "", "操作已取消", is_error=True)
                    break

                user = str(row["帳號"]).strip()
                operation = str(row["作業需求"]).strip()
                emp_id = row.get("工號", "未知工號")
                name = row.get("姓名", "未知姓名")

                self.status_update.emit(f"用戶: {user}，{operation}", "black")
                user_info = self.check_user(user)

                if operation == "密碼變更":
                    self.handle_password_change(user, emp_id, name, user_info)
                elif operation == "新增用戶":
                    self.handle_user_creation(user, emp_id, name, user_info)
                elif operation == "刪除用戶":
                    self.handle_user_deletion(user, emp_id, name, user_info)

                self.progress_update.emit(i + 1)

            self.status_update.emit("\n工具執行完畢", "black")
        except Exception as e:
            self.status_update.emit(f"執行失敗: {str(e)}", "red")
            self.log_manager.add_log("", "", "", f"執行失敗: {str(e)}", is_error=True)
        finally:
            self.finished.emit()

    def check_user(self, user: str) -> Dict[str, Any] | None:
        """檢查用戶是否存在"""
        try:
            return self.nas_client.user_exists(user)
        except Exception as e:
            self.status_update.emit(f"用戶查詢失敗: {str(e)}", "red")
            self.log_manager.add_log(user, "", "", f"用戶查詢失敗: {str(e)}", is_error=True)
            return None

    def handle_password_change(self, user: str, emp_id: str, name: str, user_info: Dict[str, Any] | None):
        """處理密碼變更操作"""
        if not user_info:
            self.status_update.emit(f"用戶 {user} 不存在，跳過此用戶", "red")
            self.log_manager.add_log(user, emp_id, name, "用戶不存在", is_error=True)
            return

        for _ in range(2):
            try:
                new_pwd = generate_random_password()
                self.nas_client.change_password(user, new_pwd)
                self.status_update.emit(f"用戶: {user} 密碼變更成功，新密碼: {new_pwd}", "green")
                self.log_manager.add_log(user, emp_id, name, "密碼變更成功", new_pwd)
                return
            except Exception as e:
                self.status_update.emit(f"密碼變更失敗: {str(e)}", "red")
                if _ == 1:
                    self.log_manager.add_log(user, emp_id, name, f"密碼變更失敗: {str(e)}", is_error=True)

    def handle_user_creation(self, user: str, emp_id: str, name: str, user_info: Dict[str, Any] | None):
        """處理用戶創建操作"""
        if user_info:
            self.status_update.emit(f"用戶 {user} 已存在，跳過此用戶", "red")
            self.log_manager.add_log(user, emp_id, name, "用戶已存在", is_error=True)
            return

        try:
            new_pwd = generate_random_password()
            self.nas_client.create_user(user, new_pwd)
            self.status_update.emit(f"用戶 {user} 創建成功，密碼: {new_pwd}", "green")
            self.log_manager.add_log(user, emp_id, name, "用戶創建成功", new_pwd)
        except Exception as e:
            self.status_update.emit(f"創建失敗: {str(e)}", "red")
            self.log_manager.add_log(user, emp_id, name, f"創建失敗: {str(e)}", is_error=True)

    def handle_user_deletion(self, user: str, emp_id: str, name: str, user_info: Dict[str, Any] | None):
        """處理用戶刪除操作"""
        if not user_info:
            self.status_update.emit(f"用戶 {user} 不存在，跳過此用戶", "red")
            self.log_manager.add_log(user, emp_id, name, "用戶不存在", is_error=True)
            return

        try:
            self.nas_client.delete_user(user)
            self.status_update.emit(f"用戶 {user} 刪除成功", "green")
            self.log_manager.add_log(user, emp_id, name, "用戶刪除成功", "")
        except Exception as e:
            self.status_update.emit(f"刪除失敗: {str(e)}", "red")
            self.log_manager.add_log(user, emp_id, name, f"刪除失敗: {str(e)}", is_error=True)

class NASecurity(QMainWindow):
    def __init__(self):
        super().__init__()
        self.nas_client: NASClient | None = None
        self.filepath: str | None = None
        self.worker: WorkerThread | None = None
        self.log_manager = LogManager()
        self.setup_ui()

    def setup_ui(self):
        """設置 GUI 界面"""
        self.setWindowTitle("NASecurity")
        self.setGeometry(100, 100, 1000, 830)
        self.setWindowIcon(QIcon(resource_path("icons/NASecurity.ico")))
        self.center_window()

        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget)

        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        self.ip_entry = self.add_field(input_layout, "NAS IP:", "例如: 10.57.78.62")
        self.port_entry = self.add_field(input_layout, "NAS 埠口:", "例如: 5000")
        self.admin_entry = self.add_field(input_layout, "管理員帳號:")
        self.pwd_entry = self.add_field(input_layout, "管理員密碼:", is_password=True)
        self.otp_entry = self.add_field(input_layout, "雙重驗證碼:", "請輸入 6 位驗證碼，若無則留空")
        self.file_entry = self.add_file_field(input_layout)
        
        start_btn = QPushButton("開始執行")
        start_btn.clicked.connect(self.start_process)
        input_layout.addWidget(start_btn)

        layout.addWidget(input_widget)

        self.status_text = QTextEdit()
        self.status_text.setReadOnly(True)
        layout.addWidget(self.status_text, stretch=1)

        self.setStyleSheet("""
            QWidget {
                background-color: #ECF0F1;
                font-family: Yu Gothic UI;
            }
            QLineEdit {
                background-color: #F9F9F9;
                border: 1px solid #979EA9;
                border-radius: 5px;
                padding: 5px;
                color: #333333;
            }
            QPushButton {
                background-color: #BFD1E5;
                color: #333333;
                border: None;
                border-radius: 5px;
                padding: 8px;
            }
            QPushButton:hover {
                background-color: #C6D9F1;
            }
            QTextEdit {
                background-color: #F9F9F9;
                border: 1px solid #979EA9;
                border-radius: 5px;
                color: #333333;
            }
            QLabel {
                color: #333333;
            }
            QMessageBox QPushButton {
                min-width: 80px;
                margin: 0 auto;
            }
        """)

        self.setup_shortcuts()

    def add_field(self, layout: QVBoxLayout, label: str, placeholder: str = "", is_password: bool = False) -> QLineEdit:
        """添加輸入欄位到布局"""
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(label))
        entry = QLineEdit()
        entry.setPlaceholderText(placeholder)
        if is_password:
            entry.setEchoMode(QLineEdit.Password)
        hbox.addWidget(entry)
        layout.addLayout(hbox)
        return entry

    def add_file_field(self, layout: QVBoxLayout) -> QLineEdit:
        """添加檔案選擇欄位"""
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel("選擇文件:"))
        entry = QLineEdit()
        entry.setReadOnly(True)
        hbox.addWidget(entry)
        btn = QPushButton("瀏覽...")
        btn.clicked.connect(self.select_file)
        hbox.addWidget(btn)
        layout.addLayout(hbox)
        return entry

    def center_window(self):
        """將視窗置中顯示"""
        screen = QApplication.desktop().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) // 2, (screen.height() - size.height()) // 2 - 50)

    def setup_shortcuts(self):
        """設置輸入欄位的快捷鍵（按 Enter 切換焦點）"""
        self.ip_entry.returnPressed.connect(lambda: self.port_entry.setFocus())
        self.port_entry.returnPressed.connect(lambda: self.admin_entry.setFocus())
        self.admin_entry.returnPressed.connect(lambda: self.pwd_entry.setFocus())
        self.pwd_entry.returnPressed.connect(lambda: self.otp_entry.setFocus())
        self.otp_entry.returnPressed.connect(self.start_process)

    def select_file(self):
        """打開檔案選擇對話框"""
        filepath, _ = QFileDialog.getOpenFileName(self, "選擇文件", get_desktop_path(), "Excel files (*.xlsx)")
        if filepath:
            self.filepath = filepath
            self.file_entry.setText(filepath)

    def start_process(self):
        """開始處理用戶操作"""
        if not self.validate_inputs():
            return

        nas_ip = self.ip_entry.text()
        nas_port = self.port_entry.text() or "5000"
        admin = self.admin_entry.text()
        pwd = self.pwd_entry.text()
        otp = self.otp_entry.text() or None

        if self.nas_client:
            try:
                self.nas_client.logout()
                append_colored_text(self.status_text, "已登出舊會話", "black")
            except Exception as e:
                # logger.warning(f"舊會話登出失敗: {str(e)}")
                append_colored_text(self.status_text, f"舊會話登出失敗: {str(e)}", "red")

        self.nas_client = NASClient(nas_ip, nas_port)
        self.status_text.clear()

        self.progress = QProgressDialog("處理中...", "取消", 0, 100, self)
        self.progress.setWindowTitle("NASecurity")
        self.progress.setWindowModality(Qt.WindowModal)
        self.progress.setMinimumDuration(0)
        self.progress.canceled.connect(self.cancel_process)
        self.progress.setFixedSize(400, 150)

        try:
            self.nas_client.login(admin, pwd, otp, self.clear_pwd, self.clear_otp)
            append_colored_text(self.status_text, f"管理員 {admin} 登入成功。\n", "black")
            
            self.worker = WorkerThread(self.nas_client, self.filepath, self.log_manager)
            self.worker.status_update.connect(lambda msg, color: append_colored_text(self.status_text, msg, color))
            self.worker.progress_update.connect(self.progress.setValue)
            self.worker.finished.connect(self.process_finished)
            self.worker.start()
        except Exception as e:
            # logger.error(f"登入失敗: {str(e)}")
            self.clear_pwd()
            self.clear_otp()
            self.progress.close()
            append_colored_text(self.status_text, f"登入失敗: {str(e)}", "red")
            QMessageBox.critical(self, "錯誤", f"登入失敗: {str(e)}")
            self.log_manager.add_log("", "", "", f"登入失敗: {str(e)}", is_error=True)

    def validate_inputs(self) -> bool:
        """驗證輸入是否有效"""
        if not self.filepath:
            QMessageBox.critical(self, "錯誤", "請選擇文件")
            return False
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", self.ip_entry.text()):
            QMessageBox.critical(self, "錯誤", "請輸入有效IP")
            return False
        port_text = self.port_entry.text() or "5000"
        if not port_text.isdigit() or not (1 <= int(port_text) <= 65535):
            QMessageBox.critical(self, "錯誤", "請輸入有效埠口（1-65535）")
            return False
        if not self.admin_entry.text():
            QMessageBox.critical(self, "錯誤", "請輸入管理員帳號")
            return False
        if not self.pwd_entry.text():
            QMessageBox.critical(self, "錯誤", "請輸入管理員密碼")
            return False
        return True

    def clear_pwd(self):
        """清空密碼欄位"""
        self.pwd_entry.clear()
        # logger.info("管理員密碼欄位已清空")

    def clear_otp(self):
        """清空雙重驗證碼欄位"""
        self.otp_entry.clear()
        # logger.info("雙重驗證碼欄位已清空")

    def process_finished(self):
        """處理完成後的清理工作"""
        self.progress.close()
        self.file_entry.clear()
        try:
            self.log_manager.save_to_file()
            # logger.info("日誌已保存至桌面")
        except Exception as e:
            # logger.error(f"日誌保存失敗: {str(e)}")
            append_colored_text(self.status_text, f"日誌保存失敗: {str(e)}", "red")
            QMessageBox.critical(self, "錯誤", f"日誌保存失敗: {str(e)}")
        self.clear_pwd()
        self.clear_otp()

    def cancel_process(self):
        """取消操作的處理"""
        if self.worker:
            self.worker.is_canceled = True
        if self.nas_client:
            try:
                self.nas_client.logout()
                append_colored_text(self.status_text, "已登出", "black")
            except Exception as e:
                # logger.warning(f"取消時登出失敗: {str(e)}")
                append_colored_text(self.status_text, f"取消時登出失敗: {str(e)}", "red")
        self.clear_pwd()
        self.clear_otp()
        self.process_finished()

    def closeEvent(self, event):
        """視窗關閉時的事件處理"""
        if self.nas_client and self.nas_client.sid:
            try:
                self.nas_client.logout()
                # append_colored_text(self.status_text, "已登出", "black")
            except Exception as e:
                # logger.warning(f"關閉時   失敗: {str(e)}")
                # append_colored_text(self.status_text, f"關閉時登出失敗: {str(e)}", "red")
                pass
        try:
            self.log_manager.save_to_file()
            # logger.info("關閉時日誌已保存至桌面")
            # append_colored_text(self.status_text, "關閉時日誌已保存至桌面", "black")
        except Exception as e:
            # logger.error(f"關閉時日誌保存失敗: {str(e)}")
            # append_colored_text(self.status_text, f"關閉時日誌保存失敗: {str(e)}", "red")
            pass
        self.clear_pwd()
        self.clear_otp()
        event.accept()

if __name__ == "__main__":
    """程式入口"""
    app = QApplication(sys.argv)
    app.setFont(QFont("Yu Gothic UI", 12))
    window = NASecurity()
    window.show()
    sys.exit(app.exec_())