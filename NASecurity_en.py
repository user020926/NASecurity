import sys
import os
import re
import pandas as pd
from PyQt5.QtWidgets import (QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QLabel, 
                            QLineEdit, QPushButton, QTextEdit, QFileDialog, QMessageBox, QProgressDialog, QSpacerItem, QSizePolicy)
from PyQt5.QtGui import QFont, QIcon
from PyQt5.QtCore import Qt, QThread, pyqtSignal
from api_en import NASClient
from utils_en import LogManager, generate_random_password, append_colored_text, get_desktop_path
from typing import Dict, Any

def resource_path(relative_path):
    """Get the resource path after packaging"""
    if hasattr(sys, '_MEIPASS'):
        return os.path.join(sys._MEIPASS, relative_path)
    return os.path.join(os.path.abspath("."), relative_path)

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
        """Thread main logic, handle user operations in Excel"""
        try:
            df = pd.read_excel(self.filepath)
            required_cols = {"Account", "Operation Requirements"}
            if not required_cols.issubset(df.columns):
                missing = required_cols - set(df.columns)
                self.status_update.emit(f"Missing required fields: {', '.join(missing)}", "red")
                self.log_manager.add_log("", "", "", f"Missing required fields: {', '.join(missing)}", is_error=True)
                return

            df = df.dropna(subset=["Account"])

            for i, row in df.iterrows():
                if self.is_canceled:
                    self.status_update.emit("Operation canceled", "red")
                    self.log_manager.add_log("", "", "", "Operation canceled", is_error=True)
                    break

                user = str(row["Account"]).strip()
                operation = str(row["Operation Requirements"]).strip().lower()
                emp_id = row.get("ID", "Unknown ID")
                name = row.get("Name", "Unknown Name")

                self.status_update.emit(f"User: {user}, {operation}", "black")
                user_info = self._check_user(user)

                if operation == "change password":
                    self._handle_password_change(user, emp_id, name, user_info)
                elif operation == "create user":
                    self._handle_user_creation(user, emp_id, name, user_info)
                elif operation == "remove user":
                    self._handle_user_deletion(user, emp_id, name, user_info)

                self.progress_update.emit(i + 1)

            self.status_update.emit("\nExcecution completed", "black")
        except Exception as e:
            self.status_update.emit(f"Excecution failed: {str(e)}", "red")
            self.log_manager.add_log("", "", "", f"Excecution failed: {str(e)}", is_error=True)
        finally:
            self.finished.emit()

    def _check_user(self, user: str) -> Dict[str, Any] | None:
        """Check if the user exists"""
        try:
            return self.nas_client.user_exists(user)
        except Exception as e:
            self.status_update.emit(f"Query failed: {str(e)}", "red")
            self.log_manager.add_log(user, "", "", f"Query failed: {str(e)}", is_error=True)
            return None

    def _handle_password_change(self, user: str, emp_id: str, name: str, user_info: Dict[str, Any] | None):
        """Handle password change operation"""
        if not user_info:
            self.status_update.emit(f"User {user} does not exist, skipping...", "red")
            self.log_manager.add_log(user, emp_id, name, "User does not exist", is_error=True)
            return

        for _ in range(2):
            try:
                new_pwd = generate_random_password()
                self.nas_client.change_password(user, new_pwd)
                self.status_update.emit(f"User: {user} Password changed successfully, new password: {new_pwd}", "green")
                self.log_manager.add_log(user, emp_id, name, "Password changed successfully", new_pwd)
                return
            except Exception as e:
                self.status_update.emit(f"Failed to change password: {str(e)}", "red")
                if _ == 1:
                    self.log_manager.add_log(user, emp_id, name, f"Failed to change password: {str(e)}", is_error=True)

    def _handle_user_creation(self, user: str, emp_id: str, name: str, user_info: Dict[str, Any] | None):
        """Handle user creation operation"""
        if user_info:
            self.status_update.emit(f"User {user} already exists, skipping...", "red")
            self.log_manager.add_log(user, emp_id, name, "User already exists", is_error=True)
            return

        try:
            new_pwd = generate_random_password()
            self.nas_client.create_user(user, new_pwd)
            self.status_update.emit(f"User {user} created successfully, password: {new_pwd}", "green")
            self.log_manager.add_log(user, emp_id, name, "User created successfully", new_pwd)
        except Exception as e:
            self.status_update.emit(f"Failed to create user: {str(e)}", "red")
            self.log_manager.add_log(user, emp_id, name, f"Failed to create user: {str(e)}", is_error=True)

    def _handle_user_deletion(self, user: str, emp_id: str, name: str, user_info: Dict[str, Any] | None):
        """Handle user deletion operation"""
        if not user_info:
            self.status_update.emit(f"User {user} does not exists, skipping...", "red")
            self.log_manager.add_log(user, emp_id, name, "User does not exists", is_error=True)
            return

        try:
            self.nas_client.delete_user(user)
            self.status_update.emit(f"user {user} removed successfully", "green")
            self.log_manager.add_log(user, emp_id, name, "User removed successfully", "")
        except Exception as e:
            self.status_update.emit(f"Failed to remove user: {str(e)}", "red")
            self.log_manager.add_log(user, emp_id, name, f"Failed to remove user: {str(e)}", is_error=True)

class NASecurity(QMainWindow):
    def __init__(self):
        super().__init__()
        self.nas_client: NASClient | None = None
        self.filepath: str | None = None
        self.worker: WorkerThread | None = None
        self.log_manager = LogManager()
        self._setup_ui()

    def _setup_ui(self):
        """Setup GUI interface"""
        self.setWindowTitle("NASecurity")
        self.setGeometry(100, 100, 1000, 800)
        self.setWindowIcon(QIcon(resource_path("NASecurity_icon.ico")))
        self._center_window()

        widget = QWidget()
        self.setCentralWidget(widget)
        layout = QVBoxLayout(widget)

        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        self.ip_entry = self._add_field(input_layout, "NAS IP:", "e.g. 10.57.78.62")
        self.admin_entry = self._add_field(input_layout, "Admin account:")
        self.pwd_entry = self._add_field(input_layout, "Admin password:", is_password=True)
        self.otp_entry = self._add_field(input_layout, "OTP-code:", "Please enter 6-digit code, leave blank if not")
        self.file_entry = self._add_file_field(input_layout)
        
        start_btn = QPushButton("Execute")
        start_btn.clicked.connect(self._start_process)
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

        self._setup_shortcuts()

    def _add_field(self, layout: QVBoxLayout, label: str, placeholder: str = "", is_password: bool = False) -> QLineEdit:
        """Add input field to layout"""
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel(label))
        entry = QLineEdit()
        entry.setPlaceholderText(placeholder)
        if is_password:
            entry.setEchoMode(QLineEdit.Password)
        hbox.addWidget(entry)
        layout.addLayout(hbox)
        return entry

    def _add_file_field(self, layout: QVBoxLayout) -> QLineEdit:
        """Add file selection to layout"""
        hbox = QHBoxLayout()
        hbox.addWidget(QLabel("Select file:"))
        entry = QLineEdit()
        entry.setReadOnly(True)
        hbox.addWidget(entry)
        btn = QPushButton("Browse...")
        btn.clicked.connect(self._select_file)
        hbox.addWidget(btn)
        layout.addLayout(hbox)
        return entry

    def _center_window(self):
        """Center the window"""
        screen = QApplication.desktop().screenGeometry()
        size = self.geometry()
        self.move((screen.width() - size.width()) // 2, (screen.height() - size.height()) // 2 - 50)

    def _setup_shortcuts(self):
        """Set up shortcuts for input fields (press Enter to switch)"""
        self.ip_entry.returnPressed.connect(lambda: self.admin_entry.setFocus())
        self.admin_entry.returnPressed.connect(lambda: self.pwd_entry.setFocus())
        self.pwd_entry.returnPressed.connect(lambda: self.otp_entry.setFocus())
        self.otp_entry.returnPressed.connect(self._start_process)

    def _select_file(self):
        """Open file selection dialog"""
        filepath, _ = QFileDialog.getOpenFileName(
            self, 
            "Select file", 
            get_desktop_path(),
            "Excel files (*.xlsx)"
        )
        if filepath:
            self.filepath = filepath
            self.file_entry.setText(filepath)

    def _start_process(self):
        """Start processing user operations"""
        if not self._validate_inputs():
            return

        nas_ip = self.ip_entry.text()
        admin = self.admin_entry.text()
        pwd = self.pwd_entry.text()
        otp = self.otp_entry.text() or None

        if self.nas_client:
            try:
                self.nas_client.logout(self.status_text)
            except Exception as e:
                append_colored_text(self.status_text, f"Failed to logout previous session: {str(e)}", "red")

        self.nas_client = NASClient(nas_ip)
        self.status_text.clear()

        self.progress = QProgressDialog("Processing...", "Cancel", 0, 100, self)
        self.progress.setWindowTitle("NASecurity")
        self.progress.setWindowModality(Qt.WindowModal)
        self.progress.setMinimumDuration(0)
        self.progress.canceled.connect(self._cancel_process)
        self.progress.setFixedSize(400, 150)

        try:
            self.nas_client.login(admin, pwd, self.status_text, otp, self._clear_pwd, self._clear_otp)
            df = pd.read_excel(self.filepath).dropna(subset=["Account"])
            self.progress.setMaximum(len(df))

            self.worker = WorkerThread(self.nas_client, self.filepath, self.log_manager)
            self.worker.status_update.connect(lambda msg, color: append_colored_text(self.status_text, msg, color))
            self.worker.progress_update.connect(self.progress.setValue)
            self.worker.finished.connect(self._process_finished)
            self.worker.start()
        except Exception as e:
            append_colored_text(self.status_text, f"Login failed: {str(e)}", "red")
            self._clear_pwd()
            self._clear_otp()
            self.progress.close()
            QMessageBox.critical(self, "Error", f"Login failed: {str(e)}")
            self.log_manager.add_log("", "", "", f"Login failed: {str(e)}", is_error=True)

    def _validate_inputs(self) -> bool:
        """Verify inputs"""
        if not self.filepath:
            QMessageBox.critical(self, "Error", "Please select a file")
            return False
        if not re.match(r"^\d+\.\d+\.\d+\.\d+$", self.ip_entry.text()):
            QMessageBox.critical(self, "Error", "Please enter a valid IP")
            return False
        if not self.admin_entry.text():
            QMessageBox.critical(self, "Error", "Please enter the admin account")
            return False
        if not self.pwd_entry.text():
            QMessageBox.critical(self, "Error", "Please enter the admin password")
            return False
        return True

    def _clear_pwd(self):
        """Clear password field"""
        self.pwd_entry.clear()

    def _clear_otp(self):
        """Clear two-factor code field"""
        self.otp_entry.clear()

    def _process_finished(self):
        """Cleanup after processing is finished"""
        self.progress.close()
        self.file_entry.clear()
        try:
            self.log_manager.save_to_file()
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Failed to save log: {str(e)}")
        self._clear_pwd()
        self._clear_otp()

    def _cancel_process(self):
        """Handle operation cancellation"""
        if self.worker:
            self.worker.is_canceled = True
        if self.nas_client:
            try:
                self.nas_client.logout(self.status_text)
            except Exception as e:
                append_colored_text(self.status_text, f"Failed to logout during cancelation: {str(e)}", "red")
        self._clear_pwd()
        self._clear_otp()
        self._process_finished()

    def closeEvent(self, event):
        """Event handling when the window is closed"""
        if self.nas_client and self.nas_client.sid:
            try:
                self.nas_client.logout(self.status_text)
            except Exception as e:
                append_colored_text(self.status_text, f"Failed to logout during closing: {str(e)}", "red")
        try:
            self.log_manager.save_to_file()
        except Exception as e:
            raise
        self._clear_pwd()
        self._clear_otp()
        event.accept()

if __name__ == "__main__":
    """Entry point"""
    app = QApplication(sys.argv)
    app.setFont(QFont("Arial", 12))
    window = NASecurity()
    window.show()
    sys.exit(app.exec_())