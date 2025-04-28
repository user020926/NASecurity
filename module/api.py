from typing import Dict, Any, Callable
import requests
from requests import Session
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

class NASClient:
    """NAS設備的API客戶端，提供用戶管理功能"""
    
    BASE_URL = "http://{ip}:{port}/webapi/"
    ERROR_MESSAGES = {
        400: "沒有該帳號或密碼錯誤",
        401: "帳戶已禁用",
        402: "權限不足",
        403: "需要雙重驗證碼",
        404: "雙重驗證失敗",
        406: "必須啟用雙重驗證",
        407: "IP被封鎖",
        408: "密碼過期且無法更改",
        409: "密碼已過期",
        410: "必須更改密碼",
    }

    def __init__(self, nas_ip: str, nas_port: str):
        """初始化NAS連線參數
        Args:
            nas_ip: NAS伺服器IP位址
            nas_port: NAS管理埠號
        """
        self.nas_ip = nas_ip
        self.nas_port = nas_port
        self.sid: str | None = None  # 會話ID(Session ID)
        self.session = Session()  # 維持連線的requests會話

    def build_url(self, endpoint: str) -> str:
        """組合完整的API請求網址
        Args:
            endpoint: API端點路徑
        Returns:
            完整的API URL
        """
        return self.BASE_URL.format(ip=self.nas_ip, port=self.nas_port) + endpoint

    def get_error_message(self, error_code: int) -> str:
        return self.ERROR_MESSAGES.get(error_code, f"未知錯誤 (代碼: {error_code})")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def login(self, account: str, password: str, otp_code: str | None = None, clear_password_callback: Callable[[], None] | None = None, clear_otp_callback: Callable[[], None] | None = None) -> str:
        """登入NAS獲取會話ID
        Args:
            account: 管理員帳號
            password: 管理員密碼
            otp_code: 雙因素驗證碼(可選)
            clear_password_callback: 密碼錯誤時的回調函數
            clear_otp_callback: OTP錯誤時的回調函數
        Returns:
            獲取的會話ID(SID)
        Raises:
            Exception: 登入失敗時拋出錯誤
        """
        url = self.build_url("auth.cgi")
        params = {
            "api": "SYNO.API.Auth",
            "method": "login",
            "version": "7",
            "account": account,
            "passwd": password,
            "format": "sid"
        }
        if otp_code:
            params["otp_code"] = otp_code

        response = self.session.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        if "data" in data and "sid" in data["data"]:
            self.sid = data["data"]["sid"]
            return self.sid

        error_code = data.get("error", {}).get("code")
        error_msg = self.get_error_message(error_code)
        
        # 根據錯誤類型觸發對應清理回調
        if error_code in (400, 408, 409, 410) and clear_password_callback:
            clear_password_callback()
        elif error_code in (404, 406) and clear_otp_callback:
            clear_otp_callback()
        
        raise Exception(error_msg)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def user_exists(self, username: str) -> Dict[str, Any] | None:
        """檢查用戶是否存在
        Args:
            username: 要檢查的用戶名
        Returns:
            用戶資訊字典，若不存在則返回None
        """
        url = self.build_url("entry.cgi")
        params = {
            "api": "SYNO.Core.User",
            "method": "list",
            "version": "1",
            "_sid": self.sid
        }
        
        response = self.session.get(url, params=params, timeout=10)
        response.raise_for_status()
        data = response.json()

        for user in data.get("data", {}).get("users", []):
            if user["name"] == username:
                return user
        return None

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def change_password(self, username: str, new_password: str) -> Dict[str, Any]:
        """變更用戶密碼
        Args:
            username: 目標用戶名
            new_password: 新密碼
        Returns:
            API響應數據
        """
        url = self.build_url("entry.cgi")
        params = {
            "api": "SYNO.Core.User",
            "method": "set",
            "version": "1",
            "name": username,
            "password": new_password,
            "_sid": self.sid
        }
        
        response = self.session.post(url, data=params, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if not result.get("success", False):
            error_code = result.get("error", {}).get("code")
            raise Exception(f"密碼變更失敗: {self.get_error_message(error_code)}")
        return result

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        """創建新用戶
        Args:
            username: 新用戶名
            password: 初始密碼
        Returns:
            API響應數據
        """
        url = self.build_url("entry.cgi")
        params = {
            "api": "SYNO.Core.User",
            "method": "create",
            "version": "1",
            "name": username,
            "password": password,
            "_sid": self.sid
        }
        
        response = self.session.post(url, data=params, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if not result.get("success", False):
            error_code = result.get("error", {}).get("code")
            raise Exception(f"用戶創建失敗: {self.get_error_message(error_code)}")
        return result

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def delete_user(self, username: str) -> Dict[str, Any]:
        """刪除用戶
        Args:
            username: 要刪除的用戶名
        Returns:
            API響應數據
        """
        url = self.build_url("entry.cgi")
        params = {
            "api": "SYNO.Core.User",
            "method": "delete",
            "version": "1",
            "name": username,
            "_sid": self.sid
        }
        
        response = self.session.post(url, data=params, timeout=10)
        response.raise_for_status()
        result = response.json()
        
        if not result.get("success", False):
            error_code = result.get("error", {}).get("code")
            raise Exception(f"用戶刪除失敗: {self.get_error_message(error_code)}")
        return result

    def logout(self) -> bool:
        """登出當前會話
        Returns:
            登出是否成功
        Raises:
            Exception: 登出失敗時拋出
        """
        if not self.sid:
            return True
        
        url = self.build_url("auth.cgi")
        params = {
            "api": "SYNO.API.Auth",
            "method": "logout",
            "version": "7", 
            "_sid": self.sid
        }
        
        response = self.session.get(url, params=params, timeout=10)
        data = response.json()
        
        if data.get("success", False):
            self.sid = None
            return True
        
        raise Exception(f"登出失敗: {data}")
            