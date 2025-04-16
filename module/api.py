# import logging
from typing import Dict, Any, Callable
import requests
from requests import Session
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

# logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
# logger = logging.getLogger(__name__)

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
        self.nas_ip = nas_ip
        self.nas_port = nas_port
        self.sid: str | None = None
        self.session = Session()

    def build_url(self, endpoint: str) -> str:
        return self.BASE_URL.format(ip=self.nas_ip, port=self.nas_port) + endpoint

    def get_error_message(self, error_code: int) -> str:
        return self.ERROR_MESSAGES.get(error_code, f"未知錯誤 (代碼: {error_code})")

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def login(self, account: str, password: str, otp_code: str | None = None, clear_password_callback: Callable[[], None] | None = None, clear_otp_callback: Callable[[], None] | None = None) -> str:
        """管理員登入"""
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
        
        if error_code in (400, 408, 409, 410) and clear_password_callback:
            clear_password_callback()
        elif error_code in (404, 406) and clear_otp_callback:
            clear_otp_callback()
        
        raise Exception(error_msg)

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def user_exists(self, username: str) -> Dict[str, Any] | None:
        """檢查用戶是否存在"""
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
        """更改用戶密碼"""
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
        """創建新用戶"""
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
        """刪除用戶"""
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
        """登出管理員會話"""
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
            # logger.info("管理員成功登出")
            self.sid = None
            return True
        
        raise Exception(f"登出失敗: {data}")
            