from typing import Dict, Any, Callable
import requests
from requests import Session
from tenacity import retry, stop_after_attempt, wait_fixed, retry_if_exception_type

class NASClient:
    """API client for NAS device, providing user management functions"""

    BASE_URL = "http://{ip}:{port}/webapi/"
    ERROR_MESSAGES = {
        400: "No such account or incorrect password",
        401: "Disabled account",
        402: "Denied account",
        403: "2-factor authentication code required",
        404: "Failed to authenticate 2-factor authentication code",
        406: "Enforce to authenticate 2-factor authentication code",
        407: "Blocked IP source",
        408: "Expired password cannot change",
        409: "Expired password",
        410: "Password must be changed",
    }

    def __init__(self, nas_ip: str, nas_port: str):
        self.nas_ip = nas_ip
        self.nas_port = nas_port
        self.sid: str | None = None
        self.session = Session()

    def build_url(self, endpoint: str) -> str:
        return self.BASE_URL.format(ip=self.nas_ip, port=self.nas_port) + endpoint

    def get_error_message(self, error_code: int) -> str:
        return self.ERROR_MESSAGES.get(error_code, f"Uknown error (code: {error_code})")

    @retry( stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def login(self, account: str, password: str, otp_code: str | None = None, clear_password_callback: Callable[[], None] | None = None, clear_otp_callback: Callable[[], None] | None = None) -> str:
        """Admin login"""
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
        """Check if the user exists"""
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
        """Change user password"""
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
            raise Exception(f"Failed to change password: {self.get_error_message(error_code)}")
        return result

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def create_user(self, username: str, password: str) -> Dict[str, Any]:
        """Create new user"""
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
            raise Exception(f"Failed to create user: {self.get_error_message(error_code)}")
        return result

    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2), retry=retry_if_exception_type(requests.RequestException))
    def delete_user(self, username: str) -> Dict[str, Any]:
        """Remove user"""
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
            raise Exception(f"Failed to remove user: {self.get_error_message(error_code)}")
        return result

    def logout(self) -> bool:
        """Logout admin"""
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
                 
        raise Exception(f"Failed to login: {data}")