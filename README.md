# NASecurity

## Overview
**NASecurity** is a PyQt5-based graphical tool designed to manage user operations on NAS devices. The tool supports the following functions:
- **Change User Passwords**
- **Add New Users**
- **Delete Users**

This tool processes user operations in batch via Excel files and provides real-time status updates and operation logs.

---

## Features
- **Integrated NAS API Client**: Communicates with the NAS API using the `NASClient` class.
- **Multi-Factor Authentication Support**: Supports two-factor authentication codes.
- **Batch Processing**: Reads user information from Excel files to perform operations in bulk.
- **Operation Logs**: Records both successful and failed operations for troubleshooting.
- **GUI Interface**: A user-friendly graphical interface for easy interaction.

---

## System Requirements
- Python 3.8 or later
- Required dependencies:
  - `requests`
  - `tenacity`
  - `PyQt5`
  - `pandas`

---

## Installation & Execution

### Installation Steps
Download and extract the files. Go to `/dist/NASecurity`, copy the path to `NASecurity.exe`, and create a desktop shortcut to launch the application.

---

## User Guide

### GUI Workflow
1. **Enter NAS IP**: Input the IP address of the NAS device (e.g., `10.57.78.62`).
2. **Enter NAS Port**: Input the NAS device port (e.g., `5000`).
3. **Enter Admin Credentials and 2FA Code**: Provide the NAS admin’s login information.
4. **Select Excel File**: Click the “Browse...” button to choose an Excel file containing user data.
5. **Start Execution**: Click the “Start Execution” button to begin batch processing of user operations.

### Excel File Format Requirements
The Excel file must include the following columns:
- `Account`: Required  
- `Operation Requirements`: Required — supports `Change Password`, `Create User`, `Remove User`

Optional columns:
- `ID`  
- `Name`

---

## Program Structure

### Core Modules
1. **`api.py`**  
   Handles communication with the NAS API, including login, checking user existence, user creation, password change, and user deletion.

2. **`NASecurity.py`**  
   The main GUI application responsible for file selection, status updates, and batch operation logic.

### Key Classes & Methods

| Class/Method         | Description                                      |
|----------------------|--------------------------------------------------|
| `NASClient`          | Client class for communicating with the NAS API. |
| `login()`            | Admin login method with two-factor authentication.|
| `user_exists()`      | Checks if a specific user exists.                |
| `change_password()`  | Changes the password of a specified user.        |
| `create_user()`      | Creates a new user and sets an initial password. |
| `delete_user()`      | Deletes a specified user.                        |
| `WorkerThread`       | Thread that reads from Excel and performs batch user operations. |

---

## Error Handling
The program provides detailed error messages. Common issues include:
- Missing required Excel columns.
- User already exists or not found.
- Password change or user creation failure (possibly due to API errors).

---

## Developer Information
**Author**: Haowei Yu  
**Contact**: [haoweiyu0926@gmail.com](mailto:haoweiyu0926@gmail.com)

If you have any questions or suggestions, feel free to reach out!
