# NASecurity

## Overview

NASecurity is a graphical tool, built with PyQt5, designed to manage user operations on NAS (Network Attached Storage) devices. It streamlines tasks like:

- **Changing user passwords**
- **Creating new users**
- **Deleting existing users**

The tool automates these operations using batch processing from Excel files, providing real-time status updates and logging.

---

## Features

- **NAS API Client Integration:** Uses the `NASClient` class to interact with the NAS API.
- **Multi-Factor Authentication Support:** Supports two-factor authentication codes.
- **Batch Processing:** Reads user information from Excel files for efficient batch operations.
- **Operation Logging:** Records successful and failed operations for easy troubleshooting.  Logs are saved to the desktop in a CSV format.
- **User Interface (GUI):** Provides an intuitive and user-friendly graphical interface.

---

## System Requirements

- Python 3.8 or higher
- Required Python Libraries:
  - `requests`
  - `tenacity`
  - `PyQt5`
  - `pandas`

---

## Installation and Execution

### Installing Dependencies

Use pip to install the necessary libraries:


### Running the Program

1.  Ensure that `api.py` and `NASecurity.py` are in the same directory.
2.  Run the program from the command line:


---

## Usage Instructions

### GUI Workflow

1.  **Enter NAS IP:**  Input the IP address of your NAS device (e.g., `10.57.78.62`).
2.  **Enter Administrator Credentials:** Provide the username and password for the NAS administrator account.
3.  **Select Excel File:** Click the "Browse..." button to select the Excel file containing user information.
4.  **Start Execution:** Click the "Start Execution" button to begin batch processing the user operations.

### Excel File Format

The Excel file must contain the following columns:

-   `帳號` (Username):  The username for the account (required).
-   `作業需求` (Operation): The type of operation to perform (required).  Valid values are: "密碼變更" ("Password Change"), "新增用戶" ("Create User"), and "刪除用戶" ("Delete User").
-   Optional columns:
    -   `工號` (Employee ID)
    -   `姓名` (Name)

---

## Code Architecture

### Core Modules

1.  **`api.py`**

    *   Provides the `NASClient` class, which handles interaction with the NAS API.  This includes functions for:
        *   Logging in
        *   Checking if a user exists
        *   Creating users
        *   Changing passwords
        *   Deleting users
        *   Logging out

2.  **`NASecurity.py`**

    *   The main program with the graphical user interface (GUI). It handles file selection, status updates, and the overall batch processing logic.

### Key Classes and Methods

| Class/Method       | Description                                                                    |
| ------------------ | ------------------------------------------------------------------------------ |
| `NASClient`        | Client class for communicating with the NAS API.                                |
| `login()`          | Administrator login method, supports two-factor authentication.                 |
| `user_exists()`    | Checks if a specified user exists.                                           |
| `change_password()` | Changes the password for a specified user.                                     |
| `create_user()`    | Creates a new user account with a default password.                             |
| `delete_user()`    | Deletes a specified user account.                                              |
| `logout()`         | Logs out the current session.                                                  |
| `WorkerThread`     | A QThread that reads from the Excel file and executes user operations in a batch. |

---

## Error Handling

The program provides detailed error messages. Common errors include:

*   Missing required columns in the Excel file.
*   User does not exist or already exists.
*   Password change or user creation failure (possibly due to API error codes).

---

## Developer Information

Author: \[Your Name]  
Contact: \[Your Email]

Feel free to reach out with questions or suggestions!
