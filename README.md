# Secure File Transfer App: Security & Setup Guide

**Threat Model:** Any user can connect to the server and upload files for sharing.

---

## Prerequisites

> Have a mysql server running (assummed to be encrypted via innoDB)

1. **Create a virtual environment**

    ```bash
    python -m venv .venv
    ```

2. **Activate the virtual environment (Windows)**

    ```bash
    .venv\Scripts\activate
    ```

3. **Install required dependencies**

    ```bash
    pip install -r requirements.txt
    ```

4. **Create a `.env` file**

    ```bash
    DB_HOST=<yourdbhostname>
    DB_USER=<yourdbusername>
    DB_PASS=<yourdbpassword>
    DB_NAME=<dbname>

    MEK=JTdPwEL12jOPhxRNKBbRy4hGa3LZjnln74NQFKWY+zw=
    ROOT_KEY_PASSPHRASE=securepa$$w0rd459
    Server_KEY_PASSPHRASE=securepa$$w0rd459
    ```

> *Note:* MEK must be a base64 encoded 32-byte data.

---

## Running the Server & Client

1. **Initialise the database (For first time only, otherwise skip)**

    ```bash
    python -m server.config.init_db
    ```

2. **Run the server**

    ```bash
    python -m server.main
    ```

> *Note:* This generates multiple certificates under `server/certificates`, for the first time, notably `root_cert.pem` and `file_sign_cert.pem`. Copy it to:

    client_path/trusted_root_store


3. **Run the client in another terminal window**

    ```bash
    python -m client.main
    ```

4. **Register a user first** 


Ensure the password is complex enough otherwise it will be rejected 

5. **Login after registering**
6. **Use the GUI to upload or download files**