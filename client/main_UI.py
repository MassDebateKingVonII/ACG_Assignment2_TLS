import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext
import os
import socket
import ssl
import json
import base64

from client.utils.certificateValidation import TRUSTED_ROOT_PATH, load_file_signing_public_key
from client.utils.file_utils import send_file, download_file, get_file_list, preview_file, DOWNLOAD_DIR, UPLOAD_DIR
from client.utils.auth_utils import authenticate_client_gui  # your new function

HOST = '127.0.0.1'
PORT = 5001

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

class FileClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Client")

        self.conn = None
        self.username = None
        self.file_pubkey = load_file_signing_public_key()

        if not self.file_pubkey:
            messagebox.showerror("Error", "Cannot continue without trusted file signing key")
            master.destroy()
            return

        # TLS Socket
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_verify_locations(TRUSTED_ROOT_PATH)
        self.context.verify_mode = ssl.CERT_REQUIRED

        self.connect_to_server()

        # ---------------- LOGIN/REGISTER FRAME ----------------
        self.login_frame = tk.Frame(master)
        self.login_frame.pack(padx=10, pady=10)

        tk.Label(self.login_frame, text="Username:").grid(row=0, column=0)
        self.username_entry = tk.Entry(self.login_frame)
        self.username_entry.grid(row=0, column=1)

        tk.Label(self.login_frame, text="Password:").grid(row=1, column=0)
        self.password_entry = tk.Entry(self.login_frame, show="*")
        self.password_entry.grid(row=1, column=1)

        tk.Button(self.login_frame, text="Login", command=self.login).grid(row=2, column=0)
        tk.Button(self.login_frame, text="Register", command=self.register).grid(row=2, column=1)

        # ---------------- FILE OPERATIONS FRAME ----------------
        self.file_frame = tk.Frame(master)

        tk.Button(self.file_frame, text="Upload File", command=self.upload_file).grid(row=0, column=0, padx=5, pady=5)
        tk.Button(self.file_frame, text="List Files", command=self.list_files).grid(row=0, column=1, padx=5, pady=5)
        tk.Button(self.file_frame, text="Download File", command=self.download_file_gui).grid(row=0, column=2, padx=5, pady=5)

        self.files_listbox = tk.Listbox(self.file_frame, width=50)
        self.files_listbox.grid(row=1, column=0, columnspan=3, padx=5, pady=5)
        self.files_listbox.bind("<Double-Button-1>", self.preview_file_gui)

        self.preview_text = scrolledtext.ScrolledText(self.file_frame, width=60, height=20)
        self.preview_text.grid(row=2, column=0, columnspan=3, padx=5, pady=5)

    def connect_to_server(self):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = self.context.wrap_socket(raw_sock, server_hostname=HOST)
        self.conn.connect((HOST, PORT))

    def login(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password required")
            return

        success, msg = authenticate_client_gui(self.conn, "login", username, password)
        if success:
            self.username = username
            messagebox.showinfo("Login", "Logged in successfully")
            self.login_frame.pack_forget()
            self.file_frame.pack(padx=10, pady=10)
        else:
            messagebox.showinfo("Login/Register", msg)

    def register(self):
        username = self.username_entry.get().strip()
        password = self.password_entry.get().strip()
        if not username or not password:
            messagebox.showwarning("Input Error", "Username and password required")
            return

        success, msg = authenticate_client_gui(self.conn, "register", username, password)
        messagebox.showinfo("Registration", msg)
        
    def preview_file_gui(self, event):
        sel = self.files_listbox.curselection()
        if not sel:
            return
        filename = self.files_listbox.get(sel[0])
        preview_file(self, self.conn, filename)


    def upload_file(self):
        path = filedialog.askopenfilename(initialdir=UPLOAD_DIR)
        if not path:
            return
        send_file(self.conn, path, self.username, self.file_pubkey)
        messagebox.showinfo("Upload", f"File {os.path.basename(path)} uploaded")

    def list_files(self):
        files = get_file_list(self.conn)
        self.files_listbox.delete(0, tk.END)
        for f in files:
            self.files_listbox.insert(tk.END, f)

    def download_file_gui(self):
        sel = self.files_listbox.curselection()
        if not sel:
            messagebox.showwarning("Select File", "Select a file first")
            return
        filename = self.files_listbox.get(sel[0])
        download_file(self.conn, filename, self.file_pubkey)
        messagebox.showinfo("Download", f"File {filename} downloaded")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileClientGUI(root)
    root.mainloop()