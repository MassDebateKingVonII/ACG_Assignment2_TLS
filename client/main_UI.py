import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import socket
import ssl
import json
import base64
from utils.socket_utils import recv_all
from client.utils.certificateValidation import TRUSTED_ROOT_PATH, load_file_signing_public_key
from client.utils.file_utils import send_file, download_file, get_file_list, DOWNLOAD_DIR, UPLOAD_DIR
from client.utils.auth_utils import authenticate_client_gui

HOST = '127.0.0.1'
PORT = 5001

os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)


class FileClientGUI:
    def __init__(self, master):
        self.master = master
        master.title("Secure File Client")
        master.geometry("900x600")

        master.rowconfigure(0, weight=1)
        master.columnconfigure(0, weight=1)

        self.conn = None
        self.username = None
        self.file_pubkey = load_file_signing_public_key()

        if not self.file_pubkey:
            messagebox.showerror("Error", "Cannot continue without trusted file signing key")
            master.destroy()
            return

        # SSL/TLS setup
        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_verify_locations(TRUSTED_ROOT_PATH)
        self.context.verify_mode = ssl.CERT_REQUIRED

        self.connect_to_server()

        # Build frames
        self.build_auth_pages()
        self.build_file_page()

        # Show only auth first
        self.show_login_page()

    def connect_to_server(self):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = self.context.wrap_socket(raw_sock, server_hostname=HOST)
        self.conn.connect((HOST, PORT))

    # ---------- AUTH UI ----------

    def build_auth_pages(self):
        self.auth_container = tk.Frame(self.master)
        self.auth_container.grid(row=0, column=0, sticky="nsew")

        self.login_frame = tk.Frame(self.auth_container)
        self.register_frame = tk.Frame(self.auth_container)

        self.build_login_page()
        self.build_register_page()

    def build_login_page(self):
        f = self.login_frame
        tk.Label(f, text="Username:").grid(row=0, column=0, sticky="e")
        self.login_user = tk.Entry(f)
        self.login_user.grid(row=0, column=1, sticky="ew")

        tk.Label(f, text="Password:").grid(row=1, column=0, sticky="e")
        self.login_pass = tk.Entry(f, show="*")
        self.login_pass.grid(row=1, column=1, sticky="ew")

        tk.Button(f, text="Login", command=self.login).grid(row=2, column=0, pady=10)
        tk.Button(f, text="Register", command=self.show_register_page).grid(row=2, column=1)

        f.columnconfigure(1, weight=1)

    def build_register_page(self):
        f = self.register_frame
        tk.Label(f, text="Username:").grid(row=0, column=0, sticky="e")
        self.reg_user = tk.Entry(f)
        self.reg_user.grid(row=0, column=1, sticky="ew")

        tk.Label(f, text="Password:").grid(row=1, column=0, sticky="e")
        self.reg_pass = tk.Entry(f, show="*")
        self.reg_pass.grid(row=1, column=1, sticky="ew")

        tk.Label(f, text="Confirm Password:").grid(row=2, column=0, sticky="e")
        self.reg_pass2 = tk.Entry(f, show="*")
        self.reg_pass2.grid(row=2, column=1, sticky="ew")

        tk.Button(f, text="Register", command=self.register).grid(row=3, column=0, pady=10)
        tk.Button(f, text="Back to Login", command=self.show_login_page).grid(row=3, column=1)

        f.columnconfigure(1, weight=1)

    def show_login_page(self):
        self.register_frame.grid_forget()
        self.login_frame.grid(row=0, column=0, sticky="nsew")
        self.file_frame.grid_forget()

    def show_register_page(self):
        self.login_frame.grid_forget()
        self.register_frame.grid(row=0, column=0, sticky="nsew")
        self.file_frame.grid_forget()

    # ---------- AUTH LOGIC ----------

    def login(self):
        username = self.login_user.get().strip()
        password = self.login_pass.get().strip()

        if not username or not password:
            messagebox.showwarning("Error", "All fields required")
            return

        success, msg = authenticate_client_gui(self.conn, "login", username, password)

        if success:
            self.username = username
            self.auth_container.grid_forget()
            self.file_frame.grid(row=0, column=0, sticky="nsew")
            self.list_files()  # populate files immediately
        else:
            messagebox.showerror("Login Failed", msg)

    def register(self):
        username = self.reg_user.get().strip()
        p1 = self.reg_pass.get().strip()
        p2 = self.reg_pass2.get().strip()

        if not username or not p1 or not p2:
            messagebox.showwarning("Error", "All fields required")
            return
        if p1 != p2:
            messagebox.showerror("Error", "Passwords do not match")
            return

        success, msg = authenticate_client_gui(self.conn, "register", username, p1)
        messagebox.showinfo("Register", msg)

        if success:
            self.show_login_page()

    # ---------- FILE PAGE ----------

    def build_file_page(self):
        self.file_frame = tk.Frame(self.master)
        self.file_frame.rowconfigure(1, weight=1)
        self.file_frame.columnconfigure(0, weight=1)

        top = tk.Frame(self.file_frame)
        top.grid(row=0, column=0, sticky="ew")

        tk.Button(top, text="Upload File", command=self.upload_file).pack(side=tk.LEFT, padx=5)
        tk.Button(top, text="List Files", command=self.list_files).pack(side=tk.LEFT, padx=5)
        tk.Button(top, text="Download File", command=self.download_file_gui).pack(side=tk.LEFT, padx=5)

        columns = ('filename', 'uploaded_by', 'created_at')
        self.tree = ttk.Treeview(self.file_frame, columns=columns, show='headings')
        self.tree.heading('filename', text='Filename')
        self.tree.heading('uploaded_by', text='Uploaded By')
        self.tree.heading('created_at', text='Created At')
        self.tree.column('filename', width=400)
        self.tree.column('uploaded_by', width=150)
        self.tree.column('created_at', width=150)
        self.tree.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.tree.bind("<Double-1>", self.preview_file_gui)

    # ---------- FILE LOGIC ----------

    def upload_file(self):
        path = filedialog.askopenfilename()
        if not path:
            return
        send_file(self.conn, path, self.username, self.file_pubkey)
        messagebox.showinfo("Upload", f"File {os.path.basename(path)} uploaded")
        self.list_files()

    def list_files(self):
        files = get_file_list(self.conn)  # expects list of dicts
        self._files_data = files

        # clear tree
        for row in self.tree.get_children():
            self.tree.delete(row)

        for f in files:
            self.tree.insert('', tk.END, values=(f['filename'], f['uploaded_by'], f['created_at']))

    def download_file_gui(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select File", "Select a file first")
            return
        idx = self.tree.index(sel[0])
        file_info = self._files_data[idx]
        download_file(self.conn, file_info['filename'], self.file_pubkey)
        messagebox.showinfo("Download", f"File {file_info['filename']} downloaded")

    def preview_file_gui(self, event):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if not self._files_data or idx >= len(self._files_data):
            return

        file_info = self._files_data[idx]
        if not file_info or 'filename' not in file_info:
            messagebox.showerror("Error", "File info not available")
            return

        self.preview_file(self.conn, file_info['filename'])

    # ---------- PREVIEW WINDOW ----------

    def preview_file(self, conn, filename):
        conn.send(b"PREV")
        fname_bytes = filename.encode()
        conn.send(len(fname_bytes).to_bytes(8, "big"))
        conn.send(fname_bytes)

        length_bytes = recv_all(conn, 8)
        if not length_bytes:
            return
        length = int.from_bytes(length_bytes, "big")
        payload_bytes = recv_all(conn, length)
        payload = json.loads(payload_bytes.decode())

        if "error" in payload:
            messagebox.showerror("Preview Error", payload["error"])
            return

        preview_bytes = base64.b64decode(payload["preview"])

        win = tk.Toplevel(self.master)
        win.title(f"Preview: {filename}")
        win.geometry("700x500")
        win.rowconfigure(0, weight=1)
        win.columnconfigure(0, weight=1)

        if filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
            from PIL import Image, ImageTk
            import io

            original_img = Image.open(io.BytesIO(preview_bytes))
            canvas = tk.Canvas(win, highlightthickness=0)
            canvas.grid(row=0, column=0, sticky="nsew")

            def resize_image(event):
                w, h = event.width, event.height
                resized = original_img.resize((w, h), Image.LANCZOS)
                self._imgtk = ImageTk.PhotoImage(resized)
                canvas.delete("all")
                canvas.create_image(0, 0, anchor="nw", image=self._imgtk)

            canvas.bind("<Configure>", resize_image)
        else:
            text_area = scrolledtext.ScrolledText(win, wrap=tk.WORD)
            text_area.grid(row=0, column=0, sticky="nsew")
            try:
                text_area.insert(tk.END, preview_bytes.decode("utf-8"))
            except:
                text_area.insert(tk.END, "[Cannot decode file]")


if __name__ == "__main__":
    root = tk.Tk()
    app = FileClientGUI(root)
    root.mainloop()