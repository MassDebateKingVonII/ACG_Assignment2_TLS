import tkinter as tk
from tkinter import messagebox, filedialog, simpledialog
import socket, ssl, os, threading

from client.utils.certificateValidation import TRUSTED_ROOT_PATH, load_file_signing_public_key
from client.utils.auth_utils import authenticate_client_gui
from client.utils.file_utils import send_file, download_file, get_file_list

HOST = "127.0.0.1"
PORT = 5001

UPLOAD_DIR = os.path.join("client_path", "upload")
DOWNLOAD_DIR = os.path.join("client_path", "download")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(DOWNLOAD_DIR, exist_ok=True)

def create_tls_socket():
    ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_3
    ctx.load_verify_locations(TRUSTED_ROOT_PATH)
    ctx.verify_mode = ssl.CERT_REQUIRED

    raw = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tls = ctx.wrap_socket(raw, server_hostname=HOST)
    tls.connect((HOST, PORT))
    return tls

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Client")

        self.sock = None
        self.username = None
        self.file_pubkey = load_file_signing_public_key()

        if not self.file_pubkey:
            messagebox.showerror("Error", "Missing trusted file signing key")
            root.destroy()
            return

        self.build_login_ui()

    def build_login_ui(self):
        self.clear()

        tk.Label(self.root, text="Username").pack()
        self.user_entry = tk.Entry(self.root)
        self.user_entry.pack()

        tk.Label(self.root, text="Password").pack()
        self.pass_entry = tk.Entry(self.root, show="*")
        self.pass_entry.pack()

        tk.Button(self.root, text="Login", command=lambda: self.auth("login")).pack(pady=5)
        tk.Button(self.root, text="Register", command=lambda: self.auth("register")).pack()
        
    def auth(self, action):
        try:
            if not self.sock:
                self.sock = create_tls_socket()

            user = self.user_entry.get()
            pw = self.pass_entry.get()

            ok, msg = authenticate_client_gui(self.sock, action, user, pw)

            if ok:
                self.username = user
                self.build_file_ui()
            else:
                messagebox.showinfo("Auth", msg)

        except Exception as e:
            messagebox.showerror("Error", str(e))

    def build_file_ui(self):
        self.clear()

        tk.Label(self.root, text=f"Logged in as {self.username}").pack()

        tk.Button(self.root, text="Upload File", command=self.upload).pack(fill="x")
        tk.Button(self.root, text="List Files", command=self.list_files).pack(fill="x")
        tk.Button(self.root, text="Download File", command=self.download).pack(fill="x")
        tk.Button(self.root, text="Quit", command=self.quit).pack(fill="x")

        self.output = tk.Text(self.root, height=12)
        self.output.pack(fill="both", expand=True)

    def upload(self):
        path = filedialog.askopenfilename(initialdir=UPLOAD_DIR)
        if path:
            send_file(self.sock, path, self.username)
            self.log(f"Uploaded: {os.path.basename(path)}")

    def list_files(self):
        files = get_file_list(self.sock)
        self.output.delete("1.0", tk.END)
        for f in files:
            self.log(f)

    def download(self):
        name = simpledialog.askstring("Download", "Filename:")
        if name:
            download_file(self.sock, name, self.file_pubkey)
            self.log(f"Downloaded: {name}")
    def log(self, msg):
        self.output.insert(tk.END, msg + "\n")

    def clear(self):
        for w in self.root.winfo_children():
            w.destroy()

    def quit(self):
        try:
            self.sock.send(b"QUIT")
            self.sock.close()
        except:
            pass
        self.root.destroy()

if __name__ == "__main__":
    root = tk.Tk()
    root.geometry("400x450")
    ClientGUI(root)
    root.mainloop()