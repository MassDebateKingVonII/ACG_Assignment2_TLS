import os, socket, ssl, io
import tkinter as tk

from dotenv import load_dotenv

load_dotenv()

from tkinter import filedialog, messagebox, scrolledtext, ttk
from PIL import Image, ImageTk

from utils.socket_utils import recv_all
from client.utils.certificateValidation import TRUSTED_ROOT_PATH, load_file_signing_public_key
from client.utils.file_utils import send_file, download_file, get_file_list, fetch_preview_bytes
from client.utils.auth_utils import authenticate_client_gui

HOST = os.getenv("SERVER_IP")
PORT = int(os.getenv("SERVER_PORT"))

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

        self.context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        self.context.minimum_version = ssl.TLSVersion.TLSv1_3
        self.context.load_verify_locations(TRUSTED_ROOT_PATH)
        self.context.verify_mode = ssl.CERT_REQUIRED

        self.connect_to_server()

        self.load_file_icons()

        self.build_auth_pages()
        self.build_file_page()

        self.show_login_page()

    def connect_to_server(self):
        raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.conn = self.context.wrap_socket(raw_sock, server_hostname=HOST)
        self.conn.connect((HOST, PORT))

    # ---------- ICONS ----------

    def load_file_icons(self):
        base = os.path.join(os.path.dirname(__file__), "icons")

        def load_icon(filename):
            img = Image.open(os.path.join(base, filename)).convert("RGBA")
            img = img.resize((16, 16), Image.Resampling.LANCZOS)  # resize to 16x16
            return ImageTk.PhotoImage(img)

        self.file_icons = {
            "txt": load_icon("text.png"),
            "md": load_icon("text.png"),
            "jpg": load_icon("image.png"),
            "jpeg": load_icon("image.png"),
            "png": load_icon("image.png"),
            "gif": load_icon("image.png"),
            "pdf": load_icon("pdf.png"),
            "zip": load_icon("zip.png"),
            "rar": load_icon("zip.png"),
            "7z": load_icon("zip.png"),
            "py": load_icon("code.png"),
            "js": load_icon("code.png"),
            "html": load_icon("code.png"),
            "css": load_icon("code.png"),
            "_default": load_icon("unknown.png"),
        }
        
        # --- UI button icons (keep references on self) ---
        def load_ui_icon(filename, size=(16, 16)):
            img = Image.open(os.path.join(base, filename)).convert("RGBA")
            img = img.resize(size, Image.Resampling.LANCZOS)
            return ImageTk.PhotoImage(img)

        self.ui_icons = {
            "upload": load_ui_icon("upload.png"),
            "download": load_ui_icon("download.png"),
            "list": load_ui_icon("list.png"),
            "logout": load_ui_icon("logout.png"),
        }

    def get_icon_for_file(self, filename):
        ext = filename.lower().split('.')[-1] if '.' in filename else ''
        return self.file_icons.get(ext, self.file_icons["_default"])

    # ---------- AUTH UI ----------

    def build_auth_pages(self):
        self.auth_container = tk.Frame(self.master)
        self.auth_container.place(relx=0.5, rely=0.5, anchor="center")

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
        f.pack()

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
        f.pack()

    def show_login_page(self):
        self.register_frame.pack_forget()
        self.login_frame.pack()
        self.file_frame.grid_forget()

    def show_register_page(self):
        self.login_frame.pack_forget()
        self.register_frame.pack()
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
            self.list_files()
            return

        # Ensure GUI/client state is not logged in
        self.username = None
        self.file_frame.grid_forget()
        self.show_login_page()

        messagebox.showerror("Login Failed", msg)

        # If auth_utils closed the connection (on failure), reconnect here
        try:
            if self.conn is None or getattr(self.conn, "fileno", lambda: -1)() == -1:
                self.connect_to_server()
        except Exception as e:
            self._files_data = []
            messagebox.showerror("Connection Error", str(e))
            
    def logout(self):
        if not self.conn:
            return

        try:
            self.conn.send(b"LOGO")
            # read ack (length-prefixed because send_resp is used on server)
            resp_len = int.from_bytes(recv_all(self.conn, 8), "big")
            _ = recv_all(self.conn, resp_len)
        except:
            pass

        # Close and reconnect so AUTH handshake is clean
        try:
            self.conn.close()
        except:
            pass

        self.conn = None
        self.username = None
        self._files_data = []

        # Reset UI
        self.file_frame.grid_forget()
        self.show_login_page()

        # Reconnect (so the next login works)
        try:
            self.connect_to_server()
        except Exception as e:
            messagebox.showerror("Connection Error", str(e))

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
        style = ttk.Style()
        style.configure("Treeview", rowheight=20)  # 20 pixels should fit 16x16 icons

        self.file_frame = tk.Frame(self.master)
        self.file_frame.rowconfigure(1, weight=1)
        self.file_frame.columnconfigure(0, weight=1)

        top = tk.Frame(self.file_frame)
        top.grid(row=0, column=0, sticky="ew")

        # Left-aligned actions
        tk.Button(
            top,
            text="Upload File",
            image=self.ui_icons["upload"],
            compound="left",
            command=self.upload_file
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            top,
            text="List Files",
            image=self.ui_icons["list"],
            compound="left",
            command=self.list_files
        ).pack(side=tk.LEFT, padx=5)

        tk.Button(
            top,
            text="Download File",
            image=self.ui_icons["download"],
            compound="left",
            command=self.download_file_gui
        ).pack(side=tk.LEFT, padx=5)

        # Right-aligned logout
        tk.Button(
            top,
            text="Logout",
            image=self.ui_icons["logout"],
            compound="left",
            command=self.logout
        ).pack(side=tk.RIGHT, padx=5)


        columns = ('filename', 'uploaded_by', 'created_at')
        self.tree = ttk.Treeview(self.file_frame, columns=columns, show='tree headings')

        self.tree.heading('#0', text='Type')
        self.tree.column('#0', width=40, anchor='center')

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
        files = get_file_list(self.conn)
        self._files_data = files

        for row in self.tree.get_children():
            self.tree.delete(row)

        for f in files:
            icon = self.get_icon_for_file(f['filename'])
            self.tree.insert(
                '',
                tk.END,
                image=icon,
                values=(f['filename'], f['uploaded_by'], f['created_at'])
            )

    def download_file_gui(self):
        sel = self.tree.selection()
        if not sel:
            messagebox.showwarning("Select File", "Select a file first")
            return
        idx = self.tree.index(sel[0])
        file_info = self._files_data[idx]

        save_path = filedialog.asksaveasfilename(
            initialfile=file_info['filename'],
            title="Save file as"
        )

        if not save_path:
            return

        download_file(self.conn, file_info['filename'], self.file_pubkey, save_path)
        messagebox.showinfo("Download", f"File saved to:\n{save_path}")

    def preview_file_gui(self, event):
        sel = self.tree.selection()
        if not sel:
            return

        idx = self.tree.index(sel[0])
        file_info = self._files_data[idx]
        self.preview_file(self.conn, file_info['filename'])

    # ---------- PREVIEW WINDOW ----------

    def preview_file(self, conn, filename):
        preview_bytes = fetch_preview_bytes(conn, filename, self.file_pubkey)
        if preview_bytes is None:
            messagebox.showerror("Preview Error", "Failed to fetch/verify preview.")
            return

        win = tk.Toplevel(self.master)
        win.title(f"Preview: {filename}")

        if filename.lower().endswith((".jpg", ".jpeg", ".png", ".gif")):
            original_img = Image.open(io.BytesIO(preview_bytes))

            # (Optional) ensure a Tk-friendly mode
            if original_img.mode not in ("RGB", "RGBA"):
                original_img = original_img.convert("RGBA")

            img_w, img_h = original_img.size

            # Set initial window size to exactly the image size
            win.geometry(f"{img_w}x{img_h}")
            # Allow resizing (to a minsize)
            win.minsize(200, 150)

            # Keep a reference on self to prevent garbage collection
            self._imgtk = ImageTk.PhotoImage(original_img)

            canvas = tk.Canvas(win, bg="black", highlightthickness=0)
            canvas.pack(fill="both", expand=True)

            # Place image; we will just re-center it on resize
            canvas_img = canvas.create_image(img_w // 2, img_h // 2, anchor="center", image=self._imgtk)

            def center_image(event=None):
                cw = canvas.winfo_width()
                ch = canvas.winfo_height()
                canvas.coords(canvas_img, cw // 2, ch // 2)

            # Center once after the canvas is realized, then on every resize
            win.after(0, center_image)
            canvas.bind("<Configure>", center_image)

        else:
            win.geometry("700x500")
            text_area = scrolledtext.ScrolledText(win, wrap=tk.WORD)
            text_area.pack(fill="both", expand=True)
            try:
                text_area.insert(tk.END, preview_bytes.decode("utf-8"))
            except:
                text_area.insert(tk.END, "[Cannot decode file]")

if __name__ == "__main__":
    root = tk.Tk()
    app = FileClientGUI(root)
    root.mainloop()