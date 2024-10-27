import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import os
from cryptography.fernet import Fernet
a=45
print(a)

class SecureCryptor:
    def __init__(self):
        self.window = tk.Tk()
        self.window.title("Secure File Cryptor")
        self.window.geometry("600x450")
        self.window.resizable(False, False)

        # Set theme colors
        self.bg_color = "#2c3e50"
        self.fg_color = "white"
        self.btn_color = "#3498db"
        self.window.configure(bg=self.bg_color)
   
        self.key = None
        self.key_path = None
        self.setup_gui()

    def setup_gui(self):
        # Main container
        main_frame = tk.Frame(self.window, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(expand=True, fill='both')

        # Title
        title_label = tk.Label(
            main_frame,
            text="Secure File Cryptor",
            font=('Helvetica', 24, 'bold'),
            bg=self.bg_color,
            fg=self.fg_color
        )
        title_label.pack(pady=(0, 20))

        # Key Frame
        key_frame = tk.LabelFrame(
            main_frame,
            text="Security Key",
            font=('Helvetica', 12),
            bg=self.bg_color,
            fg=self.fg_color,
            padx=10,
            pady=10
        )
        key_frame.pack(fill='x', pady=(0, 20))

        # Key Path Display
        self.key_label = tk.Label(
            key_frame,
            text="No key loaded",
            bg=self.bg_color,
            fg='#95a5a6',
            font=('Helvetica', 10)
        )
        self.key_label.pack(pady=(0, 10))

        # Load Key Button
        self.load_key_btn = tk.Button(
            key_frame,
            text="Load Security Key",
            command=self.load_key_file,
            bg=self.btn_color,
            fg=self.fg_color,
            font=('Helvetica', 10),
            relief=tk.RAISED,
            bd=0,
            padx=20,
            pady=5
        )
        self.load_key_btn.pack()

        # Operations Frame
        op_frame = tk.LabelFrame(
            main_frame,
            text="File Operations",
            font=('Helvetica', 12),
            bg=self.bg_color,
            fg=self.fg_color,
            padx=10,
            pady=10
        )
        op_frame.pack(fill='x')

        # Encrypt Button
        self.encrypt_btn = tk.Button(
            op_frame,
            text="Encrypt File",
            command=self.encrypt_file,
            bg='#27ae60',
            fg=self.fg_color,
            font=('Helvetica', 12),
            relief=tk.RAISED,
            bd=0,
            padx=20,
            pady=10
        )
        self.encrypt_btn.pack(pady=(0, 10), fill='x')

        # Decrypt Button
        self.decrypt_btn = tk.Button(
            op_frame,
            text="Decrypt File",
            command=self.decrypt_file,
            bg='#e74c3c',
            fg=self.fg_color,
            font=('Helvetica', 12),
            relief=tk.RAISED,
            bd=0,
            padx=20,
            pady=10
        )
        self.decrypt_btn.pack(fill='x')

        # Status Frame
        status_frame = tk.Frame(main_frame, bg=self.bg_color)
        status_frame.pack(fill='x', pady=(20, 0))

        self.status_label = tk.Label(
            status_frame,
            text="Ready",
            bg=self.bg_color,
            fg='#95a5a6',
            font=('Helvetica', 10)
        )
        self.status_label.pack()

        # Bind hover effects
        for btn in [self.load_key_btn, self.encrypt_btn, self.decrypt_btn]:
            btn.bind('<Enter>', self.on_enter)
            btn.bind('<Leave>', self.on_leave)

    def on_enter(self, e):
        """Mouse hover effect"""
        e.widget.config(bg=self.darken_color(e.widget.cget('bg')))

    def on_leave(self, e):
        """Mouse leave effect"""
        e.widget.config(bg=self.lighten_color(e.widget.cget('bg')))

    def darken_color(self, hex_color):
        """Darken a color for hover effect"""
        rgb = tuple(int(hex_color[i:i+2], 16) for i in (1, 3, 5))
        rgb = tuple(max(0, c - 20) for c in rgb)
        return f'#{rgb[0]:02x}{rgb[1]:02x}{rgb[2]:02x}'

    def lighten_color(self, hex_color):
        """Lighten a color back to original"""
        if hex_color == '#27ae60': return '#27ae60'  # encrypt button
        if hex_color == '#e74c3c': return '#e74c3c'  # decrypt button
        return self.btn_color  # default button color

    def load_key_file(self):
        file_path = filedialog.askopenfilename(
            title="Select Security Key",
            filetypes=[("Key files", "*.key"), ("All files", "*.*")]
        )
        if file_path:
            try:
                with open(file_path, 'r') as f:
                    key_data = f.read().strip()
                    self.key = key_data.encode()
                self.key_path = file_path
                self.key_label.config(
                    text=f"Key: ...{os.path.basename(file_path)}",
                    fg='#2ecc71'
                )
                self.status_label.config(
                    text="Security key loaded successfully",
                    fg='#2ecc71'
                )
            except Exception as e:
                messagebox.showerror("Error", f"Failed to load key: {str(e)}")

    def encrypt_file(self):
        if not self.key:
            messagebox.showwarning("Warning", "Please load a security key first!")
            return

        file_path = filedialog.askopenfilename(
            title="Select File to Encrypt",
            filetypes=[
                ("Text files", "*.txt"),
                ("Word documents", "*.docx"),
                ("All files", "*.*")
            ]
        )

        if file_path:
            try:
                self.status_label.config(text="Encrypting...", fg='#f1c40f')
                self.window.update()

                f = Fernet(self.key)
                with open(file_path, 'rb') as file:
                    file_data = file.read()

                encrypted_data = f.encrypt(file_data)
                output_file = file_path + '.encrypted'

                with open(output_file, 'wb') as file:
                    file.write(encrypted_data)

                self.status_label.config(
                    text="File encrypted successfully!",
                    fg='#2ecc71'
                )
                messagebox.showinfo(
                    "Success",
                    f"File encrypted successfully!\nSaved as:\n{output_file}"
                )
            except Exception as e:
                self.status_label.config(text="Encryption failed!", fg='#e74c3c')
                messagebox.showerror("Error", f"Encryption failed: {str(e)}")

    def decrypt_file(self):
        if not self.key:
            messagebox.showwarning("Warning", "Please load a security key first!")
            return

        file_path = filedialog.askopenfilename(
            title="Select File to Decrypt",
            filetypes=[("Encrypted files", "*.encrypted"), ("All files", "*.*")]
        )

        if file_path:
            try:
                self.status_label.config(text="Decrypting...", fg='#f1c40f')
                self.window.update()

                f = Fernet(self.key)
                with open(file_path, 'rb') as file:
                    encrypted_data = file.read()

                decrypted_data = f.decrypt(encrypted_data)
                output_file = file_path.replace('.encrypted', '_decrypted.txt')

                with open(output_file, 'wb') as file:
                    file.write(decrypted_data)

                self.status_label.config(
                    text="File decrypted successfully!",
                    fg='#2ecc71'
                )
                messagebox.showinfo(
                    "Success",
                    f"File decrypted successfully!\nSaved as:\n{output_file}"
                )
            except Exception as e:
                self.status_label.config(text="Decryption failed!", fg='#e74c3c')
                messagebox.showerror("Error", f"Decryption failed: {str(e)}")

    def run(self):
        self.window.mainloop()

if __name__ == "__main__":
    app = SecureCryptor()
    app.run()