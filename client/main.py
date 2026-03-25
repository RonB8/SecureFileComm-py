import sys
import os
import tkinter as tk
from tkinter import filedialog, messagebox
from app import SecureClientApp

class ClientGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Secure File Client")
        self.root.geometry("400x300")

        # UI Elements
        tk.Label(root, text="Server IP:").pack(pady=5)
        self.ip_entry = tk.Entry(root)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.pack()

        tk.Label(root, text="Server Port:").pack(pady=5)
        self.port_entry = tk.Entry(root)
        self.port_entry.insert(0, "1256")
        self.port_entry.pack()

        tk.Label(root, text="Client Name:").pack(pady=5)
        self.name_entry = tk.Entry(root)
        self.name_entry.pack()

        self.file_path = tk.StringVar()
        tk.Button(root, text="Select File to Upload", command=self.browse_file).pack(pady=10)
        tk.Label(root, textvariable=self.file_path, fg="blue").pack()

        tk.Button(root, text="Send File", command=self.start_transfer, bg="green", fg="white").pack(pady=20)

    def browse_file(self):
        filename = filedialog.askopenfilename()
        if filename:
            self.file_path.set(filename)

    def start_transfer(self):
        ip = self.ip_entry.get().strip()
        port_str = self.port_entry.get().strip()
        name = self.name_entry.get().strip()
        filepath = self.file_path.get()

        if not (ip and port_str and name and filepath):
            messagebox.showerror("Error", "Please fill all fields and select a file.")
            return

        try:
            port = int(port_str)
        except ValueError:
            messagebox.showerror("Error", "Port must be a valid number.")
            return

        if not os.path.exists(filepath):
            messagebox.showerror("Error", "Selected file does not exist.")
            return

        try:
            client_app = SecureClientApp()
            client_app.run(server_ip=ip, server_port=port, client_name=name, file_path=filepath)
            messagebox.showinfo("Success", "File transfer completed successfully!")
            self.root.destroy()
        except Exception as e:
            messagebox.showerror("Fatal Error", f"An error occurred:\n{e}")

def main():
    root = tk.Tk()
    gui = ClientGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()