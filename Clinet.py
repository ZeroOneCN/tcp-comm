import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext, messagebox
from datetime import datetime


class TCPClient:
    # 初始化客户端
    def __init__(self):
        self.client_socket = None

        self.root = tk.Tk()
        self.root.title("客户端")
        self.root.geometry("750x460")  # 设置窗口大小
        self.root.resizable(False, False)  # 禁止用户调整窗口大小

        # 输入框：IP地址
        self.ip_label = tk.Label(self.root, text="服务器IP地址:")
        self.ip_label.grid(row=0, column=0, padx=10, pady=10, sticky=tk.W)
        self.ip_entry = tk.Entry(self.root)
        self.ip_entry.insert(0, "127.0.0.1")
        self.ip_entry.grid(row=0, column=1, padx=10, pady=10, sticky=tk.W)
        # 输入框：端口号
        self.port_label = tk.Label(self.root, text="端口号:")
        self.port_label.grid(row=0, column=2, padx=10, pady=10, sticky=tk.W)
        self.port_entry = tk.Entry(self.root)
        self.port_entry.insert(0, "8888")
        self.port_entry.grid(row=0, column=3, padx=10, pady=10, sticky=tk.W)

        self.connect_button = tk.Button(self.root, text="连接服务器", command=self.connect_server)
        self.connect_button.grid(row=0, column=8, padx=10, pady=10, sticky=tk.W)

        self.disconnect_button = tk.Button(self.root, text="断开服务器", command=self.disconnect_server, state=tk.DISABLED)
        self.disconnect_button.grid(row=0, column=9, padx=10, pady=10, sticky=tk.W)
        # 发送消息框
        self.message_entry = tk.Entry(self.root)
        self.message_entry.grid(row=2, column=0, columnspan=4, padx=10, pady=10, sticky=tk.W+tk.E+tk.N+tk.S)
        self.send_message_button = tk.Button(self.root, text="发送消息", command=self.send_message, state=tk.DISABLED)
        self.send_message_button.grid(row=2, column=7, padx=10, pady=10, sticky=tk.W)

        # 接收消息框
        self.receive_text = scrolledtext.ScrolledText(self.root)
        self.receive_text.grid(row=1, column=0, columnspan=10, padx=10, pady=10, sticky=tk.W+tk.E+tk.N+tk.S)

        self.send_file_button = tk.Button(self.root, text="发送文件", command=self.send_file, state=tk.DISABLED)
        self.send_file_button.grid(row=2, column=8, padx=10, pady=10, sticky=tk.W)
        # 导出数据
        self.export_button = tk.Button(self.root, text="导出数据", command=self.export_data)
        self.export_button.grid(row=2, column=9, padx=10, pady=10, sticky=tk.W)
        # 当前时间显示
        self.time_label = tk.Label(self.root, text="")
        self.time_label.grid(row=3, column=0, columnspan=2, padx=10, pady=1, sticky=tk.W)

        # 更新时间显示
        self.update_time()

    # 连接服务器的方法
    def connect_server(self):
        host = self.ip_entry.get() if self.ip_entry.get() else "127.0.0.1"
        port = int(self.port_entry.get()) if self.port_entry.get() else 9999

        self.client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            self.client_socket.connect((host, port))
            self.receive_text.insert(tk.END, f"成功连接服务器 {host}:{port}\n")
        except Exception as e:
            messagebox.showerror("连接错误", str(e))
            return

        threading.Thread(target=self.receive_data).start()

        self.connect_button.config(state=tk.DISABLED)
        self.disconnect_button.config(state=tk.NORMAL)
        self.send_message_button.config(state=tk.NORMAL)
        self.send_file_button.config(state=tk.NORMAL)
        self.export_button.config(state=tk.NORMAL)

    # 断开服务器的方法
    def disconnect_server(self):
        self.client_socket.close()

        self.connect_button.config(state=tk.NORMAL)
        self.disconnect_button.config(state=tk.DISABLED)
        self.send_message_button.config(state=tk.DISABLED)
        self.send_file_button.config(state=tk.DISABLED)

        self.receive_text.insert(tk.END, "服务器已断开\n")

    # 发送消息
    def send_message(self):
        message = self.message_entry.get()
        if message:
            try:
                self.client_socket.send(message.encode())
                self.receive_text.insert(tk.END, f"已发送消息： {message}\n")
                self.message_entry.delete(0, tk.END)  # 清空消息框
            except (socket.error, BrokenPipeError):
                self.receive_text.insert(tk.END, "服务器已断开，无法发送消息\n")
                self.send_message_button.config(state=tk.DISABLED)

    # 发送文件
    def send_file(self):
        file_path = filedialog.askopenfilename(title="选择文件", filetypes=[("Text files", "*.txt")])
        if file_path:
            try:
                with open(file_path, "rb") as file:
                    file_data = file.read()
                    self.client_socket.send(file_data)
                    self.receive_text.insert(tk.END, f"已发送文件： {file_path}\n")
            except (socket.error, BrokenPipeError):
                self.receive_text.insert(tk.END, "服务器已断开，无法发送文件\n")
                self.send_file_button.config(state=tk.DISABLED)

    # 接收服务端的消息数据
    def receive_data(self):
        while True:
            try:
                data = self.client_socket.recv(1024)
                if not data:
                    break
                received_message = data.decode()
                self.root.after(0, self.receive_text.insert, tk.END, f"收到服务端消息： {received_message}\n")
                self.root.after(0, self.receive_text.yview, tk.END)
            except (UnicodeDecodeError, ConnectionResetError) as e:
                print(f"Error: {e}")
                break

        self.client_socket.close()
        self.root.after(0, self.receive_text.insert, tk.END, "服务器已停止，请耐心等待后再试\n")
        self.root.after(0, self.send_file_button.config, tk.DISABLED)

    def export_data(self):
        data_to_export = self.receive_text.get("1.0", tk.END)
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])

        if file_path:
            try:
                with open(file_path, "w", encoding="utf-8") as file:
                    file.write(data_to_export)
                messagebox.showinfo("导出成功", "数据成功导出到文件！")
            except Exception as e:
                messagebox.showerror("导出错误", str(e))

        self.root.after(0, self.receive_text.insert, tk.END, f"数据已导出到文件： {file_path}\n")

    # 每秒更新 GUI 中的时间显示
    def update_time(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=f"当前时间: {current_time}")
        self.root.after(1000, self.update_time)  # 每秒更新一次


if __name__ == "__main__":
    client = TCPClient()
    client.root.mainloop()