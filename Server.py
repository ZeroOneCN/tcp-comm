import os
import socket
import threading
import tkinter as tk
from tkinter import filedialog, scrolledtext
from datetime import datetime


class TCPServer:
    def __init__(self):
        self.server_socket = None
        self.clients_info = {}  # 存储所有客户端信息
        self.server_running = False
        self.message_lock = threading.Lock()  # 用于锁定消息发送

        self.root = tk.Tk()
        self.root.title("服务端")
        self.root.geometry("750x460")  # 设置窗口大小
        self.root.resizable(False, False)  # 禁止用户调整窗口大小

        # 输入框：IP地址
        self.ip_label = tk.Label(self.root, text="设置IP地址为:")
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

        self.start_button = tk.Button(self.root, text="启动服务器", command=self.start_server)
        self.start_button.grid(row=0, column=8, padx=10, pady=10, sticky=tk.W)
        self.stop_button = tk.Button(self.root, text="停止服务器", command=self.stop_server, state=tk.DISABLED)
        self.stop_button.grid(row=0, column=9, padx=10, pady=10, sticky=tk.W)
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
        self.export_data_button = tk.Button(self.root, text="导出数据", command=self.export_data, state=tk.DISABLED)
        self.export_data_button.grid(row=2, column=9, padx=10, pady=10, sticky=tk.W)
        # 当前时间显示
        self.time_label = tk.Label(self.root, text="")
        self.time_label.grid(row=3, column=0, columnspan=2, padx=10, pady=1, sticky=tk.W)

        # 更新时间显示
        self.update_time()

        self.current_directory = ""

    # 开启服务器的方法
    def start_server(self):
        ip = self.ip_entry.get() if self.ip_entry.get() else "127.0.0.1"
        port = int(self.port_entry.get()) if self.port_entry.get() else 9999

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind((ip, port))
        self.server_socket.listen(5)
        self.server_running = True

        self.start_button.config(state=tk.DISABLED)
        self.stop_button.config(state=tk.NORMAL)
        self.send_message_button.config(state=tk.NORMAL)
        self.send_file_button.config(state=tk.NORMAL)
        self.current_directory = os.getcwd()
        self.export_data_button.config(state=tk.NORMAL)
        self.receive_text.insert(tk.END, f"等待客户端接入... (IP: {ip}, 端口: {port})\n")

        threading.Thread(target=self.accept_clients).start()

    # 停止服务器的方法
    def stop_server(self):
        self.server_running = False
        self.server_socket.close()

        for client_socket, addr in self.clients_info.values():
            client_socket.close()

        self.start_button.config(state=tk.NORMAL)
        self.stop_button.config(state=tk.DISABLED)
        self.send_message_button.config(state=tk.DISABLED)
        self.send_file_button.config(state=tk.DISABLED)

        self.receive_text.insert(tk.END, "服务器已停止\n")

    # 当客户端连接上来给出提示
    def accept_clients(self):
        while self.server_running:
            client_socket, addr = self.server_socket.accept()
            self.clients_info[client_socket] = (client_socket, addr)
            threading.Thread(target=self.receive_data, args=(client_socket, addr)).start()

            self.root.after(0, self.receive_text.insert, tk.END, f"客户端 {addr} 已接入\n")
            self.root.after(0, self.receive_text.yview, tk.END)

    # 发送消息到客户端
    def send_message(self):
        message = self.message_entry.get()
        if message:
            # 使用锁确保在多线程中正确地访问和修改共享数据
            with self.message_lock:
                temp_clients_info = dict(self.clients_info)
                for client_socket, addr in temp_clients_info.values():
                    try:
                        client_socket.send(message.encode())
                    except (socket.error, BrokenPipeError):
                        # 发送失败，可能是因为套接字已关闭
                        self.clients_info.pop(client_socket)
                        self.root.after(0, self.receive_text.insert, tk.END, f"客户端 {addr} 已断开连接\n")
                        self.root.after(0, self.receive_text.yview, tk.END)

            # 清空消息框
            self.message_entry.delete(0, tk.END)
            # 在接收消息框中显示已发送的消息
            self.root.after(0, self.receive_text.insert, tk.END, f"已发送消息： {message}\n")
            self.root.after(0, self.receive_text.yview, tk.END)

    # 发送文件到客户端
    def send_file(self):
        file_path = filedialog.askopenfilename(title="选择文件")
        if file_path:
            with open(file_path, "rb") as file:
                file_data = file.read()
                with self.message_lock:
                    temp_clients_info = dict(self.clients_info)
                    for client_socket, addr in temp_clients_info.values():
                        try:
                            client_socket.send(file_data)
                        except (socket.error, BrokenPipeError):
                            # 发送失败，可能是因为套接字已关闭
                            self.clients_info.pop(client_socket)
                            self.root.after(0, self.receive_text.insert, tk.END, f"客户端 {addr} 已断开连接\n")
                            self.root.after(0, self.receive_text.yview, tk.END)

                # 在接收消息框中显示已发送的文件路径
                self.root.after(0, self.receive_text.insert, tk.END, f"已发送文件： {file_path}\n")

    # 接收客户端的消息数据
    def receive_data(self, client_socket, addr):
        while self.server_running:
            try:
                data = client_socket.recv(1024)
                if not data:
                    break
                if data.startswith(b'FILE:'):
                    file_name = data[5:].decode(errors='replace')
                    file_path = os.path.join(self.current_directory, file_name)
                    with open(file_path, "wb") as file:
                        while True:
                            data = client_socket.recv(1024)
                            if not data:
                                break
                            file.write(data)
                    self.root.after(0, self.receive_text.insert, tk.END, f"已接收文件： {file_path}\n")
                else:
                    received_message = data.decode(errors='replace')
                    self.root.after(0, self.receive_text.insert, tk.END,
                                    f"收到来自 {addr} 的消息： {received_message}\n")
                self.root.after(0, self.receive_text.yview, tk.END)
            except (UnicodeDecodeError, ConnectionResetError) as e:
                print(f"Error: {e}")
                break

        self.clients_info.pop(client_socket, None)
        client_socket.close()
        self.root.after(0, self.receive_text.insert, tk.END, f"客户端 {addr} 断开连接\n")


    def export_data(self):
        # 弹出文件对话框，让用户选择导出的文件路径和名称
        file_path = filedialog.asksaveasfilename(defaultextension=".txt", filetypes=[("Text files", "*.txt")])

        if file_path:
            # 打开选定的文件，准备写入数据
            with open(file_path, "w", encoding="utf-8") as export_file:
                # 写入接收到的消息
                export_file.write("接收到的消息：\n")
                for client_socket, addr in self.clients_info.values():
                    export_file.write(f"客户端 {addr}:\n")
                    export_file.write(self.receive_text.get("1.0", tk.END))

            self.root.after(0, self.receive_text.insert, tk.END, f"数据已导出到文件： {file_path}\n")

    # 每秒更新 GUI 中的时间显示
    def update_time(self):
        current_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.time_label.config(text=f"当前时间: {current_time}")
        self.root.after(1000, self.update_time)  # 每秒更新一次


if __name__ == "__main__":
    server = TCPServer()
    server.root.mainloop()