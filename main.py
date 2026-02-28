import os
import sys
import socket
import threading
import logging
import platform
import subprocess
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from zeroconf import Zeroconf, ServiceInfo

# Windows specific imports
if sys.platform == 'win32':
    import winreg

# Configure logging to write to a string buffer or custom handler later
# For now, we will use a custom logger class to redirect to GUI

class TextHandler(logging.Handler):
    """This class allows logging to a Tkinter Text or ScrolledText widget"""
    def __init__(self, text_widget):
        super().__init__()
        self.text_widget = text_widget

    def emit(self, record):
        msg = self.format(record)
        def append():
            self.text_widget.configure(state='normal')
            self.text_widget.insert(tk.END, msg + '\n')
            self.text_widget.see(tk.END)
            self.text_widget.configure(state='disabled')
        # Schedule the append in the main thread
        self.text_widget.after(0, append)

class SimpleFTPServer:
    def __init__(self, logger_func):
        self.logger_func = logger_func
        self.server_v4 = None
        self.server_v6 = None
        self.zeroconf = None
        self.server_thread = None

    def log(self, message):
        self.logger_func(message)

    def start_service(self, folder, port=21, encoding='utf-8', use_auth=False, username='', password=''):
        if not os.path.isdir(folder):
            self.log(f"错误: 路径不存在 -> {folder}")
            return False

        # 1. FTP Core Configuration
        authorizer = DummyAuthorizer()
        # perm="elradfmw": e-change directory, l-list, r-retrieve, a-append, d-delete, f-rename, m-make dir, w-store
        if use_auth:
            if not username or not password:
                self.log("错误: 启用密码验证时，账号和密码不能为空")
                return False
            authorizer.add_user(username, password, folder, perm="elradfmw")
            self.log(f"已启用密码验证 (账号: {username})")
        else:
            authorizer.add_anonymous(folder, perm="elradfmw")
            self.log("已启用匿名访问 (无需密码)")
        
        handler = FTPHandler
        handler.authorizer = authorizer
        handler.encoding = encoding
        # Passive ports range for firewall configuration consistency
        handler.passive_ports = range(60000, 60100)
        
        # 2. 启动服务监听 (IPv4 + IPv6 双栈)
        try:
            self.server_v4 = FTPServer(('0.0.0.0', port), handler)
        except Exception as e:
            self.log(f"启动 IPv4 服务失败 (端口被占用或无权限): {e}")
            return False

        try:
            # 手动创建 IPv6 Socket 并开启 IPV6_V6ONLY = 1，避免与 0.0.0.0 冲突
            sock_v6 = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
            try:
                sock_v6.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except (AttributeError, OSError):
                pass
            sock_v6.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock_v6.bind(('::', port))
            sock_v6.listen(5)
            self.server_v6 = FTPServer(sock_v6, handler)
        except Exception as e:
            self.log(f"提示: 本机 IPv6 监听未开启或不支持 ({e})，仅使用 IPv4。")
            self.server_v6 = None

        # 因为 pyftpdlib 默认共用 IOLoop，只要调用其中一个 serve_forever，
        # 就会同时处理 server_v4 和 server_v6 的请求。
        self.server_thread = threading.Thread(target=self.server_v4.serve_forever, daemon=True)
        self.server_thread.start()
        
        hostname = socket.gethostname()
        self.log(f"FTP 服务已启动 (支持局域网 IPv4 与 IPv6 连接)")
        self.log(f"本地路径: {folder}")
        self.log(f"编码: {encoding}")
        self.log(f"主机名访问: ftp://{hostname}.local:{port}/ (推荐)")
        
        # 获取真实 IP 列表展示给用户
        v4_list, v6_list = self.get_all_ips()
        
        if not v4_list:
            v4_list = [self.get_local_ip()]
            
        for ip in v4_list:
            self.log(f"IPv4 可用 : ftp://{ip}:{port}/")
            
        if self.server_v6:
            if v6_list:
                for ip in v6_list:
                    # Windows 文件管理器访问 IPv6 需要特殊格式: [ipv6_address]
                    # 不过复印机后台往往只需要裸的 ipv6 地址
                    clean_ip = ip.split('%')[0] if '%' in ip else ip
                    self.log(f"IPv6 可用 : {clean_ip}")
            else:
                self.log(f"IPv6 访问 : 服务已开启，但未能自动获取到网卡 IPv6 地址，请查看系统网络信息。")
        
        # 3. mDNS (.local) Broadcast
        self.start_mdns(port)
        
        return True

    def start_mdns(self, port):
        try:
            self.zeroconf = Zeroconf()
            hostname = socket.gethostname()
            # Try to find the real LAN IP
            local_ip = self.get_local_ip()
            
            desc = {'path': '/'}
            info = ServiceInfo(
                "_ftp._tcp.local.",
                f"{hostname}._ftp._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                port=port,
                properties=desc,
                server=f"{hostname}.local.",
            )
            self.zeroconf.register_service(info)
            self.log(f"mDNS 广播已激活: {hostname}.local -> {local_ip}")
        except Exception as e:
            self.log(f"mDNS 广播启动失败: {e}")

    def get_local_ip(self):
        try:
            # Trick to find the WAN facing IP without connecting
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            # 8.8.8.8 is a Google DNS, doesn't need to be reachable, just helps socket find route
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            # Fallback for offline/pure LAN
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    def get_all_ips(self):
        v4_ips = set()
        v6_ips = set()
        try:
            # 获取本机所有地址信息
            addr_infos = socket.getaddrinfo(socket.gethostname(), None)
            for info in addr_infos:
                family, _, _, _, sockaddr = info
                ip = sockaddr[0]
                if family == socket.AF_INET and not ip.startswith("127."):
                    v4_ips.add(ip)
                elif family == socket.AF_INET6 and not ip.startswith("::1"):
                    # 如果 IPv6 包含作用域 (即 %xxx)，我们可以选择展示它或者截断
                    v6_ips.add(ip)
        except Exception as e:
            self.log(f"获取网卡 IP 失败: {e}")
        
        return list(v4_ips), list(v6_ips)

    def stop_service(self):
        if self.server_v4 or self.server_v6:
            self.log("正在停止 FTP 服务...")
            if self.server_v4:
                try:
                    self.server_v4.close_all()
                except Exception:
                    pass
                self.server_v4 = None
            if self.server_v6:
                try:
                    self.server_v6.close_all()
                except Exception:
                    pass
                self.server_v6 = None
        
        if self.zeroconf:
            self.log("正在停止 mDNS 广播...")
            self.zeroconf.close()
            self.zeroconf = None
            
        self.log("服务已停止")

class FTPApp:
    def __init__(self, root):
        self.root = root
        self.ftp_server = SimpleFTPServer(self.log_message)
        self.is_running = False
        self.setup_ui()
        
        # Auto-configure firewall on Windows startup
        if sys.platform == 'win32':
             self.configure_firewall()
        
        # Check registry for startup state
        if sys.platform == 'win32':
            self.check_startup_registry()

    def setup_ui(self):
        # Styles
        style = ttk.Style()
        style.configure("Big.TButton", font=("Microsoft YaHei", 12, "bold"))
        
        # 1. Path Selection
        path_frame = ttk.LabelFrame(self.root, text="共享目录", padding=10)
        path_frame.pack(fill=tk.X, padx=10, pady=5)
        
        self.path_var = tk.StringVar()
        # Default to Desktop or Home
        default_path = os.path.join(os.path.expanduser("~"), "Desktop")
        if not os.path.exists(default_path):
             default_path = os.path.expanduser("~")
        self.path_var.set(default_path)
        
        entry = ttk.Entry(path_frame, textvariable=self.path_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))
        
        btn_browse = ttk.Button(path_frame, text="浏览...", command=self.browse_folder)
        btn_browse.pack(side=tk.RIGHT)

        # 2. Control Layout (Buttons + Options)
        ctrl_frame = ttk.Frame(self.root, padding=10)
        ctrl_frame.pack(fill=tk.X, padx=10)

        # Left side: Options
        opts_frame = ttk.Labelframe(ctrl_frame, text="设置", padding=5)
        opts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))
        
        # Encoding Toggle
        self.encoding_var = tk.StringVar(value="utf-8")
        ttk.Radiobutton(opts_frame, text="通用模式 (UTF-8)", variable=self.encoding_var, value="utf-8").pack(anchor=tk.W)
        ttk.Radiobutton(opts_frame, text="兼容模式 (GBK)", variable=self.encoding_var, value="gbk").pack(anchor=tk.W)

        # Port Configuration
        port_frame = ttk.Frame(opts_frame)
        port_frame.pack(anchor=tk.W, pady=(5,0))
        ttk.Label(port_frame, text="端口:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value="21")
        self.entry_port = ttk.Entry(port_frame, textvariable=self.port_var, width=6)
        self.entry_port.pack(side=tk.LEFT, padx=5)
        
        # Startup Checkbox (Windows Only)
        self.startup_var = tk.BooleanVar()
        if sys.platform == 'win32':
            cb_startup = ttk.Checkbutton(opts_frame, text="开机自启", variable=self.startup_var, command=self.toggle_startup)
            cb_startup.pack(anchor=tk.W, pady=(5,0))
        else:
            ttk.Label(opts_frame, text="(开机自启仅限 Windows)", state="disabled").pack(anchor=tk.W, pady=(5,0))

        # Auth Configuration
        self.use_auth_var = tk.BooleanVar(value=False)
        self.username_var = tk.StringVar(value="admin")
        self.password_var = tk.StringVar(value="123456")
        
        auth_frame = ttk.Frame(opts_frame)
        auth_frame.pack(anchor=tk.W, fill=tk.X, pady=(5,0))
        
        self.cb_auth = ttk.Checkbutton(auth_frame, text="启用访问密码", variable=self.use_auth_var, command=self.toggle_auth_ui)
        self.cb_auth.pack(anchor=tk.W)
        
        self.auth_input_frame = ttk.Frame(auth_frame)
        
        ttk.Label(self.auth_input_frame, text="账号:").pack(side=tk.LEFT)
        self.entry_user = ttk.Entry(self.auth_input_frame, textvariable=self.username_var, width=10)
        self.entry_user.pack(side=tk.LEFT, padx=(0,5))
        
        ttk.Label(self.auth_input_frame, text="密码:").pack(side=tk.LEFT)
        self.entry_pass = ttk.Entry(self.auth_input_frame, textvariable=self.password_var, width=10)
        self.entry_pass.pack(side=tk.LEFT)
        
        # Initialize hidden
        self.toggle_auth_ui()

        # Right side: Big Start Button
        self.btn_start = ttk.Button(ctrl_frame, text="启动服务", style="Big.TButton", command=self.toggle_service)
        self.btn_start.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0), ipadx=20)

        # 3. Log Window
        log_frame = ttk.LabelFrame(self.root, text="运行日志", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, state='disabled', font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # 4. Footer / Status
        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.BOTTOM, fill=tk.X)

    def toggle_auth_ui(self):
        if self.use_auth_var.get():
            self.auth_input_frame.pack(anchor=tk.W, fill=tk.X, pady=(2,0))
        else:
            self.auth_input_frame.pack_forget()

    def browse_folder(self):
        folder = filedialog.askdirectory(initialdir=self.path_var.get())
        if folder:
            self.path_var.set(folder)

    def log_message(self, msg):
        self.root.after(0, lambda: self._append_log(msg))

    def _append_log(self, msg):
        self.log_text.configure(state='normal')
        self.log_text.insert(tk.END, f"{msg}\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state='disabled')

    def toggle_service(self):
        if not self.is_running:
            # Start
            folder = self.path_var.get()
            encoding = self.encoding_var.get()
            use_auth = self.use_auth_var.get()
            username = self.username_var.get()
            password = self.password_var.get()
            
            try:
                port = int(self.port_var.get())
            except ValueError:
                self.log_message("错误: 端口必须是数字")
                return

            # Re-apply firewall rules for the chosen port (Windows only)
            if sys.platform == 'win32':
                self.configure_firewall()

            auth_status = '启用' if use_auth else '关闭'
            self.log_message(f"--- 尝试启动 (端口: {port}, 编码: {encoding}, 密码验证: {auth_status}) ---")
            success = self.ftp_server.start_service(folder, port=port, encoding=encoding, use_auth=use_auth, username=username, password=password)
            
            if success:
                self.is_running = True
                self.btn_start.configure(text="停止服务")
                self.status_var.set("状态: 运行中")
                self.entry_port.configure(state='disabled') # Lock port while running
                self.entry_user.configure(state='disabled')
                self.entry_pass.configure(state='disabled')
                self.cb_auth.configure(state='disabled')
                # Disable options while running
                # (Optional: disable encoding radio buttons)
            else:
                self.status_var.set("状态: 启动失败")
        else:
            # Stop
            self.ftp_server.stop_service()
            self.is_running = False
            self.btn_start.configure(text="启动服务")
            self.status_var.set("状态: 已停止")
            self.entry_port.configure(state='normal') # Unlock port
            self.entry_user.configure(state='normal')
            self.entry_pass.configure(state='normal')
            self.cb_auth.configure(state='normal')

    def configure_firewall(self):
        """Execute netsh commands to allow port 21 and passive ports"""
        if sys.platform != 'win32':
            return
        
        try:
            # Check if rule exists (simplification: just add it, netsh handles duplicates usually or usage 'set' logic)
            # Actually netsh add rule will duplicate if run multiple times with same name but different params.
            # Best strictly to delete then add, or ignore.
            
            # This requires Admin privileges. 
            # We assume the app is run as Admin (via UAC manifest in spec).
            
            rule_name = "SimpleFTPServer_Port21_Passive"
            
            # 0. Delete existing rules first (Clean slate)
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}_Passive"',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            # 1. Allow Port Custom (Control)
            # Note: If user changes port constantly, we might leave old rules if we only delete by name.
            # But we delete by name "SimpleFTPServer_Port21_Passive" (maybe rename rule to match generic or current?)
            # For simplicity, we stick to fixed rule name but update the port
            # Logic: Delete rule 'SimpleFTPServer_Control' -> Add new rule with current port
            
            rule_name = "SimpleFTPServer_Control"

            # 0. Delete existing rules first
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}"',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                f'netsh advfirewall firewall delete rule name="{rule_name}_Passive"',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            
            # Get current port
            try:
                current_port = int(self.port_var.get())
            except ValueError:
                current_port = 21

            # 1. Allow Control Port
            subprocess.run(
                f'netsh advfirewall firewall add rule name="{rule_name}" dir=in action=allow protocol=TCP localport={current_port}',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            # 2. Allow Passive Ports (60000-60100)
            subprocess.run(
                f'netsh advfirewall firewall add rule name="{rule_name}_Passive" dir=in action=allow protocol=TCP localport=60000-60100',
                shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self.log_message("Windows 防火墙规则配置完成 (已清理旧规则)")
        except Exception as e:
            self.log_message(f"防火墙配置失败 (即非管理员运行?): {e}")

    def check_startup_registry(self):
        if sys.platform != 'win32': return
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, winreg.KEY_READ)
            try:
                winreg.QueryValueEx(key, "SimpleFTPServer")
                self.startup_var.set(True)
            except FileNotFoundError:
                self.startup_var.set(False)
            winreg.CloseKey(key)
        except Exception as e:
            self.log_message(f"读取自启注册表失败: {e}")

    def toggle_startup(self):
        if sys.platform != 'win32': return
        
        app_path = sys.executable
        # If running as script, use python exe + script path
        if not getattr(sys, 'frozen', False):
            # We are running as script
            app_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        else:
            # We are running as exe
            app_path = f'"{sys.executable}"'

        is_checked = self.startup_var.get()
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        
        try:
            key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE)
            if is_checked:
                winreg.SetValueEx(key, "SimpleFTPServer", 0, winreg.REG_SZ, app_path)
                self.log_message("已添加开机自启")
            else:
                try:
                    winreg.DeleteValue(key, "SimpleFTPServer")
                    self.log_message("已移除开机自启")
                except FileNotFoundError:
                    pass
            winreg.CloseKey(key)
        except Exception as e:
            self.log_message(f"修改开机自启失败: {e}")
            # Revert checkbox if failed
            self.startup_var.set(not is_checked)

def main():
    root = tk.Tk()
    root.title("云铠文件共享服务 v2.0")
    root.geometry("600x500")
    # Try to set icon if exists (optional)
    # root.iconbitmap('icon.ico') 
    
    app = FTPApp(root)
    root.mainloop()

if __name__ == "__main__":
    import multiprocessing
    # 修复 Windows 下打包成 exe 后可能由于第三方库触发多进程而导致的无限重启（Fork 炸弹）问题
    multiprocessing.freeze_support()
    main()
