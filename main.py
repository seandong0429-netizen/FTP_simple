import os
import sys
import socket
import threading
import subprocess
import json
import base64
import io
import tkinter as tk
from tkinter import filedialog, ttk, scrolledtext, messagebox
import psutil

try:
    import win32serviceutil
    import win32service
    import win32event
    import servicemanager
    import win32api
    import winerror
    import win32timezone
except ImportError:
    win32serviceutil = None

# --- 托盘图标相关 ---
import pystray
from PIL import Image, ImageDraw, ImageTk

from pyftpdlib.authorizers import DummyAuthorizer
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer
from zeroconf import Zeroconf, ServiceInfo

# Windows 注册表模块（仅 Windows 平台加载）
if sys.platform == 'win32':
    import winreg


class SimpleFTPServer:
    """FTP 服务核心层，负责服务的启动、停止和网络发现"""

    def __init__(self, logger_func=None): # Modified to accept optional logger_func
        self.logger_func = logger_func if logger_func else self._default_logger
        self.server_v4 = None
        self.server_v6 = None
        self.zeroconf = None
        self.server_thread = None

    def _default_logger(self, message):
        """默认日志函数，用于服务模式下没有 GUI 的情况"""
        print(message) # In service mode, this would typically go to event log or a file

    def log(self, message):
        self.logger_func(message)

    def start_service(self, folder, port=21, encoding='utf-8', use_auth=False, username='', password=''):
        if not os.path.isdir(folder):
            self.log(f"错误: 路径不存在 -> {folder}")
            return False

        # 1. FTP 核心配置
        authorizer = DummyAuthorizer()
        # perm="elradfmw": e-切换目录, l-列表, r-下载, a-追加, d-删除, f-重命名, m-创建目录, w-上传
        if use_auth:
            if not username or not password:
                self.log("错误: 启用密码验证时，账号和密码不能为空")
                return False
            authorizer.add_user(username, password, folder, perm="elradfmw")
            self.log(f"已启用密码验证 (账号: {username})")
        else:
            authorizer.add_anonymous(folder, perm="elradfmw")
            self.log("已启用匿名访问 (账号: anonymous，密码留空)")

        # NOTE: 每次启动时动态创建 FTPHandler 的子类，避免类属性在多次启停间相互污染
        handler_class = type("SessionFTPHandler", (FTPHandler,), {})
        handler_class.authorizer = authorizer
        handler_class.encoding = encoding
        # 被动模式端口范围（便于防火墙统一放行）
        handler_class.passive_ports = range(60000, 60100)

        # 2. 启动服务监听 (IPv4 + IPv6 双栈)
        try:
            self.server_v4 = FTPServer(('0.0.0.0', port), handler_class)
        except Exception as e:
            self.log(f"启动 IPv4 服务失败 (端口被占用或无权限): {e}")
            return False

        sock_v6 = None
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
            self.server_v6 = FTPServer(sock_v6, handler_class)
        except Exception as e:
            self.log(f"提示: 本机 IPv6 监听未开启或不支持 ({e})，仅使用 IPv4。")
            # NOTE: 绑定失败时必须关闭 Socket，否则会造成资源泄漏
            if sock_v6 is not None:
                try:
                    sock_v6.close()
                except Exception:
                    pass
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
                    # 生成 Windows 兼容的 .ipv6-literal.net 格式（将 : 替换为 -，% 替换为 s）
                    literal = ip.replace(':', '-').replace('%', 's') + '.ipv6-literal.net'
                    if ip.lower().startswith("fe80"):
                        # NOTE: fe80 链路本地地址不会随网络环境变化，更适合复印机等固定设备
                        self.log(f"IPv6 本地链接 : ftp://[{ip}]:{port}/ (推荐复印机使用)")
                        self.log(f"  👉 Windows 访问: ftp://{literal}:{port}/ (推荐复印机使用)")
                    else:
                        self.log(f"IPv6 局域网络 : ftp://[{ip}]:{port}/")
                        self.log(f"  👉 Windows 访问: ftp://{literal}:{port}/")
            else:
                self.log(f"IPv6 访问 : 服务已开启，但未能自动获取到网卡 IPv6 地址，请查看系统网络信息。")

        # 3. mDNS (.local) 广播
        self.start_mdns(port)

        return True

    def start_mdns(self, port):
        try:
            self.zeroconf = Zeroconf()
            hostname = socket.gethostname()
            # 获取真实局域网 IP
            v4_ips, v6_ips = self.get_all_ips()
            local_ip = self.get_local_ip()

            # 移除 IPv6 中的作用域 ID（如 %en0），以兼容 Zeroconf parsed_addresses
            clean_v6_ips = [ip.split('%')[0] for ip in v6_ips]
            all_ips_str = v4_ips + clean_v6_ips
            if not all_ips_str:
                all_ips_str = [local_ip]

            desc = {'path': '/'}
            info = ServiceInfo(
                "_ftp._tcp.local.",
                f"{hostname}._ftp._tcp.local.",
                addresses=[socket.inet_aton(local_ip)],
                parsed_addresses=all_ips_str,
                port=port,
                properties=desc,
                server=f"{hostname}.local.",
            )
            self.zeroconf.register_service(info)
            self.log(f"mDNS 广播已激活: {hostname}.local (已注册 IPv4 与 IPv6 节点)")
        except Exception as e:
            self.log(f"mDNS 广播启动失败 (版本不支持全节点广或者端口占用): {e}")

    def get_local_ip(self):
        try:
            # 通过连接外网 DNS 来让系统自动选出最优的本机局域网 IP（无需真正建立连接）
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect(("8.8.8.8", 80))
                return s.getsockname()[0]
        except Exception:
            # 离线环境降级方案
            try:
                return socket.gethostbyname(socket.gethostname())
            except Exception:
                return "127.0.0.1"

    def get_all_ips(self):
        """基于 psutil 物理网卡遍历获取 IP 地址，自动去重、过滤虚拟网卡。IPv6 优先 fe80 本地链接。"""
        v4_ips = set()
        v6_ips = set()
        try:
            interfaces = psutil.net_if_addrs()
            stats = psutil.net_if_stats()

            for iface_name, addrs in interfaces.items():
                # 跳过未启用的网卡
                if iface_name in stats and not stats[iface_name].isup:
                    continue
                # 跳过虚拟/回环网卡
                lower_name = iface_name.lower()
                if any(kw in lower_name for kw in ("loopback", "vmware", "virtualbox", "vethernet", "wsl", "docker", "vbox")):
                    continue

                best_v4 = None
                v6_candidates = []

                for addr in addrs:
                    ip = addr.address
                    if addr.family == socket.AF_INET:
                        if not ip.startswith("127.") and not ip.startswith("169.254."):
                            best_v4 = ip
                    elif addr.family == socket.AF_INET6:
                        # 去除 Windows 可能附带的 scope id (如 %12)
                        clean_ip = ip.split('%')[0]
                        if not clean_ip.startswith("::1"):
                            weight = 0
                            if clean_ip.lower().startswith("fe80"):
                                weight = 100  # 用户首选：固定在物理网卡上，不随路由变化
                            elif clean_ip.lower().startswith("fd") or clean_ip.lower().startswith("fc"):
                                weight = 80
                            elif clean_ip.startswith("2"):
                                weight = 50
                            v6_candidates.append((weight, ip))  # 保留原始 ip（含 scope）

                if best_v4:
                    v4_ips.add(best_v4)

                if v6_candidates:
                    v6_candidates.sort(key=lambda x: x[0], reverse=True)
                    v6_ips.add(v6_candidates[0][1])

        except Exception as e:
            self.log(f"psutil 获取网卡失败，降级到 socket: {e}")
            try:
                addr_infos = socket.getaddrinfo(socket.gethostname(), None)
                for info in addr_infos:
                    family, _, _, _, sockaddr = info
                    ip = sockaddr[0]
                    if family == socket.AF_INET and not ip.startswith("127.") and not ip.startswith("169.254."):
                        v4_ips.add(ip)
                    elif family == socket.AF_INET6 and not ip.startswith("::1"):
                        v6_ips.add(ip)
            except Exception:
                pass

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
    """FTP 服务 GUI 界面层"""

    # 日志文本框最大保留行数，超出时自动清除最早的日志
    MAX_LOG_LINES = 1000

    def __init__(self, root):
        self.root = root
        self.ftp_server = SimpleFTPServer()
        self.ftp_server.logger_func = self.log_message  # BUG-1 FIX: 恢复日志回调，确保服务日志显示在 GUI
        self.server_thread = None
        self.is_running = False
        self.tray_icon = None
        self._ui_ready = False  # UI 初始化完成标志，防止 trace 回调在组件未就绪时触发保存

        # 配置文件路径修改为全体用户共享目录（兼容系统服务读取）
        if sys.platform == 'win32':
            app_data_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'FTP_Simple_Server')
        else:
            app_data_dir = os.path.expanduser('~/.ftp_simple_config')
            
        os.makedirs(app_data_dir, exist_ok=True)
        self.config_file = os.path.join(app_data_dir, 'config.json')

        self._pending_logs = []  # 暂存 UI 初始化前的日志消息
        self.config = self.load_config()

        # 日志性能缓冲队列
        self.log_buffer = []
        self.log_flush_scheduled = False

        self.setup_ui()
        self._ui_ready = True

        # 将 UI 初始化前暂存的日志输出到日志窗口
        for msg in self._pending_logs:
            self.log_message(msg)
        self._pending_logs.clear()

        # 拦截点击右上角 X 关闭窗口的事件，改为最小化到托盘
        self.root.protocol('WM_DELETE_WINDOW', self.hide_window)

        # 从注册表同步"开机自启"勾选框状态
        if sys.platform == 'win32':
            self.check_startup_registry()

        # 软件启动后，是否自动开启服务；若自动启动则同时最小化到托盘，避免窗口弹出打扰用户
        if self.auto_start_var.get():
            self.root.after(500, self._auto_start_and_minimize)

    def _auto_start_and_minimize(self):
        """自动启动服务并最小化到系统托盘"""
        self.toggle_service()
        if self.is_running:
            self.hide_window()

    def setup_ui(self):
        # 样式
        style = ttk.Style()
        style.configure("Big.TButton", font=("Microsoft YaHei", 12, "bold"))

        # 1. 共享目录选择
        path_frame = ttk.LabelFrame(self.root, text="共享目录", padding=10)
        path_frame.pack(fill=tk.X, padx=10, pady=5)

        self.path_var = tk.StringVar()
        default_path = self.config.get("folder", "")
        if not default_path or not os.path.exists(default_path):
            default_path = os.path.join(os.path.expanduser("~"), "Desktop")
            if not os.path.exists(default_path):
                default_path = os.path.expanduser("~")
        self.path_var.set(default_path)

        entry = ttk.Entry(path_frame, textvariable=self.path_var)
        entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 5))

        btn_browse = ttk.Button(path_frame, text="浏览...", command=self.browse_folder)
        btn_browse.pack(side=tk.RIGHT)

        # 2. 控制布局（选项 + 按钮）
        ctrl_frame = ttk.Frame(self.root, padding=10)
        ctrl_frame.pack(fill=tk.X, padx=10)

        # 左侧：选项区
        opts_frame = ttk.Labelframe(ctrl_frame, text="设置", padding=5)
        opts_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 5))

        # 编码切换
        self.encoding_var = tk.StringVar(value=self.config.get("encoding", "utf-8"))
        ttk.Radiobutton(opts_frame, text="通用模式 (UTF-8)", variable=self.encoding_var, value="utf-8").pack(anchor=tk.W)
        ttk.Radiobutton(opts_frame, text="兼容模式 (GBK)", variable=self.encoding_var, value="gbk").pack(anchor=tk.W)

        # 端口配置
        port_frame = ttk.Frame(opts_frame)
        port_frame.pack(anchor=tk.W, pady=(5, 0))
        ttk.Label(port_frame, text="端口:").pack(side=tk.LEFT)
        self.port_var = tk.StringVar(value=str(self.config.get("port", "21")))
        # 校验函数：只允许输入纯数字或空字符串（删除时），防止非法端口值
        vcmd = (self.root.register(lambda s: s == "" or s.isdigit()), '%P')
        self.entry_port = ttk.Entry(port_frame, textvariable=self.port_var, width=6,
                                    validate='key', validatecommand=vcmd)
        self.entry_port.pack(side=tk.LEFT, padx=5)

        # 开机自启复选框（原先的桌面快捷方式自启，跟底层系统服务二选一，保留做轻量选项）
        self.startup_var = tk.BooleanVar()
        if sys.platform == 'win32':
            cb_startup = ttk.Checkbutton(opts_frame, text="开机自启 (GUI启动)", variable=self.startup_var, command=self.toggle_startup)
            cb_startup.pack(anchor=tk.W, pady=(5, 0))
        else:
            ttk.Label(opts_frame, text="(开机自启仅限 Windows)", state="disabled").pack(anchor=tk.W, pady=(5, 0))

        # 运行后自动开启服务
        self.auto_start_var = tk.BooleanVar(value=self.config.get("auto_start_service", False))
        cb_auto_start = ttk.Checkbutton(opts_frame, text="软件运行时自动开启服务", variable=self.auto_start_var)
        cb_auto_start.pack(anchor=tk.W, pady=(2, 0))

        # 系统后台服务管理 (Windows 专属)
        if sys.platform == 'win32' and win32serviceutil:
            svc_frame = ttk.Frame(opts_frame)
            svc_frame.pack(anchor=tk.W, fill=tk.X, pady=(10, 5))
            ttk.Label(svc_frame, text="后台系统服务:").pack(side=tk.LEFT)
            self.btn_install_svc = ttk.Button(svc_frame, text="安装服务", command=lambda: self.manage_system_service("install"))
            self.btn_install_svc.pack(side=tk.LEFT, padx=5)
            self.btn_remove_svc = ttk.Button(svc_frame, text="卸载服务", command=lambda: self.manage_system_service("remove"))
            self.btn_remove_svc.pack(side=tk.LEFT)

        # 密码验证配置
        self.use_auth_var = tk.BooleanVar(value=self.config.get("use_auth", False))
        self.username_var = tk.StringVar(value=self.config.get("username", "admin"))
        # 密码从 base64 解码还原
        self.password_var = tk.StringVar(value=self._decode_password(self.config.get("password", "")))

        auth_frame = ttk.Frame(opts_frame)
        auth_frame.pack(anchor=tk.W, fill=tk.X, pady=(5, 0))

        self.cb_auth = ttk.Checkbutton(auth_frame, text="启用访问密码", variable=self.use_auth_var, command=self.toggle_auth_ui)
        self.cb_auth.pack(anchor=tk.W)

        self.auth_input_frame = ttk.Frame(auth_frame)

        ttk.Label(self.auth_input_frame, text="账号:").pack(side=tk.LEFT)
        self.entry_user = ttk.Entry(self.auth_input_frame, textvariable=self.username_var, width=10)
        self.entry_user.pack(side=tk.LEFT, padx=(0, 5))

        ttk.Label(self.auth_input_frame, text="密码:").pack(side=tk.LEFT)
        self.entry_pass = ttk.Entry(self.auth_input_frame, textvariable=self.password_var, width=10)
        self.entry_pass.pack(side=tk.LEFT)

        # 初始化时根据勾选状态显示或隐藏密码输入框
        self.toggle_auth_ui()

        # 右侧：启动按钮
        self.btn_start = ttk.Button(ctrl_frame, text="启动服务", style="Big.TButton", command=self.toggle_service)
        self.btn_start.pack(side=tk.RIGHT, fill=tk.BOTH, padx=(5, 0), ipadx=20)

        # 3. 日志窗口（只读但可选中复制）
        log_frame = ttk.LabelFrame(self.root, text="运行日志", padding=10)
        log_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.log_text = scrolledtext.ScrolledText(log_frame, height=10, font=("Consolas", 9))
        self.log_text.pack(fill=tk.BOTH, expand=True)

        # BUG-5 FIX: 用白名单策略实现只读可复制，放行所有导航和选择操作
        def _on_key(event):
            # 放行 Ctrl/Command 组合键（复制、全选等）
            if event.state & 0x4 or event.state & 0x8:  # Ctrl or Meta
                return None
            # 放行纯导航键
            if event.keysym in ('Left', 'Right', 'Up', 'Down', 'Home', 'End',
                                'Prior', 'Next', 'Shift_L', 'Shift_R',
                                'Control_L', 'Control_R', 'Alt_L', 'Alt_R',
                                'Caps_Lock', 'Escape', 'F1', 'F2', 'F3', 'F4',
                                'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12'):
                return None
            # 拦截所有其他输入（字母/数字/退格/回车/删除等）
            return "break"

        self.log_text.bind("<Key>", _on_key)

        # OPT-1: 添加右键上下文菜单
        self._log_context_menu = tk.Menu(self.log_text, tearoff=0)
        self._log_context_menu.add_command(label="复制", command=lambda: self.root.focus_get().event_generate('<<Copy>>'))
        self._log_context_menu.add_command(label="全选", command=lambda: (self.log_text.tag_add('sel', '1.0', 'end'), None)[-1])

        def _show_log_menu(event):
            self._log_context_menu.tk_popup(event.x_root, event.y_root)

        self.log_text.bind("<Button-3>", _show_log_menu)  # Windows 右键
        self.log_text.bind("<Button-2>", _show_log_menu)  # macOS 右键

        # 4. 底部状态栏（左侧状态 + 右侧帮助按钮）
        bottom_frame = ttk.Frame(self.root)
        bottom_frame.pack(side=tk.BOTTOM, fill=tk.X)

        self.status_var = tk.StringVar(value="就绪")
        status_bar = ttk.Label(bottom_frame, textvariable=self.status_var, relief=tk.SUNKEN, anchor=tk.W)
        status_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)

        btn_help = ttk.Button(bottom_frame, text="帮助", command=self.show_help)
        btn_help.pack(side=tk.RIGHT, padx=2)

        # 绑定所有变量的值变化监听以便实时保存配置
        self.path_var.trace_add("write", lambda *args: self.save_config())
        self.encoding_var.trace_add("write", lambda *args: self.save_config())
        self.port_var.trace_add("write", lambda *args: self.save_config())
        self.use_auth_var.trace_add("write", lambda *args: self.save_config())
        self.username_var.trace_add("write", lambda *args: self.save_config())
        self.password_var.trace_add("write", lambda *args: self.save_config())
        self.auto_start_var.trace_add("write", lambda *args: self.save_config())

    def toggle_auth_ui(self):
        if self.use_auth_var.get():
            self.auth_input_frame.pack(anchor=tk.W, fill=tk.X, pady=(2, 0))
        else:
            self.auth_input_frame.pack_forget()

    # --- 密码编解码（base64 视觉遮蔽，仅防止肉眼直读，并非安全加密） ---

    @staticmethod
    def _encode_password(plain: str) -> str:
        """将明文密码编码为 base64 字符串"""
        if not plain:
            return ""
        return base64.b64encode(plain.encode('utf-8')).decode('utf-8')

    @staticmethod
    def _decode_password(encoded: str) -> str:
        """将 base64 密码解码为明文；兼容旧版明文密码"""
        if not encoded:
            return ""
        try:
            return base64.b64decode(encoded.encode('utf-8')).decode('utf-8')
        except Exception:
            # 兼容旧版本直接存储的明文密码
            return encoded

    # --- 配置文件读写 ---

    def load_config(self):
        try:
            if os.path.exists(self.config_file):
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
        except Exception as e:
            # NOTE: 此时 UI 尚未初始化，将消息暂存到 _pending_logs，待 UI 就绪后统一输出
            self._pending_logs.append(f"[警告] 加载配置文件失败: {e}")
        return {}

    def save_config(self):
        # 在 UI 组件全部初始化完成之前不执行保存，避免 trace 回调触发时变量未就绪
        if not self._ui_ready:
            return

        data = {
            "folder": self.path_var.get(),
            "encoding": self.encoding_var.get(),
            "port": self.port_var.get(),
            "use_auth": self.use_auth_var.get(),
            "username": self.username_var.get(),
            "password": self._encode_password(self.password_var.get()),
            "auto_start_service": self.auto_start_var.get()
        }
        try:
            with open(self.config_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, ensure_ascii=False, indent=2)
        except Exception as e:
            self.log_message(f"[警告] 保存配置文件失败: {e}")

    def browse_folder(self):
        folder = filedialog.askdirectory(initialdir=self.path_var.get())
        if folder:
            self.path_var.set(folder)

    # --- 日志系统（缓冲写入，减少 UI 刷新次数） ---

    def log_message(self, msg):
        self.root.after(0, lambda: self._append_log(msg))

    def _append_log(self, msg):
        self.log_buffer.append(f"{msg}\n")
        if not self.log_flush_scheduled:
            self.log_flush_scheduled = True
            self.root.after(200, self._flush_log_buffer)

    def _flush_log_buffer(self):
        if not self.log_buffer:
            self.log_flush_scheduled = False
            return

        texts = "".join(self.log_buffer)
        self.log_buffer.clear()
        self.log_flush_scheduled = False

        self.log_text.insert(tk.END, texts)

        # 防止长时间运行导致日志无限增长、内存溢出：超过上限时删除最早的行
        current_lines = int(self.log_text.index('end-1c').split('.')[0])
        if current_lines > self.MAX_LOG_LINES:
            self.log_text.delete('1.0', f'{current_lines - self.MAX_LOG_LINES}.0')

        self.log_text.see(tk.END)

    # --- 服务启停控制 ---

    def toggle_service(self):
        if not self.is_running:
            # 启动服务
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

            # 端口范围校验
            if not (1 <= port <= 65535):
                self.log_message(f"错误: 端口号必须在 1-65535 之间 (当前: {port})")
                return

            # 写入权限校验
            if not os.access(folder, os.W_OK):
                messagebox.showwarning("权限提示", f"程序当前未获得对该目录的写入权限:\n{folder}\n这可能导致客户端上传或修改文件失败。")

            # macOS 特权端口警告
            if sys.platform == 'darwin' and port < 1024:
                messagebox.showwarning("特权端口提示", f"在 macOS 上监听 1024 以下的端口 (当前: {port}) 通常需要 sudo 权限。\n如果下面启动失败，请尝试使用 2121 或更大端口。")

            # 端口冲突预检（使用 try/finally 确保 Socket 必定关闭）
            test_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                test_sock.bind(('0.0.0.0', port))
            except OSError:
                messagebox.showerror("端口被占用", f"无法绑定端口 {port}。\n请检查是否有其他 FTP 软件正在运行，或者尝试更换端口。")
                return
            finally:
                test_sock.close()

            # 异步配置防火墙规则（仅 Windows），避免阻塞主线程
            if sys.platform == 'win32':
                threading.Thread(target=self.configure_firewall, args=(port,), daemon=True).start()

            auth_status = '启用' if use_auth else '关闭'
            self.log_message(f"--- 尝试启动 (端口: {port}, 编码: {encoding}, 密码验证: {auth_status}) ---")
            success = self.ftp_server.start_service(folder, port=port, encoding=encoding, use_auth=use_auth, username=username, password=password)

            if success:
                self.is_running = True
                self.btn_start.configure(text="停止服务")
                self.status_var.set("状态: 运行中")
                self.entry_port.configure(state='disabled')
                self.entry_user.configure(state='disabled')
                self.entry_pass.configure(state='disabled')
                self.cb_auth.configure(state='disabled')
            else:
                self.status_var.set("状态: 启动失败")
        else:
            # 停止服务
            self.ftp_server.stop_service()
            self.is_running = False
            self.btn_start.configure(text="启动服务")
            self.status_var.set("状态: 已停止")
            self.entry_port.configure(state='normal')
            self.entry_user.configure(state='normal')
            self.entry_pass.configure(state='normal')
            self.cb_auth.configure(state='normal')

    # --- Windows 防火墙配置 ---

    def configure_firewall(self, port=None):
        """使用 netsh 命令放行 FTP 控制端口和被动模式端口"""
        if sys.platform != 'win32':
            return

        try:
            if port is None:
                try:
                    current_port = int(self.port_var.get())
                except ValueError:
                    current_port = 21
            else:
                current_port = port

            rule_name = f"SimpleFTPServer_Port{current_port}"

            # 使用列表参数 + shell=False，避免命令注入风险
            # 0. 先删除同名旧规则
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'delete', 'rule', f'name={rule_name}_Passive'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

            # 1. 放行控制端口
            r1 = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}', 'dir=in', 'action=allow', 'protocol=TCP',
                 f'localport={current_port}'],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )
            # 2. 放行被动模式端口 (60000-60100)
            r2 = subprocess.run(
                ['netsh', 'advfirewall', 'firewall', 'add', 'rule',
                 f'name={rule_name}_Passive', 'dir=in', 'action=allow', 'protocol=TCP',
                 'localport=60000-60100'],
                stdout=subprocess.DEVNULL, stderr=subprocess.PIPE
            )

            # 检查返回码，非零说明操作失败（通常是缺少管理员权限）
            if r1.returncode != 0 or r2.returncode != 0:
                self.log_message(f"防火墙规则添加失败 (需要以管理员身份运行程序)")
            else:
                self.log_message(f"Windows 防火墙规则更新完成 (已放行 TCP {current_port} 及被动端口)")
        except Exception as e:
            self.log_message(f"防火墙配置失败 (可能由于非管理员权限运行): {e}")

    def manage_system_service(self, action):
        """以管理员身份安装或卸载 Windows 背景服务"""
        import ctypes
        
        # 必须先保存当前配置，因为服务启动时只读磁盘配置
        self.save_config()
        
        # BUG-6 FIX: 统一参数拼接逻辑
        if getattr(sys, 'frozen', False):
            # 打包后的 exe 模式：exe 本身就是入口
            exe_path = sys.executable
            args = action
        else:
            # 脚本开发模式：python.exe + 脚本路径 + 动作
            exe_path = sys.executable
            args = f'"{os.path.abspath(__file__)}" {action}'

        try:
            ret = ctypes.windll.shell32.ShellExecuteW(None, "runas", exe_path, args, None, 1)
            if ret > 32:
                self.log_message(f"系统后台服务 [{action}] 命令已下发执行。请在 services.msc 中检查 [云铠办公扫描服务] 状态。")
            else:
                self.log_message(f"服务提权操作失败，返回码: {ret}")
        except Exception as e:
            self.log_message(f"执行服务命令失败: {e}")

    # --- 开机自启 (轻量 GUI 模式) ---

    def check_startup_registry(self):
        if sys.platform != 'win32':
            return
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
        if sys.platform != 'win32':
            return

        app_path = sys.executable
        # 区分脚本运行和打包 exe 运行
        if not getattr(sys, 'frozen', False):
            app_path = f'"{sys.executable}" "{os.path.abspath(__file__)}"'
        else:
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
            # 操作失败时回滚复选框状态
            self.startup_var.set(not is_checked)

    # --- 系统托盘 ---

    def show_help(self):
        """弹出帮助窗口，展示软件信息和作者微信二维码"""
        help_win = tk.Toplevel(self.root)
        help_win.title("帮助 - 云铠办公扫描工具")
        help_win.resizable(False, False)

        ttk.Label(help_win, text="云铠办公扫描工具 v2.0", font=("Microsoft YaHei", 14, "bold")).pack(pady=(15, 5))
        ttk.Label(help_win, text="轻量级 FTP 服务端，让复印机扫描文件直达电脑").pack(pady=(0, 15))

        # 加载微信二维码图片（从内嵌资源读取）
        try:
            from assets import WECHAT_QR_B64
            qr_data = base64.b64decode(WECHAT_QR_B64)
            qr_img = Image.open(io.BytesIO(qr_data))
            qr_img = qr_img.resize((200, 200), Image.LANCZOS)
            self._help_qr_photo = ImageTk.PhotoImage(qr_img)
            ttk.Label(help_win, image=self._help_qr_photo).pack(pady=5)
        except Exception as e:
            ttk.Label(help_win, text=f"(二维码加载失败: {e})").pack(pady=5)

        ttk.Button(help_win, text="关闭", command=help_win.destroy).pack(pady=(5, 15))

        # 居中显示
        help_win.update_idletasks()
        w = help_win.winfo_width()
        h = help_win.winfo_height()
        x = self.root.winfo_x() + (self.root.winfo_width() - w) // 2
        y = self.root.winfo_y() + (self.root.winfo_height() - h) // 2
        help_win.geometry(f'+{x}+{y}')

    @staticmethod
    def _get_resource_dir():
        """获取资源文件目录（兼容 PyInstaller 打包后的路径）"""
        if getattr(sys, 'frozen', False):
            return os.path.dirname(sys.executable)
        return os.path.dirname(os.path.abspath(__file__))

    def _load_app_icon(self):
        """加载应用图标，用于窗口和托盘（从内嵌资源读取）"""
        try:
            from assets import APP_ICON_B64
            icon_data = base64.b64decode(APP_ICON_B64)
            return Image.open(io.BytesIO(icon_data))
        except Exception:
            # 降级：程序化生成简单图标
            image = Image.new('RGBA', (64, 64), color=(0, 0, 0, 0))
            draw = ImageDraw.Draw(image)
            draw.ellipse((4, 4, 60, 60), fill=(0, 122, 204, 255))
            draw.text((14, 20), "SCAN", fill=(255, 255, 255, 255))
            return image

    def hide_window(self):
        self.root.withdraw()
        if not self.tray_icon:
            # 使用 app_icon.png 作为托盘图标
            tray_image = self._load_app_icon().resize((64, 64), Image.LANCZOS)

            menu = pystray.Menu(
                pystray.MenuItem('显示窗口', self.show_window, default=True),
                pystray.MenuItem('退出', self.quit_app)
            )
            self.tray_icon = pystray.Icon("FTP_Server", tray_image, "云铠办公扫描工具", menu)

            # 在独立线程中运行托盘图标，避免阻塞 tkinter mainloop
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def show_window(self, icon=None, item=None):
        """从托盘恢复窗口（注意：pystray 回调在非主线程，需通过 root.after 调度 tkinter 操作）"""
        def _restore():
            if self.tray_icon:
                self.tray_icon.stop()
                self.tray_icon = None
            self.root.deiconify()
            # 确保窗口恢复后置顶并获得焦点，避免被其他窗口遮挡
            self.root.lift()
            self.root.focus_force()
        self.root.after(0, _restore)

    def quit_app(self, icon=None, item=None):
        """完全退出程序"""
        def _shutdown():
            if self.tray_icon:
                self.tray_icon.stop()
            self.ftp_server.stop_service()
            try:
                self.root.destroy()
            except Exception:
                pass
            sys.exit(0)
        self.root.after(0, _shutdown)


# 动态基类，如果没有装 win32，则继承 object （避免 macOS 环境下编译报错）
BaseService = win32serviceutil.ServiceFramework if win32serviceutil else object

class FTPSysService(BaseService):
    _svc_name_ = "FTPSimpleService"
    _svc_display_name_ = "云铠办公扫描服务"
    _svc_description_ = "轻量级 FTP 后台服务，让复印机扫描文件直达电脑。"

    # 关键：PyInstaller 打包后必须指定自身 exe 作为服务二进制
    # 默认会注册 pythonservice.exe，在打包环境中根本不存在
    if getattr(sys, 'frozen', False):
        _exe_name_ = sys.executable
        _exe_args_ = None

    def __init__(self, args):
        if win32serviceutil:
            win32serviceutil.ServiceFramework.__init__(self, args)
            self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.server = SimpleFTPServer()
        
        # 加载配置
        app_data_dir = os.path.join(os.environ.get('PROGRAMDATA', 'C:\\ProgramData'), 'FTP_Simple_Server')
        self.config_file = os.path.join(app_data_dir, 'config.json')
        self.config = {}
        if os.path.exists(self.config_file):
            import json
            try:
                with open(self.config_file, 'r', encoding='utf-8') as f:
                    self.config = json.load(f)
            except Exception:
                pass

        self.server.logger_func = self._log_to_event  # BUG-3 FIX: 正确的属性名
        self.running = False

    def _log_to_event(self, msg):
        if win32serviceutil:
            servicemanager.LogInfoMsg(str(msg))
        else:
            print(msg)

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.running = False
        self.server.stop_service()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        # 向 SCM 报告服务正在启动
        self.ReportServiceStatus(win32service.SERVICE_START_PENDING)
        self.running = True
        import base64
        port = int(self.config.get('port', 21))
        folder = self.config.get('folder', 'C:\\')
        encoding = self.config.get('encoding', 'utf-8')
        use_auth = self.config.get('use_auth', False)
        username = self.config.get('username', 'admin')
        password = base64.b64decode(self.config.get('password', '')).decode('utf-8') if self.config.get('password') else '123456'

        self._log_to_event(f"Starting FTP service on port {port}, folder {folder}")
        
        def run_server():
            self.server.start_service(folder, port=port, encoding=encoding,
                                      use_auth=use_auth, username=username, password=password)

        t = threading.Thread(target=run_server, daemon=True)
        t.start()

        # 向 SCM 报告服务已成功启动（关键！缺少这一步 SCM 会认为服务超时未启动）
        self.ReportServiceStatus(win32service.SERVICE_RUNNING)
        
        # 阻塞等待停止信号
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)
        self._log_to_event("FTP service stopped.")


def start_gui():
    """启动 GUI 界面模式"""
    root = tk.Tk()

    # 单实例运行锁（通过绑定本地端口实现，同一时刻只允许一个实例运行）
    try:
        root.lock_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        root.lock_socket.bind(('127.0.0.1', 58732))
        root.lock_socket.listen(1)
    except OSError:
        messagebox.showwarning("提示", "云铠办公扫描工具已经在运行中！\n请检查右下角系统托盘。")
        root.destroy()
        sys.exit(0)

    root.title("云铠办公扫描工具 v2.0")
    root.geometry("600x540")

    # 设置窗口图标
    try:
        from assets import APP_ICON_B64
        icon_img = tk.PhotoImage(data=APP_ICON_B64)
        root.iconphoto(True, icon_img)
    except Exception:
        pass

    app = FTPApp(root)
    root.mainloop()


def main():
    """
    程序入口点 —— 三种运行模式：
    1. 命令行参数 (install/remove/start/stop) → 服务管理
    2. SCM 启动 (无参数，但 StartServiceCtrlDispatcher 成功) → 后台服务
    3. 用户双击 (无参数，StartServiceCtrlDispatcher 失败) → GUI
    """
    # 模式 1: 带参数启动，处理 install/remove/start/stop 等服务管理命令
    if len(sys.argv) > 1 and win32serviceutil is not None:
        win32serviceutil.HandleCommandLine(FTPSysService)
        return

    # 模式 2 & 3: 无参数启动，尝试作为服务连接 SCM
    if win32serviceutil is not None:
        try:
            servicemanager.Initialize()
            servicemanager.PrepareToHostSingle(FTPSysService)
            servicemanager.StartServiceCtrlDispatcher()
            # 如果上面成功了，说明是 SCM 启动的，服务已在运行
            return
        except win32service.error as details:
            # ERROR_FAILED_SVC_CONTROLLER_CONNECT (1063):
            # 说明不是 SCM 启动的，是用户双击的 → 回退到 GUI
            if details.winerror == winerror.ERROR_FAILED_SVC_CONTROLLER_CONNECT:
                pass
            else:
                raise

    # 模式 3: 正常启动 GUI
    start_gui()


if __name__ == "__main__":
    import multiprocessing
    # 修复 Windows 下打包成 exe 后可能由于第三方库触发多进程而导致的无限重启（Fork 炸弹）问题
    multiprocessing.freeze_support()
    main()

