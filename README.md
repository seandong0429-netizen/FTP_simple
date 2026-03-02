# 轻量级 FTP 服务端 (Lightweight FTP Server)

一个面向非技术用户的轻量级 FTP 服务端工具，支持 Windows 11 和 macOS (M1/Apple Silicon)。

## 功能特性

*   **单文件运行**: 所有逻辑集成在一个 `main.py` 文件中。
*   **双栈监听**: 支持 IPv4 和 IPv6 (`::`)，确保 `.local` 域名解析正常。
*   **mDNS 发现**: 集成 Zeroconf，广播 `计算机名.local`，无需记忆 IP。
*   **Windows 专用优化**:
    *   自动配置防火墙 (端口 21 + 被动端口 60000-60100)。
    *   支持开机自启 (注册表)。
*   **极简 GUI**: Tkinter 界面，支持路径选择、启停控制、日志查看、**自定义端口**。
*   **编码切换**: 支持 UTF-8 和 GBK 切换，解决旧设备乱码问题。

## 快速开始

### 1. 环境准备

需要 Python 3.9+。

安装依赖：
```bash
pip install -r requirements.txt
```

### 2. 运行代码

```bash
python main.py
```

### 3. 打包指南 (PyInstaller)

为了生成独立的 `.exe` (Windows) 或 `.app` (macOS)，请使用 `pyftpdlib`。

首先安装 PyInstaller：
```bash
pip install pyinstaller
```

#### Windows 打包

在 Windows 上，我们需要请求管理员权限以支持防火墙和注册表修改。

```bash
pyinstaller --noconfirm --onefile --windowed --uac-admin --name "FTP_Simple_Server" --hidden-import=zeroconf main.py
```

*   `--onefile`: 打包成单文件。
*   `--windowed`: 运行时不显示命令行窗口。
*   `--uac-admin`: **关键参数**，让程序启动时请求管理员权限。
*   `--hidden-import`: 确保隐式导入的库 (zeroconf) 被包含。

#### macOS 打包

在 macOS 上：

```bash
pyinstaller --noconfirm --onefile --windowed --name "FTP_Simple_Server" --hidden-import=zeroconf main.py
```

> [!WARNING] macOS M 系列芯片 (Apple Silicon) 打包陷阱
>
> 如果你使用的是最新的 macOS 并在打包或运行后遇到诸如 `macOS 26 (2603) or later required, abort trap: 6` 的严重崩溃报错，这大概率是 macOS **系统自带**的 Python 在调用图形库 Tkinter 时发生的兼容性灾难。
> 
> **Apple Silicon (M1/M2) 正确的打包和运行姿势：**
> 1. 不要使用系统自带的 python3，请通过 Homebrew 全局安装原生的 Python 3：
>    `brew install python-tk@3.10` （或者你的具体 python 版本）
> 2. 使用该 Homebrew 版本的 python 创建纯净的原生虚拟环境：
>    `/opt/homebrew/bin/python3 -m venv venv2`
> 3. `source venv2/bin/activate` 激活后，再重新执行 `pip install` 和 `pyinstaller` 的打包命令。
>
> 注意：macOS 上直接运行生成的 Unix 可执行文件或 `.app` 包。由于系统级权限限制，在 macOS 若试图绑定 `21` 等 1024 以下的特权端口，必须在终端用 `sudo` 运行，否则会遭遇 Permission Denied。建议 macOS 非特权测试时将端口改为 `2121`。

## 常见问题

1.  **启动失败 (Permission denied)**:
    *   在 macOS/Linux 上，绑定 21 端口需要 root 权限。
    *   如果在 macOS 上运行报错，尝试使用 `sudo python main.py`。
2.  **Tkinter 错误 (macOS)**:
    *   如果遇到 `macOS 26 (2602) or later required` 错误，这是 Python 环境的 Tcl/Tk 版本与 macOS 系统不兼容导致。建议升级 Python 版本或使用 Homebrew 安装的 Python (`brew install python-tk`)。
3.  **防火墙拦截**:
    *   Windows 上首次运行会自动尝试添加规则。如果失败，请手动允许程序通过防火墙。

## 许可证

MIT License
