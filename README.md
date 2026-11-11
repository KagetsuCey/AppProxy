# AppProxy

Windows Fluent WPF 应用级代理注入启动工具。通过配置代理节点与目标应用程序，在启动应用时拉起独立的后台代理桥接进程并挂起目标主线程注入原生 x86/x64 Hook DLL，将应用的 TCP 连接、DNS 解析（Fake-IP）及派生子进程流量透明转发到指定的 **SOCKS5** 或 **HTTP/HTTPS CONNECT** 代理。

## 核心特性

- **独立后台桥接进程（`AppProxy.Bridge.exe`）与自动生命周期回收**：
  - 每个启动的应用会话拥有独立的无窗口后台桥接进程 `AppProxy.Bridge.exe`（脱离 UI 进程树运行）。
  - **退出/关闭 `AppProxy.UI.exe` 不会中断已启动应用的代理连接与 Fake-IP DNS 解析**；重新打开 UI 界面可自动重新连接运行中的后台桥接并恢复实时监控。
  - 通过 **Windows Job Object + IOCP (`JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO`)** 绑定目标应用及其全部派生子进程树，当目标应用及其所有子进程退出后，对应的 `AppProxy.Bridge.exe` 自动释放回环端口与共享内存并退出。
- **双架构支持 (`x86` / `x64`) + 自动子进程继承**：
  - 使用 `IsWow64Process2` 自动识别实际运行位数（兼容 `.NET AnyCPU` 与跨架构子进程）。
  - 通过 OEP (`EB FE`) 捕获 + `CreateRemoteThread(LoadLibraryW)` 完成零 Loader-Lock 死锁注入。
  - Hook `CreateProcessW` / `CreateProcessA` / `CreateProcessAsUserW` / `ResumeThread`，支持父进程到子进程的同构或跨架构自动注入继承。
- **Winsock & 异步 Socket 拦截**：
  - Hook `connect`、`WSAConnect`、`WSAConnectByNameW/A`、`WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER -> ConnectEx)`、`getpeername`、`closesocket`。
  - 兼容阻塞、非阻塞（`FIONBIO`）、`WSAEventSelect` 及 `ConnectEx` + IOCP 模型（支持 Chromium/Electron、Go、Node.js、Python、.NET、cURL、Git 等）。
  - 针对 Fake-IP 与远程 DNS 模式下的 UDP/QUIC 发包返回快速失败（`WSAECONNREFUSED`），促使浏览器迅速回退至 TCP HTTPS。
- **远程 DNS 解析 / Fake-IP (`198.18.0.0/15`)**：
  - Hook `getaddrinfo`、`GetAddrInfoW`、`GetAddrInfoExW`、`gethostbyname` 与对应的 `freeaddrinfo*`。
  - 域名在本地分配虚拟 IP 并写入跨进程共享内存，实际隧道建立时由独立桥接器还原原始域名发送给代理服务器（零本地 DNS 泄漏）。
- **C# .NET 8 WPF Fluent UI**：
  - 应用管理：支持拖放 `.exe` 或应用快捷方式（`.lnk`）自动提取图标、启动参数、工作目录与 PE 架构识别，快速切换代理与一键注入启动；支持为任意应用生成桌面快捷方式，无需打开 UI 界面即可双击直接以代理模式启动。
  - 代理节点管理：支持 SOCKS5（含 RFC 1929 认证）、HTTP / HTTPS CONNECT（含 Basic 认证）及实时握手延迟测速。
  - 实时监控：通过命名管道聚合所有活跃后台桥接的连接目标、Fake-IP、代理状态、握手延迟、实时上传/下载字节统计及进程注入/DNS 事件日志。
  - 应用相对目录便携存储：配置文件（`data\config.json`）、Chromium 系浏览器隔离目录（`data\profiles\`）与崩溃日志（`data\logs\`）统一保存在程序根目录下的相对 `data\` 目录中（不依赖 `%AppData%`，也不读取或迁移旧路径配置），支持便携压缩包解压即用与安装包跨目录迁移。

## 目录结构

```text
AppProxy.sln
├── src/
│   ├── native/
│   │   ├── AppProxy.Common/      # 跨进程 Shared Memory 与 Named Pipe 日志协议头文件
│   │   ├── AppProxy.Hook/        # x86/x64 注入 Hook DLL (MinHook + /MT 静态运行时)
│   │   └── AppProxy.Injector/    # x86/x64 挂起注入器与跨架构委派入口
│   ├── AppProxy.Core/            # 共享模型、AppPaths、隧道客户端、共享内存与 Job Object 生命周期跟踪
│   ├── AppProxy.Bridge/          # 独立无窗口后台代理桥接进程 (AppProxy.Bridge.exe)
│   └── AppProxy.UI/              # .NET 8 WPF-UI 桌面界面与多桥接实例实时监控面板
├── installer/
│   └── AppProxy.iss              # Inno Setup 7 安装包脚本（原生 x64 安装器、免 UAC 用户安装 + 系统级目录权限）
├── tests/
│   └── AppProxy.Tests/           # xUnit 单元测试与端到端 Bridge / Job Object 集成测试
└── scripts/
    ├── build.bat                 # 一键构建 x86/x64 原生模块、Bridge、UI 与运行测试
    ├── package.bat               # 一键自包含打包（便携版 ZIP + Inno Setup 安装包 .exe）
    └── package.ps1               # Release 打包、校验与 SHA-256 生成主脚本
```

## 构建与打包

### 环境要求
- Windows 10 / 11 (x64)
- Visual Studio 2022（需包含 **使用 C++ 的桌面开发** x86/x64 工具链 与 **.NET 桌面开发 / .NET 8 SDK**）
- *可选（仅生成 `.exe` 安装包时需要）*：[Inno Setup 7](https://jrsoftware.org/isinfo.php)（`ISCC.exe`，支持 `winget install --id JRSoftware.InnoSetup.7 -e -s winget`、`scoop install inno-setup` 或放置到 `tools\InnoSetup7\ISCC.exe`）

### 开发构建与测试
在工作区根目录运行：

```bat
scripts\build.bat
```

### 发布打包（便携版 ZIP + 安装包）
在工作区根目录运行（产出 .NET 8 自包含 `win-x64` 发布件，目标机器无需预装 .NET 运行时）：

```bat
scripts\package.bat
```

打包完成后，将在 `artifacts\release\` 生成：
- `AppProxy-v<Version>-win-x64-portable.zip`：绿色便携版压缩包，解压 `AppProxy\` 文件夹即可运行，数据自动保存在同级 `data\` 目录。
- `AppProxy-v<Version>-win-x64-setup.exe`：Inno Setup 7 原生 64 位安装包（需安装 Inno Setup 7；若仅需便携包可加传 `-PortableOnly`）。默认免 UAC 安装到 `%LocalAppData%\Programs\AppProxy\`，支持自定义路径或切换为所有用户安装（自动为 `{app}\data\` 配置普通用户写权限）；覆盖升级保留 `data\` 数据。
- `SHA256SUMS.txt`：发布产物 SHA-256 校验清单。

首次编译 `AppProxy.Hook.vcxproj` 时，MSBuild 会自动从 GitHub 下载并解压 `MinHook v1.3.3` 源码到 `third_party\minhook\`（若无法访问 GitHub，可手动下载 `TsudaKageyu/minhook` v1.3.3 解压至 `third_party\minhook\minhook-1.3.3\`）。

## 已知限制

- 受 Windows 系统安全机制保护的 **Protected Process Light (PPL)** 系统进程或 **UWP / Microsoft Store AppContainer** 沙盒应用会拦截用户态 `CreateRemoteThread` 注入。
- 当前版本转发 TCP 流量；UDP 流量不走代理隧道。
