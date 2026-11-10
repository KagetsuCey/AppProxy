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
  - 应用管理：支持拖放 `.exe` 自动提取图标与 PE 架构识别，快速切换代理与一键注入启动。
  - 代理节点管理：支持 SOCKS5（含 RFC 1929 认证）、HTTP / HTTPS CONNECT（含 Basic 认证）及实时握手延迟测速。
  - 实时监控：通过命名管道聚合所有活跃后台桥接的连接目标、Fake-IP、代理状态、握手延迟、实时上传/下载字节统计及进程注入/DNS 事件日志。
  - 便携配置：所有配置默认保存在 `AppProxy.UI.exe` 同级目录的 `config.json` 中（不依赖 `%AppData%`）。

## 目录结构

```text
AppProxy.sln
├── src/
│   ├── native/
│   │   ├── AppProxy.Common/      # 跨进程 Shared Memory 与 Named Pipe 日志协议头文件
│   │   ├── AppProxy.Hook/        # x86/x64 注入 Hook DLL (MinHook + /MT 静态运行时)
│   │   └── AppProxy.Injector/    # x86/x64 挂起注入器与跨架构委派入口
│   ├── AppProxy.Core/            # 共享模型、隧道客户端、共享内存与 Job Object 生命周期跟踪
│   ├── AppProxy.Bridge/          # 独立无窗口后台代理桥接进程 (AppProxy.Bridge.exe)
│   └── AppProxy.UI/              # .NET 8 WPF-UI 桌面界面与多桥接实例实时监控面板
├── tests/
│   └── AppProxy.Tests/           # xUnit 单元测试与端到端 Bridge / Job Object 集成测试
└── scripts/
    └── build.bat                 # 一键构建 x86/x64 原生模块、Bridge、UI 与运行测试
```

## 构建与运行

### 环境要求
- Windows 10 / 11 (x64)
- Visual Studio 2022（需包含 **使用 C++ 的桌面开发** x86/x64 工具链 与 **.NET 桌面开发 / .NET 8 SDK**）

### 构建步骤
在工作区根目录运行：

```bat
scripts\build.bat
```

首次编译 `AppProxy.Hook.vcxproj` 时，MSBuild 会自动从 GitHub 下载并解压 `MinHook v1.3.3` 源码到 `third_party\minhook\`（若无法访问 GitHub，可手动下载 `TsudaKageyu/minhook` v1.3.3 解压至 `third_party\minhook\minhook-1.3.3\`）。

## 已知限制

- 受 Windows 系统安全机制保护的 **Protected Process Light (PPL)** 系统进程或 **UWP / Microsoft Store AppContainer** 沙盒应用会拦截用户态 `CreateRemoteThread` 注入。
- 当前版本转发 TCP 流量；UDP 流量不走代理隧道。
