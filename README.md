# AppProxy

Windows Fluent WPF 应用级代理注入启动工具。通过配置代理节点与目标应用程序，在启动应用时拉起独立的后台代理桥接进程并挂起目标主线程注入原生 x86/x64 Hook DLL，将应用的 TCP 连接、DNS 解析（Fake-IP）及派生子进程流量透明转发到指定的 **SOCKS5** 或 **HTTP/HTTPS CONNECT** 代理（配置可选托管 `xray-core` 后亦支持 **VLESS / REALITY / TLS**）。

## 核心特性

- **独立后台桥接进程（`AppProxy.Bridge.exe`）与自动生命周期回收**：
  - 每个启动的应用会话拥有独立的无窗口后台桥接进程 `AppProxy.Bridge.exe`（通过 `CREATE_BREAKAWAY_FROM_JOB | CREATE_NEW_PROCESS_GROUP` 脱离 UI 进程树运行）；`AppProxy.Core` 与 `AppProxy.Bridge` 均已彻底脱离 WPF 依赖（仅依赖轻量级 `Microsoft.NETCore.App`）。
  - **退出/关闭 `AppProxy.UI.exe` 不会中断已启动应用的代理连接与 Fake-IP DNS 解析**；重新打开 UI 界面可自动重新发现运行中的后台桥接并恢复实时监控快照。
  - 通过 **Windows Job Object + IOCP (`JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO`) + 退出看门狗** 绑定目标应用及其全部派生子进程树（Hook 层自动剥离 `CREATE_BREAKAWAY_FROM_JOB`）。当主目标进程退出后，自动识别并清理残余的 `ELECTRON_RUN_AS_NODE`、Chromium `--type=renderer/gpu/utility` 子进程及 `crashpad_handler` 等孤儿进程（同时保留具备可见 GUI 窗口的自重启子进程），随后释放回环端口与共享内存并优雅退出。
- **双架构支持 (`x86` / `x64`) + ACG/CFG 安全注入与子进程继承**：
  - 使用 `IsWow64Process2` 自动识别实际运行位数（兼容 `.NET AnyCPU` 与跨架构子进程）。
  - 通过 **Early-Bird User APC (`QueueUserAPC(LoadLibraryW)`)** 在主线程恢复进入 OEP 前完成注入（仅分配 `PAGE_READWRITE` 内存，不修改 `.text` 为 RWX，兼容 ACG / CFG），并在创建目标及子进程时显式剥离 CIG / ACG 等缓解策略，支持注入 Edge 等微软签名与沙盒系应用。
  - Hook `CreateProcessW` / `CreateProcessA` / `CreateProcessAsUserW` / `ResumeThread` 与 `LoadLibrary*`（支持延迟加载模块补装 Hook），实现父子进程同构或跨架构自动注入继承。
- **系统代理隔离（`IgnoreSystemProxy`，默认开启）与全局 TUN 网卡绕过（`BypassGlobalTun`，默认开启）**：
  - 确保通过 AppProxy 启动的应用**不受本机全局系统代理（如 Clash / v2rayN）或全局 TUN 虚拟网卡干扰**，流量严格走 AppProxy 指定代理节点。
  - 启动与注入阶段同步清除 `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY` / `FTP_PROXY` / `SOCKS_PROXY`（含小写变体）并在派生子进程环境块中持续剥离。
  - 原生层 Hook `kernelbase` 注册表查询（`RegQueryValueEx*` / `RegGetValue*`，拦截 `Internet Settings` 及 `DefaultConnectionSettings` 二进制配置）、**WinINet**（`InternetOpen*` / `InternetQueryOption*`）与 **WinHTTP**（`WinHttpOpen`、`WinHttpGetIEProxyConfigForCurrentUser`、`WinHttpGetProxyForUrl`、`WinHttpReadProxySettings` 等 9 个 API），向目标进程统一返回直连配置，使连接交由 Winsock Hook 透明接管。
  - 后台桥接与节点测速在网络出口层自动过滤 `Wintun` / `sing-tun` / `Clash` / `TAP-Windows` 等虚拟网卡，通过 **`IP_UNICAST_IF` / `IPV6_UNICAST_IF`** 绑定物理出口网卡，并对域名代理节点采用物理网卡 **DoH over IP:443** 解析（绕开 `strict_route` 的 53 端口 WFP 拦截与 Fake-IP 污染）；同时监听操作系统网卡变化事件，在网线拔插、DHCP IP 变更或有线/Wi-Fi 切换时自动故障转移。
- **Winsock & 异步 Socket 拦截**：
  - Hook `connect`、`WSAConnect`、`WSAConnectByNameW/A`、`WSAIoctl(SIO_GET_EXTENSION_FUNCTION_POINTER -> ConnectEx)`、`getpeername`、`closesocket`。
  - 兼容阻塞、非阻塞（`FIONBIO`）、`WSAEventSelect` 及 `ConnectEx` + IOCP 模型（支持 Chromium/Electron、Go、Node.js、Python、.NET、cURL、Git 等）。
  - 针对 Fake-IP 与远程 DNS 模式下的 UDP/QUIC 发包及 UDP:53 返回快速失败（`WSAECONNREFUSED`），促使浏览器迅速回退至 TCP HTTPS。
- **远程 DNS 解析 / Fake-IP (`198.18.0.0/15` 与 `fd98:0018::/96`)**：
  - Hook `getaddrinfo`、`GetAddrInfoW`、`GetAddrInfoExW`、`gethostbyname` 与对应的 `freeaddrinfo*`。
  - `GetAddrInfoExW` / `FreeAddrInfoExW` 完整兼容 `AI_EXTENDED` 扩展结构体（`ADDRINFOEX2W` ~ `ADDRINFOEX7`，通过全零超集结构 `FakeAddrInfoExNode` 与双架构 `static_assert` 偏移校验，正确填充 `ai_version` / `ai_fqdn` / `ai_canonname` / `ai_ttl`），彻底兼容依赖 WinHTTP / `webio.dll` 的应用（如 Steam WebSocket CM）。
  - 域名在本地分配虚拟 IP 并写入跨进程共享内存，实际隧道建立时由独立桥接器还原原始域名发送给代理服务器（零本地 DNS 泄漏）。
  - 进程内 Fake-IP 缓存命中时执行 O(1) 跨进程共享内存一致性校验；环形缓冲（16,384 槽位）回绕时基于 `lastUsedTick` 采用窗口近似 LRU 驱逐，避免热点域名被立刻覆盖或命中陈旧缓存。
- **安全通信与稳定性加固**：
  - UI 启动后台桥接进程时通过**一次性匿名 Stdin 管道 (`--launch-stdin`)** 传递启动配置，代理用户名与密码不出现在常驻进程命令行中。
  - UI 遥测命名管道（`AppProxy_Ui_<pid>`）通过 `PipeSecurity` ACL 限制仅当前登录用户可连接，防止同机其他用户窃听连接目标与事件日志。
  - UI 监控面板采用有序 FIFO 队列在 UI 线程统一批量刷盘连接更新与桥接断开事件，避免高并发下的跨线程竞争。
- **C# .NET 8 WPF Fluent UI**：
  - 应用管理：支持拖放 `.exe` 或应用快捷方式（`.lnk`，自动解析 Squirrel/Electron `Update.exe` 目标）自动提取图标、启动参数、工作目录与 PE 架构识别；顶部提供**4 栏运行时概览卡片**（应用数与 x64/x86 分布、代理绑定汇总、DNS/隔离策略、实时活跃桥接联动）及**按绑定策略 / PE 架构组合筛选与搜索**；支持**最大运行实例数上限**配置、**Chromium 系浏览器隔离 Profile**（自动追加 `--user-data-dir`）与**一键生成桌面快捷方式**（免打开 UI 双击直启代理）。
  - 代理节点管理：支持 SOCKS5（含 RFC 1929 认证）、HTTP / HTTPS CONNECT（含 Basic 认证），配置 `xray-core` 后额外开放 **VLESS**（REALITY / TLS / Vision / TCP / WS / gRPC / HTTPUpgrade / XHTTP）；顶部展示**4 栏概览条与 Xray-core 就绪快捷状态徽章**，工具栏支持**全选、关键字搜索、按协议筛选与按默认/延迟/名称排序**，勾选节点后自动展开**上下文批量操作栏**（导出选中、测速选中、查出口选中、删除选中）。支持**添加/编辑弹窗顶部粘贴单条链接快速填充**（`ProxyEditDialog` 直接粘贴 `socks5://` / `http(s)://` / `vless://` / `host:port:user:pass` 等自动解析填表）、**多格式批量导入 / 双栏勾选导出**（`ProxyBatchExportDialog` 支持左侧清单勾选/搜索/全选反选 + 右侧 URI / JSON 实时预览与保存）、**节点落地出口 IP / 国家地区与运营商检测**（经代理隧道直连并绕过全局 TUN，点击出口徽章就地复制且优先采用 Win32 原生剪贴板 API 避免卡顿），以及节点卡片右侧**一键复制单节点链接**与**一键克隆已有节点**。
  - **可选托管 `xray-core` 内核（VLESS / REALITY / TLS）**：
    - 未配置 `xray.exe` 时保持轻量并仅开放原生 `SOCKS5 / HTTP / HTTPS`；在「系统设置」顶部提供**3 栏运行态概览卡**与语义配色状态横幅（醒目展示 `Xray-core` 就绪版本号、内核路径与全局 TUN 隔离状态），可手动浏览指定本地 `xray.exe`，或一键从 GitHub `XTLS/Xray-core` 最新 Release 自动下载解压至 `data\cores\xray.exe` 并校验版本。
    - 运行时通过 `xray.exe run -c stdin:` 内存管道传递配置（不落盘明文节点文件），并绑定 `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE` Windows Job Object；出站流量通过 `dialerProxy` 链入本地 `PhysicalDirectSocksProxy`（底层走 `OutboundSocketConnector`），自动继承全局 TUN 绕过、DoH over IP:443 与物理网卡故障转移；批量测速与批量出口检测自动复用单个多入站 Sidecar 实例。
  - 实时监控：顶部提供**运行状态徽章与 4 栏实时遥测概览卡片**，支持双标签页分别按**连接状态**（活跃 / 连接中 / 已关闭 / 异常）或**事件类别**（启动与注入 / 连接与网络 / DNS Fake-IP / 告警与错误）组合搜索过滤，并提供带指引的空状态视图与列悬浮完整详情提示。
  - 应用相对目录便携存储：配置文件（`data\config.json`）、Chromium 系浏览器隔离目录（`data\profiles\`）、崩溃日志（`data\logs\`）及可选托管内核（`data\cores\`）统一保存在程序根目录下的相对 `data\` 目录中（不依赖 `%AppData%`），支持便携压缩包解压即用与跨目录迁移；多实例启动串行化采用 Windows 内核命名 `Mutex`，不在磁盘产生 `.lock` 残留文件。

## 目录结构

```text
AppProxy.sln
├── src/
│   ├── native/
│   │   ├── AppProxy.Common/      # 跨进程 Shared Memory 与 Named Pipe 日志协议头文件
│   │   ├── AppProxy.Hook/        # x86/x64 注入 Hook DLL (MinHook + /MT 静态运行时)
│   │   └── AppProxy.Injector/    # x86/x64 挂起 APC 注入器与跨架构委派入口
│   ├── AppProxy.Core/            # 共享模型、AppPaths、隧道客户端、共享内存、实例计数与 Job Object 生命周期跟踪
│   ├── AppProxy.Bridge/          # 独立无窗口后台代理桥接进程 (AppProxy.Bridge.exe)
│   └── AppProxy.UI/              # .NET 8 WPF-UI 桌面界面与多桥接实例实时监控面板
├── installer/
│   └── AppProxy.iss              # Inno Setup 7 安装包脚本（原生 x64 安装器、免 UAC 用户安装 + 系统级目录权限）
├── tests/
│   └── AppProxy.Tests/           # xUnit 单元测试与端到端 Bridge / Job Object / 系统代理隔离 / 稳定性安全集成测试
└── scripts/
    ├── build.bat                 # 一键构建 x86/x64 原生模块、Bridge、UI 与运行全部自动化测试
    ├── package.bat               # 一键自包含打包（便携版 ZIP + Inno Setup 安装包 .exe）
    └── package.ps1               # Release 打包、校验与 SHA-256 生成主脚本
```

## 重要操作指南

### 1. 日常使用操作

1. **配置代理节点**：
   - 在「代理节点」页面点击「添加节点」手动录入或直接**粘贴单条代理链接（`socks5://` / `http(s)://` / `vless://` / `host:port:user:pass`）快速填充**；也可通过「批量导入」一次解析多条节点，支持勾选节点进行批量测速、查出口、删除或**选择性导出**（URI 列表 / JSON）。
   - 若需直接导入/使用 `vless://`（含 REALITY / TLS）节点，请先前往「系统设置 → Xray-core 托管内核」指定本地 `xray.exe` 路径或点击「一键下载 Xray-core」。
2. **添加目标应用**：
   - 支持直接将 `.exe` 或桌面/开始菜单 `.lnk` 快捷方式拖放到应用列表（自动解析目标路径、参数、工作目录、图标与 x86/x64 架构；自动识别 Squirrel/Electron 的 `Update.exe --processStart`）。
   - 为应用绑定目标代理节点（或选择 `Direct` 直连）。
3. **关键应用选项说明**：
   - **忽略系统代理（`IgnoreSystemProxy`，推荐保持开启）**：即使 Windows 当前开启了全局系统代理（如 Clash / v2rayN）、配置了 `HTTP_PROXY` 环境变量或开启了全局 TUN 虚拟网卡，经 AppProxy 启动的应用也会忽略它们（配合「系统设置 → 全局 TUN 网卡隔离（`BypassGlobalTun`，默认开启）」自动或手动绑定物理出口网卡，并在网线拔插、切换 Wi-Fi 或 DHCP 换 IP 时自动故障转移；即使应用绑定 `Direct` 直连，在检测到活跃 TUN 时也会经物理网卡直连分流），只走 AppProxy 指定链路。
   - **远程 DNS（`RemoteDns`，推荐保持开启）**：启用 Fake-IP，防止本地 DNS 泄漏。
   - **绕过局域网（`BypassLan`）**：私网与回环地址直连，避免内网访问失败（Fake-IP 网段永远不会被绕过）。
   - **注入子进程（`InjectChildren`）**：自动向应用派生的所有子进程（含跨位数子进程）继承代理拦截。
   - **最大运行实例数（`MaxInstances`，默认 `1`）**：防止单实例应用在已有后台进程运行时重复启动导致接管失效；无论实例是否通过代理启动均计入总数，超限时阻止启动并提示。
   - **浏览器数据目录隔离（`IsolateProfileDir`）**：对 Edge / Chrome / Brave / Vivaldi / Opera / Chromium 默认开启，自动附加 `--user-data-dir="<AppProxyDir>\data\profiles\<AppName>"`，避免与普通未代理浏览器进程合并。
4. **免 UI 桌面快捷方式启动**：
   - 在应用卡片点击「创建桌面快捷方式」，会在桌面生成 `<应用名> (AppProxy).lnk`，其目标指向 `AppProxy.Bridge.exe --launch-app-id <AppGuid>`。
   - 双击该快捷方式无需打开 `AppProxy.UI.exe`，即可直接读取 `data\config.json` 最新配置并拉起独立代理桥接；后续随时打开 `AppProxy.UI.exe` 也会自动发现并接管监控。
5. **独立后台运行与热重连**：
   - 启动应用后可直接关闭 `AppProxy.UI.exe`，后台 `AppProxy.Bridge.exe` 继续维持代理转发；当目标应用及其子进程树全部关闭后，对应桥接进程自动退出并释放资源。

### 2. 桥接进程启动模式说明（开发者/高级用户）

`AppProxy.Bridge.exe` 支持三种启动入口：

- `--launch-stdin`（**UI 默认模式，推荐**）：由父进程通过匿名 Stdin 管道写入单行 UTF-8 `BridgeLaunchRequest` JSON 并关闭写端，Stdout 返回单行 `BridgeHandshakeResponse` JSON；避免代理账号密码出现在进程命令行中。
- `--launch-app-id <Guid>`（**桌面快捷方式模式**）：从程序同级 `data\config.json` 读取指定 `AppProfile` 与绑定代理配置启动，失败时弹出桌面错误提示框。
- `--launch-b64 <Base64Json>`（**兼容/脚本模式**）：保留用于自动化测试或脚本兼容（注意：该方式会将配置编码放在命令行参数中，不建议在包含代理密码的生产场景使用）。

### 3. 数据备份、迁移与卸载清理

- **绿色便携迁移**：直接复制整个 `AppProxy\` 文件夹（含 `data\` 子目录）到其他路径或机器即可完整保留配置与浏览器隔离数据。
- **快速定位配置与日志**：在 UI 中点击「打开数据目录」或查看：
  - 配置文件：`data\config.json`
  - 浏览器隔离数据：`data\profiles\`
  - 崩溃日志：`data\logs\AppProxy.UI.crash.log`、`data\logs\AppProxy.Bridge.crash.log`
- **安装包卸载数据控制**：通过 Inno Setup 卸载程序卸载时，默认保留 `data\` 并交互询问是否删除；静默卸载若需一并清除用户数据，可附加 `/PURGEDATA` 参数。

### 4. 常见问题排查

- **应用启动后秒退或流量未被捕获**：多为单实例应用（如未隔离的浏览器、Electron/聊天客户端）后台托盘已有未注入实例并接管了新窗口。请先完全退出目标应用的所有后台进程，或为 Chromium 系浏览器开启「隔离 Profile 目录」。
- **本机同时开启了其他全局代理或 TUN 工具（如 Clash/v2rayN）**：确认对应应用的「忽略系统代理（`IgnoreSystemProxy`）」与「系统设置 → 全局 TUN 网卡隔离（`BypassGlobalTun`）」均已勾选，且设置页已识别到正确的物理出口网卡；可在监控面板事件日志中确认包含 `system-proxy-isolated` 与 `[Outbound: <物理网卡> (TUN Bypassed)]`。
- **排查 Bridge 进程命令行是否泄露凭据**：在 PowerShell 中运行：
  ```powershell
  Get-CimInstance Win32_Process -Filter "Name='AppProxy.Bridge.exe'" | Select-Object ProcessId, CommandLine
  ```
  经 UI 启动的桥接进程命令行应仅包含 `--launch-stdin`，不含代理账号密码。
- **SmartScreen 拦截或杀软误报**：由于当前发布包尚未配置代码签名证书，且程序包含 APC 注入与 Winsock/WinHTTP Hook 原生模块，Windows SmartScreen 或部分安全软件可能会发出提示。请务必对比发布页 `SHA256SUMS.txt` 校验压缩包/安装包哈希，确认一致后点击「仍要运行」或将程序目录加入安全软件白名单。

## 构建与打包

### 环境要求
- Windows 10 / 11 (x64)
- Visual Studio 2022+（需包含 **使用 C++ 的桌面开发** x86/x64 工具链 与 **.NET 桌面开发 / .NET 8 SDK**）
- *可选（仅生成 `.exe` 安装包时需要）*：[Inno Setup 7](https://jrsoftware.org/isinfo.php)（`ISCC.exe`，支持 `winget install --id JRSoftware.InnoSetup.7 -e -s winget`、`scoop install inno-setup` 或放置到 `tools\InnoSetup7\ISCC.exe`）

### 开发构建与自动化测试
在工作区根目录运行（自动编译 Win32/x64 原生 Hook & Injector、.NET 8 Bridge & UI，并执行全部 xUnit 测试）：

```bat
scripts\build.bat
```

若仅需定向回归核心集成测试（需先完成至少一次原生 x86/x64 构建）：

```powershell
dotnet test tests\AppProxy.Tests\AppProxy.Tests.csproj -c Release --filter "FullyQualifiedName~SystemProxyIsolationTests|FullyQualifiedName~BridgeLifecycleTests|FullyQualifiedName~StabilityAndSecurityTests|FullyQualifiedName~LocalProxyBridgeTests"
```

### 发布打包（便携版 ZIP + 安装包）
在工作区根目录运行（产出 .NET 8 自包含 `win-x64` 发布件，目标机器无需预装 .NET 运行时）：

```bat
scripts\package.bat
```

或使用 PowerShell 脚本按需指定参数（例如跳过安装包仅生成便携版、指定版本号）：

```powershell
powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -PortableOnly
powershell -ExecutionPolicy Bypass -File scripts\package.ps1 -Version 1.1.0
```

打包完成后，将在 `artifacts\release\` 生成：
- `AppProxy-v<Version>-win-x64-portable.zip`：绿色便携版压缩包，解压 `AppProxy\` 文件夹即可运行，数据自动保存在同级 `data\` 目录。
- `AppProxy-v<Version>-win-x64-setup.exe`：Inno Setup 7 原生 64 位安装包（需安装 Inno Setup 7）。默认免 UAC 安装到 `%LocalAppData%\Programs\AppProxy\`，支持自定义路径或切换为所有用户安装（自动为 `{app}\data\` 配置普通用户写权限）；覆盖升级保留 `data\` 数据。
- `SHA256SUMS.txt`：发布产物 SHA-256 校验清单。

首次编译 `AppProxy.Hook.vcxproj` 时，MSBuild 会自动从 GitHub 下载并解压 `MinHook v1.3.3` 源码到 `third_party\minhook\`（若无法访问 GitHub，可手动下载 `TsudaKageyu/minhook` v1.3.3 解压至 `third_party\minhook\minhook-1.3.3\`）。

## 开发接手与维护约定（Architecture & Invariants）

便于新会话或协作者快速接手，修改代码时请务必遵守以下架构边界与核心不变量：

1. **分层与命名空间约束**：
   - `AppProxy.Core`（`AppProxy.Core.{Models,Services,Interop}`）与 `AppProxy.Bridge` **禁止引入 `<UseWPF>true</UseWPF>`**（由 `PeInspectorTests.CoreAndBridge_AreDecoupledFromWpfAssemblies` 自动化守卫）；`AppProfile.Icon` 使用 `object?` 承接 UI 层冻结的 `BitmapSource`。
   - PE 架构检测统一复用 `AppProxy.Core.Services.PeArchitectureDetector`，不要在 Bridge/UI 中重复实现 PE/CLR 解析。
2. **系统代理隔离与全局 TUN 绕过不可破坏（`IgnoreSystemProxy` / `BypassGlobalTun`）**：
   - 系统代理由四层协同完成：环境变量清除（`BridgeDaemonHost` / `HooksSystemProxy.cpp` / `HooksProcess.cpp`）、`kernelbase` 注册表 Hook（`Internet Settings` & `DefaultConnectionSettings`）、WinINet Hook 与 WinHTTP Hook（`HooksWinHttp.cpp`）。
   - 全局 TUN 绕过由 `PhysicalNetworkSelector` / `PhysicalDnsResolver` / `OutboundSocketConnector` 协同完成：仅按网卡索引设置 `IP_UNICAST_IF`（大端序）与 `IPV6_UNICAST_IF`（主机序），**切勿** `Bind` 缓存的本地 IP（避免 DHCP 改 IP 失败），也**绝不**对回环地址（`127.0.0.0/8` / `::1` / `localhost`）施加接口绑定；公网域名代理节点优先经物理网卡 **DoH over IP:443** 解析以绕开 `strict_route` 53 端口 WFP 封锁与 Fake-IP 污染，并随 `NetworkEpoch` 自动失效缓存；托管 `xray-core` Sidecar 通过 `PhysicalDirectSocksProxy`（`dialerProxy`）统一走该物理出口链路。任何涉及启动流程、网络出口或 Hook 的改动后必须确保 `SystemProxyIsolationTests` 与 `TunBypassTests` 全部通过。
3. **跨进程二进制布局与扩展 DNS 结构体**：
   - `src/native/AppProxy.Common/SharedLayout.h` 与 `src/AppProxy.Core/Services/SharedMemoryService.cs` 共享内存二进制偏移必须严格一一对应；修改原生代码后必须同时重编 `Win32` 与 `x64`（`scripts\build.bat`）。
   - `HooksDns.cpp` 的 `HookedGetAddrInfoExW` 必须通过 `FakeAddrInfoExNode` 覆盖 `ADDRINFOEXW` ~ `ADDRINFOEX7`（切勿退回仅分配基础 `ADDRINFOEXW`，否则会导致 `webio.dll` 越界读 `ai_fqdn` 触发 `0xC0000409` 崩溃，例如 Steam 登录闪退）。
4. **管道权限与 UI 线程安全**：
   - `AppProxy_Ui_<pid>` 遥测管道保持当前登录用户 ACL（`NamedPipeServerStreamAcl`）；**切勿**对 `AppProxy_Log_<pid>` 施加拒绝低完整性/AppContainer 令牌的窄 ACL，以免阻断 Chromium/Edge/Electron 沙盒渲染/网络子进程日志上报。
   - `MainViewModel` 中 `_connectionIndex` 与 WPF 绑定属性仅允许在 UI 线程访问，后台管道回调统一经 `_pendingConnectionOps` FIFO 队列入队并在 `OnFlushTimerTick` 刷盘。
5. **桥接启动兼容与打包数据注意**：
   - `AppProxy.UI` 默认使用 `--launch-stdin` 匿名管道隐藏代理凭据，同时必须保留 `--launch-app-id <Guid>`（桌面快捷方式）与 `--launch-b64`（测试/脚本兼容）。
   - 运行 `scripts\package.ps1` 会先清空 `artifacts\package\AppProxy\`；若日常曾直接在该目录运行并生成了 `data\config.json`，打包前请先备份其中的 `data\` 目录。
6. **回归测试基线**：
   - 任何修改完成后运行 `cmd /c scripts\build.bat`，当前基线包含 **78 项**自动化测试（覆盖核心单元、Bridge 生命周期、孤儿进程清理、多开实例限制与命名 Mutex 锁清理、系统代理隔离、全局 TUN 绕过与多网卡故障转移、代理单链接/批量导入导出与落地 IP 检测、托管 Xray-core / VLESS REALITY 解析与物理直连拨号（`XrayCoreTests`）、Fake-IP 缓存一致性、UI 并发队列、版本资源元数据及真实 `WinHTTP / webio.dll` 端到端转发）。

## 已知限制

- 受 Windows 系统安全机制保护的 **Protected Process Light (PPL)** 系统进程或 **UWP / Microsoft Store AppContainer** 沙盒应用会拦截用户态注入。
- 当前版本转发 TCP 流量；UDP 流量不走代理隧道。

## 开源协议

- 本项目采用 [MIT License](LICENSE) 开源。
- 第三方开源组件版权与许可声明见 [THIRD-PARTY-NOTICES.txt](THIRD-PARTY-NOTICES.txt)（包含 MinHook v1.3.3 BSD-2-Clause、WPF-UI MIT 与 CommunityToolkit.Mvvm MIT）。
