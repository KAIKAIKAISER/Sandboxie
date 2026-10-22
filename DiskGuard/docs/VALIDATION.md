# 构建与真实运行验证

## 云端构建

`.github/workflows/diskguard.yml` 仅在 Fork 中运行，使用 `windows-2022`、Node 22、Rust stable/MSVC x64 和 .NET 8。提交 `DiskGuard/` 或该 workflow 的变更会触发构建；也支持 Actions 页手动运行。`diskguard-v<version>` 标签必须与 Tauri 版本完全一致，构建成功后上传 GitHub Release。

构建先按锁文件下载官方 Classic x64 安装器，要求 SHA-256 匹配且 Authenticode Valid，然后执行 `npm ci`、前端编译、可用的前端测试、`cargo fmt --check`、`cargo clippy --locked --all-targets -- -D warnings`、`cargo test --locked --all-targets` 以及 Tauri NSIS 打包。构建任务仅打包官方安装器，不在该构建机安装驱动；驱动部署与行为验证由独立的一次性 VM 任务执行。

成功产物包括集成官方运行时的 x64 NSIS 安装包、便携 ZIP、`BUILD-MANIFEST.json` 与 `SHA256SUMS.txt`。构建 transcript 包含工具版本和编译输出，失败时也尝试上传单独日志 Artifact。GitHub Actions 的任务日志是开始执行脚本之前发生故障时的诊断来源。Release 作业仅在标签推送时获取 `contents: write`；普通构建使用只读仓库权限。

0.2.0 的 Push/手动/标签构建在编译完成后调用 `diskguard-integrated-runtime.yml`，分别使用全新 Windows Server 2022 VM 验证安装包与便携包。安装包测试只启动 DiskGuard setup，由其 POSTINSTALL 自动部署缺失运行时；便携包测试使用与界面按钮共用的原生安装函数。探针不会预先安装 Sandboxie 或代替产品启动缺失服务。需验证官方签名、实际驱动/服务可用、重复安装不改变运行时二进制/配置/服务进程、原生 UI 与适配器以及真实访问阻断。便携测试另要求损坏资源副本被拒绝且不注册驱动或服务。两项都通过后标签作业才发布 Release；PR 仅执行普通编译，不部署驱动。交互式 UAC 接受/拒绝仍需客户端验收。

独立的 `diskguard-signed-runtime.yml` 支持手动设置 `run_signed_runtime_tests=true`，在一次性 GitHub hosted Windows Server 2022 VM 上执行真实运行时探针。它按 `scripts/runtime.lock.json` 固定官方 Classic 5.73.8（发布标签 v1.18.8）及 SHA256，安装前要求哈希匹配且 Authenticode 信任状态为 Valid，随后要求服务与驱动运行，并执行文件访问、强制启动和子进程探针。不会改变 Windows 驱动签名配置，也不会在本地开发机安装。若 hosted 环境无法加载签名驱动，此任务明确失败并上传系统事件，不能转为“跳过即通过”。该结果属于 Server 2022，不能替代下表的 Windows 10/11 客户端验收。

手动触发时可同时提供成功构建的 `build_run_id`，额外下载该次构建的便携 UI，执行应用自身的 `--runtime-diagnostics`。测试要求实际 Rust 适配器连接成功、启动监控、轮询成功，且至少解析出一条真实记录；保存应用诊断和构建来源 SHA256。省略该输入时不会执行已构建应用的适配器测试，不能把独立 .NET 探针通过视为 Rust FFI 已验证。

```powershell
# 在 Fork 的仓库目录中，使用有 Windows 构建依赖的环境：
./DiskGuard/scripts/Build.ps1
```

构建失败时应依据失败步骤及 transcript 修复原因后重新运行，不应删除测试、放宽错误检查或把缺少运行时计为通过。Tauri 的安装包配置和 CI 参考官方 [Windows Installer](https://v2.tauri.app/distribute/windows-installer/) 与 [GitHub Pipeline](https://v2.tauri.app/distribute/pipelines/github/) 文档。

## 一次性 VM 的真实文件访问测试

原生二进制验证先于上游探针运行。冷会话测试仅在一次性 hosted VM 停止路径与句柄均确认的官方 Classic 代理，验证无可信日志会话时策略仍可写入、回验、移除，且真实界面的驱动可用状态不被误报为断开。随后使用持续存活并反复打开系统目录的沙箱进程，要求至少一条真实 `file_open` 事件同时具有沙箱名、进程名、PID 和路径，再验证热会话界面与正常退出。JSON 的文件打开事件不被当作读取字节证据。

需要分别准备 Windows 10 x64 与 Windows 11 x64 VM 快照，使用官方签名运行时，开启系统默认驱动签名强制，并安装 64 位 PowerShell 7 和 .NET 8 SDK。关闭 SandMan 资源监控和其他监控消费者。该步骤不在当前宿主机自动执行。

```powershell
# 仅在已准备好的隔离 VM 内，管理员 PowerShell 7：
./DiskGuard/scripts/Test-Runtime.ps1 -AcknowledgeDisposableVm
```

脚本只创建唯一 `DGTest_<随机值>` 沙箱和测试目录，不修改已有沙箱。它检查服务、驱动运行状态与驱动 Windows 信任签名，构建无外部包依赖的 .NET 探针，先在宿主执行基线，再通过 Start.exe 显式启动，最后直接启动已配置 ForceProcess 的探针。探针还启动子进程，并通过进程实际注入的 SbieDll 查询各自沙箱名。

成功断言包括：基线与无附加拒绝规则的只监控沙箱可枚举且可打开、读取测试文件；黑名单下私有文件不能打开读取，私有目录无法泄露条目；清除规则后可以重新访问；允许文件及共享路径前缀的相邻目录文件确实可读取 1 字节，避免 `private` 规则误封 `privateSibling`；显式与强制启动均落入指定沙箱；子进程也在同一沙箱。拒绝被映射为目录不可见时允许“空枚举”结果，因此验收措辞是条目不可见，而不是强行假定所有 API 必须返回 Access Denied。

脚本保留 `runtime.json`、父子进程 JSON、transcript 和成功时的 `RESULT.txt`。结束时回验移除专用测试沙箱配置；保留文件证据与沙箱存储以便排查。超时或清理报错后，先检查并停止测试进程，再从 VM 快照恢复。缺少运行时、签名不受信任、读回不匹配或结果不符都会失败；不存在自动跳过后报告通过的路径。

该脚本验证上游配置行为及启动继承，不覆盖 Tauri UI 全流程；JSON 中的实际字节读取计数来自测试探针自身，不能冒充产品读取日志。

## 发布验收矩阵

| 场景 | Windows 10 x64 | Windows 11 x64 | 所需证据 |
| --- | --- | --- | --- |
| NSIS 安装、启动、卸载与 WebView2 | 待执行 | 待执行 | 安装日志、版本、系统构建 |
| 便携 UI 与已安装运行时 | 待执行 | 待执行 | 实际启动截图和运行时版本 |
| 黑名单真实打开/读取/枚举控制 | 待执行 | 待执行 | 脚本 runtime.json 与探针结果 |
| 强制启动、子进程、UI 关闭后重启 | 待执行 | 待执行 | 进程沙箱归属与读取结果 |
| 白名单有效证书与无证书拒绝 | 待执行 | 待执行 | 能力门禁、30 分钟运行结果 |
| 只监控、规则停用与重启持久化 | 待执行 | 待执行 | 配置读回、真实行为记录 |
| 实时日志、过滤、导出字段与 unknown | 待执行 | 待执行 | 原始记录对照与导出文件 |
| QQ/微信登录、收发文件、更新、重启 | 待执行 | 待执行 | 具体版本、各操作结果 |
| 标准用户、UAC 拒绝、服务停止 | 待执行 | 待执行 | 明确错误、未误标已保护 |
| 路径含中文、长路径、重解析点、网络盘 | 待执行 | 待执行 | 各类边界输入实际测试 |
| 托盘、深色、开机启动、后台占用 | 待执行 | 待执行 | 任务管理器/性能计数器与交互结果 |
| 大量日志、监控竞争、队列溢出 | 待执行 | 待执行 | 错误、丢失指标与响应性 |

待执行项必须保持未验证状态，直到有对应平台证据；不能因 Windows Server hosted runner 编译通过而填为 Windows 10/11 验收通过。
