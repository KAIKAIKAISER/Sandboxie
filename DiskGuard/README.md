# DiskGuard / 磁盘访问保护

面向 Windows 10/11 x64 的独立 Rust + Tauri 2 控制器。复用 Sandboxie 驱动、SbieSvc 服务及沙箱，不启动或依赖原版 Qt 界面。上游代码保持原样；本项目位于 `DiskGuard/`，工作流位于 `.github/workflows/diskguard*.yml`。

## 安装与运行

1. 安装 DiskGuard NSIS 包。0.2.0 起内置未经修改的官方签名 Classic x64 5.73.8 安装器：缺少运行时时，安装流程验证固定 SHA-256 与 Authenticode，再通过 Windows UAC 请求管理员权限部署驱动和服务，无需另行下载。提示需要重启时按提示操作，保持驱动签名强制检查启用。
2. 也可解压便携包，打开 DiskGuard 后点击“安装内置运行时”。便携包包含安装器，但驱动与服务仍须获得管理员授权安装到系统。已有 Classic/Plus 安装会保留，不自动替换或降级；异常安装应使用其官方安装程序修复。系统需要 Microsoft Edge WebView2（DiskGuard 安装包会按需安装）。
3. 在软件页为 QQ、微信预设选择实际 EXE，或添加任意 EXE。每个软件使用独立 `DiskGuard_` 沙箱。
4. 保存配置并应用策略，再从界面启动。普通权限无法修改受保护的 Sandboxie 配置时，会返回实际错误；按运行时管理策略使用相应权限。

运行时安装取消或失败会显示真实结果，可在界面重试。卸载 DiskGuard 不会移除可能被其他软件使用的共享 Sandboxie 运行时或沙箱数据。官方安装器来源、哈希及对应完整源码见 [运行时声明](runtime/NOTICE.md) 和 [锁文件](scripts/runtime.lock.json)。

## 已实现的行为与边界

| 功能 | 行为 |
| --- | --- |
| 黑名单 | 使用 `ClosedFilePath` 阻止指定目录对象及可选递归子树的路径访问；包括文件打开与目录访问，不能独立选择“只禁枚举” |
| 白名单 | `ClosedFilePath=*` 与 `NormalFilePath` 例外；需运行时证书启用安全功能，应用前检查，缺少时拒绝应用。系统、Program Files、Sandboxie 及目标程序目录作为兼容例外，写入仍重定向到沙箱 |
| 只监控 | 不增加目录阻断规则；仍运行在 Sandboxie 标准沙箱内，其默认隔离和写入重定向仍生效 |
| 非递归规则 | 只匹配目录对象，不能保证阻止通过已知完整路径打开子文件；保护目录内容应启用递归 |
| 自动保护 | 使用驱动 `ForceProcess`；完整路径后缀 `*` 是上游路径匹配机制要求，也会匹配此 EXE 文件名后附加字符的路径。策略在 UI 退出后保持有效 |
| 子进程 | 沙箱内子进程原生继承沙箱；附加开关控制未入箱匹配父进程的 `ForceChildren`，不允许子进程逃离原生继承 |
| 日志 | 消费真实会话 MonitorGet2 事件，保留原始标志与详情；文件打开/策略判定与实际读取严格区分。无法可靠提供目录枚举或实际内容读取的完整事件，未知结果显示未知 |
| 日志存储 | 本次运行内存环形缓冲最多 10,000 条，支持搜索/过滤和 UTF-8 CSV 导出；UI 退出期间不采集，不是无损系统审计 |
| 托盘与启动 | 系统托盘、关闭到托盘、深浅/系统主题、当前用户登录启动、单实例 |

已经在沙箱外运行的进程不能事后迁移。应用/删除策略时拒绝有活动进程的沙箱；需先退出受控软件。上游配置接口逐条刷新，无法保证并发启动与策略更新之间完全原子。全局禁用强制规则、管理员改写配置或运行时失效会影响自动保护；界面展示可检测的错误，不宣称不可绕过。

实时监控流由整个 Windows 会话共享，不能同时与其他监控器争抢。若 SandMan 正在监控，请先关闭其监控功能。短命进程退出后若无法验证沙箱归属，事件不会被猜测归入某个软件。

日志还需要官方运行时的可信会话代理。无 Qt 的已验证路径是官方 Classic 运行时，其默认设置可能自动运行签名的 `SbieCtrl.exe`（MFC 后台代理，可能带系统托盘图标）。DiskGuard 不启动或接管该代理，也不绕过驱动信任检查；尚无可信会话或关闭运行时自动代理时，磁盘策略仍可应用，界面明确显示日志未就绪并继续重试。仅安装驱动和服务不保证日志会话已建立。

白名单会额外检查全局规则、模板和 `TemplateDefaultPaths` 内置例外；发现磁盘放行规则或无法确认的路径时拒绝应用。官方默认模板中的打印目录例外也可能导致拒绝，因此拥有证书仍不等于可直接使用严格白名单。程序不会自动改写共享模板。所有模式也会拒绝已发现的逃逸规则、关闭隔离或关闭文件过滤的设置。

## 云端构建

[Fork 仓库](https://github.com/KAIKAIKAISER/Sandboxie) · [Windows 构建记录](https://github.com/KAIKAIKAISER/Sandboxie/actions/workflows/diskguard.yml)

- Push/PR 修改 DiskGuard 时构建，支持手动触发。
- `diskguard-v<版本>` 标签构建并发布 GitHub Release；标签必须与 `tauri.conf.json` 版本匹配。
- Artifacts 包含集成官方签名运行时的 x64 NSIS 安装包、便携 ZIP、SHA-256、构建清单及构建日志。构建时固定下载、验证并原样打包官方安装器；不会在构建机部署驱动。
- 不重编译或分发自签内核驱动，不改变 Windows 签名要求。UI 本身尚未使用发布者代码签名，Windows 可能显示未知发布者。
- 编译通过不等于真实驱动验证通过。详见 [验证说明](docs/VALIDATION.md) 与独立签名运行时测试工作流。

本地开发（可选）：Node.js 22、Rust stable、MSVC C++ Build Tools 和 Windows SDK；先运行 `DiskGuard/scripts/Get-BundledRuntime.ps1`（仅下载与验证，不安装），再执行 `cd DiskGuard/ui && npm ci`，然后在 `DiskGuard/` 运行 `node ui/node_modules/@tauri-apps/cli/tauri.js dev`。正式构建使用 `scripts/Build.ps1`。优先由 GitHub Windows runner 安装工具链并执行构建。

## 架构与许可证

见 [源码接口分析](docs/ARCHITECTURE.md)。上游固定基线 `c3e59fdb18d50199ebfccf7764e1d6c4e007de96`；使用独立 `diskguard` 分支，定期合并上游 `master`，每次 API 变更必须重新验证 ABI 与真实运行时行为。

DiskGuard 新代码使用 GPL-3.0-or-later（[LICENSE](LICENSE)）。复用 GPL Sandboxie core 的公开导出 API，保留上游各组件许可；未复制或链接 SandMan 自定义许可的 Qt UI。下载安装的官方二进制适用其附带许可。具体第三方与上游声明见 [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md)。
