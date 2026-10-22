# 架构与上游接口审查

源代码审查基线：Sandboxie 提交 `c3e59fdb18d50199ebfccf7764e1d6c4e007de96`。本目录新增独立的 Rust + Tauri 2 用户界面；不修改驱动、服务、注入 DLL 或上游 Qt 用户界面。

```text
Tauri WebView2 UI（本地前端、无远程页面）
              │ 受限 Tauri commands
Rust 应用状态 / 配置 / 规则编译 / 日志缓冲 / CSV 导出
              │
Sandboxie 适配器（Windows x64 FFI）
   ├─ 注册表 SbieSvc ImagePath → 可信安装目录
   ├─ 绝对路径 SbieDll.dll → 配置、进程查询、监控 IOCTL
   └─ 绝对路径 Start.exe /box:<独立沙箱> <EXE>
              │
已安装的官方签名 SbieSvc + SbieDrv + SbieDll
              │
受控程序及其继承沙箱的子进程
```

## 组件边界

| 组件 | 职责 | 权限与边界 |
| --- | --- | --- |
| `ui/` | 软件、规则、实时日志、设置界面 | 不执行 shell，不直接修改 Sandboxie.ini |
| `src-tauri/` 应用层 | 校验输入、持久化、应用策略、日志搜索与导出 | 只操作应用管理的独立沙箱；错误必须返回界面 |
| Sandboxie 适配器 | 动态链接现有 API、配置读写回验、进程与监控查询 | 使用注册表确定安装目录；不从工作目录或下载位置加载 DLL |
| 内置运行时安装模块 | 检查固定资源、SHA-256、Authenticode，通过标准 UAC 部署官方 Classic | 不接受 UI 输入的路径或 URL；存在 SbieSvc 时保留原安装；GUI 与安装包调用相同原生安装函数 |
| 上游运行时 | 文件访问判定、沙箱继承、强制程序启动 | 由官方签名运行时提供；没有自行实现内核访问拦截 |
| `scripts/Build.ps1` | 固定下载验证官方安装器、格式检查、静态分析、单元测试、NSIS 与便携打包 | 原样打包官方安装器，不构建或在构建机安装驱动 |
| `scripts/Test-Runtime.ps1` | 独立 VM 内无敏感数据的真实行为验证 | 显式管理员运行；需要已安装并运行的签名驱动 |

## 已审查接口

0.2.0 安装模块将 `scripts/runtime.lock.json` 编译到应用作为信任锚，随包资源中的锁文件不能改变允许安装的官方二进制。安装前验证 SHA-256 与原生 WinVerifyTrust，持有禁止写入和删除共享的文件句柄直到安装进程结束，随后检查实际服务与驱动状态。只在确实不存在 SbieSvc 时部署；不将“文件已复制”或“安装器退出”单独当成驱动已经可用。NSIS POSTINSTALL 和便携界面的按钮复用相同代码，取消、失败和需重启分别上报。卸载 UI 保留共享运行时。

下列链接固定到审查提交，避免上游移动分支改变引用含义。

| 用途 | 上游依据 | 应用处理 |
| --- | --- | --- |
| 查询 API 与进程 | [`sbieapi.h`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/core/dll/sbieapi.h) | `SbieApi_GetVersion`、`SbieApi_QueryProcess`、`SbieApi_EnumProcessEx` 等现有导出 |
| 配置修改 | [`apps/ini/update.c`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/apps/ini/update.c)、[`SbieIniServer.cpp`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/core/svc/SbieIniServer.cpp) | 复用 `SbieDll_UpdateConf`；检查 NTSTATUS，并通过 `SbieApi_QueryConf` 逐项回验。不能把 SbieIni 退出码 0 单独当成功依据 |
| 禁止目录与例外 | [`drv/file.c`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/core/drv/file.c) | `ClosedFilePath`、`NormalFilePath` 等原生配置；不生成自定义内核规则 |
| 强制启动与子进程 | [`drv/process_force.c`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/core/drv/process_force.c) | `ForceProcess`、`ForceChildren` 使用完整 EXE 路径前缀并附加 `*`，选择原生路径模式匹配器；避免仅按 QQ.exe 等文件名误匹配，同 EXE 路径前缀也可能被匹配 |
| 显式沙箱启动 | [`apps/Start/start.cpp`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/apps/Start/start.cpp) | 调用现有 `Start.exe /box:...`；不启动 SandMan.exe |
| 监控数据获取 | [`drv/session.c`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/core/drv/session.c)、[`api_defs.h`](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/core/drv/api_defs.h) | `SbieApi_MonitorControl` 与 `API_MONITOR_GET2`，只解码实际返回的记录 |

## 策略语义与限制

- 黑名单模式把启用的目录规则编译为 `ClosedFilePath`。递归规则覆盖目录本身及后代；非递归规则不声称阻止后代的直接路径访问。
- 上游文件路径规则会为不含通配符的普通路径自动补 `*`。精确目录规则必须使用内部原生标记 `|D:\Secret`；递归时另加 `D:\Secret\*`，避免错误地同时匹配 `D:\SecretSibling`。此标记由规则编译器生成，用户无需手写。
- 白名单依赖原生规则优先级：全局关闭匹配与更具体的正常沙箱路径例外必须具有可靠的优先关系。上游 `UseRuleSpecificity` 受有效 `opt_sec` 证书限制；`drv/process.c` 的证书检查会对未获授权的相关高级设置安排 5 分钟后终止进程。应用必须检测并拒绝不满足条件的白名单，不能悄悄写入、试用绕过或声称免费版可完整启用。
- 白名单还要求继承的全局/模板路径例外可被完整约束。适配器在修改前和写回后检查有效 `OpenFilePath`、`ReadFilePath`、`WriteFilePath`、`OpenPipePath` 和非本应用维护的 `NormalFilePath`；发现冲突即拒绝或回滚。默认兼容性模板也可能包含例外，因此即使证书有效，白名单仍可能不可用。黑名单适合作为保持软件兼容性的默认选择。
- 白名单通常需要显式允许 Windows、应用安装、配置和数据目录。目录过窄会导致软件启动失败；不存在对任意 EXE 都无影响的通用白名单。
- 只监控模式不附加用户磁盘拒绝规则；进程仍在 Sandboxie 沙箱内，继续受其文件重定向和其他默认隔离行为影响。
- `ClosedFilePath` 保护内容与枚举，但上游部分属性查询存在目录元数据例外。不能宣称被禁目录的存在和一切元数据都不可见。
- 新规则不能撤回已经打开的文件句柄，也不能把正在宿主机运行的程序迁入沙箱。应用策略前必须退出相关进程；修改运行中的沙箱策略应被拒绝。
- 同路径的受控 EXE 已在宿主机运行时，适配器拒绝应用策略并返回其 PID；同名进程路径无法读取时也保守拒绝，避免误标已受保护。
- 上游逐项配置更新不提供本应用可用的完整原子事务；更新期间由外部同时发起的新进程仍存在竞态。运行中进程检查和配置回验降低风险，但不能声称完全消除此窗口。
- 强制规则由运行时执行，应用退出后仍可生效；管理员停用强制程序、停止服务、改写全局配置或系统启动异常均会影响保护。无法把普通用户态 UI 当作对本机管理员不可绕过的安全边界。
- 关联的普通子进程继承同一沙箱。通过系统服务、提升权限、更新器、已有宿主进程或显式 breakout 路径启动的组件需要逐一验证；应用不添加 breakout 例外。

## 日志的准确含义

| 界面操作/结果 | 证据 | 允许声称的内容 |
| --- | --- | --- |
| `file_open` / allow、deny 或 unknown | `FileTrace=ad` 生成 `(FA)` / `(FD)`，含访问掩码、创建方式及选项 | `(FA)` 表示跟踪位置允许；仅有 `(FD)` 表示失败且原因不明（也可能文件不存在），只有明确拒绝标志才显示 deny；不能等同整个 `CreateFile` 最终成功或已读取字节 |
| `file_policy_check` | 普通 `MONITOR_FILE` 与策略标志 | 文件策略检查及其已知处置；未明确处置时显示 unknown |
| API trace | 上游提供的原始跟踪字符串 | 仅按原始 API 名称与状态展示；不猜测缺失的路径或操作 |
| directory enumeration | 当前审查路径没有完整、专用的枚举完成事件 | 不虚构枚举日志；拒绝枚举只能通过真实运行探针验证 |
| actual read / bytes read | 现有监控接口没有完整的实际读取事件 | 不显示为已实现；探针自身执行读取获得的字节数只属于测试证据 |

监控记录含上游时间戳、类型、PID、TID 和 UTF-16 字符串。程序名由进程查询关联；PID 可能在查询前退出或复用，无法可靠关联时保留 PID 并标记未知。原始字段应保留供审计。

监控是当前 Windows 会话的共享、消费式队列；`Session_Api_MonitorGet2` 在返回记录后调用 `log_buffer_pop_entry`。适配器检测到会话已启用监控时拒绝抢占；另一个消费者在之后启动仍可能争抢记录，不能承诺完整日志。无法归属到受管沙箱的记录可能被舍弃，快速退出的进程尤其需要注意。内核队列或应用缓冲区满时也可能丢失；日志不是完整、不可篡改的取证审计。不能以无日志推断无访问。

## 同步上游

保持更改集中在 `DiskGuard/`、单独 workflow 和必要的变更记录，尽量不更改上游组件。Fork 的默认分支保留上游历史；同步时先审查 API 参数大小、调用约定、监控记录布局、配置行为和证书限制，再执行单元测试与签名运行时 VM 矩阵。更新审查提交、测试运行时版本及清单后再发布。不得仅因代码编译成功就扩大运行时支持范围。

上游许可证仍按各目录原样保留。新独立应用代码按 GPL-3.0-or-later 发布；没有复制 Qt SandMan 实现。第三方 crate/npm 依赖保留自身许可证；发行者需要维护对应的依赖锁文件与许可证说明。
