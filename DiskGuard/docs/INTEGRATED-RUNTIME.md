# 官方运行时集成安装与验证

安装包和便携包携带 `runtime/`，包括未经修改的官方 Classic 5.73.8 安装器、固定 SHA256 的 `runtime.lock.json` 和来源/许可证说明。构建只下载、验证和打包，不在开发机安装驱动。运行时安装由同一个 Rust 函数提供给应用界面及无 WebView 依赖的命令行入口。

```text
DiskGuard.exe --install-bundled-runtime [--report <绝对 JSON 路径>]
```

该入口检查现有服务/驱动注册。健康的既有安装只读检测后返回 `alreadyInstalled`；异常的既有安装给出修复说明，不自动覆盖、降级或卸载。缺少运行时时，原生代码校验内嵌固定值、安装包 SHA256 和 Windows 信任签名，保持文件锁，再通过标准 `runas` 调用官方安装器的 `/install /S`。应用本体和任意报告路径不会以自定义管理员 worker 身份执行；报告由调用者进程按其自身权限写入。

默认诊断文件为当前用户 `%LOCALAPPDATA%\DiskGuard\runtime-install.json`。报告字段为 `outcome`、`message`、`exitCode`、`runtimeVersion`、`driverAvailable`、`rebootRequired`。命令退出码与 NSIS 行为如下：

| 退出码 | 含义 | 安装包处理 |
| --- | --- | --- |
| 0 | 新安装完成或保留健康的既有安装 | 正常完成 |
| 3010 | 需要重启才能完成 | 明确提示、设置重启标志并返回 3010，不自动重启 |
| 1223 | 用户取消 UAC 授权或安装 | 明确提示并中止当前安装流程，保留已写入的 UI 文件供重试 |
| 其他非零值 | 校验或安装失败 | 明确提示、失败退出，不能显示运行时已就绪 |

`installer/runtime-hooks.nsh` 只定义 `NSIS_HOOK_POSTINSTALL`，在 Tauri 已复制 EXE、资源并写入卸载信息后，使用 `ExecWait` 同步调用上述命令。不另写一套 PowerShell 提权流程，不自动启动原版 Qt 界面；卸载 DiskGuard 不移除共享的官方 Sandboxie 运行时。

## 全新云端 VM 验证

`.github/workflows/diskguard-integrated-runtime.yml` 支持 `workflow_call` 和手动触发，均接受字符串 `build_run_id`。两个 matrix job 使用相互独立的 Windows Server 2022 hosted VM：

- `installer`：仅运行 DiskGuard 的 NSIS 安装包，要求后置 hook 自动完成官方运行时安装；测试不会预先安装 Sandboxie 或替安装器启动服务。
- `portable`：解压原包，先只对测试副本破坏 runtime payload，要求命令非零退出、报告 `failed` 且服务/驱动仍未注册；再从未修改的原包调用本地安装入口完成部署。

两条路径都要求实际 SbieSvc/SbieDrv 运行、驱动 Windows 签名为 Valid、随包官方安装器哈希/签名匹配、资源来源说明齐全。随后再执行一次安装，要求报告 `alreadyInstalled`，六个运行时二进制 SHA256、共享配置文件和主服务 PID 均保持不变；专用配置哨兵也必须保留。之后执行已安装应用的原生适配器/UI bridge 检查及独立文件访问探针。

同一个构建 run 内的 reusable job 可在父 run 尚未结束时下载已完成的 build artifact，但必须验证源 SHA 相同且 `build` job 已成功。手工指定另一个 run 时要求其已整体成功。所有测试均保留过程、签名、配置、哈希和原始结果；失败不能改成跳过即通过。

此 workflow 的管理员 hosted runner 可以验证正常安装链路，但不会产生可由真人操作的 UAC 安全桌面交互。因此，“用户接受/拒绝 UAC”的实际交互、Windows 10/11 客户端和 QQ/微信兼容性仍需单独验收；不能用 Server 2022 的成功结果替代这些结论。

## 接入依据：只读来源核对

- [Tauri 官方 Windows installer 文档](https://v2.tauri.app/distribute/windows-installer/#extending-the-installer)：公开定义四种 installer hooks；POSTINSTALL 位于资源复制之后。
- [本项目 CLI 2.12.3 对应的原版 NSIS 模板](https://github.com/tauri-apps/tauri/blob/tauri-cli-v2.12.3/crates/tauri-bundler/src/bundle/windows/nsis/installer.nsi)：`MAINBINARYNAME`、`INSTDIR` 和 POSTINSTALL 调用点用于本接入；保留官方模板，仅通过 hook 扩展。
- [NSIS ExecWait 文档](https://nsis.sourceforge.io/Reference/ExecWait)：等待子进程完成并获取退出码；[NSIS 命令行规则](https://nsis.sourceforge.io/Docs/Chapter3.html#installerusage)：`/S` 为静默安装，`/D` 必须使用绝对路径、放在最后且不加引号。
- [Sandboxie 固定审查提交的安装器源码](https://github.com/sandboxie-plus/Sandboxie/blob/c3e59fdb18d50199ebfccf7764e1d6c4e007de96/Sandboxie/install/SandboxieVS.nsi)：`/install` 选择初次安装；静默路径进入驱动/服务安装，调用其官方 KmdUtil 并启动服务。未修改原安装器。
- [官方 v1.18.8 发行资产](https://github.com/sandboxie-plus/Sandboxie/releases/expanded_assets/v1.18.8)：Classic x64 v5.73.8 的固定 SHA256 为 `47b8dd6bc070d17c66e03a097df043214685208ea1c1522228e7ee009053fe5f`。构建与运行时均验证原始文件，并保留原始驱动签名。
