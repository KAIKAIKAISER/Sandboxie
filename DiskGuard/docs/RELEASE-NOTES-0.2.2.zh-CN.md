# DiskGuard v0.2.2（预发布）

独立的 Rust + Tauri 2 Windows x64 磁盘访问控制器，复用 Sandboxie 官方签名运行时，不依赖原版 Qt 界面。

## 本次改进

- 配置保存增加操作日志和 last-good 备份；部分保存失败后进入只读恢复状态，可继续完成保存，不静默丢弃文件。
- 损坏配置不再导致直接退出；提供错误目录、恢复入口及明确的保护状态提示。
- 增加产品自身保存/应用策略后的真实黑名单探针，覆盖读取和枚举阻断、相邻目录、强制启动、子进程、进程重启、规则停用及应用删除。
- 增加前端回归、布局断言和发布版本一致性检查，补齐 CI 触发范围及统一质量门禁。
- 将 Tokio 更新至 1.54.1；增加依赖审计、CodeQL、依赖自动更新，固定受支持的 Actions 和 Rust 工具链。
- 安装包和便携包均附带中文使用指南；设置页新增 Sandboxie 原生 SBIE 提示速查。

## 下载与安装

- **安装版：**`DiskGuard_0.2.2_x64-setup.exe`
- **便携版：**`DiskGuard_0.2.2_windows-x64-portable.zip`，请完整解压并保留 `runtime/`，不要只复制 EXE。
- 使用同页的 `SHA256SUMS.txt` 核对下载文件；`BUILD-MANIFEST.json` 记录源码提交、工具链及签名状态。

缺少运行时时可安装随附的、未经修改的官方 **Sandboxie Classic x64 5.73.8** 安装器，安装前要求固定 SHA-256 和 Authenticode 验证，通过标准 UAC 请求权限。已有 Plus/Classic 安装和配置会保留。驱动与服务仍需要系统安装；便携版不代表免管理员权限。系统还需要 Microsoft Edge WebView2。

## 验证范围与已知限制

发布门禁包含 Rust/前端测试、安全扫描，以及全新 Windows Server 2022 VM 上两种包的部署、重复安装保留配置和真实产品访问控制探针。它**不等于 Windows 10/11 客户端、交互式 UAC 或 QQ/微信业务兼容性验收**。

- DiskGuard 应用自身尚未使用受信发布者代码签名，Windows 可能显示未知发布者；官方运行时的签名保留。
- 未重编译或重新签署 Sandboxie 驱动，不改变 Windows 驱动签名强制要求。
- RustSec 仍有 5 项信息级跨平台传递依赖告警，未在当前 Windows x64 构建图中引用；未屏蔽，详见依赖审阅文档。
- 日志不是无损审计，也不证明实际读取了文件字节；UI 关闭期间不采集日志，但已经应用的强制策略继续生效。
- 卸载 DiskGuard 不移除共享运行时或沙箱数据。卸载前如不希望继续强制入箱，请先停用应用并保存。

## 文档

- [中文使用指南与 Sandboxie 原生提示](https://github.com/KAIKAIKAISER/Sandboxie/blob/diskguard-v0.2.2/DiskGuard/docs/USER-GUIDE.zh-CN.md)
- [测试范围与客户端待验收矩阵](https://github.com/KAIKAIKAISER/Sandboxie/blob/diskguard-v0.2.2/DiskGuard/docs/VALIDATION.md)
- [依赖告警审阅](https://github.com/KAIKAIKAISER/Sandboxie/blob/diskguard-v0.2.2/DiskGuard/docs/DEPENDENCY-REVIEW.md)
- [官方运行时对应完整源码](https://github.com/sandboxie-plus/Sandboxie/archive/refs/tags/v1.18.8.zip)

本版作为预发布提供，不覆盖旧版本资产；默认分支保持不变。
