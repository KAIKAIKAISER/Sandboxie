// Explanations, not synthesized runtime events. Source: Sbie-English-1033.txt.
export const nativeMessages = [
  { code: 'SBIE1101', meaning: '驱动已初始化（正常提示）', action: '仍需确认服务连接和目标进程沙箱归属；不代表每条目录规则已生效。' },
  { code: 'SBIE1301', meaning: '程序在沙箱外启动', action: '停止该程序及后台进程，核对实际 EXE、自动保护与全局强制规则，再重新启动。' },
  { code: 'SBIE1307', meaning: '程序受网络限制', action: '检查原生网络策略；这不是磁盘目录黑名单提示，不要为联网关闭隔离。' },
  { code: 'SBIE1308', meaning: '启动受限制', action: '检查原生启动/运行限制及对应程序路径。' },
  { code: 'SBIE2102', meaning: '文件过大，无法复制到沙箱', action: '检查原生文件迁移限制；先备份数据，不要直接添加宿主写穿例外。' },
  { code: 'SBIE2203', meaning: '无法与 Sandboxie 服务通信', action: '检查 SbieSvc、安装是否完整及是否要求重启；不要把连接失败当作已保护。' },
  { code: 'SBIE2204', meaning: '无法启动沙箱内服务', action: '保留服务名及括号内错误码，检查对应版本和应用兼容性。' },
  { code: 'SBIE2335', meaning: '进程初始化失败', action: '保留完整消息、程序版本和系统构建，退出该进程后检查运行时兼容性。' },
  { code: 'SBIE9153', meaning: '无法启动驱动', action: '检查官方签名、系统事件、安装完整性及重启要求；不要关闭签名强制或安全启动。' },
  { code: 'SBIE9154', meaning: '驱动与服务版本不一致', action: '完成要求的重启或用同一官方安装包修复；不要手工混换 DLL、服务或驱动。' },
  { code: 'SBIE9156', meaning: '驱动初始化尚未完成', action: '查看完整错误与系统事件，确认安装和重启状态。' },
] as const;
