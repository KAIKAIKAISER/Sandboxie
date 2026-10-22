import { invoke, isTauri } from '@tauri-apps/api/core';
import { open, save } from '@tauri-apps/plugin-dialog';
import type { AppState, Config, LogFilter, LogResponse, RuntimeInstallation, RuntimeInstallResult, RuntimeStatus } from './types';

export const nativeAvailable = isTauri();

async function command<T>(name: string, args?: Record<string, unknown>): Promise<T> {
  if (!nativeAvailable) throw new Error('当前为界面预览。请在 Windows 桌面程序中连接 Sandboxie 运行时。');
  return invoke<T>(name, args);
}

export const api = {
  getState: () => command<AppState>('get_state'),
  frontendReady: () => command<void>('frontend_ready'),
  saveConfig: (config: Config) => command<void>('save_config', { config }),
  applyPolicy: (appId: string) => command<{ message: string }>('apply_policy', { appId }),
  launchApp: (appId: string) => command<{ message: string }>('launch_app', { appId }),
  getLogs: (filter: LogFilter) => command<LogResponse>('get_logs', { filter }),
  exportLogs: (filter: LogFilter, destination: string) => command<{ path: string; count: number }>('export_logs', { filter, destination }),
  runtimeStatus: () => command<RuntimeStatus>('runtime_status'),
  runtimeInstallation: () => command<RuntimeInstallation>('get_runtime_installation'),
  installRuntime: () => command<RuntimeInstallResult>('install_bundled_runtime'),
  setAutostart: (enabled: boolean) => command<void>('set_autostart', { enabled }),
  chooseExecutable: async () => {
    if (!nativeAvailable) throw new Error('选择程序需要在 Windows 桌面程序中操作。');
    return open({ title: '选择需要管理的程序', multiple: false, directory: false, filters: [{ name: 'Windows 应用程序', extensions: ['exe'] }] });
  },
  chooseDirectory: async () => {
    if (!nativeAvailable) throw new Error('选择目录需要在 Windows 桌面程序中操作。');
    return open({ title: '选择访问规则目录', multiple: false, directory: true });
  },
  chooseExportPath: async () => {
    if (!nativeAvailable) throw new Error('导出日志需要在 Windows 桌面程序中操作。');
    return save({ title: '导出访问日志', defaultPath: `DiskGuard-logs-${new Date().toISOString().slice(0, 10)}.csv`, filters: [{ name: 'CSV 日志文件', extensions: ['csv'] }] });
  },
};
