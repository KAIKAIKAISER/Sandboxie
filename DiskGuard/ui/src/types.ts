export type Page = 'dashboard' | 'apps' | 'rules' | 'logs' | 'settings';
export type PolicyMode = 'blacklist' | 'whitelist' | 'monitor';
export type Theme = 'dark' | 'light' | 'system';

export interface Rule {
  id: string;
  path: string;
  enabled: boolean;
  recursive: boolean;
}

export interface ManagedApp {
  id: string;
  name: string;
  executable: string;
  sandbox: string;
  mode: PolicyMode;
  enabled: boolean;
  autoProtect: boolean;
  includeChildren: boolean;
  rules: Rule[];
}

export interface Config {
  version: number;
  apps: ManagedApp[];
  settings: { theme: Theme; closeToTray: boolean; autostart: boolean };
}

export interface RuntimeStatus {
  driverAvailable: boolean;
  serviceRunning: boolean;
  runtimePath: string | null;
  version: string | null;
  message: string;
  monitorSupported: boolean;
  monitoring: boolean;
  securityFeaturesAvailable: boolean;
  forceRulesDisabled: boolean;
}

export interface RuntimeInstallation {
  installed: boolean;
  bundled: boolean;
  installing: boolean;
  rebootRequired: boolean;
  message: string;
  canInstall: boolean;
}

export interface RuntimeInstallResult {
  outcome: 'installed' | 'rebootRequired' | 'alreadyInstalled' | 'cancelled' | 'failed';
  message: string;
  exitCode: number | null;
  runtimeVersion: string;
  driverAvailable: boolean;
  rebootRequired: boolean;
}

export interface LogEntry {
  id: number;
  timestamp: string;
  appId: string;
  appName: string;
  pid: number;
  path: string;
  operation: string;
  result: 'allowed' | 'denied' | 'unknown';
  source: string;
  detail?: string;
}

export interface LogFilter {
  search: string;
  appId: string;
  result: string;
  operation: string;
}

export interface LogResponse { entries: LogEntry[]; notice?: string; dropped?: number }
export interface AppState { config: Config; runtime: RuntimeStatus; appliedAppIds: string[]; pendingAppIds: string[] }
