import './style.css';
import { api, nativeAvailable } from './api';
import type { AppState, Config, LogEntry, LogFilter, LogResponse, ManagedApp, Page, PolicyMode, Rule, RuntimeStatus, Theme } from './types';

const icons: Record<string, string> = {
  shield: '<path d="M12 3 4 6v6c0 5 8 9 8 9s8-4 8-9V6l-8-3Z"/><path d="m8.5 11.5 2.5 2.5 4.5-5"/>',
  overview: '<rect x="3" y="3" width="7" height="7" rx="2"/><rect x="14" y="3" width="7" height="7" rx="2"/><rect x="3" y="14" width="7" height="7" rx="2"/><rect x="14" y="14" width="7" height="7" rx="2"/>',
  apps: '<rect x="3" y="4" width="18" height="15" rx="3"/><path d="M3 9h18M8 4v5m1 5 2 2 4-4"/>',
  folder: '<path d="M3 7a2 2 0 0 1 2-2h5l2 2h7a2 2 0 0 1 2 2v9a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2V7Z"/>',
  logs: '<path d="M8 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2V9l-6-6H8Z"/><path d="M14 3v6h7M7 13h10M7 17h7"/>',
  settings: '<path d="m9 3-.6 2.4-2 .9-2.2-.7-2 3.4L4 10.7v2.6L2.2 15l2 3.4 2.2-.7 2 .9L9 21h4l.6-2.4 2-.9 2.2.7 2-3.4-1.8-1.7v-2.6L19.8 9l-2-3.4-2.2.7-2-.9L13 3H9Z"/><circle cx="11" cy="12" r="3"/>',
  plus: '<path d="M12 5v14M5 12h14"/>',
  arrow: '<path d="m9 5 7 7-7 7"/>',
  external: '<path d="M14 3h7v7m0-7L10 14M10 3H5a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-5"/>',
  refresh: '<path d="M20 7v5h-5M4 17v-5h5"/><path d="M6.1 6a8 8 0 0 1 12.6 1L20 12M4 12l1.3 5A8 8 0 0 0 18 18"/>',
  check: '<path d="m5 12 4 4L19 6"/>',
  close: '<path d="m6 6 12 12M6 18 18 6"/>',
  search: '<circle cx="10.5" cy="10.5" r="6.5"/><path d="m16 16 4 4"/>',
  download: '<path d="M12 3v12m-5-5 5 5 5-5M4 16v4h16v-4"/>',
  play: '<path d="m8 4 12 8-12 8V4Z"/>',
  trash: '<path d="M3 6h18M9 6V3h6v3M5 6l1 15h12l1-15M10 10v7m4-7v7"/>',
  clock: '<circle cx="12" cy="12" r="9"/><path d="M12 7v5l3 2"/>',
  info: '<circle cx="12" cy="12" r="9"/><path d="M12 11v6m0-10v.01"/>',
  lock: '<rect x="5" y="10" width="14" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3m-4 5v2"/>',
  sun: '<circle cx="12" cy="12" r="4"/><path d="M12 2v2m0 16v2M2 12h2m16 0h2M5 5l1.5 1.5m11 11L19 19M5 19l1.5-1.5m11-11L19 5"/>',
  moon: '<path d="M21 13a9 9 0 0 1-10-10 9 9 0 1 0 10 10Z"/>',
  monitor: '<rect x="3" y="3" width="18" height="14" rx="2"/><path d="M8 21h8m-4-4v4"/>',
  bolt: '<path d="m13 2-9 12h7l-1 8 10-13h-7l1-7Z"/>',
  disk: '<path d="M5 3h12l4 4v14H3V3h2Z"/><path d="M7 3v6h10V3M7 21v-8h10v8m-3-16v2"/>',
  eye: '<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7S2 12 2 12Z"/><circle cx="12" cy="12" r="3"/>',
  qq: '<path d="M7 16c-1 3-3 3-3 1l1-6c0-5 2-8 7-8s7 3 7 8l1 6c0 2-2 2-3-1M7 20h10M7 9h10M9 13h6"/><path d="M9 7h.01M15 7h.01"/>',
  wechat: '<path d="M12 16c-1.2.6-2.5.9-4 .9l-4 2 1-4C1 12 3 5 9 5c5 0 8 3 8 6"/><path d="M13 10c-4 0-6 5-2 8 2 1 4 1 6 0l3 1-.5-3C23 13 20 10 17 10h-4Z"/><path d="M7 9h.01M12 9h.01M13 14h.01M17 14h.01"/>',
};
const icon = (name: string, size = 20) => `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.65" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${icons[name] ?? icons.apps}</svg>`;
const escape = (value: unknown) => String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]!);
const checked = (value: boolean) => value ? 'checked' : '';
const selected = (value: boolean) => value ? 'selected' : '';
const uid = () => crypto.randomUUID();
const modeNames: Record<PolicyMode, string> = { blacklist: '目录黑名单', whitelist: '目录白名单', monitor: '只监控' };
const operationNames: Record<string, string> = { file_open: '文件打开', file_open_request: '文件打开请求', file_policy_check: '文件策略检查', file_metadata: '文件元数据', runtime_event: '运行时事件', other: '其他' };
const resultNames: Record<string, string> = { allowed: '允许', denied: '拒绝', unknown: '未确认' };

const emptyConfig: Config = { version: 1, apps: [], settings: { theme: 'dark', closeToTray: true, autostart: false } };
let state: AppState = {
  config: structuredClone(emptyConfig),
  runtime: { driverAvailable: false, serviceRunning: false, runtimePath: null, version: null, message: nativeAvailable ? '正在检测 Sandboxie 运行时…' : '当前为浏览器界面预览，未连接 Windows 运行时。', monitorSupported: false, monitoring: false, securityFeaturesAvailable: false, forceRulesDisabled: false },
  appliedAppIds: [], pendingAppIds: [],
};
let page: Page = 'dashboard';
let currentAppId = '';
let dirty = false;
let busy = false;
let logs: LogResponse = { entries: [], notice: '尚未接收运行时事件。' };
let logFilter: LogFilter = { search: '', appId: '', result: '', operation: '' };
let lastRefresh = '';
let modal: { type: 'app'; preset?: string } | { type: 'rule'; appId: string } | { type: 'delete'; appId: string } | { type: 'log'; entry: LogEntry } | null = null;
let logsRequest = 0;
let searchTimer: ReturnType<typeof setTimeout>;
const root = document.querySelector<HTMLDivElement>('#app')!;
const modalRoot = document.querySelector<HTMLDivElement>('#modal-root')!;

const currentApp = () => state.config.apps.find(app => app.id === currentAppId) ?? state.config.apps[0];
const runtimeReady = () => state.runtime.driverAvailable && state.runtime.serviceRunning;
const policyStatus = (app: ManagedApp) => !app.enabled ? badge('策略停用') : dirty ? badge('有未保存更改') : state.pendingAppIds.includes(app.id) ? badge('待应用', 'purple-tone') : state.appliedAppIds.includes(app.id) ? badge('策略已写入', 'good') : badge('尚未应用');
const appIcon = (app: Pick<ManagedApp, 'name'>, big = false) => {
  const kind = /微信|wechat|weixin/i.test(app.name) ? 'wechat' : /^qq|腾讯qq/i.test(app.name) ? 'qq' : 'apps';
  return `<span class="app-icon ${kind} ${big ? 'large' : ''}">${icon(kind, big ? 27 : 22)}</span>`;
};
const switchControl = (action: string, value: boolean, label: string, data = '') => `<label class="switch"><input type="checkbox" data-action="${action}" ${data} ${checked(value)} aria-label="${escape(label)}"/><span></span></label>`;
const badge = (text: string, tone = 'neutral') => `<span class="badge ${tone}">${tone === 'good' ? '<i></i>' : ''}${escape(text)}</span>`;

function setTheme(theme: Theme) {
  document.documentElement.dataset.theme = theme === 'system' ? (matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light') : theme;
  localStorage.setItem('diskguard-theme', theme);
}
setTheme((localStorage.getItem('diskguard-theme') as Theme) || 'dark');
matchMedia('(prefers-color-scheme: dark)').addEventListener('change', () => { if (state.config.settings.theme === 'system') setTheme('system'); });

function markDirty() {
  dirty = true;
  document.querySelectorAll<HTMLButtonElement>('[data-save]').forEach(button => {
    button.disabled = busy;
    button.innerHTML = `${icon('disk', 16)}保存更改<span class="unsaved-dot"></span>`;
  });
  document.querySelectorAll('.save-state').forEach(element => { element.textContent = '有未保存的更改'; });
}

function toast(message: string, type = 'success') {
  const container = document.querySelector('#toast-root')!;
  const element = document.createElement('div');
  element.className = `toast ${type}`;
  element.innerHTML = `${icon(type === 'error' ? 'info' : 'check', 19)}<span>${escape(message)}</span><button class="icon-button" aria-label="关闭提示">${icon('close', 15)}</button>`;
  element.querySelector('button')!.onclick = () => element.remove();
  container.append(element);
  setTimeout(() => element.remove(), type === 'error' ? 12000 : 6500);
}

function render() {
  const nav: { id: Page; icon: string; label: string }[] = [
    { id: 'dashboard', icon: 'overview', label: '总览' },
    { id: 'apps', icon: 'apps', label: '应用管理' },
    { id: 'rules', icon: 'folder', label: '访问规则' },
    { id: 'logs', icon: 'logs', label: '访问日志' },
    { id: 'settings', icon: 'settings', label: '设置' },
  ];
  const titles: Record<Page, [string, string]> = {
    dashboard: ['保护总览', '每个应用，都有自己的边界。'],
    apps: ['应用管理', '为每个程序配置独立的沙箱与访问策略。'],
    rules: ['访问规则', '以目录为单位，精确管理应用的文件访问边界。'],
    logs: ['访问日志', '查看运行时提供的真实事件与访问判定。'],
    settings: ['设置', '让 DiskGuard 按照你的习惯运行。'],
  };
  root.innerHTML = `<div class="shell">
    <aside class="sidebar">
      <div class="brand"><span class="brand-symbol">${icon('shield', 26)}</span><div>DiskGuard<span>应用磁盘访问控制</span></div></div>
      <div class="nav-label">工作空间</div>
      <nav aria-label="主导航">${nav.map(item => `<button class="nav-item ${page === item.id ? 'active' : ''}" data-page="${item.id}" ${page === item.id ? 'aria-current="page"' : ''}>${icon(item.icon)}<span>${item.label}</span>${item.id === 'apps' && state.config.apps.length ? `<b>${state.config.apps.length}</b>` : ''}${page === item.id ? '<span class="nav-mark"></span>' : ''}</button>`).join('')}</nav>
      <div class="sidebar-bottom"><div class="engine-label"><span class="status-dot ${runtimeReady() ? 'good' : 'warning'}"></span><span>Sandboxie 引擎</span>${icon('shield', 15)}</div><p>${runtimeReady() ? '驱动与服务已连接' : '等待运行时连接'}</p><div class="sidebar-version">DiskGuard <span>v0.1.0</span></div></div>
    </aside>
    <main class="main-content">
      <header class="topbar"><div class="breadcrumbs">工作空间 ${icon('arrow', 12)} <span>${titles[page][0]}</span></div><div class="topbar-right"><span class="local-tag">${icon('lock', 13)}本地运行</span><span class="topbar-divider"></span><button class="icon-button" data-action="theme-cycle" aria-label="切换深浅色主题" title="切换深浅色主题">${icon(document.documentElement.dataset.theme === 'dark' ? 'sun' : 'moon', 18)}</button></div></header>
      <div class="page-body"><div class="page-heading"><div><div class="eyebrow">${page === 'dashboard' ? 'YOUR DIGITAL BOUNDARIES' : 'DISKGUARD WORKSPACE'}</div><h1>${titles[page][0]}</h1><p>${titles[page][1]}</p></div><div class="heading-actions">${page === 'logs' ? `<button class="button secondary" data-action="export-logs" ${busy ? 'disabled' : ''}>${icon('download', 16)}导出日志</button>` : page === 'dashboard' || page === 'apps' ? `<button class="button secondary" data-action="add-app">${icon('plus', 17)}添加应用</button>` : ''}<button class="button primary" data-action="save" data-save ${!dirty || busy ? 'disabled' : ''}>${icon('disk', 16)}${dirty ? '保存更改<span class="unsaved-dot"></span>' : '已保存'}</button></div></div>
      ${page === 'dashboard' ? dashboardView() : page === 'apps' ? appsView() : page === 'rules' ? rulesView() : page === 'logs' ? logsView() : settingsView()}
      <footer class="page-footer"><span>${icon('shield', 13)}基于 Sandboxie 开源沙箱能力</span><span class="save-state">${dirty ? '有未保存的更改' : '配置保存在本机'}</span></footer></div>
    </main></div>`;
}

function dashboardView() {
  const apps = state.config.apps;
  const ruleCount = apps.reduce((sum, app) => sum + app.rules.filter(rule => rule.enabled).length, 0);
  return `<section class="hero"><div class="hero-text"><div class="hero-kicker"><span class="tiny-line"></span>明确边界，安心使用</div><h2>把应用的访问范围，<br>掌握在自己手中。</h2><p>独立沙箱、目录策略与真实访问日志。<br>从一个应用开始，为私人文件留出空间。</p><button class="button hero-button" data-page="apps">管理我的应用 ${icon('arrow', 16)}</button></div><div class="hero-art" aria-hidden="true"><div class="orbital orbit-one"></div><div class="orbital orbit-two"></div><div class="art-spark spark-one">+</div><div class="art-spark spark-two">+</div><div class="floating-file file-one">${icon('folder', 26)}<span></span><span></span></div><div class="floating-file file-two">${icon('logs', 25)}<span></span></div><div class="shield-object">${icon('shield', 99)}</div><div class="art-caption">YOUR FILES. YOUR RULES.</div></div></section>
    <section class="stat-grid" aria-label="配置统计"><div class="stat-card"><span class="stat-icon purple">${icon('apps', 21)}</span><div><span>已添加应用</span><strong>${apps.length}<small>个</small></strong></div><span class="stat-note">独立沙箱配置</span></div><div class="stat-card"><span class="stat-icon teal">${icon('folder', 21)}</span><div><span>已启用目录规则</span><strong>${ruleCount}<small>条</small></strong></div><span class="stat-note">${apps.filter(app => app.enabled).length} 个应用启用策略</span></div><div class="stat-card"><span class="stat-icon amber">${icon('logs', 21)}</span><div><span>本次已接收日志</span><strong>${logs.entries.length}<small>条</small></strong></div><span class="stat-note">来自运行时事件</span></div></section>
    <div class="dashboard-columns"><section class="panel apps-panel"><div class="panel-heading"><div><h3>我的应用 <span class="count-label">${apps.length}</span></h3><p>按应用管理，策略彼此独立</p></div><button class="text-button" data-page="apps">查看全部 ${icon('arrow', 13)}</button></div>${apps.length ? `<div class="dashboard-apps">${apps.slice(0, 4).map(app => `<button class="dashboard-app" data-action="select-app" data-id="${escape(app.id)}">${appIcon(app)}<div><strong>${escape(app.name)}</strong><span>${escape(app.sandbox)}</span></div>${policyStatus(app)}${icon('arrow', 15)}</button>`).join('')}</div>` : `<div class="empty-apps"><div class="empty-graphic">${icon('apps', 31)}</div><h4>还没有添加应用</h4><p>选择一个实际安装的 EXE，开始配置访问边界。</p><div class="preset-buttons"><button class="button secondary" data-action="add-preset" data-preset="QQ">${icon('qq', 17)}添加 QQ</button><button class="button secondary" data-action="add-preset" data-preset="微信">${icon('wechat', 18)}添加微信</button></div></div>`}</section>
    <section class="panel runtime-panel"><div class="panel-heading"><div><h3>运行时状态</h3><p>安全能力来自实际连接的组件</p></div><button class="icon-button" data-action="refresh-runtime" title="重新检测运行时" aria-label="重新检测运行时">${icon('refresh', 17)}</button></div><div class="runtime-rows">${runtimeRow('Sandboxie 驱动', state.runtime.driverAvailable, '已连接', '未检测到')}${runtimeRow('Sandboxie 服务', state.runtime.serviceRunning, '运行中', '未连接')}${runtimeRow('访问事件监控', state.runtime.monitoring, '监控中', state.runtime.monitorSupported ? '等待事件' : '不可用')}</div><div class="runtime-note">${icon('info', 16)}<span>${escape(state.runtime.message)}</span></div>${lastRefresh ? `<div class="last-checked">上次检测 ${escape(lastRefresh)}</div>` : ''}</section></div>
    <aside class="info-strip">${icon('eye', 20)}<div><strong>看清每一次访问的含义</strong><p>日志按运行时来源标识文件打开与策略检查。当前接口不提供独立目录枚举或实际读取事件。</p></div><button class="text-button" data-page="logs">查看日志 ${icon('arrow', 14)}</button></aside>`;
}

function runtimeRow(label: string, good: boolean, goodText: string, badText: string) {
  return `<div class="runtime-row"><span>${label}</span><span class="runtime-value ${good ? 'success-text' : 'muted'}"><i class="status-dot ${good ? 'good' : ''}"></i>${good ? goodText : badText}</span></div>`;
}

function appList() {
  const app = currentApp();
  return `<aside class="app-list panel"><div class="app-list-title"><span>受控应用</span><button class="icon-button" data-action="add-app" aria-label="添加应用">${icon('plus', 18)}</button></div>${state.config.apps.map(item => `<button class="app-list-item ${item.id === app?.id ? 'selected' : ''}" data-action="pick-app" data-id="${escape(item.id)}">${appIcon(item)}<span><strong>${escape(item.name)}</strong><small>${modeNames[item.mode]}</small></span><i class="status-dot ${item.enabled ? 'good' : ''}" title="${item.enabled ? '配置已启用' : '配置已停用'}"></i></button>`).join('')}<div class="app-list-bottom">${icon('lock', 14)}每个应用使用独立沙箱</div></aside>`;
}

function noAppsView() {
  return `<section class="panel big-empty"><div class="empty-graphic">${icon('apps', 38)}</div><h2>为第一个应用设置边界</h2><p>添加 QQ、微信或任意 EXE 程序。<br>选择实际可执行文件后，为它创建独立的沙箱配置。</p><div class="preset-buttons"><button class="button secondary" data-action="add-preset" data-preset="QQ">${icon('qq', 18)}QQ</button><button class="button secondary" data-action="add-preset" data-preset="微信">${icon('wechat', 19)}微信</button><button class="button primary" data-action="add-app">${icon('plus', 17)}选择 EXE</button></div><span class="subtle-caption">程序不会在添加时自动运行</span></section>`;
}

function appsView() {
  const app = currentApp();
  if (!app) return noAppsView();
  return `<div class="workspace-grid">${appList()}<div class="app-detail"><section class="panel app-profile"><div class="app-profile-header">${appIcon(app, true)}<div><h2>${escape(app.name)}</h2><div class="app-caption">${badge('独立沙箱', 'purple-tone')}${policyStatus(app)}<code>${escape(app.sandbox)}</code></div></div><div class="profile-actions"><button class="button secondary small" data-action="launch" ${busy ? 'disabled' : ''}>${icon('play', 15)}沙箱启动</button><button class="icon-button danger-hover" data-action="delete-app" data-id="${escape(app.id)}" title="移除应用" aria-label="移除应用">${icon('trash', 18)}</button></div></div><div class="profile-fields"><label>应用名称<input value="${escape(app.name)}" data-field="app-name" maxlength="80"/></label><label>沙箱名称<input value="${escape(app.sandbox)}" data-field="app-sandbox" maxlength="32" spellcheck="false"/></label><label class="full-width">程序位置<div class="input-with-button"><input readonly value="${escape(app.executable)}" title="${escape(app.executable)}"/><button class="button secondary small" data-action="change-exe">更换</button></div></label></div></section>
    <section class="panel"><div class="panel-heading"><div><h3>访问策略</h3><p>配置策略后，保存并应用到 Sandboxie</p></div>${switchControl('app-enabled', app.enabled, '启用应用策略')}</div><div class="mode-options">${modeOption(app, 'blacklist', 'lock', '禁止访问指定目录', '保留沙箱默认访问边界')}${modeOption(app, 'whitelist', 'shield', '仅开放指定目录', '需为应用依赖设置白名单')}${modeOption(app, 'monitor', 'eye', '观察访问，不额外拦截', '保留 Sandboxie 基础隔离')}</div><div class="policy-explanation">${icon('info', 16)}<span>${app.mode === 'blacklist' ? '黑名单目录将拒绝文件访问。请避免直接屏蔽 Windows、程序安装位置及应用数据目录。' : app.mode === 'whitelist' ? '严格白名单依赖 Sandboxie 安全功能授权，未获授权时后端会拒绝应用。系统组件、程序依赖与数据目录也需显式开放，请先验证兼容性。' : '只监控模式不添加目录封锁规则。日志以运行时实际提供的事件为准。'}</span></div></section>
    <section class="panel"><div class="panel-heading"><div><h3>启动与进程关联</h3><p>自动保护依赖运行时成功应用强制沙箱策略</p></div>${icon('bolt', 20)}</div><div class="setting-row"><div><strong>自动保护此应用</strong><p>应用在沙箱外启动时，交由 Sandboxie 强制进入指定沙箱</p></div>${switchControl('auto-protect', app.autoProtect, '自动保护此应用')}</div><div class="setting-row"><div><strong>强制关联子进程</strong><p>在沙箱外匹配父进程时强制纳入其子进程；沙箱内子进程默认继承</p></div>${switchControl('include-children', app.includeChildren, '强制关联子进程')}</div><div class="panel-action-footer"><span>${icon('info', 14)}策略写入与运行时保护状态分别验证</span><button class="button primary small" data-action="apply" ${busy ? 'disabled' : ''}>${icon('check', 16)}保存并应用策略</button></div></section>
    <section class="panel"><div class="panel-heading"><div><h3>目录规则 <span class="count-label">${app.rules.length}</span></h3><p>${app.mode === 'whitelist' ? '允许访问的目录' : app.mode === 'monitor' ? '规则在只监控模式下不执行封锁' : '禁止访问的目录'}</p></div><button class="button secondary small" data-action="add-rule" data-id="${escape(app.id)}">${icon('plus', 15)}添加目录</button></div>${ruleTable(app)}</section></div></div>`;
}

function modeOption(app: ManagedApp, mode: PolicyMode, image: string, text: string, description: string) {
  const unavailable = mode === 'whitelist' && !state.runtime.securityFeaturesAvailable;
  return `<button class="mode-option ${app.mode === mode ? 'selected' : ''}" data-action="mode" data-mode="${mode}" aria-pressed="${app.mode === mode}" ${unavailable ? 'disabled title="需要有效的 Sandboxie 安全功能授权"' : ''}><div class="mode-option-top">${icon(image, 20)}<i class="radio-indicator"></i></div><strong>${modeNames[mode]}</strong><span>${text}</span><small>${unavailable ? '需要 Sandboxie 安全功能授权' : description}</small></button>`;
}

function rulesView() {
  const app = currentApp();
  if (!app) return noAppsView();
  return `<div class="workspace-grid">${appList()}<div class="app-detail"><section class="panel"><div class="panel-heading"><div class="rule-heading-app">${appIcon(app)}<div><h3>${escape(app.name)} 的访问规则</h3><p>当前策略：${modeNames[app.mode]}</p></div></div><button class="button primary small" data-action="add-rule" data-id="${escape(app.id)}">${icon('plus', 16)}添加目录</button></div><div class="rules-context ${app.mode === 'monitor' ? 'warning-context' : ''}">${icon(app.mode === 'monitor' ? 'eye' : 'info', 18)}<span>${app.mode === 'monitor' ? '当前为只监控模式。下列目录规则保留在配置中，不添加目录封锁。' : app.mode === 'blacklist' ? '启用的目录规则会作为黑名单，禁止此应用访问匹配路径。' : '启用的目录规则会作为白名单；严格模式可能影响应用兼容性。'}</span></div>${ruleTable(app)}<div class="panel-action-footer"><span>${app.rules.filter(rule => rule.enabled).length} 条启用 · ${app.rules.filter(rule => rule.recursive).length} 条递归</span><button class="button primary small" data-action="apply" ${busy ? 'disabled' : ''}>${icon('check', 16)}保存并应用策略</button></div></section><aside class="info-card">${icon('folder', 25)}<h3>规则如何匹配？</h3><p>选择一个实际目录，并设置是否递归匹配其子目录。每个应用的规则单独保存，停用规则后不再写入相应访问策略。</p><p>已经运行的程序可能持有打开的文件句柄。更改策略后，请重新在沙箱内启动应用。</p></aside></div></div>`;
}

function ruleTable(app: ManagedApp) {
  if (!app.rules.length) return `<div class="rules-empty">${icon('folder', 28)}<h4>暂无目录规则</h4><p>${app.mode === 'monitor' ? '只监控模式无需额外目录规则。' : '添加一个目录，为此应用设定访问范围。'}</p><button class="text-button" data-action="add-rule" data-id="${escape(app.id)}">${icon('plus', 15)}添加第一条规则</button></div>`;
  return `<div class="table-scroll"><table class="rules-table"><thead><tr><th>目录路径</th><th>子目录</th><th>状态</th><th><span class="visually-hidden">操作</span></th></tr></thead><tbody>${app.rules.map(rule => `<tr class="${!rule.enabled ? 'disabled-rule' : ''}"><td><span class="path-cell">${icon('folder', 17)}<code title="${escape(rule.path)}">${escape(rule.path)}</code></span></td><td><label class="checkbox-label"><input type="checkbox" data-action="rule-recursive" data-id="${escape(rule.id)}" ${checked(rule.recursive)}/><span>递归</span></label></td><td>${switchControl('rule-enabled', rule.enabled, `启用目录 ${rule.path}`, `data-id="${escape(rule.id)}"`)}</td><td><button class="icon-button danger-hover" data-action="delete-rule" data-id="${escape(rule.id)}" aria-label="删除目录规则">${icon('trash', 16)}</button></td></tr>`).join('')}</tbody></table></div>`;
}

function logsView() {
  return `<section class="panel logs-panel"><div class="log-filters"><div class="search-field">${icon('search', 18)}<input data-filter="search" value="${escape(logFilter.search)}" placeholder="搜索路径、程序名称或 PID…" aria-label="搜索访问日志"/><kbd>⌕</kbd></div><select data-filter="appId" aria-label="筛选应用"><option value="">全部应用</option>${state.config.apps.map(app => `<option value="${escape(app.id)}" ${selected(logFilter.appId === app.id)}>${escape(app.name)}</option>`).join('')}</select><select data-filter="result" aria-label="筛选结果"><option value="">全部结果</option>${Object.entries(resultNames).map(([value, label]) => `<option value="${value}" ${selected(logFilter.result === value)}>${label}</option>`).join('')}</select><select data-filter="operation" aria-label="筛选操作"><option value="">全部操作</option>${Object.entries(operationNames).map(([value, label]) => `<option value="${value}" ${selected(logFilter.operation === value)}>${label}</option>`).join('')}</select><button class="icon-button" data-action="refresh-logs" aria-label="刷新日志" title="刷新日志">${icon('refresh', 18)}</button></div><div class="log-status-bar"><span><i class="status-dot ${state.runtime.monitoring ? 'good' : 'warning'}"></i>${state.runtime.monitoring ? '运行时监控已连接' : '等待运行时事件'}</span><span id="log-count">${logs.entries.length} 条记录</span></div><div id="log-content">${logTable()}</div><div class="log-bottom-note">${icon('info', 15)}<span id="log-notice">${escape(logNotice())}</span></div></section><aside class="info-strip log-explainer">${icon('eye', 20)}<div><strong>真实事件，准确解释</strong><p>“文件打开”记录打开或创建请求，策略检查表示路径访问判定。当前接口不提供独立目录枚举或实际读取字节事件，本界面不据此推断文件内容已被读取。</p></div></aside>`;
}

function logNotice() {
  const notice = logs.notice || '日志来自 Sandboxie 运行时；访问结果无法确认时明确标为“未确认”。';
  return `${notice}${logs.dropped ? ` · ${logs.dropped} 条旧事件已从内存缓存移除` : ''}`;
}

function logTable() {
  if (!logs.entries.length) return `<div class="log-empty"><div class="empty-graphic">${icon('logs', 37)}</div><h3>${logFilter.search || logFilter.appId || logFilter.operation || logFilter.result ? '没有匹配的访问记录' : '等待第一条真实访问记录'}</h3><p>${state.runtime.monitoring ? '在沙箱中启动应用，实际事件将在这里显示。' : '连接 Sandboxie 运行时后，监控事件将在这里显示。'}<br>本界面不会生成演示日志或推断访问结果。</p>${logFilter.search || logFilter.appId || logFilter.operation || logFilter.result ? '<button class="button secondary small" data-action="reset-filters">清除筛选</button>' : '<button class="button secondary small" data-page="apps">管理应用</button>'}</div>`;
  return `<div class="table-scroll"><table class="logs-table"><thead><tr><th>时间</th><th>应用 / PID</th><th>访问路径</th><th>操作</th><th>结果</th></tr></thead><tbody>${logs.entries.map(entry => `<tr data-action="log-detail" data-id="${entry.id}" tabindex="0" role="button" aria-label="查看日志详情"><td><time title="${escape(entry.timestamp)}">${escape(formatTime(entry.timestamp))}</time></td><td><span class="log-app-name">${escape(entry.appName || '未知程序')}</span><small class="log-pid">PID ${entry.pid}</small></td><td><code class="log-path" title="${escape(entry.path)}">${escape(entry.path)}</code></td><td><span class="operation-label">${escape(operationNames[entry.operation] || entry.operation)}</span></td><td>${badge(resultNames[entry.result] || '未确认', entry.result === 'allowed' ? 'good' : entry.result === 'denied' ? 'danger' : 'neutral')}</td></tr>`).join('')}</tbody></table></div>`;
}

function formatTime(value: string) {
  const date = new Date(value);
  return Number.isNaN(date.valueOf()) ? value : date.toLocaleTimeString('zh-CN', { hour12: false, fractionalSecondDigits: 3 });
}

function settingsView() {
  const settings = state.config.settings;
  return `<div class="settings-layout"><section class="panel"><div class="panel-heading"><div><h3>外观</h3><p>选择适合你的界面主题</p></div>${icon('sun', 20)}</div><div class="theme-options">${(['light', 'dark', 'system'] as Theme[]).map(theme => `<button class="theme-card ${settings.theme === theme ? 'selected' : ''}" data-action="theme" data-theme="${theme}" aria-pressed="${settings.theme === theme}"><div class="theme-preview ${theme}"><i></i><div><span></span><span></span><span></span></div></div><span>${icon(theme === 'light' ? 'sun' : theme === 'dark' ? 'moon' : 'monitor', 16)}${theme === 'light' ? '浅色' : theme === 'dark' ? '深色' : '跟随系统'}<i class="radio-indicator"></i></span></button>`).join('')}</div></section><section class="panel"><div class="panel-heading"><div><h3>常规</h3><p>窗口与启动方式</p></div>${icon('settings', 20)}</div><div class="setting-row"><div><strong>关闭窗口时最小化到托盘</strong><p>从系统托盘中重新打开界面或退出程序</p></div>${switchControl('close-to-tray', settings.closeToTray, '关闭窗口时最小化到托盘')}</div><div class="setting-row"><div><strong>登录 Windows 时启动</strong><p>为当前用户注册 DiskGuard 开机启动项</p></div>${switchControl('autostart', settings.autostart, '登录 Windows 时启动')}</div></section><section class="panel"><div class="panel-heading"><div><h3>Sandboxie 运行时</h3><p>复用现有驱动、服务与沙箱配置能力</p></div><button class="button secondary small" data-action="refresh-runtime">${icon('refresh', 15)}重新检测</button></div><dl class="runtime-details"><div><dt>安装位置</dt><dd><code>${escape(state.runtime.runtimePath || '尚未检测到')}</code></dd></div><div><dt>运行时版本</dt><dd>${escape(state.runtime.version || '未知')}</dd></div><div><dt>驱动连接</dt><dd>${badge(state.runtime.driverAvailable ? '已连接' : '未连接', state.runtime.driverAvailable ? 'good' : 'neutral')}</dd></div><div><dt>服务状态</dt><dd>${badge(state.runtime.serviceRunning ? '运行中' : '未连接', state.runtime.serviceRunning ? 'good' : 'neutral')}</dd></div><div><dt>监控能力</dt><dd>${state.runtime.monitorSupported ? '支持运行时事件' : '当前不可用'}</dd></div></dl><div class="runtime-note settings-runtime-note">${icon('info', 16)}<span>${escape(state.runtime.message)}</span></div></section><section class="about-card"><span class="brand-symbol">${icon('shield', 26)}</span><div><h3>DiskGuard <span>0.1.0</span></h3><p>轻量界面 · 独立策略 · 本地数据</p><p class="about-footnote">Windows 10 / 11 x64 · Rust + Tauri 2 · Sandboxie</p></div></section></div>`;
}

function showModal() {
  if (!modal) { modalRoot.innerHTML = ''; return; }
  let content = '';
  if (modal.type === 'app') {
    content = `<div class="modal-heading"><span class="modal-symbol">${icon('apps', 23)}</span><div><h2>${modal.preset ? `添加 ${escape(modal.preset)}` : '添加应用'}</h2><p>选择实际 EXE 文件，创建独立沙箱</p></div></div><form id="app-form"><label class="form-label">应用名称<input name="name" required maxlength="80" value="${escape(modal.preset || '')}" placeholder="例如：我的应用" autofocus/></label><label class="form-label">可执行文件<div class="input-with-button"><input name="executable" required placeholder="选择程序的 .exe 文件" autocomplete="off" spellcheck="false"/><button type="button" class="button secondary small" data-action="browse-exe">${icon('folder', 16)}浏览</button></div></label><div class="modal-note">${icon('info', 17)}<p>不会猜测 QQ 或微信的安装位置。请选择已安装程序的真实可执行文件。新增应用默认采用只监控模式，自动保护默认关闭。</p></div><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">取消</button><button class="button primary" type="submit">${icon('plus', 16)}添加应用</button></div></form>`;
  } else if (modal.type === 'rule') {
    const appId = modal.appId;
    const app = state.config.apps.find(item => item.id === appId);
    content = `<div class="modal-heading"><span class="modal-symbol">${icon('folder', 24)}</span><div><h2>添加目录规则</h2><p>${escape(app?.name)} · ${app ? modeNames[app.mode] : ''}</p></div></div><form id="rule-form"><label class="form-label">目录路径<div class="input-with-button"><input name="path" required placeholder="选择需要设置规则的目录" autocomplete="off" spellcheck="false"/><button type="button" class="button secondary small" data-action="browse-directory">${icon('folder', 16)}浏览</button></div></label><label class="option-checkbox"><input name="recursive" type="checkbox" checked/><span><strong>递归匹配子目录</strong><small>将规则应用到该目录下的所有子目录</small></span></label><label class="option-checkbox"><input name="enabled" type="checkbox" checked/><span><strong>启用此规则</strong><small>保存并应用策略后写入运行时配置</small></span></label><div class="modal-footer"><button type="button" class="button secondary" data-action="close-modal">取消</button><button class="button primary" type="submit">${icon('plus', 16)}添加规则</button></div></form>`;
  } else if (modal.type === 'delete') {
    const appId = modal.appId;
    const app = state.config.apps.find(item => item.id === appId);
    content = `<div class="modal-heading"><span class="modal-symbol danger">${icon('trash', 24)}</span><div><h2>移除 ${escape(app?.name)}？</h2><p>从 DiskGuard 应用列表中移除</p></div></div><p class="delete-explanation">将删除本应用的 DiskGuard 策略配置。已经运行的进程和沙箱中的文件需要在 Sandboxie 中单独处理。</p><div class="modal-footer"><button class="button secondary" data-action="close-modal">取消</button><button class="button danger-button" data-action="confirm-delete" data-id="${escape(modal.appId)}">确认移除</button></div>`;
  } else {
    const entry = modal.entry;
    content = `<div class="modal-heading"><span class="modal-symbol">${icon('logs', 24)}</span><div><h2>访问事件详情</h2><p>运行时原始事件 #${entry.id}</p></div></div><dl class="event-details">${[['时间', entry.timestamp], ['应用', entry.appName], ['PID', entry.pid], ['路径', entry.path], ['操作', operationNames[entry.operation] || entry.operation], ['结果', resultNames[entry.result] || '未确认'], ['来源', entry.source], ['详细信息', entry.detail || '运行时未提供更多信息']].map(([label, value]) => `<div><dt>${escape(label)}</dt><dd>${escape(value)}</dd></div>`).join('')}</dl><div class="modal-footer"><button class="button primary" data-action="close-modal">关闭</button></div>`;
  }
  modalRoot.innerHTML = `<div class="modal-overlay"><section class="modal" role="dialog" aria-modal="true" aria-label="${modal.type === 'app' ? '添加应用' : modal.type === 'rule' ? '添加目录规则' : modal.type === 'delete' ? '移除应用' : '访问事件详情'}"><button class="modal-close icon-button" data-action="close-modal" aria-label="关闭对话框">${icon('close', 20)}</button>${content}</section></div>`;
  setTimeout(() => modalRoot.querySelector<HTMLElement>('input, .modal-footer button')?.focus(), 0);
}

async function saveConfig() {
  await api.saveConfig(state.config);
  state = await api.getState();
  dirty = false;
}

async function withBusy(action: () => Promise<void>, success?: string) {
  if (busy) return;
  busy = true;
  root.classList.add('busy');
  try { await action(); if (success) toast(success); }
  catch (error) { toast(String(error instanceof Error ? error.message : error), 'error'); }
  finally { busy = false; root.classList.remove('busy'); render(); }
}

async function refreshRuntime(silent = false) {
  try {
    state.runtime = await api.runtimeStatus();
    lastRefresh = new Date().toLocaleTimeString('zh-CN', { hour12: false });
    if (!silent) render();
  } catch (error) { if (!silent) toast(String(error), 'error'); }
}

async function refreshLogs(showError = false) {
  const request = ++logsRequest;
  try {
    const response = await api.getLogs(logFilter);
    if (request !== logsRequest) return;
    logs = response;
    if (page === 'logs') {
      document.querySelector('#log-content')!.innerHTML = logTable();
      document.querySelector('#log-count')!.textContent = `${logs.entries.length} 条记录`;
      document.querySelector('#log-notice')!.textContent = logNotice();
    }
  } catch (error) { if (showError) toast(String(error), 'error'); }
}

document.addEventListener('click', async event => {
  const target = (event.target as HTMLElement).closest<HTMLElement>('[data-action], [data-page]');
  if (!target) return;
  if (target instanceof HTMLInputElement) return;
  if (target instanceof HTMLButtonElement && target.disabled) return;
  if (target.dataset.page) {
    page = target.dataset.page as Page;
    render();
    if (page === 'logs' && nativeAvailable) void refreshLogs(true);
    return;
  }
  const action = target.dataset.action;
  const app = currentApp();
  if (action === 'add-app' || action === 'add-preset') { modal = { type: 'app', preset: target.dataset.preset }; showModal(); }
  else if (action === 'close-modal') { modal = null; showModal(); }
  else if (action === 'pick-app' || action === 'select-app') { currentAppId = target.dataset.id!; if (action === 'select-app') page = 'apps'; render(); }
  else if (action === 'save') await withBusy(saveConfig, '配置已保存到本机。');
  else if (action === 'mode' && app) { app.mode = target.dataset.mode as PolicyMode; markDirty(); render(); }
  else if (action === 'theme' || action === 'theme-cycle') {
    state.config.settings.theme = action === 'theme-cycle' ? (document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark') : target.dataset.theme as Theme;
    setTheme(state.config.settings.theme); markDirty(); render();
  }
  else if (action === 'add-rule' && app) { modal = { type: 'rule', appId: target.dataset.id || app.id }; showModal(); }
  else if (action === 'delete-rule' && app) { app.rules = app.rules.filter(rule => rule.id !== target.dataset.id); markDirty(); render(); }
  else if (action === 'delete-app') { modal = { type: 'delete', appId: target.dataset.id! }; showModal(); }
  else if (action === 'confirm-delete') {
    state.config.apps = state.config.apps.filter(item => item.id !== target.dataset.id); currentAppId = ''; markDirty(); modal = null; showModal(); render();
    toast('应用已从配置中移除。请保存更改以同步策略。', 'info');
  }
  else if (action === 'browse-exe' || action === 'browse-directory' || action === 'change-exe') {
    try {
      const path = action === 'browse-directory' ? await api.chooseDirectory() : await api.chooseExecutable();
      if (!path || Array.isArray(path)) return;
      if (action === 'change-exe' && app) { app.executable = path; markDirty(); render(); }
      else {
        const input = modalRoot.querySelector<HTMLInputElement>(`input[name="${action === 'browse-directory' ? 'path' : 'executable'}"]`);
        if (input) input.value = path;
        const name = modalRoot.querySelector<HTMLInputElement>('input[name="name"]');
        if (name && !name.value) name.value = path.split(/[\\/]/).pop()!.replace(/\.exe$/i, '');
      }
    } catch (error) { toast(String(error), 'error'); }
  }
  else if (action === 'apply' && app) await withBusy(async () => { await saveConfig(); const result = await api.applyPolicy(app.id); toast(result.message || '访问策略已提交到运行时。'); state = await api.getState(); });
  else if (action === 'launch' && app) await withBusy(async () => { await saveConfig(); const result = await api.launchApp(app.id); toast(result.message || '已请求在沙箱中启动应用。'); state = await api.getState(); });
  else if (action === 'refresh-runtime') await withBusy(() => refreshRuntime(true), '运行时状态已更新。');
  else if (action === 'refresh-logs') await refreshLogs(true);
  else if (action === 'reset-filters') { logFilter = { search: '', appId: '', result: '', operation: '' }; render(); if (nativeAvailable) void refreshLogs(true); }
  else if (action === 'export-logs') await withBusy(async () => {
    const destination = await api.chooseExportPath();
    if (!destination) return;
    const result = await api.exportLogs(logFilter, destination);
    toast(`已导出 ${result.count} 条日志：${result.path}`);
  });
  else if (action === 'log-detail') {
    const entry = logs.entries.find(item => item.id === Number(target.dataset.id));
    if (entry) { modal = { type: 'log', entry }; showModal(); }
  }
});

document.addEventListener('input', event => {
  const input = event.target as HTMLInputElement;
  const app = currentApp();
  if (input.dataset.field === 'app-name' && app) { app.name = input.value; markDirty(); }
  if (input.dataset.field === 'app-sandbox' && app) { app.sandbox = input.value; markDirty(); }
  if (input.dataset.filter === 'search') {
    logFilter.search = input.value;
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => { if (nativeAvailable) void refreshLogs(true); }, 250);
  }
});

document.addEventListener('change', async event => {
  const input = event.target as HTMLInputElement | HTMLSelectElement;
  const app = currentApp();
  if (input.dataset.filter) {
    logFilter[input.dataset.filter as keyof LogFilter] = input.value;
    if (nativeAvailable) void refreshLogs(true);
    return;
  }
  const value = (input as HTMLInputElement).checked;
  const action = input.dataset.action;
  if (action === 'app-enabled' && app) app.enabled = value;
  else if (action === 'auto-protect' && app) app.autoProtect = value;
  else if (action === 'include-children' && app) app.includeChildren = value;
  else if ((action === 'rule-enabled' || action === 'rule-recursive') && app) {
    const rule = app.rules.find(item => item.id === input.dataset.id);
    if (!rule) return;
    if (action === 'rule-enabled') rule.enabled = value;
    else rule.recursive = value;
  }
  else if (action === 'close-to-tray') state.config.settings.closeToTray = value;
  else if (action === 'autostart') {
    const previous = state.config.settings.autostart;
    await withBusy(async () => {
      await api.setAutostart(value);
      state.config.settings.autostart = value;
      markDirty();
      try { await saveConfig(); toast(value ? '已启用当前用户开机启动。' : '已关闭开机启动。'); }
      catch (error) { state.config.settings.autostart = previous; throw error; }
    });
    return;
  }
  else return;
  markDirty(); render();
});

document.addEventListener('submit', event => {
  const form = event.target as HTMLFormElement;
  if (form.id !== 'app-form' && form.id !== 'rule-form') return;
  event.preventDefault();
  const data = new FormData(form);
  if (form.id === 'app-form') {
    const executable = String(data.get('executable') || '').trim();
    const name = String(data.get('name') || '').trim();
    if (!name || !/^[A-Za-z]:[\\/].*\.exe$/i.test(executable)) { toast('请输入应用名称，并选择完整的 Windows EXE 路径。', 'error'); return; }
    if (state.config.apps.some(app => app.executable.toLowerCase() === executable.toLowerCase())) { toast('这个可执行文件已经添加到应用列表。', 'error'); return; }
    const id = uid();
    state.config.apps.push({ id, name, executable, sandbox: `DiskGuard_${id.replace(/-/g, '').slice(0, 12)}`, mode: 'monitor', enabled: true, autoProtect: false, includeChildren: true, rules: [] });
    currentAppId = id; page = 'apps';
  } else if (modal?.type === 'rule') {
    const appId = modal.appId;
    const app = state.config.apps.find(item => item.id === appId);
    if (!app) return;
    const path = String(data.get('path') || '').trim();
    if (!/^(?:[A-Za-z]:[\\/]|\\\\[^\\]+\\[^\\]+)/.test(path)) { toast('请输入完整的 Windows 目录路径。', 'error'); return; }
    if (app.rules.some(rule => rule.path.toLowerCase().replace(/[\\/]+$/, '') === path.toLowerCase().replace(/[\\/]+$/, ''))) { toast('此应用已经配置了相同目录。', 'error'); return; }
    const rule: Rule = { id: uid(), path, recursive: data.get('recursive') === 'on', enabled: data.get('enabled') === 'on' };
    app.rules.push(rule);
  }
  markDirty(); modal = null; showModal(); render();
});

document.addEventListener('keydown', event => {
  if (event.key === 'Escape' && modal) { modal = null; showModal(); }
  if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 's') { event.preventDefault(); if (dirty) void withBusy(saveConfig, '配置已保存到本机。'); }
  if (event.key === 'Enter' && (event.target as HTMLElement).matches('tr[data-action="log-detail"]')) (event.target as HTMLElement).click();
  if (event.key === 'Tab' && modal) {
    const elements = [...modalRoot.querySelectorAll<HTMLElement>('button:not([disabled]), input, select, [tabindex="0"]')];
    const first = elements[0]; const last = elements[elements.length - 1];
    if (event.shiftKey && document.activeElement === first) { event.preventDefault(); last?.focus(); }
    else if (!event.shiftKey && document.activeElement === last) { event.preventDefault(); first?.focus(); }
  }
});

render();
if (nativeAvailable) {
  api.getState().then(value => { state = value; currentAppId = value.config.apps[0]?.id || ''; setTheme(value.config.settings.theme); lastRefresh = new Date().toLocaleTimeString('zh-CN', { hour12: false }); render(); return refreshLogs(); }).catch(error => { state.runtime.message = String(error); render(); toast(`无法载入配置：${String(error)}`, 'error'); });
  setInterval(() => { if (!document.hidden) void refreshLogs(); }, 2500);
  setInterval(() => { if (!document.hidden && !busy) void refreshRuntime(true); }, 15000);
}

