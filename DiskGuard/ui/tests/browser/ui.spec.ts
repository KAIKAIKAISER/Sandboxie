import { test, expect } from '@playwright/test';

// The browser tests mock only the native bridge. They do NOT validate a driver.
test.beforeEach(async ({ page }) => {
  await page.addInitScript(() => {
    const app = { id: 'fixture', name: '测试应用', executable: 'C:\\Apps\\test.exe', sandbox: 'DiskGuard_fixture', enabled: true, mode: 'blacklist', autoProtect: true, includeChildren: true, rules: [] };
    (window as any).fixture = {
      state: { config: { version: 1, apps: [app], settings: { theme: 'light', closeToTray: true, autostart: false } },
        runtime: { driverAvailable: true, serviceRunning: true, monitoring: false, monitorSupported: true, securityFeaturesAvailable: false, forceRulesDisabled: false, message: '测试桥接（非真实运行时）', runtimePath: 'C:\\Sandboxie', version: 'fixture' },
        appliedAppIds: ['fixture'], pendingAppIds: [], configurationError: null, configurationDirectory: 'C:\\Fixture' },
      failSave: false, journalFailure: false, installOutcome: 'failed', saves: 0,
    };
  });
  await page.route('**/src/api.ts', route => route.fulfill({ contentType: 'application/javascript', body: String.raw`
    export const nativeAvailable = true;
    const f = window.fixture;
    export const api = {
      getState: async () => structuredClone(f.state), frontendReady: async () => {},
      runtimeStatus: async () => structuredClone(f.state.runtime),
      runtimeInstallation: async () => ({installed:false,bundled:true,canInstall:true,installing:false,rebootRequired:false,message:'测试资源'}),
      recoverConfiguration: async () => { f.state.configurationError = null; },
      saveConfig: async config => {
        if (f.failSave) { if(f.journalFailure) f.state.configurationError='保存未完成，操作日志已保留'; throw new Error('模拟磁盘写入失败'); }
        f.state.config=structuredClone(config); f.saves++;
      },
      getLogs: async filter => ({entries:[{id:1,timestamp:'2026-10-30T00:00:00Z',appId:'fixture',appName:'测试应用',pid:42,path:'D:\\private',operation:'file_open',result:'denied',source:'fixture'}].filter(e => !filter.result || filter.result===e.result)}),
      installRuntime: async () => ({outcome:f.installOutcome,message:f.installOutcome==='cancelled'?'已取消 Windows 管理员授权':'测试安装失败',rebootRequired:false}),
      chooseExecutable: async () => null, chooseDirectory: async () => null,
      setAutostart: async enabled => { f.state.config.settings.autostart=enabled; },
    };` }));
  await page.goto('/');
  await expect(page.locator('.hero')).toBeVisible();
});

test('failed save preserves draft and allows retry', async ({ page }) => {
  await page.locator('nav [data-page="apps"]').click();
  await page.locator('[data-field="app-name"]').fill('尚未保存的名称');
  await page.evaluate(() => { (window as any).fixture.failSave = true; });
  await page.locator('[data-save]').click();
  await expect(page.locator('.toast.error')).toContainText('模拟磁盘写入失败');
  await expect(page.locator('[data-field="app-name"]')).toHaveValue('尚未保存的名称');
  await expect(page.locator('.save-state')).toContainText('未保存');
  await page.evaluate(() => { (window as any).fixture.failSave = false; });
  await page.locator('[data-save]').click();
  await expect(page.locator('.save-state')).toContainText('配置保存在本机');
});

test('partial save enters read-only recovery instead of claiming protection', async ({ page }) => {
  await page.locator('nav [data-page="apps"]').click();
  await page.locator('[data-field="app-name"]').fill('恢复测试');
  await page.evaluate(() => { Object.assign((window as any).fixture, {failSave:true,journalFailure:true}); });
  await page.locator('[data-save]').click();
  await expect(page.locator('.load-error')).toContainText('操作日志已保留');
  await expect(page.locator('.policy-state')).toContainText('状态待恢复');
  await page.locator('[data-action="retry-load"]').click();
  await expect(page.locator('.load-error')).toHaveCount(0);
});

test('deletion needs confirmation and does not persist before save', async ({ page }) => {
  await page.locator('nav [data-page="apps"]').click();
  await page.locator('[data-action="delete-app"]').click();
  await page.locator('[data-action="close-modal"]').last().click();
  await expect(page.locator('.app-profile h2')).toHaveText('测试应用');
  await page.locator('[data-action="delete-app"]').click();
  await page.locator('[data-action="confirm-delete"]').click();
  expect(await page.evaluate(() => (window as any).fixture.state.config.apps.length)).toBe(1);
  await page.locator('[data-save]').click();
  expect(await page.evaluate(() => (window as any).fixture.state.config.apps.length)).toBe(0);
});

test('log result filters preserve denied versus unknown semantics', async ({ page }) => {
  await page.locator('nav [data-page="logs"]').click();
  await expect(page.locator('.logs-table tbody tr')).toHaveCount(1);
  await page.locator('[data-filter="result"]').selectOption('unknown');
  await expect(page.locator('.logs-table tbody tr')).toHaveCount(0);
  await page.locator('[data-filter="result"]').selectOption('denied');
  await expect(page.locator('.logs-table tbody tr')).toHaveCount(1);
});

for (const outcome of ['failed', 'cancelled']) {
  test(`installation ${outcome} is surfaced without a success claim`, async ({ page }) => {
    await page.evaluate(value => { (window as any).fixture.installOutcome = value; }, outcome);
    await page.locator('[data-action="install-runtime"]').click();
    await expect(page.locator(outcome === 'failed' ? '.toast.error' : '.toast.info')).toContainText(outcome === 'failed' ? '测试安装失败' : '已取消');
  });
}

test('native message help is clearly labelled as reference material', async ({ page }) => {
  await page.locator('nav [data-page="settings"]').click();
  await page.getByText('查看 SBIE 消息与处理建议').click();
  await expect(page.getByText('SBIE9154', { exact: true })).toBeVisible();
  await expect(page.getByText(/以下是说明索引，不是当前系统告警/)).toBeVisible();
});

test('configuration load error preserves the recovery UI and blocks saving', async ({ page }) => {
  await page.addInitScript(() => { (window as any).fixture.state.configurationError = 'config.json 无法解析，原文件已保留'; });
  await page.reload();
  await expect(page.locator('.load-error')).toContainText('config.json 无法解析');
  await page.locator('nav [data-page="apps"]').click();
  await expect(page.locator('[data-field="app-name"]')).toBeDisabled();
  await expect(page.locator('[data-save]')).toBeDisabled();
  await page.locator('[data-action="retry-load"]').click();
  await expect(page.locator('.load-error')).toHaveCount(0);
});
