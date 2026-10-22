// SPDX-License-Identifier: GPL-3.0-or-later
// Cloud-only visual review of the browser preview. No runtime or access events
// are simulated; the example application/rule remain unsaved browser drafts.
const fs = require('node:fs/promises');
const http = require('node:http');
const path = require('node:path');
const project = path.resolve(__dirname, '..');
const { chromium } = require(path.join(project, 'work/ui-review/node_modules/playwright'));

(async () => {
  const dist = path.join(project, 'ui/dist');
  const output = path.join(project, 'work/ui-review-captures');
  await fs.mkdir(output, { recursive: true });
  const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };
  const server = http.createServer(async (request, response) => {
    try {
      const relative = decodeURIComponent(new URL(request.url, 'http://localhost').pathname);
      const file = path.resolve(dist, '.' + (relative === '/' ? '/index.html' : relative));
      if (!file.startsWith(dist + path.sep)) { response.writeHead(403).end(); return; }
      response.setHeader('Content-Type', types[path.extname(file)] || 'application/octet-stream');
      response.end(await fs.readFile(file));
    } catch { response.writeHead(404).end(); }
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  let browser;
  const measurements = [];
  try {
    browser = await chromium.launch();
    for (const theme of ['light', 'dark']) {
      for (const [width, height] of [[1000, 680], [1280, 820], [1920, 1080]]) {
        const context = await browser.newContext({ viewport: { width, height } });
        await context.addInitScript(value => localStorage.setItem('diskguard-theme', value), theme);
        const page = await context.newPage();
        await page.goto(`http://127.0.0.1:${server.address().port}/`);
        await page.locator('.hero').waitFor();
        const capture = async name => {
          await page.evaluate(() => document.fonts.ready);
          await page.screenshot({ path: path.join(output, `${theme}-${width}-${name}.png`),
            fullPage: !name.endsWith('dialog'), animations: 'disabled' });
          measurements.push(await page.evaluate(({ theme, width, name }) => {
            const fonts = [...document.querySelectorAll('body *')].filter(e =>
              e.getClientRects().length && [...e.childNodes].some(n => n.nodeType === 3 && n.textContent.trim()))
              .map(e => parseFloat(getComputedStyle(e).fontSize));
            return { theme, width, page: name, previewOnly: true,
              rootFontPx: parseFloat(getComputedStyle(document.documentElement).fontSize),
              smallestVisibleTextPx: Math.min(...fonts),
              viewportWidth: document.documentElement.clientWidth,
              documentWidth: document.documentElement.scrollWidth };
          }, { theme, width, name }));
        };
        await capture('overview');
        if (theme === 'light' && width === 1000) {
          const scale = await page.addStyleTag({ content: ':root { font-size: 200%; }' });
          await capture('overview-text-200');
          await scale.evaluate(element => element.remove());
        }
        if (width !== 1920) {
          await page.locator('[data-action="add-app"]').first().click();
          await capture('add-application-dialog');
          await page.locator('#app-form input[name="name"]').fill('布局预览：较长的中文应用名称与路径');
          await page.locator('#app-form input[name="executable"]').fill('C:\\Program Files\\布局预览目录\\示例应用.exe');
          await page.locator('#app-form button[type="submit"]').click();
          await capture('application');
          await page.locator('nav [data-page="rules"]').click();
          await page.locator('[data-action="add-rule"]').first().click();
          await page.locator('#rule-form input[name="path"]').fill('D:\\布局预览目录\\用于检查长路径换行的示例子目录\\个人文件');
          await capture('add-rule-dialog');
          await page.locator('#rule-form button[type="submit"]').click();
          await capture('rules');
          await page.locator('nav [data-page="logs"]').click();
          await capture('logs-empty');
          await page.locator('nav [data-page="settings"]').click();
          await capture('settings');
        }
        await context.close();
      }
    }
    await fs.writeFile(path.join(output, 'measurements.json'), JSON.stringify(measurements, null, 2));
    console.log(`Saved ${measurements.length} browser-preview screenshots and font/layout measurements.`);
  } finally {
    if (browser) await browser.close();
    await new Promise(resolve => server.close(resolve));
  }
})().catch(error => { console.error(error); process.exitCode = 1; });
