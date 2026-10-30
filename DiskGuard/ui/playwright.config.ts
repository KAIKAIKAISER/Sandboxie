import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: true,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  reporter: [['list']],
  use: { baseURL: 'http://127.0.0.1:1420', trace: 'retain-on-failure' },
  webServer: {
    command: 'npm run dev -- --port 1420 --strictPort',
    url: 'http://127.0.0.1:1420',
    reuseExistingServer: false,
  },
});
