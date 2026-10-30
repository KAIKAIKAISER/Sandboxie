import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';

const read = (path: string) => readFileSync(new URL(path, import.meta.url), 'utf8');

test('release versions agree across native, frontend, lockfiles and visible UI', () => {
  const version = JSON.parse(read('../../src-tauri/tauri.conf.json')).version;
  assert.match(version, /^\d+\.\d+\.\d+$/);
  for (const path of ['../../package.json', '../package.json']) {
    assert.equal(JSON.parse(read(path)).version, version, path);
  }
  for (const path of ['../../package-lock.json', '../package-lock.json']) {
    const lock = JSON.parse(read(path));
    assert.equal(lock.version, version, path);
    assert.equal(lock.packages[''].version, version, path);
  }
  assert.equal(read('../../src-tauri/Cargo.toml').match(/^version = "([^"]+)"/m)?.[1], version);
  const packageBlock = read('../../src-tauri/Cargo.lock').split('[[package]]').find(block => /^name = "diskguard"$/m.test(block));
  assert.equal(packageBlock?.match(/^version = "([^"]+)"/m)?.[1], version);
  const ui = read('../src/main.ts');
  assert.ok(ui.includes(`<span>v${version}</span>`));
  assert.ok(ui.includes(`<h3>DiskGuard <span>${version}</span>`));
});
