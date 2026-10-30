import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import test from 'node:test';
import { nativeMessages } from '../src/native-messages.ts';

test('native help codes exist in upstream messages and are unique', () => {
  const upstream = readFileSync(new URL('../../../Sandboxie/msgs/Sbie-English-1033.txt', import.meta.url), 'utf8');
  assert.equal(new Set(nativeMessages.map(item => item.code)).size, nativeMessages.length);
  for (const item of nativeMessages) {
    assert.match(upstream, new RegExp(`^${item.code} `, 'm'));
    assert.ok(item.meaning.length > 0 && item.action.length > 0);
  }
});

test('driver guidance does not recommend weakening Windows signature enforcement', () => {
  assert.match(nativeMessages.find(item => item.code === 'SBIE9153')!.action, /不要关闭签名强制/);
  assert.match(nativeMessages.find(item => item.code === 'SBIE1307')!.action, /不是磁盘/);
});

test('native help is documented and guides are included in both package formats', () => {
  const guide = readFileSync(new URL('../../docs/USER-GUIDE.zh-CN.md', import.meta.url), 'utf8');
  for (const item of nativeMessages) assert.ok(guide.includes(item.code), item.code);
  const config = JSON.parse(readFileSync(new URL('../../src-tauri/tauri.conf.json', import.meta.url), 'utf8'));
  const build = readFileSync(new URL('../../scripts/Build.ps1', import.meta.url), 'utf8');
  for (const name of ['USER-GUIDE.zh-CN.md', 'RELEASE-CHECKLIST.zh-CN.md', 'DEPENDENCY-REVIEW.md', 'VALIDATION.md']) {
    assert.equal(config.bundle.resources[`../docs/${name}`], name);
    assert.ok(build.includes(name), name);
  }
});
