import assert from 'node:assert/strict';
import test from 'node:test';
import { launchAcceptanceBrowser } from '../scripts/lib/acceptance-browser.mjs';

const missingDistribution = channel => new Error(`browserType.launch: Chromium distribution '${channel}' is not found at /missing/browser`);
const missingBundled = () => new Error("browserType.launch: Executable doesn't exist at /missing/chromium");

function fixture(t, outcomes) {
  const calls = [];
  const browser = { version: () => '123.0.1' };
  const log = t.mock.method(console, 'log', () => {});
  return {
    calls, browser, log,
    browserType: {
      async launch(options) {
        calls.push(options);
        const outcome = outcomes[calls.length - 1];
        if (outcome instanceof Error) throw outcome;
        return browser;
      },
    },
  };
}

test('default browser selection uses Edge and reports the actual version', async t => {
  const f = fixture(t, []);
  assert.equal(await launchAcceptanceBrowser({}, { env: {}, browserType: f.browserType }), f.browser);
  assert.deepEqual(f.calls, [{ headless: true, channel: 'msedge' }]);
  assert.match(f.log.mock.calls[0].arguments[0], /channel msedge; version 123\.0\.1/);
});

test('missing Edge falls back to Chrome and preserves caller launch options', async t => {
  const f = fixture(t, [missingDistribution('msedge')]);
  const options = { headless: false, args: ['--disable-dev-shm-usage'], timeout: 5000 };
  assert.equal(await launchAcceptanceBrowser(options, { env: {}, browserType: f.browserType }), f.browser);
  assert.deepEqual(f.calls, [{ ...options, channel: 'msedge' }, { ...options, channel: 'chrome' }]);
  assert.deepEqual(options, { headless: false, args: ['--disable-dev-shm-usage'], timeout: 5000 });
  assert.match(f.log.mock.calls[0].arguments[0], /channel chrome/);
});

test('missing Edge and Chrome fall back to Playwright bundled Chromium', async t => {
  const f = fixture(t, [missingDistribution('msedge'), missingDistribution('chrome')]);
  assert.equal(await launchAcceptanceBrowser({}, { env: {}, browserType: f.browserType }), f.browser);
  assert.deepEqual(f.calls, [{ headless: true, channel: 'msedge' }, { headless: true, channel: 'chrome' }, { headless: true }]);
  assert.match(f.log.mock.calls[0].arguments[0], /channel bundled Chromium/);
});

test('explicit channel selects exactly that channel', async t => {
  const f = fixture(t, []);
  await launchAcceptanceBrowser({}, { env: { PLAYWRIGHT_BROWSER_CHANNEL: 'chromium' }, browserType: f.browserType });
  assert.deepEqual(f.calls, [{ headless: true, channel: 'chromium' }]);
});

test('explicit executable path is passed unchanged and logged', async t => {
  const f = fixture(t, []);
  const executablePath = '/Applications/Custom Browser.app/Contents/MacOS/browser';
  await launchAcceptanceBrowser({}, { env: { PLAYWRIGHT_BROWSER_EXECUTABLE_PATH: executablePath }, browserType: f.browserType });
  assert.deepEqual(f.calls, [{ headless: true, executablePath }]);
  assert.ok(f.log.mock.calls[0].arguments[0].includes(JSON.stringify(executablePath)));
});

test('explicit channel and executable failures never fall back', async t => {
  for (const [env, error] of [
    [{ PLAYWRIGHT_BROWSER_CHANNEL: 'chrome' }, missingDistribution('chrome')],
    [{ PLAYWRIGHT_BROWSER_EXECUTABLE_PATH: '/missing/browser' }, new Error("browserType.launch: Failed to launch chromium because executable doesn't exist at /missing/browser")],
  ]) {
    const f = fixture(t, [error]);
    await assert.rejects(launchAcceptanceBrowser({}, { env, browserType: f.browserType }), failure => {
      assert.match(failure.message, /no fallback was attempted/);
      assert.equal(failure.cause, error);
      return true;
    });
    assert.equal(f.calls.length, 1);
  }
});

test('caller channel and executable options are also explicit selections', async t => {
  for (const options of [{ channel: 'chrome-beta' }, { executablePath: '/missing/browser' }]) {
    const f = fixture(t, [missingBundled()]);
    await assert.rejects(launchAcceptanceBrowser(options, { env: {}, browserType: f.browserType }), /no fallback was attempted/);
    assert.deepEqual(f.calls, [{ headless: true, ...options }]);
  }
});

test('conflicting selectors and unsupported channels fail before browser launch', async t => {
  const f = fixture(t, []);
  await assert.rejects(launchAcceptanceBrowser({}, { env: { PLAYWRIGHT_BROWSER_CHANNEL: 'chrome', PLAYWRIGHT_BROWSER_EXECUTABLE_PATH: '/browser' }, browserType: f.browserType }), /cannot both be set/);
  await assert.rejects(launchAcceptanceBrowser({ channel: 'msedge' }, { env: { PLAYWRIGHT_BROWSER_EXECUTABLE_PATH: '/browser' }, browserType: f.browserType }), /cannot both be set/);
  await assert.rejects(launchAcceptanceBrowser({}, { env: { PLAYWRIGHT_BROWSER_CHANNEL: 'firefox' }, browserType: f.browserType }), /Unsupported acceptance browser channel/);
  assert.equal(f.calls.length, 0);
});

test('permission, dependency, crash and timeout errors propagate without fallback', async t => {
  for (const message of [
    'browserType.launch: spawn /Applications/Browser EACCES',
    'browserType.launch: spawn /Applications/Browser EPERM',
    'browserType.launch: Host system is missing dependencies to run browsers.',
    'browserType.launch: Target page, context or browser has been closed',
    'browserType.launch: Timeout 30000ms exceeded.',
  ]) {
    const error = new Error(message);
    const f = fixture(t, [error]);
    await assert.rejects(launchAcceptanceBrowser({}, { env: {}, browserType: f.browserType }), failure => failure === error);
    assert.equal(f.calls.length, 1);
  }
});

test('all missing browsers produce configuration guidance without claiming a launch', async t => {
  const error = missingBundled();
  const f = fixture(t, [missingDistribution('msedge'), missingDistribution('chrome'), error]);
  await assert.rejects(launchAcceptanceBrowser({}, { env: {}, browserType: f.browserType }), failure => {
    assert.match(failure.message, /No acceptance browser executable found \(msedge, chrome, bundled Chromium\)/);
    assert.match(failure.message, /PLAYWRIGHT_BROWSER_CHANNEL/);
    assert.match(failure.message, /PLAYWRIGHT_BROWSER_EXECUTABLE_PATH/);
    assert.equal(failure.cause, error);
    return true;
  });
  assert.equal(f.calls.length, 3);
  assert.equal(f.log.mock.calls.length, 0);
});
