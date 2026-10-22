import { chromium } from 'playwright-core';

const channels = new Set([
  'chromium', 'chrome', 'chrome-beta', 'chrome-dev', 'chrome-canary',
  'msedge', 'msedge-beta', 'msedge-dev', 'msedge-canary',
]);
const configurationHint = 'Set PLAYWRIGHT_BROWSER_CHANNEL to an installed Chrome/Edge channel or PLAYWRIGHT_BROWSER_EXECUTABLE_PATH to a browser executable (choose one).';

function missingExecutable(error) {
  // Do not mask permissions, missing shared libraries, crashes or startup timeouts.
  return /^(?:browserType\.launch:\s*)?(?:Chromium distribution '[^']+' is not found(?:\s|$)|Executable doesn't exist at |Failed to launch chromium because executable doesn't exist at )/.test(error?.message || '');
}

export async function launchAcceptanceBrowser(options = {}, { env = process.env, browserType = chromium } = {}) {
  const channel = env.PLAYWRIGHT_BROWSER_CHANNEL?.trim() || options.channel;
  const executablePath = env.PLAYWRIGHT_BROWSER_EXECUTABLE_PATH || options.executablePath;
  if (channel && executablePath) {
    throw new Error(`Acceptance browser channel and executable path cannot both be set. ${configurationHint}`);
  }
  if (channel && !channels.has(channel)) {
    throw new Error(`Unsupported acceptance browser channel ${JSON.stringify(channel)}. Supported channels: ${[...channels].join(', ')}.`);
  }

  const { channel: _channel, executablePath: _executablePath, ...launchOptions } = options;
  const explicitSelection = Boolean(channel || executablePath);
  const candidates = executablePath ? [{ executablePath }] : channel ? [{ channel }] : [{ channel: 'msedge' }, { channel: 'chrome' }, {}];
  let lastMissingError;
  for (const candidate of candidates) {
    let browser;
    try {
      browser = await browserType.launch({ headless: true, ...launchOptions, ...candidate });
    } catch (error) {
      if (!missingExecutable(error)) throw error;
      lastMissingError = error;
      if (explicitSelection) {
        const selection = executablePath ? `executable ${JSON.stringify(executablePath)}` : `channel ${JSON.stringify(channel)}`;
        throw new Error(`Requested acceptance browser ${selection} was not found; no fallback was attempted. ${configurationHint}`, { cause: error });
      }
      continue;
    }
    const selection = candidate.executablePath ? `executable ${JSON.stringify(candidate.executablePath)}` : `channel ${candidate.channel || 'bundled Chromium'}`;
    console.log(`[acceptance-browser] ${selection}; version ${browser.version()}`);
    return browser;
  }
  throw new Error(`No acceptance browser executable found (msedge, chrome, bundled Chromium). ${configurationHint}`, { cause: lastMissingError });
}
