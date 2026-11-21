'use strict';

const identities = new WeakMap();

async function configurePage(page) {
  if (identities.has(page)) return identities.get(page);
  const pending = (async () => {
    const browser = page.context().browser();
    const control = await browser.newBrowserCDPSession();
    let version;
    try {
      version = await control.send('Browser.getVersion');
    } finally {
      await control.detach();
    }
    const fullVersion = version.product.split('/').at(-1);
    const session = await page.context().newCDPSession(page);
    await session.send('Emulation.setUserAgentOverride', {
      userAgent: version.userAgent.replace('HeadlessChrome/', 'Chrome/'),
      platform: 'Linux x86_64', acceptLanguage: 'en-US,en',
      userAgentMetadata: {
        brands: [{ brand: 'Chromium', version: fullVersion.split('.')[0] }],
        fullVersionList: [{ brand: 'Chromium', version: fullVersion }],
        fullVersion, platform: 'Linux', platformVersion: '',
        architecture: process.arch === 'arm64' ? 'arm' : 'x86',
        model: '', mobile: false, bitness: '64', wow64: false,
      },
    });
    return session;
  })();
  identities.set(page, pending);
  try {
    return await pending;
  } catch (error) {
    identities.delete(page);
    throw error;
  }
}

module.exports = { configurePage };
