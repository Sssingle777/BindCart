import { readFile } from 'node:fs/promises';

// Full public MyStore application; raw upstream bytes remain preserved.
export async function createNativeRenderer() {
  let html = await readFile(new URL('../../third-party/mystore-web/index.html', import.meta.url), 'utf8');
  html = html.replace('lang="en"', 'lang="zh-CN"')
    .replace('<title>MyStore Demo</title>', '<title>MyStore 商城</title>')
    .replace(/<link[^>]+(?:rel="preconnect"|favicon|apple-touch-icon|mask-icon)[^>]*>/g, '')
    .replace(/<meta[^>]+name="msapplication-config"[^>]*>/g, '')
    .replace('https://rsms.me/inter/inter.css', '/store/mystore/fonts/inter.css')
    .replace('href="vendors.css"', 'href="/store/mystore/vendors.css"')
    .replace('href="main.css"', 'href="/store/mystore/main.css"')
    .replace(/<script src="https:\/\/checkoutshopper[^>]*><\/script>/, '')
    .replace('src="runtime.bundle.js"', 'src="/store/mystore/runtime.bundle.js"')
    .replace('src="vendors.bundle.js"', 'src="/store/mystore/vendors.bundle.js"')
    .replace('<script defer="defer" src="main.bundle.js"></script>', '<script defer src="/store/app.js"></script><script defer src="/store/mystore/main.local.bundle.js"></script>')
    .replace(/<script async src="https:\/\/www.googletagmanager[^>]*><\/script>/, '')
    .replace(/<script>window\.dataLayer[\s\S]*?<\/script>/, '');
  return function renderNativePage() { return html; };
}
export function nativeView() { return ['application']; }
