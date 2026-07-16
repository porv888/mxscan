const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
    const dir = '/home/mxscan/public_html/dev.mxscan.me/storage/app/report-screenshots';
    const label = (process.env.REPORT_SNAPSHOT_LABEL || 'after').replace(/[^a-z0-9_-]/gi, '') || 'after';
    const fallbackChrome = '/home/mxscan/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome';

    const browser = await puppeteer.launch({
        headless: 'new',
        executablePath: process.env.PUPPETEER_EXECUTABLE_PATH || puppeteer.executablePath() || fallbackChrome,
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    async function capture(width, height, mobile = false) {
        const page = await browser.newPage();
        await page.setViewport({ width, height, deviceScaleFactor: mobile ? 2 : 1, isMobile: mobile });
        await page.goto('file://' + path.join(dir, `mxscan-me-report-${label}.html`), { waitUntil: 'networkidle0' });
        await page.waitForSelector('#technical-checks');
        await new Promise((resolve) => setTimeout(resolve, 400));
        await page.screenshot({
            path: path.join(dir, `mxscan-me-report-${label}-${width}.png`),
            fullPage: true,
        });
        await page.close();
    }

    await capture(1440, 1600);
    await capture(390, 1200, true);
    await capture(320, 1200, true);

    await browser.close();
    console.log(`${label} screenshots saved to ${dir}`);
})();
