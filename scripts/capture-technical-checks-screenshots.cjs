const puppeteer = require('puppeteer');
const path = require('path');

(async () => {
    const dir = '/home/mxscan/public_html/dev.mxscan.me/storage/app/report-screenshots';

    const browser = await puppeteer.launch({
        headless: 'new',
        executablePath: '/home/mxscan/.cache/puppeteer/chrome/linux-131.0.6778.204/chrome-linux64/chrome',
        args: ['--no-sandbox', '--disable-setuid-sandbox'],
    });

    async function capture(file, viewport, output, mobile = false) {
        const page = await browser.newPage();
        await page.setViewport(viewport);
        await page.goto('file://' + path.join(dir, file), { waitUntil: 'networkidle0' });
        await page.waitForSelector('#technical-checks');
        const section = await page.$('#technical-checks');
        await page.evaluate((el) => el.scrollIntoView({ block: 'start' }), section);
        await new Promise((r) => setTimeout(r, 400));
        const box = await section.boundingBox();
        if (!box) {
            throw new Error('Could not measure #technical-checks');
        }
        const padding = mobile ? 8 : 16;
        await page.screenshot({
            path: path.join(dir, output),
            clip: {
                x: Math.max(0, box.x - padding),
                y: Math.max(0, box.y - padding),
                width: Math.min(viewport.width, box.width + padding * 2),
                height: Math.min(viewport.height - box.y, box.height + padding * 2),
            },
        });
        await page.close();
    }

    await capture('mxscan-me-report-after-desktop.html', { width: 1440, height: 1600, deviceScaleFactor: 1 }, 'technical-checks-after-desktop.png');
    await capture('mxscan-me-report-after-mobile.html', { width: 390, height: 1600, deviceScaleFactor: 2, isMobile: true }, 'technical-checks-after-mobile.png', true);

    await browser.close();
    console.log('Screenshots saved to', dir);
})();
