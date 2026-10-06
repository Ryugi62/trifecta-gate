// Serve dist/ on 127.0.0.1, capture 390px and 1280px screenshots (+ checker run), then shut the server down.
import { preview } from 'vite'
import { chromium } from 'playwright'
const out = process.argv[2] ?? 'docs/shots'
const server = await preview({ preview: { port: 4329, host: '127.0.0.1', strictPort: true } })
const url = 'http://127.0.0.1:4329/'
const browser = await chromium.launch()
try {
  for (const w of [390, 1280]) {
    const p = await browser.newPage({ viewport: { width: w, height: 900 }, deviceScaleFactor: 2 })
    await p.goto(url); await p.waitForSelector('.stat')
    await p.click('[data-preset="town"]')
    await p.screenshot({ path: `${out}/page-${w}.png`, fullPage: true })
    const overflow = await p.evaluate(() => document.documentElement.scrollWidth - window.innerWidth)
    console.log(w, 'horizontal overflow px:', overflow)
    await p.close()
  }
} finally { await browser.close(); server.httpServer.close() }
