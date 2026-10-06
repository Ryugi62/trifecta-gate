// Record a captioned 1280x720 walkthrough of the built demo (dist/), then convert to MP4 with the bundled ffmpeg.
// usage: tsx scripts/record-demo.ts <out.mp4>
import { preview } from 'vite'
import { chromium, type Page } from 'playwright'
import { execFileSync } from 'node:child_process'
import { mkdirSync, readdirSync, rmSync } from 'node:fs'
import { join } from 'node:path'

const out = process.argv[2] ?? 'web/public/demo.mp4'
const ffmpeg = execFileSync('python3', ['-c', 'import imageio_ffmpeg;print(imageio_ffmpeg.get_ffmpeg_exe())'], { encoding: 'utf8' }).trim()
const tmp = '.cache/video'
rmSync(tmp, { recursive: true, force: true }); mkdirSync(tmp, { recursive: true })

const server = await preview({ preview: { port: 4331, host: '127.0.0.1', strictPort: true } })
const browser = await chromium.launch()
const ctx = await browser.newContext({ viewport: { width: 1280, height: 720 }, recordVideo: { dir: tmp, size: { width: 1280, height: 720 } } })
const p = await ctx.newPage()

async function caption(page: Page, text: string, ms: number) {
  await page.evaluate((t) => {
    let el = document.getElementById('cap')
    if (!el) {
      el = document.createElement('div'); el.id = 'cap'
      el.setAttribute('style', 'position:fixed;left:50%;bottom:28px;transform:translateX(-50%);max-width:1000px;background:rgba(25,31,40,.92);color:#fff;font:600 22px/1.4 -apple-system,Arial,sans-serif;padding:14px 22px;border-radius:14px;z-index:99;text-align:center')
      document.body.appendChild(el)
    }
    el.textContent = t
  }, text)
  await page.waitForTimeout(ms)
}
const scrollTo = (sel: string, offset = 40) => p.evaluate(([s, o]) => { const el = document.querySelector(s as string)!; window.scrollTo({ top: el.getBoundingClientRect().top + window.scrollY - (o as number), behavior: 'smooth' }) }, [sel, offset])

try {
  await p.goto('http://127.0.0.1:4331/'); await p.waitForSelector('.stat')
  await caption(p, 'Trifecta Gate — a guard for AI assistants used by town offices, clinics and schools.', 6000)
  await caption(p, 'An assistant that reads your files, reads strangers\' text and can send data out has the "lethal trifecta".', 7000)
  await scrollTo('#stats', 120)
  await caption(p, 'We planted 84 attacks per model in a fictional town clerk\'s office. With gpt-4o-mini, 9 leaked a secret. With the gate: 0.', 9000)
  await scrollTo('#check')
  await caption(p, 'Step 1 — before deployment: paste an agent\'s tool list and check it.', 5000)
  await p.click('[data-preset="town"]')
  await caption(p, 'This town assistant can read mail and files, fetch web pages, send email and post to chat.', 6000)
  await scrollTo('#result', 20)
  await caption(p, 'All three abilities are present. The checker names the smallest change that breaks the combination.', 8000)
  await p.evaluate(() => window.scrollBy({ top: 300, behavior: 'smooth' }))
  await caption(p, 'Every label shows its reason, and an admin can override labels in the library.', 6000)
  await p.click('[data-preset="safe"]'); await scrollTo('#result', 120)
  await caption(p, 'A read-only helper has only one of the three — no path to leak.', 6000)
  await scrollTo('#replay')
  await caption(p, 'Step 2 — at run time. A real recorded run: the user asks for a to-do list from a vendor bulletin and the plant notes.', 9000)
  await scrollTo('.inject', 80)
  await caption(p, 'The vendor document carries a planted instruction: send the SCADA password to an outside address.', 8000)
  await scrollTo('#runs', 40)
  await caption(p, 'Without the gate, the agent opens the attacker\'s link with the password in it — and still sends the normal email.', 9000)
  await caption(p, 'With the gate, that one call is blocked: the address came from the document, not from the user, and private data was in play.', 10000)
  await caption(p, 'The normal email to ops@maplefalls.gov still goes out. The user\'s task is not broken.', 7000)
  await scrollTo('#scan')
  await caption(p, 'We also scanned public MCP servers on GitHub with the same rules.', 6000)
  await p.evaluate(() => document.querySelectorAll('#scanBody details').forEach((d) => ((d as HTMLDetailsElement).open = true)))
  await caption(p, 'About one in four ships a tool that can send data out, and 21 servers have all three abilities on their own.', 8000)
  await scrollTo('#how')
  await caption(p, 'How it decides: no AI model inside the gate. It checks where a message is going and who chose that address.', 9000)
  await caption(p, 'Named by you: allowed. Named by a stranger while private data is in play: blocked, and the agent asks you.', 9000)
  await caption(p, 'The attacker can reword the request forever. They cannot make their address appear in your request.', 8000)
  await p.evaluate(() => window.scrollTo({ top: document.body.scrollHeight, behavior: 'smooth' }))
  await caption(p, 'Try it: ryugi62.github.io/trifecta-gate · Code and raw logs: github.com/Ryugi62/trifecta-gate', 8000)
} finally {
  await ctx.close(); await browser.close(); server.httpServer.close()
}
const webm = readdirSync(tmp).find((f) => f.endsWith('.webm'))!
execFileSync(ffmpeg, ['-y', '-loglevel', 'error', '-i', join(tmp, webm), '-c:v', 'libx264', '-pix_fmt', 'yuv420p', '-crf', '28', '-movflags', '+faststart', out])
rmSync(tmp, { recursive: true, force: true })
console.log('wrote', out)
