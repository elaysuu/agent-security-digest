#!/usr/bin/env node
// Generates one weekly issue of "This Week in AI-Agent Security Advisories".
// Sources: AKRENON MCP dataset (CC BY 4.0, via agent-advisory-gate data file),
// GitHub Advisory Database (public REST API), every entry verified against OSV.
import fs from 'node:fs';
const DATA_URL = 'https://raw.githubusercontent.com/elaysuu/agent-advisory-gate/main/data/mcp-advisories.json';
const GATE = 'https://github.com/elaysuu/agent-advisory-gate';
const PRO = 'https://setrov.gumroad.com/l/zdojns';
const SPONSOR_FILE = new URL('../sponsor.json', import.meta.url);
const KW = /\b(mcp|model context protocol|langchain|llamaindex|llama-index|autogen|crewai|agent|agents|llm|openai|anthropic|ollama|litellm|vllm|n8n|flowise|langflow|dify)\b/i;

const KW_SUMMARY = /\b(mcp|model context protocol|langchain|llamaindex|crewai|autogen|llm|ai agents?)\b/i;
export function isAgentRelated(a) { return KW.test(a.package || '') || KW_SUMMARY.test(a.summary || ''); }
export function inWindow(iso, end, days = 7) { const t = Date.parse(iso); return t > end - days * 864e5 && t <= end; }
const esc = s => String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');

async function j(url, opt) { const r = await fetch(url, opt); if (!r.ok) throw new Error(`${r.status} ${url}`); return r.json(); }

async function ghsa(sinceISO) {
  const out = []; const h = { accept: 'application/vnd.github+json', 'user-agent': 'weekly-digest' };
  if (process.env.GITHUB_TOKEN) h.authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  for (const eco of ['npm', 'pip']) {
    let url = `https://api.github.com/advisories?type=reviewed&ecosystem=${eco}&published=>=${sinceISO.slice(0,10)}&per_page=100`;
    for (let p = 0; url && p < 5; p++) {
      const r = await fetch(url, { headers: h }); if (!r.ok) throw new Error(`GHSA ${r.status}`);
      for (const a of await r.json()) for (const v of a.vulnerabilities || []) out.push({
        id: a.ghsa_id, aliases: [a.ghsa_id, a.cve_id].filter(Boolean), ecosystem: eco === 'pip' ? 'PyPI' : 'npm',
        package: v.package?.name, severity: (a.severity || '').toUpperCase(), summary: a.summary,
        published: a.published_at, fixed: v.first_patched_version || null, source: 'GitHub Advisory Database' });
      const m = /<([^>]+)>;\s*rel="next"/.exec(r.headers.get('link') || ''); url = m && m[1];
    }
  }
  return out;
}

export async function osvVerify(id) {
  try { const v = await j(`https://api.osv.dev/v1/vulns/${id}`); return { ok: true, modified: v.modified, withdrawn: v.withdrawn || null }; }
  catch { return { ok: false }; }
}

export function render(items, { start, end, issue, sponsor }) {
  const d = x => new Date(x).toISOString().slice(0, 10);
  const sev = ['CRITICAL','HIGH','MODERATE','MEDIUM','LOW',''];
  items.sort((a, b) => sev.indexOf(a.severity) - sev.indexOf(b.severity) || a.package.localeCompare(b.package));
  const mcp = items.filter(i => /mcp|model context protocol/i.test(`${i.package} ${i.summary}`));
  let md = `# This Week in AI-Agent Security Advisories, #${issue}\n\n_${d(start)} to ${d(end)} (UTC)_\n\n`;
  md += `**${items.length}** advisory entries (package x advisory) this week affect AI-agent / LLM tooling packages on npm and PyPI, **${mcp.length}** of them MCP servers or MCP SDKs. Every ID below was looked up in OSV when this issue was generated.\n\n`;
  md += `## Sponsor\n\n${sponsor ? `**${sponsor.name}**: ${sponsor.text} ${sponsor.url}` : `_This slot is open. One sponsor per issue, $29/week: https://setrov.gumroad.com/l/digest-sponsor (Agent Security Digest Sponsor Slot)._`}\n\n`;
  md += `## Advisories\n\n| Severity | Package | Ecosystem | Advisory | Fixed in | Summary |\n|---|---|---|---|---|---|\n`;
  for (const i of items) md += `| ${i.severity || 'n/a'} | \`${i.package}\` | ${i.ecosystem} | [${i.id}](https://osv.dev/vulnerability/${i.id}) | ${i.fixed || 'no fix listed'} | ${i.summary.replace(/\|/g, '/')} |\n`;
  if (!items.length) md += `| | | | | | No matching advisories this week. |\n`;
  md += `\n## Block these in CI\n\n[agent-advisory-gate](${GATE}) is a free GitHub Action that fails a PR when your repo pulls in an MCP server with a known advisory. Pro (daily data, SARIF, fix hints): ${PRO}\n\n`;
  md += `## Sources and license\n\n- MCP advisory data: AKRENON Security, "MCP Security Vulnerabilities Dataset", https://data.akrenon.com/mcp-advisories/ , licensed CC BY 4.0 (https://creativecommons.org/licenses/by/4.0/). Filtered and reformatted.\n- GitHub Advisory Database (CC BY 4.0), https://github.com/advisories\n- Verification: OSV, https://osv.dev\n`;
  return md;
}

export function rss(items, { end, issue, link }) {
  return `<?xml version="1.0" encoding="UTF-8"?>\n<rss version="2.0"><channel><title>This Week in AI-Agent Security Advisories</title><link>${esc(link)}</link><description>Weekly MCP and AI-agent package advisories, verified against OSV.</description>\n<item><title>Issue #${issue}: ${items.length} advisories</title><link>${esc(link)}</link><guid isPermaLink="false">issue-${issue}</guid><pubDate>${new Date(end).toUTCString()}</pubDate><description>${esc(items.map(i => `${i.severity} ${i.package} ${i.id}`).join('; '))}</description></item>\n</channel></rss>\n`;
}

async function main() {
  const end = process.env.DIGEST_END ? Date.parse(process.env.DIGEST_END) : Date.now();
  const start = end - 7 * 864e5;
  const issue = Number(process.env.ISSUE || 1);
  const ak = (await j(DATA_URL)).advisories.filter(a => inWindow(a.published, end));
  const gh = (await ghsa(new Date(start).toISOString())).filter(a => a.package && inWindow(a.published, end) && isAgentRelated(a));
  const map = new Map();
  for (const a of [...ak, ...gh]) { const k = `${a.id}|${a.package}`; if (!map.has(k)) map.set(k, a); }
  const items = [];
  for (const a of map.values()) { const v = await osvVerify(a.id); if (v.ok && !v.withdrawn) items.push({ ...a, osv_modified: v.modified }); else console.error('dropped (not in OSV or withdrawn):', a.id); }
  const sponsor = fs.existsSync(SPONSOR_FILE) ? JSON.parse(fs.readFileSync(SPONSOR_FILE)) : null;
  fs.mkdirSync('issues', { recursive: true });
  const base = `issues/${String(issue).padStart(3, '0')}`;
  fs.writeFileSync(`${base}.md`, render(items, { start, end, issue, sponsor }));
  fs.writeFileSync(`${base}.json`, JSON.stringify({ issue, start: new Date(start).toISOString(), end: new Date(end).toISOString(), items }, null, 1));
  fs.writeFileSync('issues/feed.xml', rss(items, { end, issue, link: `https://github.com/elaysuu/agent-security-digest/blob/main/${base}.md` }));
  console.log(`issue ${issue}: ${items.length} verified (${ak.length} AKRENON-window, ${gh.length} GHSA agent-related)`);
}
if (import.meta.url === `file://${process.argv[1]}`) main().catch(e => { console.error(e); process.exit(1); });
