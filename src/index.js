// dsar-warden: assemble Data Subject Access Request exports from multiple sources into one
// structured, machine-readable bundle, and check the request and bundle. Zero dependencies. Louis Wright, MIT.
import { readFileSync, existsSync, statSync, mkdirSync, writeFileSync } from 'node:fs';
import { resolve, dirname, join, relative } from 'node:path';
import { createHash } from 'node:crypto';
import { buildReport, UsageError } from './core.js';

export * from './core.js';

export const RULES = {
  'dsar-manifest-error': { severity: 'high', title: 'Manifest is invalid or a source is misconfigured' },
  'dsar-source-missing': { severity: 'high', title: 'Source file does not exist' },
  'dsar-source-parse-error': { severity: 'high', title: 'Source file cannot be parsed' },
  'dsar-overdue': { severity: 'high', title: 'Response deadline has passed' },
  'dsar-no-subject': { severity: 'high', title: 'No subject identifiers were given' },
  'dsar-third-party-data': { severity: 'medium', title: 'Exported records contain personal data about other people (email/phone) that is not redacted' },
  'dsar-deadline-near': { severity: 'medium', title: 'Response is due within the warning window' },
  'dsar-identity-unverified': { severity: 'medium', title: 'Requester identity is not marked as verified' },
  'dsar-match-field-missing': { severity: 'medium', title: 'Source records never contain the configured match field' },
  'dsar-secret-field': { severity: 'low', title: 'Secret-looking field (password, token, hash) removed from the export; exclude it explicitly' },
  'dsar-metadata-missing': { severity: 'low', title: 'Source lacks Article 15 context: purpose, category, recipients or retention' },
  'dsar-no-records': { severity: 'info', title: 'Source holds no records for the subject' },
};

// ---- parsers -----------------------------------------------------------------------------------
export function parseCsv(text, delimiter = ',') {
  const rows = []; let row = []; let f = ''; let q = false; let i = 0;
  if (text.charCodeAt(0) === 0xfeff) i = 1;
  for (; i < text.length; i++) {
    const ch = text[i];
    if (q) { if (ch === '"') { if (text[i + 1] === '"') { f += '"'; i++; } else q = false; } else f += ch; }
    else if (ch === '"' && f === '') q = true;
    else if (ch === delimiter) { row.push(f); f = ''; }
    else if (ch === '\n' || ch === '\r') { if (ch === '\r' && text[i + 1] === '\n') i++; row.push(f); rows.push(row); row = []; f = ''; }
    else f += ch;
  }
  if (q) throw new Error('unterminated quoted field');
  if (f !== '' || row.length) { row.push(f); rows.push(row); }
  const data = rows.filter((r) => !(r.length === 1 && r[0] === ''));
  if (!data.length) return [];
  const head = data[0].map((h) => h.trim());
  return data.slice(1).map((r) => Object.fromEntries(head.map((h, j) => [h, r[j] ?? ''])));
}
function formatOf(src) { if (src.format) return String(src.format).toLowerCase(); const m = /\.(jsonl|ndjson|json|csv|tsv)$/i.exec(src.path || ''); return m ? m[1].toLowerCase() : 'json'; }
export function loadRecords(file, src = {}) {
  const text = readFileSync(file, 'utf8'); const fmt = formatOf({ ...src, path: file });
  if (fmt === 'csv' || fmt === 'tsv') return parseCsv(text, src.delimiter || (fmt === 'tsv' ? '\t' : ','));
  if (fmt === 'jsonl' || fmt === 'ndjson') return text.split(/\r?\n/).map((l, n) => { if (!l.trim()) return null; try { return JSON.parse(l); } catch (e) { throw new Error(`line ${n + 1}: ${e.message}`); } }).filter(Boolean);
  let v = JSON.parse(text);
  if (src.recordsPath) for (const k of String(src.recordsPath).split('.')) v = v?.[k];
  if (Array.isArray(v)) return v;
  if (v && typeof v === 'object') { const arrKey = Object.keys(v).find((k) => Array.isArray(v[k])); if (!src.recordsPath && arrKey) return v[arrKey]; return [v]; }
  throw new Error('expected an array of records');
}

// ---- matching & cleaning -----------------------------------------------------------------------
const norm = (k, v) => { let s = String(v ?? '').trim().toLowerCase(); if (/phone|mobile|tel/i.test(k)) s = s.replace(/[^\d+]/g, ''); return s; };
const getPath = (o, p) => String(p).split('.').reduce((a, k) => (a == null ? a : a[k]), o);
const SECRET = /(pass(word|wd)?|secret|token|api[_-]?key|hash|salt|otp|mfa|totp|private[_-]?key|session)$/i;
const EMAIL = /[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/gi;
const OWN = /^(e-?mail|email_?address|phone|mobile|tel(ephone)?|phone_?number)$/i;
const PHONE = /(?<![\w.])\+?\d[\d ()-]{8,}\d(?![\w.])/g;

export function matchesSubject(rec, match, subject) {
  for (const [idKey, fields] of Object.entries(match)) {
    const want = subject[idKey]; if (!want) continue;
    const wants = (Array.isArray(want) ? want : [want]).map((w) => norm(idKey, w));
    for (const f of Array.isArray(fields) ? fields : [fields]) { const v = getPath(rec, f); const vals = Array.isArray(v) ? v : [v]; if (vals.some((x) => x != null && wants.includes(norm(idKey, x)))) return true; }
  }
  return false;
}
function clean(rec, { include, exclude, redact }, removed) {
  let out = include?.length ? Object.fromEntries(include.map((k) => [k, getPath(rec, k)]).filter(([, v]) => v !== undefined)) : structuredClone(rec);
  const walk = (o, path = '') => { if (!o || typeof o !== 'object') return; for (const k of Object.keys(o)) { const p = path ? `${path}.${k}` : k; if (exclude.has(p) || exclude.has(k)) { delete o[k]; continue; } if (SECRET.test(k) && !(redact.has(p) || redact.has(k))) { removed.add(p.replace(/\.\d+(?=\.|$)/g, '[]')); delete o[k]; continue; } if (redact.has(p) || redact.has(k)) { o[k] = '[REDACTED]'; continue; } walk(o[k], p); } };
  walk(out); return out;
}
function thirdParty(rec, subjectValues) {
  const hits = new Set(); const walk = (o, p) => {
    if (o == null) return; if (typeof o === 'string') { for (const m of o.match(EMAIL) || []) if (!subjectValues.has(m.toLowerCase())) hits.add(`${p}: email`); for (const m of o.match(PHONE) || []) if (!subjectValues.has(m.replace(/[^\d+]/g, ''))) hits.add(`${p}: phone`); return; }
    if (typeof o === 'object') for (const [k, v] of Object.entries(o)) walk(v, p ? (Array.isArray(o) ? `${p}[]` : `${p}.${k}`) : k);
  }; walk(rec, ''); return hits;
}

// ---- build ----------------------------------------------------------------------------------
const ADD_DAYS = (d, n) => new Date(d.getTime() + n * 864e5);
export function dueDate(received, { days, months = 1, extended = false } = {}) {
  const r = new Date(received); if (Number.isNaN(r.getTime())) return null;
  if (days) return ADD_DAYS(r, Number(days) + (extended ? 60 : 0));
  const d = new Date(Date.UTC(r.getUTCFullYear(), r.getUTCMonth() + months + (extended ? 2 : 0), r.getUTCDate()));
  if (d.getUTCDate() !== r.getUTCDate()) d.setUTCDate(0); // e.g. 31 Jan -> 28/29 Feb
  return d;
}
const sha = (s) => createHash('sha256').update(s).digest('hex');

/**
 * Assemble a bundle. manifest: { request: { id, subject: { email, ... }, received, verified, extended },
 * sources: [{ id, name, path, format, match: { email: "email" | ["email","contact.email"] }, include, exclude, redact, purpose, category, recipients, retention }] }
 */
export function assemble(manifest, { baseDir = '.', subject: cliSubject = {}, now = new Date(), warnDays = 7 } = {}) {
  const raw = []; const add = (rule, subject, message, fix, file) => raw.push({ rule, severity: RULES[rule].severity, subject, message, fix, file });
  const req = manifest?.request || {}; const subject = { ...(req.subject || {}), ...cliSubject };
  for (const k of Object.keys(subject)) if (subject[k] == null || subject[k] === '') delete subject[k];
  if (!Object.keys(subject).length) add('dsar-no-subject', 'request', 'No subject identifiers (request.subject or --subject key=value)', 'Give at least one identifier, e.g. --subject email=jane@example.com.');
  const subjectValues = new Set(Object.entries(subject).flatMap(([k, v]) => (Array.isArray(v) ? v : [v]).map((x) => norm(k, x))));
  if (req.verified !== true) add('dsar-identity-unverified', 'request', 'Requester identity is not marked verified', 'Verify identity proportionately, then set request.verified: true (and verifiedBy/verifiedAt).');
  let due = null;
  if (req.received) {
    due = dueDate(req.received, { days: req.deadlineDays ?? manifest.deadlineDays, extended: req.extended === true });
    if (!due) add('dsar-manifest-error', 'request.received', `Invalid received date "${req.received}"`, 'Use YYYY-MM-DD.');
    else if (!req.completed) { const left = (due - now) / 864e5; if (left < 0) add('dsar-overdue', 'deadline', `Response was due ${due.toISOString().slice(0, 10)} (${Math.ceil(-left)} day(s) ago)`, 'Respond now and record the delay reason; extensions must be notified within the first month.'); else if (left <= warnDays) add('dsar-deadline-near', 'deadline', `Response due ${due.toISOString().slice(0, 10)} (${Math.floor(left)} day(s) left)`, 'Prioritise this request.'); }
  }
  const sources = Array.isArray(manifest?.sources) ? manifest.sources : [];
  if (!sources.length) add('dsar-manifest-error', 'sources', 'Manifest has no sources', 'Add sources: [{ id, path, match }].');
  const out = []; const ids = new Set(); const pending = [];
  sources.forEach((s, i) => {
    const id = String(s?.id || s?.name || `source-${i + 1}`); const file = s?.path ? resolve(baseDir, s.path) : null; const relf = file ? relative(process.cwd(), file) || file : undefined;
    if (ids.has(id)) add('dsar-manifest-error', id, `Duplicate source id "${id}"`, 'Give each source a unique id.'); ids.add(id);
    if (!file) { add('dsar-manifest-error', id, `Source "${id}" has no path`, 'Set path to an export file (json, jsonl, csv, tsv).'); return; }
    const match = typeof s.match === 'string' ? { [Object.keys(subject)[0] || 'email']: s.match } : s.match || Object.fromEntries(Object.keys(subject).map((k) => [k, k]));
    const meta = { id, name: s.name || id, category: s.category, purpose: s.purpose, recipients: s.recipients, retention: s.retention, source: s.system || s.path };
    const missingMeta = ['purpose', 'category', 'recipients', 'retention'].filter((k) => s[k] == null);
    if (missingMeta.length) add('dsar-metadata-missing', id, `Source "${id}" has no ${missingMeta.join(', ')}`, 'Article 15 requires purposes, categories, recipients and retention for each processing activity.', relf);
    if (!existsSync(file) || !statSync(file).isFile()) { add('dsar-source-missing', id, `Source "${id}": ${relf} not found`, 'Export the system first or fix the path.', relf); out.push({ ...meta, status: 'missing', count: 0, records: [] }); return; }
    let recs; try { recs = loadRecords(file, s); } catch (e) { add('dsar-source-parse-error', id, `Source "${id}": ${e.message}`, 'Check the export format.', relf); out.push({ ...meta, status: 'error', count: 0, records: [] }); return; }
    const fieldsSeen = Object.values(match).flat().some((f) => recs.some((r) => getPath(r, f) !== undefined));
    if (recs.length && !fieldsSeen) add('dsar-match-field-missing', id, `Source "${id}": no record has match field(s) ${Object.values(match).flat().join(', ')}`, 'Fix "match" so it names the column/field holding the identifier.', relf);
    const removed = new Set(); const opts = { include: s.include, exclude: new Set(s.exclude || []), redact: new Set(s.redact || []) };
    const mine = recs.filter((r) => r && typeof r === 'object' && matchesSubject(r, match, subject)).map((r) => clean(r, opts, removed));
    if (removed.size) add('dsar-secret-field', id, `Source "${id}": removed ${[...removed].join(', ')}`, 'List these under "exclude" so the export is deliberate.', relf);
    for (const r of mine) for (const [k, v] of Object.entries(r)) if (OWN.test(k) && typeof v === 'string' && v !== '[REDACTED]') { subjectValues.add(norm(k, v)); subjectValues.add(v.toLowerCase()); }
    pending.push({ id, relf, mine, reviewed: s.thirdPartyReviewed === true });
    if (!mine.length) add('dsar-no-records', id, `Source "${id}" holds no records for the subject`, 'Confirm the match fields; "no data" is still part of the response.', relf);
    out.push({ ...meta, status: 'ok', count: mine.length, records: mine });
  });
  // second pass: a subject's own email/phone fields (in any source) are not third-party data
  for (const p of pending) {
    const tp = new Set(); for (const r of p.mine) for (const h of thirdParty(r, subjectValues)) tp.add(h);
    if (tp.size && !p.reviewed) add('dsar-third-party-data', p.id, `Source "${p.id}": other people's data in ${[...tp].slice(0, 5).join('; ')}${tp.size > 5 ? ` (+${tp.size - 5})` : ''}`, 'Redact these fields ("redact"), or review and set thirdPartyReviewed: true.', p.relf);
  }
  const bundle = {
    schema: 'https://github.com/MrLouisWright/dsar-warden/bundle/v1', generatedAt: now.toISOString(), generator: 'dsar-warden',
    request: { id: req.id, received: req.received, due: due ? due.toISOString().slice(0, 10) : undefined, extended: req.extended === true || undefined, verified: req.verified === true, subject: Object.keys(subject) },
    summary: { sources: out.length, withRecords: out.filter((s) => s.count).length, records: out.reduce((a, s) => a + s.count, 0) },
    sources: out,
  };
  return { bundle, raw };
}

/** Write bundle.json, one JSON file per source, a SHA-256 manifest and a human summary into outDir. */
export function writeBundle(bundle, outDir) {
  mkdirSync(join(outDir, 'sources'), { recursive: true });
  const files = {};
  const put = (name, text) => { writeFileSync(join(outDir, name), text); files[name] = sha(text); };
  for (const s of bundle.sources) put(`sources/${s.id.replace(/[^\w.-]+/g, '_')}.json`, JSON.stringify(s, null, 2) + '\n');
  put('bundle.json', JSON.stringify(bundle, null, 2) + '\n');
  const lines = [`Data Subject Access Request${bundle.request.id ? ` ${bundle.request.id}` : ''}`, `Generated: ${bundle.generatedAt}`, bundle.request.due ? `Due: ${bundle.request.due}` : null, '', `${bundle.summary.records} record(s) from ${bundle.summary.withRecords} of ${bundle.summary.sources} source(s):`, '',
    ...bundle.sources.map((s) => `- ${s.name}: ${s.count} record(s)${s.status !== 'ok' ? ` [${s.status}]` : ''}${s.purpose ? `; purpose: ${s.purpose}` : ''}${s.retention ? `; retention: ${s.retention}` : ''}${[].concat(s.recipients ?? []).length ? `; recipients: ${[].concat(s.recipients).join(', ')}` : ''}`), ''].filter((l) => l !== null);
  put('SUMMARY.txt', lines.join('\n'));
  writeFileSync(join(outDir, 'SHA256SUMS'), Object.entries(files).map(([f, h]) => `${h}  ${f}`).join('\n') + '\n');
  return Object.keys(files).concat('SHA256SUMS');
}

export const DEFAULT_FILES = ['dsar.json', 'dsar-manifest.json', '.dsar.json'];
export function parseSubject(list = []) {
  const s = {}; for (const kv of list) { const m = /^([\w.-]+)=(.+)$/.exec(kv); if (!m) throw new UsageError(`--subject must be key=value, got "${kv}"`); s[m[1]] = s[m[1]] ? [].concat(s[m[1]], m[2]) : m[2]; } return s;
}
export function check(target, opts = {}, config = {}, configFile) {
  const tool = { name: 'dsar-warden', version: opts.toolVersion || '1.0.0', rules: RULES, emoji: '📦', defaultFile: 'dsar.json' };
  let file = target ? resolve(target) : null;
  if (!file || (existsSync(file) && statSync(file).isDirectory())) { const dir = file || process.cwd(); file = DEFAULT_FILES.map((n) => resolve(dir, n)).find((p) => existsSync(p)); if (!file) throw new UsageError(`No manifest found (looked for ${DEFAULT_FILES.join(', ')})`); }
  if (!existsSync(file)) throw new UsageError(`No such file: ${file}`);
  const rel = relative(process.cwd(), file) || file;
  let manifest; try { manifest = JSON.parse(readFileSync(file, 'utf8')); } catch (e) { return buildReport(tool, rel, [{ rule: 'dsar-manifest-error', severity: 'high', file: rel, subject: 'manifest', message: `Invalid JSON: ${e.message}`, fix: 'Fix the manifest.' }], config, { now: opts.now, configFile }); }
  const { bundle, raw } = assemble(manifest, { baseDir: dirname(file), subject: opts.subject, now: opts.now, warnDays: opts.warnDays ?? config.warnDays });
  for (const f of raw) f.file ??= rel;
  let written;
  if (opts.out) written = writeBundle(bundle, resolve(opts.out));
  return buildReport(tool, rel, raw, config, { now: opts.now, configFile, summaryLine: `${bundle.summary.records} record(s) from ${bundle.summary.withRecords}/${bundle.summary.sources} source(s)${bundle.request.due ? `, due ${bundle.request.due}` : ''}${opts.out ? `, bundle written to ${relative(process.cwd(), resolve(opts.out)) || '.'}` : ''}`, info: { manifest: rel, out: opts.out, files: written, summary: bundle.summary, due: bundle.request.due }, bundle: opts.includeBundle ? bundle : undefined });
}
