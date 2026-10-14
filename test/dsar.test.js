import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, writeFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { check, assemble, parseCsv, dueDate, matchesSubject, parseSubject, runCli, RULES } from '../src/index.js';

const now = new Date('2026-10-14T00:00:00Z');
const ids = (r) => r.findings.map((f) => f.rule);
const tmp = () => mkdtempSync(join(tmpdir(), 'dsar-'));
const io = () => { const o = { s: '', e: '' }; return { o, io: { stdout: { write: (x) => { o.s += x; } }, stderr: { write: (x) => { o.e += x; } } } }; };
const meta = { purpose: 'p', category: 'c', recipients: [], retention: '1y' };
const req = { subject: { email: 'jane@acme.io' }, verified: true, completed: true };

test('parseCsv handles quotes, CRLF, BOM and embedded newlines', () => {
  assert.deepEqual(parseCsv('\ufeffa,b\r\n"x,1","he said ""hi""\nok"\r\n'), [{ a: 'x,1', b: 'he said "hi"\nok' }]);
  assert.deepEqual(parseCsv('a\tb\n1\t2', '\t'), [{ a: '1', b: '2' }]);
  assert.throws(() => parseCsv('a\n"x'));
});
test('dueDate: one calendar month, month-end clamp, extension, days', () => {
  assert.equal(dueDate('2026-09-20').toISOString().slice(0, 10), '2026-10-20');
  assert.equal(dueDate('2026-01-31').toISOString().slice(0, 10), '2026-02-28');
  assert.equal(dueDate('2026-01-10', { extended: true }).toISOString().slice(0, 10), '2026-04-10');
  assert.equal(dueDate('2026-01-01', { days: 45 }).toISOString().slice(0, 10), '2026-02-15');
  assert.equal(dueDate('nope'), null);
});
test('matching is case-insensitive, nested, multi-field and phone-normalised', () => {
  assert.ok(matchesSubject({ c: { e: 'JANE@acme.io' } }, { email: 'c.e' }, { email: 'jane@acme.io' }));
  assert.ok(matchesSubject({ cc: ['x@y.z', 'jane@acme.io'] }, { email: ['to', 'cc'] }, { email: 'jane@acme.io' }));
  assert.ok(matchesSubject({ tel: '+44 (20) 7946-0000' }, { phone: 'tel' }, { phone: '+442079460000' }));
  assert.ok(!matchesSubject({ e: 'bob@acme.io' }, { email: 'e' }, { email: 'jane@acme.io' }));
});
test('parseSubject', () => { assert.deepEqual(parseSubject(['email=a@b.c', 'email=d@e.f', 'id=1']), { email: ['a@b.c', 'd@e.f'], id: '1' }); assert.throws(() => parseSubject(['bad'])); });
test('good fixture is clean and writes a checksummed bundle', () => {
  const out = tmp(); const r = check('test/fixtures/good', { now, out });
  assert.deepEqual(ids(r), []); assert.equal(r.info.summary.records, 4);
  const b = JSON.parse(readFileSync(join(out, 'bundle.json'), 'utf8'));
  assert.equal(b.request.due, '2026-10-20'); assert.deepEqual(b.sources.map((s) => s.count), [1, 2, 1]);
  const crm = b.sources[0].records[0]; assert.equal(crm.password_hash, undefined); assert.equal(crm.Name, 'Jane Doe');
  assert.equal(b.sources[2].records[0].agent_email, '[REDACTED]');
  for (const line of readFileSync(join(out, 'SHA256SUMS'), 'utf8').trim().split('\n')) { const [h, f] = line.split('  '); assert.equal(createHash('sha256').update(readFileSync(join(out, f))).digest('hex'), h); }
  assert.ok(existsSync(join(out, 'SUMMARY.txt')));
  assert.ok(!JSON.stringify(b).includes('bob@acme.io'));
});
test('bad fixture finds the expected problems', () => {
  const s = new Set(ids(check('test/fixtures/bad/dsar.json', { now })));
  for (const k of ['dsar-source-parse-error', 'dsar-overdue', 'dsar-manifest-error', 'dsar-source-missing', 'dsar-match-field-missing', 'dsar-identity-unverified', 'dsar-third-party-data', 'dsar-metadata-missing', 'dsar-secret-field', 'dsar-no-records']) assert.ok(s.has(k), k);
});
test('deadline near and CLI subject override', () => {
  const d = tmp(); writeFileSync(join(d, 'a.json'), JSON.stringify([{ email: 'x@y.io' }]));
  writeFileSync(join(d, 'dsar.json'), JSON.stringify({ request: { received: '2026-09-17', verified: true }, sources: [{ id: 'a', path: 'a.json', ...meta }] }));
  const r = check(d, { now, subject: { email: 'x@y.io' } }); assert.deepEqual(ids(r), ['dsar-deadline-near']); assert.equal(r.info.summary.records, 1);
  assert.ok(ids(check(d, { now })).includes('dsar-no-subject'));
});
test('include whitelists fields; secrets removed even if nested', () => {
  const { bundle, raw } = assemble({ request: req, sources: [{ id: 'a', path: 'a.json', ...meta, match: { email: 'email' } }] }, { baseDir: (() => { const d = tmp(); writeFileSync(join(d, 'a.json'), JSON.stringify([{ email: 'jane@acme.io', auth: { session: 's', otp: 1 }, n: 1 }])); return d; })(), now });
  assert.deepEqual(bundle.sources[0].records[0], { email: 'jane@acme.io', auth: {}, n: 1 }); assert.deepEqual(raw.map((f) => f.rule), ['dsar-secret-field']);
  const d = tmp(); writeFileSync(join(d, 'a.json'), JSON.stringify([{ email: 'jane@acme.io', n: 1, x: 2 }]));
  assert.deepEqual(assemble({ request: req, sources: [{ id: 'a', path: 'a.json', ...meta, include: ['email', 'n'] }] }, { baseDir: d, now }).bundle.sources[0].records[0], { email: 'jane@acme.io', n: 1 });
});
test('third-party data can be marked reviewed', () => {
  const d = tmp(); writeFileSync(join(d, 'm.jsonl'), '{"from":"jane@acme.io","to":"bob@x.org"}\n');
  const m = (rev) => ({ request: req, sources: [{ id: 'm', path: 'm.jsonl', match: { email: 'from' }, ...meta, thirdPartyReviewed: rev }] });
  assert.deepEqual(assemble(m(false), { baseDir: d, now }).raw.map((f) => f.rule), ['dsar-third-party-data']);
  assert.deepEqual(assemble(m(true), { baseDir: d, now }).raw, []);
});
test('invalid manifest JSON and empty sources', () => {
  const d = tmp(); writeFileSync(join(d, 'dsar.json'), '{'); assert.deepEqual(ids(check(d, { now })), ['dsar-manifest-error']);
  assert.ok(assemble({ request: req }, { now }).raw.some((f) => f.rule === 'dsar-manifest-error'));
});
test('CLI exit codes and SARIF', async () => {
  const cli = { name: 'dsar-warden', version: '1.0.0', configKey: 'dsarWarden', rules: RULES, tagline: 't', usage: 'u', help: '', options: { out: { type: 'string' } }, dirFrom: () => '.', run: async ({ positionals, values }) => check(positionals[0], { now, out: values.out }) };
  let t = io(); assert.equal(await runCli(cli, ['test/fixtures/good', '--fail-on', 'low'], t.io), 0);
  t = io(); assert.equal(await runCli(cli, ['test/fixtures/bad', '-f', 'sarif'], t.io), 1); assert.equal(JSON.parse(t.o.s).version, '2.1.0');
  t = io(); assert.equal(await runCli(cli, ['test/fixtures/none'], t.io), 2);
  t = io(); assert.equal(await runCli(cli, ['test/fixtures/bad', '--fail-on', 'none', '-f', 'json'], t.io), 0); assert.ok(JSON.parse(t.o.s).findings.length > 5);
});
