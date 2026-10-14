#!/usr/bin/env node
import { readFileSync } from 'node:fs';
import { mainCli, check, RULES, parseSubject } from '../src/index.js';

const pkg = JSON.parse(readFileSync(new URL('../package.json', import.meta.url), 'utf8'));
mainCli({
  name: 'dsar-warden', version: pkg.version, configKey: 'dsarWarden', rules: RULES,
  tagline: 'assemble and check Data Subject Access Request exports',
  usage: 'Usage: dsar-warden [dsar.json|dir] [--subject key=value ...] [--out dir] [options]',
  dirFrom: () => '.',
  help: `Request
  -s, --subject <k=v>      Subject identifier, repeatable (e.g. email=jane@acme.io, customer_id=C123)
  -o, --out <dir>          Write the bundle: bundle.json, sources/*.json, SUMMARY.txt, SHA256SUMS
      --warn-days <n>      Warn when the response is due within n days (default 7)
`,
  options: { subject: { type: 'string', short: 's', multiple: true }, out: { type: 'string', short: 'o' }, 'warn-days': { type: 'string' } },
  run: async ({ positionals, values: o, config, configFile }) => check(positionals[0], { subject: parseSubject(o.subject), out: o.out, warnDays: o['warn-days'] != null ? Number(o['warn-days']) : undefined, toolVersion: pkg.version }, config, configFile),
});
