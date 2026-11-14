const specs = {
  append: { type: 1, actor: 1, tool: 1, outcome: 1, data: 1, time: 1, 'key-file': 1 },
  verify: { anchor: 1, 'key-file': 1, 'require-keyed': 0, format: 1 },
  anchor: { out: 1, 'key-file': 1, force: 0 },
  show: { from: 1, to: 1, format: 1 },
  summary: { details: 0, format: 1 },
  export: { out: 1, format: 1, force: 0 },
};
const isOption = (token, spec) => {
  const m = /^--([^=]+)(?:=[\s\S]*)?$/.exec(token);
  return m !== null && Object.hasOwn(spec, m[1]);
};
export function parseArgs(argv) {
  if (argv.length === 1 && ['--help', '--version'].includes(argv[0])) return { command: argv[0].slice(2) };
  const [command, ...rest] = argv;
  if (!Object.hasOwn(specs, command)) throw new Error('usage');
  const spec = specs[command];
  const options = Object.create(null), positions = [];
  for (let i = 0; i < rest.length; i++) {
    const token = rest[i];
    if (!token.startsWith('--')) {
      positions.push(token);
      continue;
    }
    const match = /^--([^=]+)(?:=([\s\S]*))?$/.exec(token);
    if (!match || !Object.hasOwn(spec, match[1]) || Object.hasOwn(options, match[1])) throw new Error('usage');
    const [, key, inline] = match;
    if (!spec[key]) {
      if (inline !== undefined) throw new Error('usage');
      options[key] = true;
      continue;
    }
    const value = inline === undefined ? rest[++i] : inline;
    if (!value || value === '--' || (inline === undefined && isOption(value, spec))) throw new Error('usage');
    options[key] = value;
  }
  if (options['require-keyed'] && !options['key-file']) throw new Error('usage');
  if (positions.length !== 1 || positions[0].startsWith('-')) throw new Error('usage');
  for (
    const key of command === 'append'
      ? ['type']
      : command === 'anchor'
      ? ['out']
      : command === 'export'
      ? ['out', 'format']
      : []
  ) if (!options[key]) throw new Error('usage');
  if (
    options.format &&
    !(command === 'summary'
      ? ['terminal', 'json', 'markdown']
      : command === 'export'
      ? ['json', 'csv']
      : ['terminal', 'json']).includes(options.format)
  ) throw new Error('usage');
  for (const k of ['from', 'to']) {
    if (options[k] && (!/^[1-9][0-9]*$/.test(options[k]) || !Number.isSafeInteger(Number(options[k])))) {
      throw new Error('usage');
    }
  }
  if (options.from && options.to && (+options.from > +options.to || +options.to - +options.from >= 10000)) {
    throw new Error('usage');
  }
  return { command, log: positions[0], options };
}
