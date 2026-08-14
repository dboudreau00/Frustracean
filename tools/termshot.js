#!/usr/bin/env node
//
// Render captured terminal output as an SVG "screenshot".
//
// The README needs pictures of the tool working, and a picture of a terminal
// has an obvious failure mode: it goes stale, and nobody notices because a PNG
// cannot be diffed. So the screenshots are generated from real captured output
// by `tools/screenshots.ps1`, which runs the commands and pipes them through
// here. Regenerating them is one command, and a stale one shows up in `git diff`
// as changed text.
//
// The colouring follows the project's own console conventions - status is
// carried by words (`OK:`, `ERROR:`, `WARNING:`, `INFO:`), so those are what get
// highlighted. Colour is decoration here, never the only signal, exactly as in
// the terminal.
//
// Usage: node tools/termshot.js <input.txt> <output.svg> "<command line>"

'use strict';

const fs = require('fs');

const THEME = {
  bg: '#14181F',
  chrome: '#1C222C',
  border: '#2A313D',
  text: '#C7D0DC',
  dim: '#6B7787',
  label: '#8FA0B4',
  value: '#E6EDF5',
  accent: '#F2622B',
  ok: '#5BC98C',
  warn: '#E3B341',
  error: '#F2666B',
  info: '#5FA8D3',
  heading: '#FFB088',
  prompt: '#4FB3A7',
};

const FONT =
  "ui-monospace, 'Cascadia Mono', 'SF Mono', Menlo, Consolas, 'DejaVu Sans Mono', monospace";
const FONT_SIZE = 14;
const CHAR_W = 8.4; // Advance width of the stack above at 14px.
const LINE_H = 21;
const PAD_X = 18;
const PAD_TOP = 44; // Room for the title bar.
const PAD_BOTTOM = 16;
const MAX_COLS = 118;

function esc(s) {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');
}

/// Split one line into coloured spans, following the console conventions.
function spans(line) {
  if (line.trim() === '') return [];

  const status = [
    ['OK:', THEME.ok],
    ['ERROR:', THEME.error],
    ['WARNING:', THEME.warn],
    ['INFO:', THEME.info],
  ];
  for (const [prefix, colour] of status) {
    if (line.startsWith(prefix)) {
      return [
        { text: prefix, fill: colour, bold: true },
        { text: line.slice(prefix.length), fill: THEME.text },
      ];
    }
  }

  // Indented continuation lines are supporting detail.
  if (/^\s\s+\S/.test(line)) {
    return [{ text: line, fill: THEME.dim }];
  }

  // `Name: value` is the tool's primary output shape.
  const labelled = line.match(/^([A-Za-z][A-Za-z0-9 _().\/-]*?):\s(.*)$/);
  if (labelled) {
    return [
      { text: labelled[1] + ':', fill: THEME.label },
      { text: ' ' + labelled[2], fill: THEME.value },
    ];
  }

  // A bare line with no colon and no indent is a section heading.
  if (/^[A-Za-z][A-Za-z0-9 ,'()-]*$/.test(line)) {
    return [{ text: line, fill: THEME.heading, bold: true }];
  }

  return [{ text: line, fill: THEME.text }];
}

function main() {
  const [input, output, command] = process.argv.slice(2);
  if (!input || !output) {
    console.error('usage: node tools/termshot.js <input.txt> <output.svg> "<command>"');
    process.exit(1);
  }

  const raw = fs.readFileSync(input, 'utf8').replace(/\r/g, '');
  let lines = raw.split('\n');
  while (lines.length && lines[lines.length - 1].trim() === '') lines.pop();

  // Long lines are wrapped rather than clipped, so nothing is silently lost.
  const wrapped = [];
  for (const line of lines) {
    if (line.length <= MAX_COLS) {
      wrapped.push(line);
      continue;
    }
    let rest = line;
    let first = true;
    while (rest.length > MAX_COLS) {
      let cut = rest.lastIndexOf(' ', MAX_COLS);
      if (cut < MAX_COLS * 0.5) cut = MAX_COLS;
      wrapped.push(rest.slice(0, cut));
      rest = (first ? '    ' : '    ') + rest.slice(cut).trimStart();
      first = false;
    }
    if (rest.trim()) wrapped.push(rest);
  }

  const body = command ? ['$ ' + command, ''].concat(wrapped) : wrapped;
  const cols = Math.max(48, ...body.map((l) => l.length));
  const width = Math.ceil(PAD_X * 2 + cols * CHAR_W);
  const height = Math.ceil(PAD_TOP + body.length * LINE_H + PAD_BOTTOM);

  const out = [];
  out.push(
    `<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 ${width} ${height}" ` +
      `width="${width}" height="${height}" role="img" aria-label="Terminal output: ${esc(
        command || input
      )}">`
  );
  out.push(`<rect x="0" y="0" width="${width}" height="${height}" rx="10" fill="${THEME.bg}"/>`);
  out.push(
    `<path d="M0 10 a10 10 0 0 1 10 -10 h${width - 20} a10 10 0 0 1 10 10 v22 h-${width} z" fill="${
      THEME.chrome
    }"/>`
  );
  out.push(
    `<rect x="0.5" y="0.5" width="${width - 1}" height="${
      height - 1
    }" rx="9.5" fill="none" stroke="${THEME.border}"/>`
  );
  // Window buttons.
  out.push(`<circle cx="18" cy="16" r="5" fill="#F2666B"/>`);
  out.push(`<circle cx="36" cy="16" r="5" fill="#E3B341"/>`);
  out.push(`<circle cx="54" cy="16" r="5" fill="#5BC98C"/>`);
  out.push(
    `<text x="${width / 2}" y="21" font-family="${FONT}" font-size="12" fill="${
      THEME.dim
    }" text-anchor="middle">frustracean</text>`
  );

  out.push(`<g font-family="${FONT}" font-size="${FONT_SIZE}" xml:space="preserve">`);
  body.forEach((line, i) => {
    const y = PAD_TOP + i * LINE_H + FONT_SIZE;
    if (command && i === 0) {
      out.push(
        `<text x="${PAD_X}" y="${y}"><tspan fill="${THEME.prompt}" font-weight="600">$</tspan>` +
          `<tspan fill="${THEME.value}">${esc(line.slice(1))}</tspan></text>`
      );
      return;
    }
    const parts = spans(line);
    if (parts.length === 0) return;
    const tspans = parts
      .map(
        (p) =>
          `<tspan fill="${p.fill}"${p.bold ? ' font-weight="600"' : ''}>${esc(p.text)}</tspan>`
      )
      .join('');
    out.push(`<text x="${PAD_X}" y="${y}">${tspans}</text>`);
  });
  out.push('</g>');
  out.push('</svg>');

  fs.writeFileSync(output, out.join('\n') + '\n');
  console.log(`wrote ${output} (${width}x${height}, ${body.length} lines)`);
}

main();
