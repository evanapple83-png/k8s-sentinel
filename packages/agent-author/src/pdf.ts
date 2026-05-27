import { SEVERITIES, type Severity } from '@k8s-sentinel/core';
import type { SecurityReport } from './report.js';

/**
 * Dependency-free PDF renderer.
 *
 * The product is self-hosted and runs air-gapped (BUILD.md §10), so we don't
 * pull a headless browser or a native PDF lib just to export a report. This
 * lays the report out as flowing text across US-Letter pages using the base-14
 * Helvetica fonts (no font embedding needed) and emits a valid PDF 1.4 file.
 */

const PAGE_W = 612;
const PAGE_H = 792;
const MARGIN = 56;
const TOP = PAGE_H - MARGIN;
const BOTTOM = MARGIN;
const CONTENT_W = PAGE_W - 2 * MARGIN;

type RGB = [number, number, number];
const BLACK: RGB = [0.11, 0.11, 0.12];
const MUTED: RGB = [0.43, 0.43, 0.45];
const ACCENT: RGB = [0.04, 0.52, 1];
const RED: RGB = [1, 0.23, 0.19];
const AMBER: RGB = [1, 0.62, 0.04];
const GREEN: RGB = [0.2, 0.78, 0.35];

interface LineOpts {
  size?: number;
  bold?: boolean;
  color?: RGB;
  indent?: number;
  /** Extra space added before the line. */
  before?: number;
}

class Pdf {
  readonly pages: string[][] = [[]];
  private page = 0;
  private y = TOP;

  private cur(): string[] {
    return this.pages[this.page]!;
  }

  private newPage(): void {
    this.pages.push([]);
    this.page++;
    this.y = TOP;
  }

  private ensure(h: number): void {
    if (this.y - h < BOTTOM) this.newPage();
  }

  spacer(h: number): void {
    this.y -= h;
    if (this.y < BOTTOM) this.newPage();
  }

  rule(): void {
    this.ensure(12);
    this.y -= 8;
    this.cur().push(`0.82 0.82 0.84 rg ${MARGIN} ${fmt(this.y)} ${CONTENT_W} 0.7 re f`);
    this.y -= 6;
  }

  line(text: string, opts: LineOpts = {}): void {
    const size = opts.size ?? 10.5;
    const lh = size * 1.42;
    if (opts.before) this.spacer(opts.before);
    this.ensure(lh);
    this.y -= lh;
    const c = opts.color ?? BLACK;
    const font = opts.bold ? 'F2' : 'F1';
    const x = MARGIN + (opts.indent ?? 0);
    this.cur().push(`${fmt(c[0])} ${fmt(c[1])} ${fmt(c[2])} rg`);
    this.cur().push(`BT /${font} ${size} Tf ${x} ${fmt(this.y)} Td (${escapePdf(text)}) Tj ET`);
  }

  paragraph(text: string, opts: LineOpts = {}): void {
    const size = opts.size ?? 10.5;
    const indent = opts.indent ?? 0;
    const lines = wrap(text, CONTENT_W - indent, size, Boolean(opts.bold));
    let first = true;
    for (const ln of lines) {
      this.line(ln, { ...opts, before: first ? opts.before : 0 });
      first = false;
    }
  }
}

function fmt(n: number): string {
  return (Math.round(n * 100) / 100).toString();
}

/** Coarse Helvetica advance — fine for wrapping body text. */
function approxWidth(text: string, size: number, bold: boolean): number {
  return text.length * size * (bold ? 0.56 : 0.51);
}

function wrap(text: string, width: number, size: number, bold: boolean): string[] {
  const words = text.split(/\s+/).filter(Boolean);
  const lines: string[] = [];
  let line = '';
  for (const w of words) {
    const candidate = line ? `${line} ${w}` : w;
    if (approxWidth(candidate, size, bold) > width && line) {
      lines.push(line);
      line = w;
    } else {
      line = candidate;
    }
  }
  if (line) lines.push(line);
  return lines.length ? lines : [''];
}

function escapePdf(s: string): string {
  return s
    .replace(/[\r\n]+/g, ' ')
    .replace(/[^\x20-\x7e]/g, '?') // base-14 WinAnsi: keep it ASCII-safe
    .replace(/\\/g, '\\\\')
    .replace(/\(/g, '\\(')
    .replace(/\)/g, '\\)');
}

function sevColor(sev: Severity): RGB {
  if (sev === 'critical') return RED;
  if (sev === 'high') return [1, 0.39, 0.28];
  if (sev === 'medium') return AMBER;
  return GREEN;
}

function ratingColor(rating: string): RGB {
  return rating === 'critical' ? RED : rating === 'low' ? GREEN : AMBER;
}

function layout(pdf: Pdf, r: SecurityReport): void {
  pdf.line('K8S SENTINEL', { size: 11, bold: true, color: ACCENT });
  pdf.line('Security Report', { size: 26, bold: true, before: 2 });
  pdf.line(
    `Run ${r.meta.runId}  ·  ${r.meta.generatedAt}  ·  engine ${r.meta.engine}` +
      (r.meta.usedFixtures ? '  ·  offline fixtures' : ''),
    { size: 9.5, color: MUTED, before: 4 },
  );
  pdf.rule();

  // Posture
  pdf.line('POSTURE', { size: 10, bold: true, color: MUTED, before: 8 });
  pdf.line(`${r.posture.riskScore}/100   ${r.posture.rating.toUpperCase()} RISK`, {
    size: 22,
    bold: true,
    color: ratingColor(r.posture.rating),
    before: 4,
  });
  pdf.paragraph(r.posture.summary, { before: 6 });
  const sev = SEVERITIES.filter((s) => r.posture.bySeverity[s])
    .map((s) => `${r.posture.bySeverity[s]} ${s}`)
    .join('   ');
  pdf.line(`Findings: ${r.posture.totalFindings}  (${r.posture.reachableFindings} reachable)`, {
    color: MUTED,
    before: 6,
  });
  if (sev) pdf.line(`By severity: ${sev}`, { color: MUTED });

  // Attack paths
  pdf.line(`ATTACK PATHS (${r.attackPaths.length})`, { size: 10, bold: true, color: MUTED, before: 18 });
  if (r.attackPaths.length === 0) {
    pdf.line('No correlated attack paths — nothing both reachable and exploitable.', { color: MUTED, before: 4 });
  }
  for (const p of r.attackPaths) {
    pdf.line(`${p.score}/100   from ${p.entryPoint}`, {
      bold: true,
      color: ratingColor(rateScore(p.score)),
      before: 10,
    });
    pdf.paragraph(p.narrative, { before: 3 });
    pdf.line(p.steps.map((s) => s.kind).join('  ->  '), { color: ACCENT, size: 9.5, before: 3 });
  }

  // Top findings
  pdf.line('TOP FINDINGS — BY EXPLOITABILITY', { size: 10, bold: true, color: MUTED, before: 18 });
  for (const f of r.topFindings) {
    const reach = f.reachable ? ' [reachable]' : '';
    pdf.paragraph(
      `${String(f.exploitScore).padStart(3)}  ${f.severity.toUpperCase()}  [${f.source}]${reach}  ${f.title} — ${f.resource}`,
      { size: 10, color: sevColor(f.severity), before: 5 },
    );
  }

  // Compliance
  if (r.compliance.length) {
    pdf.line('COMPLIANCE', { size: 10, bold: true, color: MUTED, before: 18 });
    for (const c of r.compliance) {
      pdf.paragraph(`${c.framework} — ${c.findingCount} finding(s): ${c.controls.join(', ')}`, {
        before: 4,
      });
    }
  }

  // Remediations
  pdf.line(`RECOMMENDED REMEDIATIONS (${r.remediations.length})`, {
    size: 10,
    bold: true,
    color: MUTED,
    before: 18,
  });
  if (r.remediations.length === 0) pdf.line('None proposed.', { color: MUTED, before: 4 });
  for (const m of r.remediations) {
    pdf.line(`${m.title}  ·  ${m.severity}`, { bold: true, before: 10 });
    pdf.line(`${m.kind} · ${m.path} · ${m.status}`, { size: 9, color: MUTED, before: 2 });
    pdf.paragraph(m.rationale, { before: 3 });
    if (m.controls.length) pdf.line(`Controls: ${m.controls.join(', ')}`, { size: 9, color: MUTED, before: 2 });
  }

  pdf.rule();
  pdf.line('Generated by K8s Sentinel · Author agent. Read-only by design; all fixes require human approval.', {
    size: 9,
    color: MUTED,
    before: 4,
  });
}

function rateScore(score: number): string {
  return score >= 70 ? 'critical' : score >= 40 ? 'elevated' : 'low';
}

export function renderPdf(report: SecurityReport): Uint8Array {
  const pdf = new Pdf();
  layout(pdf, report);
  const N = pdf.pages.length;

  // Object id layout: 1 Catalog, 2 Pages, 3 F1, 4 F2, then per page (page, content).
  const objects = new Map<number, string | Buffer>();
  const pageIds: number[] = [];
  for (let k = 0; k < N; k++) pageIds.push(5 + 2 * k);

  objects.set(1, `<< /Type /Catalog /Pages 2 0 R >>`);
  objects.set(
    2,
    `<< /Type /Pages /Kids [${pageIds.map((id) => `${id} 0 R`).join(' ')}] /Count ${N} >>`,
  );
  objects.set(3, `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>`);
  objects.set(4, `<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>`);

  for (let k = 0; k < N; k++) {
    const pageId = 5 + 2 * k;
    const contentId = 6 + 2 * k;
    objects.set(
      pageId,
      `<< /Type /Page /Parent 2 0 R /MediaBox [0 0 ${PAGE_W} ${PAGE_H}] ` +
        `/Resources << /Font << /F1 3 0 R /F2 4 0 R >> >> /Contents ${contentId} 0 R >>`,
    );
    const stream = pdf.pages[k]!.join('\n');
    const len = Buffer.byteLength(stream, 'latin1');
    objects.set(contentId, `<< /Length ${len} >>\nstream\n${stream}\nendstream`);
  }

  const maxId = 4 + 2 * N;
  const chunks: Buffer[] = [];
  const offsets: number[] = new Array(maxId + 1).fill(0);
  let pos = 0;
  const push = (s: string | Buffer): void => {
    const b = Buffer.isBuffer(s) ? s : Buffer.from(s, 'latin1');
    chunks.push(b);
    pos += b.length;
  };

  push('%PDF-1.4\n');
  push(Buffer.from([0x25, 0xe2, 0xe3, 0xcf, 0xd3, 0x0a])); // binary marker comment
  for (let id = 1; id <= maxId; id++) {
    offsets[id] = pos;
    push(`${id} 0 obj\n`);
    push(objects.get(id)!);
    push(`\nendobj\n`);
  }

  const xrefPos = pos;
  let xref = `xref\n0 ${maxId + 1}\n0000000000 65535 f \n`;
  for (let id = 1; id <= maxId; id++) {
    xref += `${String(offsets[id]).padStart(10, '0')} 00000 n \n`;
  }
  push(xref);
  push(`trailer\n<< /Size ${maxId + 1} /Root 1 0 R >>\nstartxref\n${xrefPos}\n%%EOF\n`);

  return Buffer.concat(chunks);
}
