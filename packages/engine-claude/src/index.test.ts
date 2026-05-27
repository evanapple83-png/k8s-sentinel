import { describe, expect, it } from 'vitest';
import { extractJson } from './index.js';

describe('extractJson', () => {
  it('parses a fenced ```json block', () => {
    const out = extractJson('Here you go:\n```json\n{"a":1,"b":[2,3]}\n```\nthanks');
    expect(out).toEqual({ a: 1, b: [2, 3] });
  });

  it('parses bare JSON embedded in prose', () => {
    const out = extractJson('result: [{"id":"x"}] done');
    expect(out).toEqual([{ id: 'x' }]);
  });

  it('returns undefined when there is no JSON', () => {
    expect(extractJson('no json here')).toBeUndefined();
    expect(extractJson('')).toBeUndefined();
  });
});
