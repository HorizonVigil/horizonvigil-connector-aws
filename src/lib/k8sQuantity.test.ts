import { describe, it, expect } from 'vitest';
import { parseCpuMillicores, parseMemoryBytes } from './k8sQuantity';

describe('parseCpuMillicores', () => {
  it('parses a millicore-suffixed value', () => {
    expect(parseCpuMillicores('500m')).toBe(500);
    expect(parseCpuMillicores('250m')).toBe(250);
    expect(parseCpuMillicores('1m')).toBe(1);
  });
  it('parses a bare core count as millicores', () => {
    expect(parseCpuMillicores('1')).toBe(1000);
    expect(parseCpuMillicores('0.5')).toBe(500);
    expect(parseCpuMillicores('2')).toBe(2000);
  });
  it('returns null for missing or malformed input, never 0', () => {
    expect(parseCpuMillicores(undefined)).toBeNull();
    expect(parseCpuMillicores(null)).toBeNull();
    expect(parseCpuMillicores('')).toBeNull();
    expect(parseCpuMillicores('not-a-number')).toBeNull();
    expect(parseCpuMillicores('-500m')).toBeNull();
  });
});

describe('parseMemoryBytes', () => {
  it('parses binary suffixes', () => {
    expect(parseMemoryBytes('512Mi')).toBe(512 * 1024 * 1024);
    expect(parseMemoryBytes('1Gi')).toBe(1024 ** 3);
    expect(parseMemoryBytes('1Ki')).toBe(1024);
  });
  it('parses decimal suffixes', () => {
    expect(parseMemoryBytes('1G')).toBe(1000 ** 3);
    expect(parseMemoryBytes('500M')).toBe(500 * 1000 * 1000);
    expect(parseMemoryBytes('2k')).toBe(2000);
  });
  it('parses a bare byte count', () => {
    expect(parseMemoryBytes('1000000')).toBe(1000000);
    expect(parseMemoryBytes('0')).toBe(0);
  });
  it('returns null for missing or malformed input, never 0', () => {
    expect(parseMemoryBytes(undefined)).toBeNull();
    expect(parseMemoryBytes(null)).toBeNull();
    expect(parseMemoryBytes('')).toBeNull();
    expect(parseMemoryBytes('garbage')).toBeNull();
    expect(parseMemoryBytes('-1Gi')).toBeNull();
  });
  it('prefers the longer binary suffix over a shadowing single-letter decimal suffix', () => {
    // "Ki" must not be parsed as "K" + stray "i" -- exercises the longest-suffix-first ordering.
    expect(parseMemoryBytes('4Ki')).toBe(4 * 1024);
  });
});
