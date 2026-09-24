import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * AWS-P1-05: "Read-only CloudTrail events such as List* and Describe* are
 * included as changes" and "Temporary AWS session access-key identifiers
 * can appear in event summaries."
 *
 * Rule 12 forbids exposing temporary access-key IDs in UI, logs, events,
 * reports or telemetry — and a change feed is all four at once.
 */
const src = readFileSync(join(__dirname, 'cloudtrailEvents.ts'), 'utf8');
const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

describe('the change feed shows changes, not reads', () => {
  it('asks AWS for non-read events by default', () => {
    // Pushed down to LookupEvents rather than filtered afterwards: a page of
    // 50 reads filtered locally would display two rows and look empty.
    expect(code).toMatch(/AttributeKey: 'ReadOnly', AttributeValue: 'false'/);
  });

  it('only includes reads when the caller explicitly asks', () => {
    expect(code).toMatch(/includeReadOnly = url\.searchParams\.get\('includeReadOnly'\) === 'true'/);
  });

  it('falls back to filtering locally when AWS cannot take the filter', () => {
    // LookupEvents accepts exactly one attribute per call, so a caller
    // already filtering by EventName cannot also push down ReadOnly.
    expect(code).toMatch(/filteredLocally/);
    expect(code).toMatch(/events\.filter\(\(e\) => e\.readOnly !== true\)/);
  });

  it('keeps an event CloudTrail did not classify', () => {
    // `!== true`, not `=== false`. Dropping an event we cannot classify
    // would silently hide changes, which is the failure being fixed.
    expect(code).not.toMatch(/e\.readOnly === false/);
  });

  it('states which filter was applied, so the UI never guesses', () => {
    expect(code).toMatch(/appliedBy: includeReadOnly \? 'none' : filteredLocally \? 'server' : 'aws'/);
  });
});

describe('access-key identifiers are redacted from the feed', () => {
  it('matches both temporary and long-lived key ids', () => {
    expect(code).toMatch(/AKIA\|ASIA/);
  });

  it('redacts the two fields CloudTrail can put a key id into', () => {
    expect(code).toMatch(/username: redactKeyIds\(/);
    expect(code).toMatch(/userIdentityArn: redactKeyIds\(/);
  });

  it('redacts rather than blanks, so attribution survives', () => {
    // Blanking the actor would make the row look like a system event.
    expect(code).toMatch(/\[redacted access key\]/);
  });
});
