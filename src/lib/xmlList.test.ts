import { describe, it, expect } from 'vitest';
import { extractSection, extractListItems, field, boolField, numField, tagsFromSet } from './xmlList';

describe('extractSection', () => {
  it('returns the inner content of the named tag', () => {
    expect(extractSection('<a><b>x</b></a>', 'b')).toBe('x');
  });

  it('returns null when the tag is absent', () => {
    expect(extractSection('<a></a>', 'missing')).toBeNull();
  });

  it('returns an empty string for a present-but-empty tag', () => {
    expect(extractSection('<a><b></b></a>', 'b')).toBe('');
  });
});

describe('extractListItems', () => {
  it('returns an empty array for null input', () => {
    expect(extractListItems(null)).toEqual([]);
  });

  it('returns an empty array for empty input', () => {
    expect(extractListItems('')).toEqual([]);
  });

  it('splits sibling <item> blocks', () => {
    const xml = '<item>A</item><item>B</item><item>C</item>';
    expect(extractListItems(xml)).toEqual(['A', 'B', 'C']);
  });

  it('does not truncate an item whose own content nests the same tag name (depth tracking)', () => {
    // The exact shape the doc comment calls out: an EC2 instance item whose
    // own tagSet nests further <item> elements — a naive "first </item>"
    // regex would stop at the tagSet's inner closing tag, not the outer one.
    const xml =
      '<item><instanceId>i-1</instanceId><tagSet><item><key>Name</key><value>a</value></item></tagSet></item>' +
      '<item><instanceId>i-2</instanceId></item>';
    const items = extractListItems(xml);
    expect(items).toHaveLength(2);
    expect(items[0]).toContain('i-1');
    expect(items[0]).toContain('<tagSet>');
    expect(items[1]).toContain('i-2');
  });

  it('supports a custom repeated tag name (e.g. IAM\'s <member>)', () => {
    const xml = '<member>A</member><member>B</member>';
    expect(extractListItems(xml, 'member')).toEqual(['A', 'B']);
  });

  it('ignores tags with attributes on the opening tag', () => {
    const xml = '<item id="1">A</item><item id="2">B</item>';
    expect(extractListItems(xml)).toEqual(['A', 'B']);
  });
});

describe('field', () => {
  it('extracts direct text content', () => {
    expect(field('<a><name>Alice</name></a>', 'name')).toBe('Alice');
  });

  it('returns null when the tag is absent', () => {
    expect(field('<a></a>', 'name')).toBeNull();
  });

  it('decodes XML entities', () => {
    expect(field('<a>&lt;tag&gt; &amp; &quot;quoted&quot; &apos;s&apos;</a>', 'a')).toBe('<tag> & "quoted" \'s\'');
  });
});

describe('boolField', () => {
  it('is true only for the literal string "true"', () => {
    expect(boolField('<a><f>true</f></a>', 'f')).toBe(true);
  });

  it('is false for any other value, including "True" or "1"', () => {
    expect(boolField('<a><f>True</f></a>', 'f')).toBe(false);
    expect(boolField('<a><f>1</f></a>', 'f')).toBe(false);
    expect(boolField('<a><f>false</f></a>', 'f')).toBe(false);
  });

  it('is false when the tag is absent', () => {
    expect(boolField('<a></a>', 'f')).toBe(false);
  });
});

describe('numField', () => {
  it('parses a numeric field', () => {
    expect(numField('<a><n>42</n></a>', 'n')).toBe(42);
  });

  it('returns undefined when the tag is absent', () => {
    expect(numField('<a></a>', 'n')).toBeUndefined();
  });
});

describe('tagsFromSet', () => {
  it('builds a key/value map from a tagSet of key/value items', () => {
    const xml = '<tagSet><item><key>Name</key><value>web-1</value></item><item><key>Env</key><value>prod</value></item></tagSet>';
    expect(tagsFromSet(xml)).toEqual({ Name: 'web-1', Env: 'prod' });
  });

  it('returns an empty object when there is no tagSet', () => {
    expect(tagsFromSet('<a></a>')).toEqual({});
  });

  it('defaults a missing value to an empty string', () => {
    const xml = '<tagSet><item><key>Name</key></item></tagSet>';
    expect(tagsFromSet(xml)).toEqual({ Name: '' });
  });

  it('supports a custom set tag name', () => {
    const xml = '<Tags><item><key>Name</key><value>x</value></item></Tags>';
    expect(tagsFromSet(xml, 'Tags')).toEqual({ Name: 'x' });
  });
});
