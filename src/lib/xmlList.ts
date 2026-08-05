/**
 * Regex-based extraction for the repeated <item> structures AWS's
 * Query-protocol XML responses use everywhere (DescribeInstances,
 * DescribeVolumes, tag lists, ...). Deliberately not a DOM parser —
 * `@xmldom/xmldom` + `DOMParser` were tried in this project's earlier
 * (pre-2026-07-28) build and confirmed to add real bundle/CPU cost in
 * Workers (see docs/about-project.md and awsApi.ts's extractXmlField),
 * which is why every AWS call in this rebuild avoids it. Single flat
 * fields already had `extractXmlField`; this adds the other half — pulling
 * out a *list* of sibling elements, correctly handling one being nested
 * inside another (an EC2 instance item's own `tagSet` has its own `item`
 * children), which a naive "first `</item>`" regex would truncate on.
 */

/** Inner content of the first non-self-nesting `<tag>...</tag>` — safe for AWS's container tags (reservationSet, instancesSet, tagSet, ...), none of which recurse into themselves. */
export function extractSection(xml: string, tag: string): string | null {
  const openTag = `<${tag}>`;
  const closeTag = `</${tag}>`;
  const start = xml.indexOf(openTag);
  if (start === -1) return null;
  const contentStart = start + openTag.length;
  const end = xml.indexOf(closeTag, contentStart);
  if (end === -1) return null;
  return xml.slice(contentStart, end);
}

/**
 * Splits a section's inner XML into its top-level `<tagName>...</tagName>`
 * blocks by tracking nesting depth (rather than matching the first closing
 * tag found), so an item whose own fields contain a nested list of the same
 * tag name doesn't get truncated at that inner list's first closing tag.
 *
 * EC2's Query-protocol dialect repeats `<item>` for every list member
 * (reservationSet/item, instancesSet/item, ...), which is what the default
 * covers. Other Query-protocol services don't share that convention — IAM
 * repeats `<member>` (ListUsersResult/Users/member), RDS repeats a
 * type-named tag (DescribeDBInstancesResult/DBInstances/DBInstance) — so
 * the repeated tag name is a parameter here, not hardcoded.
 */
export function extractListItems(sectionXml: string | null, tagName = 'item'): string[] {
  if (!sectionXml) return [];
  const items: string[] = [];
  const tagPattern = new RegExp(`<(/?)${tagName}(?:\\s[^>]*)?>`, 'g');
  let depth = 0;
  let itemStart = -1;
  let match: RegExpExecArray | null;
  while ((match = tagPattern.exec(sectionXml)) !== null) {
    const isClosing = match[1] === '/';
    if (!isClosing) {
      if (depth === 0) itemStart = match.index + match[0].length;
      depth++;
    } else {
      depth--;
      if (depth === 0 && itemStart !== -1) {
        items.push(sectionXml.slice(itemStart, match.index));
        itemStart = -1;
      }
    }
  }
  return items;
}

/** `<tag>value</tag>` -> "value", or null if absent/self-closing. Only looks at direct text content, not nested tags with the same name deeper in the item. */
export function field(xml: string, tag: string): string | null {
  const match = new RegExp(`<${tag}>([^<]*)</${tag}>`).exec(xml);
  return match ? decodeXmlEntities(match[1]) : null;
}

function decodeXmlEntities(s: string): string {
  return s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&apos;/g, "'").replace(/&amp;/g, '&');
}

/** `<tagSet><item><key>Name</key><value>x</value></item></tagSet>` -> { Name: 'x' }. */
export function tagsFromSet(itemXml: string, setTag = 'tagSet'): Record<string, string> {
  const out: Record<string, string> = {};
  for (const item of extractListItems(extractSection(itemXml, setTag))) {
    const key = field(item, 'key');
    if (key) out[key] = field(item, 'value') ?? '';
  }
  return out;
}

export function boolField(xml: string, tag: string): boolean {
  return field(xml, tag) === 'true';
}

export function numField(xml: string, tag: string): number | undefined {
  const v = field(xml, tag);
  return v === null ? undefined : Number(v);
}
