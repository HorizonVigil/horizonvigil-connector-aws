import { extractSection, extractListItems } from '../xmlList';

/**
 * Small XML-shape helpers for the regex-based reader in xmlList.ts.
 *
 * `field(xml, name)` returns the FIRST <name> anywhere in `xml`, including
 * inside nested lists. When a nested child reuses a top-level element name
 * (an ASG instance's LaunchConfigurationName, a CloudFront cache behaviour's
 * TrustedSigners/Enabled, a stack Output's Description), reading the parent
 * directly returns the CHILD's value. Read top-level fields from
 * `withoutSections(parent, [...nested lists])` instead.
 */
export function withoutSections(xml: string, sections: readonly string[]): string {
  let out = xml;
  for (const s of sections) {
    // Remove every occurrence at this level, not just the first.
    for (let guard = 0; guard < 1000; guard++) {
      const inner = extractSection(out, s);
      if (inner === null) break;
      const full = `<${s}>${inner}</${s}>`;
      if (!out.includes(full)) {
        const selfClosing = `<${s}/>`;
        if (out.includes(selfClosing)) { out = out.replace(selfClosing, ''); continue; }
        break;
      }
      out = out.replace(full, '');
    }
  }
  return out;
}

/** `<section><member>text</member>…</section>` → trimmed strings. */
export function memberTexts(xml: string, section: string, itemTag = 'member'): string[] {
  return extractListItems(extractSection(xml, section), itemTag).map((s) => s.trim()).filter(Boolean);
}