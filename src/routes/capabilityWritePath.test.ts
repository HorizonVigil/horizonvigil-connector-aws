import { describe, it, expect } from 'vitest';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';

/**
 * Capability health must be written with the SERVICE ROLE.
 *
 * `connector_capability_status` has RLS enabled with a member-READ policy and
 * no insert policy. That is the correct design — capability health is evidence
 * about whether a connection works, and evidence a customer can write is not
 * evidence.
 *
 * The interactive validation route passed the caller's own db into the write,
 * so every insert was silently rejected by RLS. Measured in production on
 * 2026-09-15:
 *
 *   POST /accounts/{kamal}/permissions/validate
 *     -> { ok: true, status: 'succeeded', checks: 12 }
 *   select count(*) from connector_capability_status where connection = kamal
 *     -> 0
 *
 * The button reported success and wrote nothing, and the capabilities panel
 * kept saying the connection had never been evaluated. The only rows in the
 * table belonged to the other connection and were dated 09-09 — the weekly
 * SCHEDULED run, which alone uses the service role.
 *
 * Source-level because the defect is about WHICH CLIENT performs the write.
 * A behavioural test with a stubbed db would accept either one happily, which
 * is exactly why this shipped.
 */
const SOURCE = readFileSync(join(__dirname, 'permissions.ts'), 'utf8');

describe('capability status write path', () => {
  it('writes capability status with a service-role client', () => {
    expect(SOURCE).toMatch(/const statusDb = env\.SUPABASE_SERVICE_ROLE_KEY\s*\?\s*createDb\(env, env\.SUPABASE_SERVICE_ROLE_KEY\)/);
    expect(SOURCE).toMatch(/writeCapabilityStatuses\(\s*statusDb,/);
  });

  /**
   * The load-bearing negative, verbatim from the pre-fix source. Restoring the
   * caller's db fails here rather than silently writing nothing to production
   * again.
   */
  it('does not pass the caller db straight into the capability write', () => {
    expect(SOURCE).not.toMatch(/writeCapabilityStatuses\(\s*db,/);
  });

  /**
   * Still guarded on an org. A capability row is per-org, and writing one
   * without an org would put unattributable evidence in a shared table.
   */
  it('still requires an org before writing', () => {
    expect(SOURCE).toMatch(/if \(actor\?\.orgId\) \{/);
  });

  /**
   * A missing service key must degrade, not throw. It then writes nothing —
   * exactly the old behaviour — rather than taking a validation down.
   */
  it('falls back rather than throwing when no service key is configured', () => {
    expect(SOURCE).toMatch(/SUPABASE_SERVICE_ROLE_KEY\s*\?\s*createDb\([^)]*\)\s*:\s*db/);
  });
});
