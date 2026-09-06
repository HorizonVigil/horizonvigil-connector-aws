/**
 * Parsers for Kubernetes `resource.Quantity` strings -- the real format the
 * K8s API returns for CPU/memory requests, limits, node capacity, and node
 * allocatable (see https://kubernetes.io/docs/reference/kubernetes-api/common-definitions/quantity/).
 * Used by k8sCostAllocation.ts to turn eksWorkloads.ts's raw captured
 * strings into comparable numbers. Both parsers return `null` (never 0) for
 * missing/malformed input -- a pod with no CPU request has an UNKNOWN
 * allocation share, not a zero one, and the caller must treat that
 * distinction as "exclude this pod from allocation," not "this pod costs
 * nothing."
 */

/**
 * CPU quantities are either a bare number of cores ("1", "0.5") or a
 * millicore count suffixed with "m" ("500m", "250m"). Returns millicores.
 */
export function parseCpuMillicores(q?: string | null): number | null {
  if (q == null) return null;
  const s = q.trim();
  if (s === '') return null;
  if (s.endsWith('m')) {
    const n = Number(s.slice(0, -1));
    return Number.isFinite(n) && n >= 0 ? n : null;
  }
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n * 1000 : null;
}

// Binary (power-of-1024) and decimal (power-of-1000) suffixes, per the K8s
// quantity spec -- Ki/Mi/Gi/Ti/Pi/Ei are binary, K/M/G/T/P/E (K8s allows a
// bare "K" though the spec technically only defines "k" for decimal -- both
// are accepted here since real clusters emit both) are decimal. Longest
// suffix first so "Ki" doesn't get shadowed by a "K"-prefix check.
const MEMORY_SUFFIXES: [string, number][] = [
  ['Ei', 1024 ** 6], ['Pi', 1024 ** 5], ['Ti', 1024 ** 4], ['Gi', 1024 ** 3], ['Mi', 1024 ** 2], ['Ki', 1024],
  ['E', 1000 ** 6], ['P', 1000 ** 5], ['T', 1000 ** 4], ['G', 1000 ** 3], ['M', 1000 ** 2], ['K', 1000], ['k', 1000],
];

/** Memory quantities are a bare byte count or a byte count with a binary/decimal suffix ("512Mi", "1Gi", "1000000"). Returns bytes. */
export function parseMemoryBytes(q?: string | null): number | null {
  if (q == null) return null;
  const s = q.trim();
  if (s === '') return null;
  for (const [suffix, multiplier] of MEMORY_SUFFIXES) {
    if (s.endsWith(suffix)) {
      const n = Number(s.slice(0, -suffix.length));
      return Number.isFinite(n) && n >= 0 ? n * multiplier : null;
    }
  }
  const n = Number(s);
  return Number.isFinite(n) && n >= 0 ? n : null;
}
